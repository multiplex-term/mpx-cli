//! mpx — bind this machine to Multiplex.
//!
//! `mpx bind` publishes a two-minute bind offer over QR + optional clipboard +
//! Bonjour, then enrolls the app's public key over an encrypted handshake.
//! `mpx unbind` lists/removes keys mpx enrolled (matched by their
//! `multiplex:bind:` comment marker). MPX_BIND_TEST_* env hooks pin
//! randomness for the Multiplex dev harness and only weaken a bind the
//! operator deliberately staged.

use clap::{Args, Parser, Subcommand};
use mpx::server::{BindOutcome, OfferRecord, ServerEvent, SessionConfig};
use mpx::util::{self, device_slug, hex_decode};
use mpx::{authkeys, cancel, clip, hostinfo, payload, qr, server};
use rand_core::{OsRng, RngCore};
use ssh_key::{Algorithm, PrivateKey};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Parser)]
#[command(
    name = "mpx",
    version,
    about = "Companion CLI for Multiplex — bind this machine to the app"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Offer this machine to Multiplex: QR + local-network (+ --copy)
    /// announcement, then enroll the app's SSH key on confirmation.
    Bind(BindArgs),
    /// List or remove keys mpx enrolled in authorized_keys.
    Unbind(UnbindArgs),
}

#[derive(Args)]
struct BindArgs {
    /// No listener/handshake: generate a keypair here, install its public
    /// half, and put the private key IN the payload. For hosts the device
    /// can only reach over SSH itself (VPS behind a firewall). The app
    /// retires the transported key on first connect.
    #[arg(long)]
    offline: bool,
    /// Skip the terminal QR.
    #[arg(long)]
    no_qr: bool,
    /// Also put the payload on the clipboard — the platform tool locally,
    /// OSC 52 over SSH so Universal Clipboard carries it to the device.
    /// Off by default on purpose: this string is credential-grade, and
    /// taking someone's clipboard (and, with Universal Clipboard, every
    /// signed-in device's) is not something a bind offer should do unasked.
    #[arg(long)]
    copy: bool,
    /// Skip the Bonjour announcement.
    #[arg(long)]
    no_announce: bool,
    /// Enroll without the interactive [Y/n] confirmation.
    #[arg(long)]
    yes: bool,
    /// Name shown in the app (default: this machine's hostname).
    #[arg(long)]
    name: Option<String>,
    /// SSH username the app should connect as (default: current user).
    #[arg(long)]
    user: Option<String>,
    /// SSH port the app should connect to.
    #[arg(long, default_value_t = 22)]
    ssh_port: u16,
    /// Address the app should reach this machine at, replacing the detected
    /// interface addresses. Repeatable, tried in order. For hosts whose
    /// reachable address isn't one of their own interfaces — behind NAT, a
    /// tunnel, or a port forward.
    #[arg(long = "addr")]
    addrs: Vec<String>,
    /// Seconds this offer stays valid (max 600).
    ///
    /// Shorter is better hygiene: it bounds how long an unattended `mpx bind`
    /// sits announcing. It is not the control that authenticates the peer,
    /// so do not reach for it as one. Raise it for a slow hand-off —
    /// re-running the command is the cheap recovery.
    #[arg(long, default_value_t = 60)]
    expires: u64,
    /// Handshake listener port (default: OS-assigned).
    #[arg(long, default_value_t = 0)]
    listen_port: u16,
    /// authorized_keys file to enroll into (default: ~/.ssh/authorized_keys;
    /// for sshds running with a custom AuthorizedKeysFile).
    #[arg(long)]
    authorized_keys: Option<PathBuf>,
    /// Directory holding ssh_host_*_key.pub files (default: /etc/ssh).
    #[arg(long, default_value = "/etc/ssh")]
    hostkeys_dir: PathBuf,
}

#[derive(Args)]
struct UnbindArgs {
    /// The 8-hex id shown by --list.
    id: Option<String>,
    /// Remove every key mpx enrolled.
    #[arg(long)]
    all: bool,
    /// List enrolled keys and exit.
    #[arg(long)]
    list: bool,
    #[arg(long)]
    authorized_keys: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Bind(args) => bind(args),
        Command::Unbind(args) => unbind(args),
    };
    std::process::exit(code);
}

/// The `MPX_BIND_TEST_*` hooks ship in the release binary because that is the
/// binary the Multiplex dev harness drives. The risk they carry is not an
/// attacker setting them — anyone who can write this process's environment
/// can already run anything as this user — it is one of them *outliving* the
/// harness in a shell rc and quietly weakening a bind someone meant to be
/// real: `MPX_BIND_TEST_YES` enrols whoever asks first with no prompt at all,
/// and a pinned token or session seed makes the offer forgeable by anyone who
/// has read the fixture. So none of them take effect silently.
fn warn_about_test_hooks() {
    const HOOKS: [(&str, &str); 4] = [
        (
            "MPX_BIND_TEST_SESSION_SEED",
            "session key is fixed, not random",
        ),
        ("MPX_BIND_TEST_TOKEN", "token is fixed, not random"),
        ("MPX_BIND_TEST_PIN", "PIN is fixed, not random"),
        (
            "MPX_BIND_TEST_YES",
            "enrollment skips the confirmation prompt",
        ),
    ];
    let active: Vec<&(&str, &str)> = HOOKS
        .iter()
        .filter(|(var, _)| match *var {
            // Only `=1` actually bypasses the prompt; say so for that value
            // and no other, or the warning starts crying wolf.
            "MPX_BIND_TEST_YES" => std::env::var(var).as_deref() == Ok("1"),
            _ => std::env::var_os(var).is_some(),
        })
        .collect();
    if active.is_empty() {
        return;
    }
    util::warn("test hooks are set — this bind is NOT secure:");
    for (var, effect) in active {
        util::warn(&format!("    {var}: {effect}"));
    }
    util::warn("    unset them before binding a machine you care about");
}

fn bind(args: BindArgs) -> i32 {
    warn_about_test_hooks();
    let name = args.name.clone().unwrap_or_else(hostinfo::machine_name);
    let user = args
        .user
        .clone()
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "root".into());
    let addrs = if args.addrs.is_empty() {
        hostinfo::local_addrs()
    } else {
        args.addrs.clone()
    };
    let hostkeys = hostinfo::host_key_fingerprints(&args.hostkeys_dir);
    let authorized_keys = args
        .authorized_keys
        .clone()
        .unwrap_or_else(authkeys::default_path);

    let addr_summary = if addrs.is_empty() {
        "no LAN address".to_string()
    } else {
        addrs.join(", ")
    };
    println!(
        "● multiplex bind · {name} ({addr_summary} · ssh :{} · user {user})",
        args.ssh_port
    );
    match hostkeys.first() {
        Some(first) => util::ok(&format!("host keys read — {first}")),
        None => util::warn(&format!(
            "no host keys under {} — the app will connect unpinned",
            args.hostkeys_dir.display()
        )),
    }

    if args.offline {
        return bind_offline(&args, &name, &user, addrs, &authorized_keys);
    }

    // Session material — MPX_BIND_TEST_* pins it for the dev harness.
    let secret = match test_env_bytes::<32>("MPX_BIND_TEST_SESSION_SEED") {
        Some(seed) => StaticSecret::from(seed),
        None => StaticSecret::random_from_rng(OsRng),
    };
    let spub = PublicKey::from(&secret).to_bytes();
    let token = test_env_bytes::<16>("MPX_BIND_TEST_TOKEN").unwrap_or_else(|| {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        bytes
    });
    let pin = std::env::var("MPX_BIND_TEST_PIN").unwrap_or_else(|_| {
        let mut bytes = [0u8; 4];
        OsRng.fill_bytes(&mut bytes);
        format!("{:06}", u32::from_be_bytes(bytes) % 1_000_000)
    });

    let listener = match TcpListener::bind(("0.0.0.0", args.listen_port)) {
        Ok(listener) => listener,
        Err(err) => {
            util::warn(&format!(
                "cannot listen on port {}: {err}",
                args.listen_port
            ));
            return 1;
        }
    };
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);

    let bind_payload = payload::Payload {
        addrs: parsed_addrs(&addrs),
        port,
        spub,
        token,
        name: name.clone(),
        offline: None,
    };
    let url = bind_payload.to_url();

    let announcer = if args.no_announce {
        None
    } else {
        match mpx::announce::Announcer::start(&mpx::announce::AnnounceConfig {
            instance: name.clone(),
            port,
            spub,
            ssh_user: user.clone(),
            ssh_port: args.ssh_port,
            first_fingerprint: hostkeys.first().cloned(),
        }) {
            Ok(announcer) => {
                util::ok("announcing on your network — visible to Multiplex nearby");
                Some(announcer)
            }
            Err(err) => {
                util::warn(&format!(
                    "announce unavailable ({err}) — QR, clipboard, and PIN still work"
                ));
                None
            }
        }
    };

    let expires = args.expires.clamp(10, 600);
    let panel = vec![
        String::new(),
        "scan with Multiplex on iPhone".into(),
        "or iPad, or confirm the PIN".into(),
        "it discovers on your network:".into(),
        String::new(),
        format!("PIN  {}", spaced_digits(&pin)),
        String::new(),
        format!(
            "expires in {}:{:02} · single use",
            expires / 60,
            expires % 60
        ),
    ];
    publish_payload(&url, args.copy, args.no_qr, &panel);
    println!();
    util::wait("waiting for Multiplex…  (Ctrl-C cancels)");
    // Only while a discovery answer is on the network. The QR and clipboard
    // payloads carry this machine's session key, so an app holding one is
    // already talking to *this* process and nothing else can answer for it. A
    // PIN typed against a discovered row has no such guarantee — mDNS
    // authenticates nothing — and the check that survives that gap is the one
    // below: the enrollment happens HERE, or it did not happen to this machine.
    if announcer.is_some() {
        util::note(
            "this terminal confirms the bind — if Multiplex reports success and nothing \
             appears here,\n  it enrolled somewhere else: Ctrl-C, delete that host in the \
             app, and prefer the QR.",
        );
    }

    let config = SessionConfig {
        secret,
        spub,
        token,
        pin,
        deadline: Instant::now() + Duration::from_secs(expires),
        offer: OfferRecord {
            name: name.clone(),
            addrs,
            user: user.clone(),
            ssh_port: args.ssh_port,
            hostkeys,
        },
        authorized_keys: authorized_keys.clone(),
        marker_id: format!("{}{}", authkeys::MARKER_PREFIX, random_id8()),
    };

    let auto_yes = args.yes || std::env::var("MPX_BIND_TEST_YES").as_deref() == Ok("1");
    let confirm = |device: &str| -> bool {
        let display = if device.is_empty() {
            "A device"
        } else {
            device
        };
        if auto_yes {
            println!("→ {display} asks to bind as {user}@{name} — enrolling (--yes)");
            return true;
        }
        confirm_on_tty(&format!(
            "→ {display} asks to bind as {user}@{name} — enroll? [Y/n] "
        ))
    };
    let progress = |event: ServerEvent| match event {
        ServerEvent::WrongPin { remaining } => {
            util::warn(&format!("wrong PIN ({remaining} tries left)"));
        }
        ServerEvent::PinRetired => {
            util::warn("too many wrong PINs — PIN entry is off for this offer");
            util::note("  the QR still works; re-run `mpx bind` for a fresh PIN");
        }
    };

    // From here on the process owns an mDNS registration, so a signal must
    // unwind rather than kill: otherwise every browsing device keeps showing
    // this offer long after it stopped listening.
    cancel::install();
    let outcome = server::run(&listener, &config, &confirm, &progress);
    if let Some(announcer) = announcer {
        announcer.stop();
    }
    match outcome {
        BindOutcome::Enrolled {
            device: _,
            comment,
            acknowledged,
        } => {
            util::ok(&format!(
                "key enrolled → {} ({comment})",
                authorized_keys.display()
            ));
            if !acknowledged {
                // The key is enrolled either way, so the operator has to hear
                // about it — silence here is how a key stays on disk without
                // anyone knowing it arrived.
                util::warn("the device never acknowledged it — if this wasn't your device,");
                util::warn(&format!(
                    "  remove it with `mpx unbind {}`",
                    marker_id8(&comment)
                ));
            }
            util::ok(&format!("bound. Multiplex has {name} on the wall."));
            0
        }
        BindOutcome::Expired => {
            util::warn("offer expired with no bind — run `mpx bind` again");
            2
        }
        BindOutcome::Declined => {
            util::note("declined — nothing was enrolled");
            1
        }
        BindOutcome::Canceled => {
            util::note("canceled — nothing was enrolled");
            130
        }
    }
}

fn bind_offline(
    args: &BindArgs,
    name: &str,
    user: &str,
    addrs: Vec<String>,
    authorized_keys: &std::path::Path,
) -> i32 {
    let mut rng = OsRng;
    let key = match PrivateKey::random(&mut rng, Algorithm::Ed25519) {
        Ok(key) => key,
        Err(err) => {
            util::warn(&format!("keygen failed: {err}"));
            return 1;
        }
    };
    let public = match key.public_key().to_openssh() {
        Ok(text) => text,
        Err(err) => {
            util::warn(&format!("keygen failed: {err}"));
            return 1;
        }
    };
    // The payload carries the raw 32-byte seed, not the armored OpenSSH text
    // it would otherwise take ~370 bytes to spell: the app derives the
    // identical key from it, and those bytes are QR modules.
    let seed: [u8; 32] = match key.key_data().ed25519() {
        Some(keypair) => keypair.private.to_bytes(),
        None => {
            util::warn("keygen produced a non-ed25519 key");
            return 1;
        }
    };
    let mut fields = public.split_whitespace();
    let (Some(key_type), Some(key_b64)) = (fields.next(), fields.next()) else {
        util::warn("keygen produced an unreadable public key");
        return 1;
    };
    let comment = format!(
        "{}{}:{}",
        authkeys::MARKER_PREFIX,
        random_id8(),
        device_slug(name)
    );
    if let Err(err) = authkeys::ensure_line(authorized_keys, key_type, key_b64, &comment) {
        util::warn(&format!(
            "could not write {}: {err}",
            authorized_keys.display()
        ));
        return 1;
    }
    util::ok(&format!(
        "keypair generated · public key installed → {} ({comment})",
        authorized_keys.display()
    ));

    let bind_payload = payload::Payload {
        addrs: parsed_addrs(&addrs),
        port: 0,
        spub: [0; 32],
        token: [0; 16],
        name: name.into(),
        offline: Some(payload::OfflineKey {
            ssh_user: user.into(),
            ssh_port: args.ssh_port,
            seed,
            // Only worth carrying when it is not the default the app assumes.
            authorized_keys: args
                .authorized_keys
                .as_ref()
                .map(|path| path.display().to_string()),
            hostkey_sha256: hostinfo::ed25519_host_key_digest(&args.hostkeys_dir),
        }),
    };
    let url = bind_payload.to_url();
    util::warn("this payload CONTAINS a private key — treat the QR and clipboard like a password");
    let panel = vec![
        String::new(),
        "scan or paste this in Multiplex.".into(),
        "It works over SSH alone — no".into(),
        "local network needed.".into(),
        String::new(),
        "The app replaces this key with".into(),
        "one of its own as soon as it".into(),
        "connects.".into(),
    ];
    publish_payload(&url, args.copy, args.no_qr, &panel);
    0
}

/// Prints the offer. `panel` rides to the RIGHT of the QR when both fit an
/// 80-column terminal, so the code and the PIN it belongs to are read as one
/// object and the whole offer stays on one screen; otherwise the panel goes
/// underneath, which always fits.
fn publish_payload(url: &str, copy: bool, no_qr: bool, panel: &[String]) {
    if copy {
        match clip::copy(url) {
            clip::CopyOutcome::Copied(method) => {
                util::ok(&format!("payload copied to clipboard ({method})"));
                if let Some(hint) = clip::tmux_passthrough_hint() {
                    util::note(&format!("  {hint}"));
                }
            }
            clip::CopyOutcome::Failed => {
                util::warn("clipboard unavailable — scan the QR or copy the line below");
                println!("{url}");
            }
        }
    }
    let art = if no_qr { None } else { qr::render(url) };
    if !no_qr && art.is_none() {
        util::warn("payload too large for a QR — use the clipboard");
        println!("{url}");
    }
    match art {
        Some(art) => {
            println!();
            let widest = panel
                .iter()
                .map(|line| line.chars().count())
                .max()
                .unwrap_or(0);
            if qr::width(&art) + 2 + widest <= 80 {
                print_side_by_side(&art, panel);
            } else {
                println!("{art}");
                for line in panel {
                    println!("  {line}");
                }
            }
        }
        None => {
            for line in panel {
                println!("  {line}");
            }
        }
    }
    if !copy && no_qr {
        println!("{url}");
    }
    if !copy {
        // Say it here rather than let someone press a dead Paste button in
        // the app: without this flag nothing reached any clipboard.
        util::note("clipboard untouched — re-run with --copy to paste this into Multiplex");
    }
}

fn print_side_by_side(art: &str, panel: &[String]) {
    let rows: Vec<&str> = art.lines().collect();
    let width = qr::width(art);
    // Vertically centre the panel against the code.
    let top = rows.len().saturating_sub(panel.len()) / 2;
    for (index, row) in rows.iter().enumerate() {
        let pad = width - row.chars().count();
        match index.checked_sub(top).and_then(|i| panel.get(i)) {
            Some(line) if !line.is_empty() => {
                println!("{row}{:pad$}  {line}", "", pad = pad)
            }
            _ => println!("{row}"),
        }
    }
}

fn parsed_addrs(addrs: &[String]) -> Vec<std::net::IpAddr> {
    // Hostnames cannot ride the compact payload (it stores raw address
    // bytes); the app resolves nothing, it dials what it is given.
    addrs.iter().filter_map(|addr| addr.parse().ok()).collect()
}

fn unbind(args: UnbindArgs) -> i32 {
    let path = args
        .authorized_keys
        .clone()
        .unwrap_or_else(authkeys::default_path);
    // An unreadable file must not read as "nothing enrolled here" — that
    // answer looks exactly like a successful revocation.
    let keys = match authkeys::marked_keys(&path) {
        Ok(keys) => keys,
        Err(err) => {
            util::warn(&format!("could not read {}: {err}", path.display()));
            return 1;
        }
    };
    if args.list || (args.id.is_none() && !args.all) {
        if keys.is_empty() {
            util::note(&format!("no multiplex-enrolled keys in {}", path.display()));
        } else {
            for key in &keys {
                println!("{}  {:24}  {}", key.id, key.device, key.key_type);
            }
            if args.id.is_none() && !args.all && !args.list {
                util::note("remove one with `mpx unbind <id>` or all with `mpx unbind --all`");
            }
        }
        return 0;
    }
    let filter: Box<dyn Fn(&authkeys::MarkedKey) -> bool> = if args.all {
        Box::new(|_| true)
    } else {
        let id = args.id.clone().unwrap_or_default();
        Box::new(move |key: &authkeys::MarkedKey| key.id == id)
    };
    match authkeys::remove_marked(&path, filter) {
        Ok(removed) if removed.is_empty() => {
            util::warn("no matching enrolled key");
            1
        }
        Ok(removed) => {
            for key in removed {
                util::ok(&format!("removed {} ({})", key.id, key.device));
            }
            0
        }
        Err(err) => {
            util::warn(&format!("could not rewrite {}: {err}", path.display()));
            1
        }
    }
}

fn confirm_on_tty(prompt: &str) -> bool {
    let Ok(mut tty_out) = std::fs::OpenOptions::new().write(true).open("/dev/tty") else {
        util::warn("no terminal to confirm on — rerun with --yes to allow enrollment");
        return false;
    };
    let Ok(tty_in) = std::fs::File::open("/dev/tty") else {
        util::warn("no terminal to confirm on — rerun with --yes to allow enrollment");
        return false;
    };
    let _ = tty_out.write_all(prompt.as_bytes());
    let _ = tty_out.flush();
    let mut line = String::new();
    if BufReader::new(tty_in).read_line(&mut line).is_err() {
        return false;
    }
    let answer = line.trim().to_ascii_lowercase();
    answer.is_empty() || answer == "y" || answer == "yes"
}

/// The 8-hex id out of a `multiplex:bind:<id>:<slug>` comment — what
/// `mpx unbind` takes as its argument.
fn marker_id8(comment: &str) -> &str {
    comment
        .strip_prefix(authkeys::MARKER_PREFIX)
        .and_then(|rest| rest.split(':').next())
        .unwrap_or(comment)
}

fn spaced_digits(pin: &str) -> String {
    pin.chars()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn random_id8() -> String {
    let mut bytes = [0u8; 4];
    OsRng.fill_bytes(&mut bytes);
    util::hex(&bytes)
}

fn test_env_bytes<const N: usize>(var: &str) -> Option<[u8; N]> {
    let value = std::env::var(var).ok()?;
    let bytes = hex_decode(&value)?;
    bytes.as_slice().try_into().ok()
}
