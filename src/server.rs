//! The bind session's TCP side: accept connections until the deadline, run
//! the sealed HELLO → OFFER → ENROLL → DONE exchange, and write exactly one
//! authorized_keys line on success. Token failures close silently (128-bit
//! space needs no lockout and counting them would hand a spammer a DoS);
//! three wrong PINs retire the PIN for the rest of the offer, leaving the
//! QR's token serving — anyone can reach that counter, so it must bound
//! guessing without becoming a way to cancel someone's bind.

use crate::authkeys::{self, AddOutcome};
use crate::frame::{self, Channel, FrameError};
use ciborium::value::Value;
use ssh_key::PublicKey as SshPublicKey;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

pub const MAX_PIN_ATTEMPTS: u32 = 3;

/// How long an *unauthenticated* peer gets to send INTRO and HELLO.
///
/// Connections are served one at a time — the accept loop has to be serial
/// because the `[Y/n]` confirmation owns the terminal — so every second a
/// stranger keeps a socket open is a second the app cannot bind. Anyone on
/// the network can open one: the listener is on 0.0.0.0 and the offer
/// advertises the port. Keeping the pre-proof budget short bounds what that
/// costs. INTRO and HELLO need no human, so 5 s is slack even over a tunnel;
/// it is the *stall* that has to be cheap, not the round trip.
const PREAUTH_TIMEOUT: Duration = Duration::from_secs(5);

/// And how long an authenticated one gets per frame afterwards. Generous on
/// purpose: between OFFER and ENROLL the app is showing the host record to a
/// human, and 10 s of someone reading a fingerprint used to drop the
/// connection. A peer that reaches this has already proved the token or the
/// PIN, so the time it can hold is not an anonymous DoS.
const POSTAUTH_TIMEOUT: Duration = Duration::from_secs(120);

pub struct OfferRecord {
    pub name: String,
    pub addrs: Vec<String>,
    pub user: String,
    pub ssh_port: u16,
    pub hostkeys: Vec<String>,
}

pub struct SessionConfig {
    pub secret: StaticSecret,
    pub spub: [u8; 32],
    pub token: [u8; 16],
    pub pin: String,
    pub deadline: Instant,
    pub offer: OfferRecord,
    pub authorized_keys: PathBuf,
    /// `multiplex:bind:<uuid8>` — the device slug is appended per enrollment.
    pub marker_id: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BindOutcome {
    Enrolled {
        device: String,
        comment: String,
        /// Whether the client received the DONE frame. The key is on disk
        /// either way — see `ConnectionResult::Enrolled`.
        acknowledged: bool,
    },
    Expired,
    Declined,
    /// Ctrl-C (or SIGTERM). Returned rather than exiting on the spot so the
    /// caller still unregisters the Bonjour service — see `crate::cancel`.
    Canceled,
}

pub enum ServerEvent {
    WrongPin {
        remaining: u32,
    },
    /// The PIN is spent for this session; the QR's token still works.
    PinRetired,
}

enum ConnectionResult {
    Enrolled {
        device: String,
        comment: String,
        /// False when the write succeeded but DONE never reached the client.
        ///
        /// The key is enrolled at that point, so this cannot be reported as
        /// "nothing happened": doing so let a peer commit a key and then drop
        /// the connection, leaving the operator to watch a *different* client
        /// bind successfully while the first key sat in authorized_keys
        /// unmentioned. Enrollment is terminal the moment the file is
        /// written; delivery of the receipt is a separate fact.
        acknowledged: bool,
    },
    PinFailure,
    Declined,
    Ignore,
}

pub fn run(
    listener: &TcpListener,
    config: &SessionConfig,
    confirm: &dyn Fn(&str) -> bool,
    progress: &dyn Fn(ServerEvent),
) -> BindOutcome {
    listener
        .set_nonblocking(true)
        .expect("nonblocking accept is how the deadline is enforced");
    let mut pin_failures = 0u32;
    // Guessing the PIN stays bounded, but running out of guesses no longer
    // ends the offer: any peer could reach this counter without a token or a
    // PIN, so letting it cancel the bind handed the whole network a
    // three-packet off switch. Retire the PIN instead and keep serving the
    // QR's token, which is the path that was never in doubt.
    let mut pin_retired = false;
    loop {
        // Same tick that enforces the deadline notices a cancel, so Ctrl-C
        // leaves through the ordinary path and the goodbye packet goes out.
        if crate::cancel::requested() {
            return BindOutcome::Canceled;
        }
        if Instant::now() >= config.deadline {
            return BindOutcome::Expired;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_write_timeout(Some(PREAUTH_TIMEOUT));
                match handle(stream, config, confirm, pin_retired) {
                    ConnectionResult::Enrolled {
                        device,
                        comment,
                        acknowledged,
                    } => {
                        return BindOutcome::Enrolled {
                            device,
                            comment,
                            acknowledged,
                        };
                    }
                    ConnectionResult::PinFailure => {
                        pin_failures += 1;
                        if pin_failures >= MAX_PIN_ATTEMPTS {
                            if !pin_retired {
                                pin_retired = true;
                                progress(ServerEvent::PinRetired);
                            }
                        } else {
                            progress(ServerEvent::WrongPin {
                                remaining: MAX_PIN_ATTEMPTS - pin_failures,
                            });
                        }
                    }
                    ConnectionResult::Declined => return BindOutcome::Declined,
                    ConnectionResult::Ignore => {}
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn handle(
    stream: TcpStream,
    config: &SessionConfig,
    confirm: &dyn Fn(&str) -> bool,
    pin_retired: bool,
) -> ConnectionResult {
    match exchange(&stream, config, confirm, pin_retired) {
        Ok(result) => result,
        Err(_) => ConnectionResult::Ignore,
    }
}

/// A reader that bounds the whole exchange rather than each syscall.
///
/// A socket read timeout restarts every time a read makes *any* progress, so
/// a peer trickling one byte at a time satisfied a 5-second "timeout"
/// forever, and connections are served one at a time. Recomputing the
/// remaining budget before every read turns that into a real deadline: the
/// slow peer gets exactly its window and no more.
struct Deadlined<'a> {
    stream: &'a TcpStream,
    deadline: Instant,
}

impl std::io::Read for Deadlined<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "exchange deadline reached",
            ));
        }
        self.stream.set_read_timeout(Some(remaining))?;
        std::io::Read::read(&mut &*self.stream, buf)
    }
}

fn read_by(stream: &TcpStream, deadline: Instant) -> Result<Vec<u8>, FrameError> {
    frame::read_frame(&mut Deadlined { stream, deadline })
}

fn write_to(stream: &TcpStream, frame: &[u8]) -> Result<(), FrameError> {
    frame::write_frame(&mut { stream }, frame)
}

/// The offer's own expiry, never exceeded by a per-phase budget. An offer
/// that says it lasts two minutes must not enroll a key in its third.
fn phase_deadline(config: &SessionConfig, budget: Duration) -> Instant {
    (Instant::now() + budget).min(config.deadline)
}

fn exchange(
    stream: &TcpStream,
    config: &SessionConfig,
    confirm: &dyn Fn(&str) -> bool,
    pin_retired: bool,
) -> Result<ConnectionResult, FrameError> {
    // One deadline for INTRO *and* HELLO together, so a stranger's whole
    // pre-authentication window is 5 s no matter how it paces its bytes.
    let preauth = phase_deadline(config, PREAUTH_TIMEOUT);

    // Cleartext intro: {v, epub, mode}.
    let intro = frame::decode(&read_by(stream, preauth)?)?;
    let version = match frame::map_get(&intro, "v") {
        Some(Value::Integer(i)) => u64::try_from(*i).unwrap_or(0),
        _ => 0,
    };
    if version != 1 {
        return Ok(ConnectionResult::Ignore);
    }
    let epub: [u8; 32] = frame::get_bytes(&intro, "epub")
        .and_then(|b| b.as_slice().try_into().ok())
        .ok_or(FrameError::Malformed)?;
    let mode = frame::get_text(&intro, "mode").ok_or(FrameError::Malformed)?;

    let shared = config.secret.diffie_hellman(&PublicKey::from(epub));
    // A low-order `epub` drives the shared secret to a constant, which makes
    // the channel keys a public function of epub‖spub — anyone watching the
    // wire could then read the OFFER and the ENROLL. It cannot forge the
    // token or the PIN proof, so this is not how someone gets in, but there
    // is no legitimate client that sends one, and a session that would be
    // readable in transit is not one to continue.
    if !shared.was_contributory() {
        return Ok(ConnectionResult::Ignore);
    }
    let mut channel = Channel::derive(shared.as_bytes(), &epub, &config.spub);

    // Sealed HELLO: {proof}.
    let hello = frame::decode(&channel.open_c2s(&read_by(stream, preauth)?)?)?;
    let proof = frame::get_bytes(&hello, "proof").ok_or(FrameError::Malformed)?;
    let authorized = match mode.as_str() {
        "token" => proof.ct_eq(&config.token).into(),
        "pin" if pin_retired => {
            let _ = send_done(stream, &mut channel, Err("pin retired for this offer"));
            return Ok(ConnectionResult::Ignore);
        }
        "pin" => {
            let expected = frame::pin_proof(&config.pin, &epub, &config.spub);
            let good: bool = proof.ct_eq(&expected).into();
            if !good {
                let _ = send_done(stream, &mut channel, Err("wrong pin"));
                return Ok(ConnectionResult::PinFailure);
            }
            true
        }
        _ => return Ok(ConnectionResult::Ignore),
    };
    if !authorized {
        return Ok(ConnectionResult::Ignore);
    }
    // Proof accepted — this peer has earned the longer clock for *reads*,
    // still bounded by the offer's own expiry. The write timeout is not
    // deadline-capped: DONE is a few dozen bytes, and an expired offer is
    // precisely when the client most needs to be told why.
    let postauth = phase_deadline(config, POSTAUTH_TIMEOUT);
    let _ = stream.set_write_timeout(Some(POSTAUTH_TIMEOUT));

    // OFFER: the host record the app will save.
    let offer = Value::Map(vec![
        (frame::text("name"), frame::text(&config.offer.name)),
        (
            frame::text("addrs"),
            Value::Array(config.offer.addrs.iter().map(|a| frame::text(a)).collect()),
        ),
        (
            frame::text("ssh"),
            Value::Map(vec![
                (frame::text("user"), frame::text(&config.offer.user)),
                (
                    frame::text("port"),
                    Value::Integer(config.offer.ssh_port.into()),
                ),
                (
                    frame::text("hostkeys"),
                    Value::Array(
                        config
                            .offer
                            .hostkeys
                            .iter()
                            .map(|k| frame::text(k))
                            .collect(),
                    ),
                ),
            ]),
        ),
    ]);
    let sealed = channel.seal_s2c(&frame::encode(&offer));
    write_to(stream, &sealed)?;

    // ENROLL: {pubkey, device}.
    let enroll = frame::decode(&channel.open_c2s(&read_by(stream, postauth)?)?)?;
    let pubkey_line = frame::get_text(&enroll, "pubkey").ok_or(FrameError::Malformed)?;
    let device_raw = frame::get_text(&enroll, "device").unwrap_or_default();
    let device: String = device_raw
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();

    let Ok(parsed) = SshPublicKey::from_openssh(pubkey_line.trim()) else {
        let _ = send_done(stream, &mut channel, Err("unparseable public key"));
        return Ok(ConnectionResult::Ignore);
    };
    if !parsed.algorithm().as_str().contains("ed25519") {
        let _ = send_done(stream, &mut channel, Err("only ed25519 keys are accepted"));
        return Ok(ConnectionResult::Ignore);
    }

    // The offer's clock is checked again on both sides of the prompt. A
    // credential holder who connected a second before expiry could otherwise
    // sit in the handshake and enroll well after the countdown the operator
    // was shown reached zero.
    if Instant::now() >= config.deadline {
        let _ = send_done(stream, &mut channel, Err("offer expired"));
        return Ok(ConnectionResult::Ignore);
    }
    if !confirm(&device) {
        let _ = send_done(stream, &mut channel, Err("declined on the host"));
        return Ok(ConnectionResult::Declined);
    }
    if Instant::now() >= config.deadline {
        let _ = send_done(stream, &mut channel, Err("offer expired"));
        return Ok(ConnectionResult::Ignore);
    }

    // Canonical two fields from the parsed key; client comments never land.
    let canonical = parsed.to_openssh().map_err(|_| FrameError::Malformed)?;
    let mut fields = canonical.split_whitespace();
    let (Some(key_type), Some(key_b64)) = (fields.next(), fields.next()) else {
        return Err(FrameError::Malformed);
    };
    let comment = format!("{}:{}", config.marker_id, crate::util::device_slug(&device));
    let comment = match authkeys::ensure_line(&config.authorized_keys, key_type, key_b64, &comment)
    {
        Ok(AddOutcome::Added) => comment,
        Ok(AddOutcome::AlreadyPresent { comment: existing }) => existing,
        Err(err) => {
            let message = format!("could not write authorized_keys: {err}");
            let _ = send_done(stream, &mut channel, Err(&message));
            return Ok(ConnectionResult::Ignore);
        }
    };

    // Past this line the key is on disk. Whether the receipt arrives is the
    // client's problem; reporting it as a failed connection would be a lie
    // the operator acts on.
    let acknowledged = send_done(stream, &mut channel, Ok(&comment)).is_ok();
    Ok(ConnectionResult::Enrolled {
        device,
        comment,
        acknowledged,
    })
}

fn send_done(
    stream: &TcpStream,
    channel: &mut Channel,
    result: Result<&str, &str>,
) -> Result<(), FrameError> {
    let body = match result {
        Ok(comment) => Value::Map(vec![
            (frame::text("ok"), Value::Bool(true)),
            (frame::text("comment"), frame::text(comment)),
        ]),
        Err(message) => Value::Map(vec![
            (frame::text("ok"), Value::Bool(false)),
            (frame::text("err"), frame::text(message)),
        ]),
    };
    let sealed = channel.seal_s2c(&frame::encode(&body));
    write_to(stream, &sealed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{pin_proof, read_frame, write_frame};
    use std::net::TcpStream;

    fn test_config(dir: &std::path::Path) -> SessionConfig {
        let secret = StaticSecret::from([0x11u8; 32]);
        let spub = PublicKey::from(&secret).to_bytes();
        SessionConfig {
            secret,
            spub,
            token: [0x22; 16],
            pin: "482163".into(),
            deadline: Instant::now() + Duration::from_secs(10),
            offer: OfferRecord {
                name: "devbox".into(),
                addrs: vec!["192.168.1.24".into()],
                user: "jhen".into(),
                ssh_port: 2222,
                hostkeys: vec!["ssh-ed25519 SHA256:testfp".into()],
            },
            authorized_keys: dir.join("authorized_keys"),
            marker_id: "multiplex:bind:9f3a1c2e".into(),
        }
    }

    fn client_pubkey() -> String {
        let mut rng = rand_core::OsRng;
        let key = ssh_key::PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519).unwrap();
        key.public_key().to_openssh().unwrap()
    }

    struct Client {
        stream: TcpStream,
        channel: Channel,
        epub: [u8; 32],
        spub: [u8; 32],
    }

    impl Client {
        fn connect(port: u16, spub: [u8; 32]) -> Self {
            let eph = StaticSecret::from([0x33u8; 32]);
            let epub = PublicKey::from(&eph).to_bytes();
            let shared = eph.diffie_hellman(&PublicKey::from(spub));
            let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let intro = Value::Map(vec![
                (frame::text("v"), Value::Integer(1.into())),
                (frame::text("epub"), Value::Bytes(epub.to_vec())),
                (frame::text("mode"), frame::text("token")),
            ]);
            write_frame(&mut stream, &frame::encode(&intro)).unwrap();
            Client {
                stream,
                channel: Channel::derive(shared.as_bytes(), &epub, &spub),
                epub,
                spub,
            }
        }

        fn connect_pin(port: u16, spub: [u8; 32], pin: &str) -> Self {
            let eph = StaticSecret::from([0x44u8; 32]);
            let epub = PublicKey::from(&eph).to_bytes();
            let shared = eph.diffie_hellman(&PublicKey::from(spub));
            let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let intro = Value::Map(vec![
                (frame::text("v"), Value::Integer(1.into())),
                (frame::text("epub"), Value::Bytes(epub.to_vec())),
                (frame::text("mode"), frame::text("pin")),
            ]);
            write_frame(&mut stream, &frame::encode(&intro)).unwrap();
            let mut client = Client {
                stream,
                channel: Channel::derive(shared.as_bytes(), &epub, &spub),
                epub,
                spub,
            };
            let proof = pin_proof(pin, &client.epub, &client.spub);
            client.send(&Value::Map(vec![(
                frame::text("proof"),
                Value::Bytes(proof.to_vec()),
            )]));
            client
        }

        fn send(&mut self, body: &Value) {
            let sealed = self.channel.seal_c2s(&frame::encode(body));
            write_frame(&mut self.stream, &sealed).unwrap();
        }

        fn receive(&mut self) -> Value {
            let sealed = read_frame(&mut self.stream).unwrap();
            frame::decode(&self.channel.open_s2c(&sealed).unwrap()).unwrap()
        }
    }

    #[test]
    fn token_handshake_enrolls_once() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let spub = config.spub;
        let token = config.token;
        let pubkey = client_pubkey();
        let pubkey_for_client = pubkey.clone();

        let client_thread = std::thread::spawn(move || {
            let mut client = Client::connect(port, spub);
            client.send(&Value::Map(vec![(
                frame::text("proof"),
                Value::Bytes(token.to_vec()),
            )]));
            let offer = client.receive();
            assert_eq!(frame::get_text(&offer, "name").unwrap(), "devbox");
            client.send(&Value::Map(vec![
                (frame::text("pubkey"), frame::text(&pubkey_for_client)),
                (frame::text("device"), frame::text("Jhen's Vision Pro")),
            ]));
            let done = client.receive();
            assert_eq!(frame::map_get(&done, "ok"), Some(&Value::Bool(true)));
            frame::get_text(&done, "comment").unwrap()
        });

        let outcome = run(
            &listener,
            &config,
            &|device| {
                assert_eq!(device, "Jhen's Vision Pro");
                true
            },
            &|_| {},
        );
        let comment = client_thread.join().unwrap();
        assert_eq!(
            outcome,
            BindOutcome::Enrolled {
                device: "Jhen's Vision Pro".into(),
                comment: "multiplex:bind:9f3a1c2e:jhen-s-vision-pro".into(),
                acknowledged: true,
            }
        );
        assert_eq!(comment, "multiplex:bind:9f3a1c2e:jhen-s-vision-pro");
        let written = std::fs::read_to_string(dir.path().join("authorized_keys")).unwrap();
        assert!(written.contains("multiplex:bind:9f3a1c2e:jhen-s-vision-pro"));
        assert!(written.starts_with("ssh-ed25519 "));
    }

    /// Three wrong PINs retire the PIN — they must not end the offer. Any
    /// peer can reach that counter without a token or a PIN, so ending the
    /// session on it handed the whole network a three-packet off switch.
    /// The QR's token has to keep working, and a fourth PIN attempt must not
    /// be answerable even by chance.
    #[test]
    fn three_wrong_pins_retire_the_pin_but_not_the_offer() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let spub = config.spub;
        let token = config.token;
        let pubkey = client_pubkey();

        let client_thread = std::thread::spawn(move || {
            for _ in 0..3 {
                let mut client = Client::connect_pin(port, spub, "000000");
                let done = client.receive();
                assert_eq!(frame::map_get(&done, "ok"), Some(&Value::Bool(false)));
            }
            // The *correct* PIN is refused now that it is retired.
            let mut late = Client::connect_pin(port, spub, "482163");
            let done = late.receive();
            assert_eq!(frame::map_get(&done, "ok"), Some(&Value::Bool(false)));
            assert_eq!(
                frame::get_text(&done, "err").unwrap(),
                "pin retired for this offer"
            );
            drop(late);

            // ...and the QR path still binds.
            let mut client = Client::connect(port, spub);
            client.send(&Value::Map(vec![(
                frame::text("proof"),
                Value::Bytes(token.to_vec()),
            )]));
            let _offer = client.receive();
            client.send(&Value::Map(vec![
                (frame::text("pubkey"), frame::text(&pubkey)),
                (frame::text("device"), frame::text("Jhen's Vision Pro")),
            ]));
            let done = client.receive();
            assert_eq!(frame::map_get(&done, "ok"), Some(&Value::Bool(true)));
        });

        let retired = std::cell::Cell::new(0u32);
        let outcome = run(&listener, &config, &|_| true, &|event| {
            if matches!(event, ServerEvent::PinRetired) {
                retired.set(retired.get() + 1);
            }
        });
        client_thread.join().unwrap();
        assert!(matches!(outcome, BindOutcome::Enrolled { .. }));
        assert_eq!(
            retired.get(),
            1,
            "the operator is told once, not per attempt"
        );
        let written = std::fs::read_to_string(dir.path().join("authorized_keys")).unwrap();
        assert!(written.starts_with("ssh-ed25519 "));
    }

    /// A key that reached authorized_keys is enrolled even if the client
    /// never reads DONE. Reporting the connection as a nothing-happened
    /// meant a peer could commit a key and vanish, and the operator would be
    /// told only about whichever client bound *next*.
    #[test]
    fn a_key_survives_a_client_that_hangs_up_before_done() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let spub = config.spub;
        let token = config.token;
        let pubkey = client_pubkey();

        let client_thread = std::thread::spawn(move || {
            let mut client = Client::connect(port, spub);
            client.send(&Value::Map(vec![(
                frame::text("proof"),
                Value::Bytes(token.to_vec()),
            )]));
            let _offer = client.receive();
            client.send(&Value::Map(vec![
                (frame::text("pubkey"), frame::text(&pubkey)),
                (frame::text("device"), frame::text("Ghost")),
            ]));
            // Gone before DONE can land.
            client
                .stream
                .shutdown(std::net::Shutdown::Both)
                .expect("shutdown");
        });

        let outcome = run(&listener, &config, &|_| true, &|_| {});
        client_thread.join().unwrap();
        match outcome {
            BindOutcome::Enrolled { device, .. } => assert_eq!(device, "Ghost"),
            other => panic!("expected the key to count as enrolled, got {other:?}"),
        }
        let written = std::fs::read_to_string(dir.path().join("authorized_keys")).unwrap();
        assert!(
            written.contains("multiplex:bind:9f3a1c2e:ghost"),
            "{written}"
        );
    }

    /// The offer's countdown is what the operator was shown. A peer that
    /// authenticated before it ran out must not enroll after — including
    /// when the offer expires while the operator is still at the prompt,
    /// which is the one path no read timeout can catch.
    #[test]
    fn an_offer_that_expires_at_the_prompt_enrolls_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config(dir.path());
        config.deadline = Instant::now() + Duration::from_millis(600);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let spub = config.spub;
        let token = config.token;
        let pubkey = client_pubkey();

        let client_thread = std::thread::spawn(move || {
            let mut client = Client::connect(port, spub);
            client.send(&Value::Map(vec![(
                frame::text("proof"),
                Value::Bytes(token.to_vec()),
            )]));
            let _offer = client.receive();
            client.send(&Value::Map(vec![
                (frame::text("pubkey"), frame::text(&pubkey)),
                (frame::text("device"), frame::text("Latecomer")),
            ]));
            let done = client.receive();
            assert_eq!(frame::map_get(&done, "ok"), Some(&Value::Bool(false)));
            assert_eq!(frame::get_text(&done, "err").unwrap(), "offer expired");
        });

        // The human takes longer to answer than the offer had left.
        let outcome = run(
            &listener,
            &config,
            &|_| {
                std::thread::sleep(Duration::from_millis(900));
                true
            },
            &|_| {},
        );
        client_thread.join().unwrap();
        assert_eq!(outcome, BindOutcome::Expired);
        assert!(!dir.path().join("authorized_keys").exists());
    }

    /// A low-order `epub` would make the channel keys derivable by anyone
    /// watching. The connection must be dropped, and the session must carry
    /// on for the real client.
    #[test]
    fn a_low_order_ephemeral_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let spub = config.spub;
        let token = config.token;
        let pubkey = client_pubkey();

        let client_thread = std::thread::spawn(move || {
            // The identity element: X25519 against it yields all zeros.
            let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let intro = Value::Map(vec![
                (frame::text("v"), Value::Integer(1.into())),
                (frame::text("epub"), Value::Bytes(vec![0u8; 32])),
                (frame::text("mode"), frame::text("token")),
            ]);
            write_frame(&mut stream, &frame::encode(&intro)).unwrap();
            // Whatever we send next, nothing comes back and the peer hangs up.
            let _ = write_frame(&mut stream, &[0u8; 32]);
            assert!(read_frame(&mut stream).is_err());
            drop(stream);

            let mut client = Client::connect(port, spub);
            client.send(&Value::Map(vec![(
                frame::text("proof"),
                Value::Bytes(token.to_vec()),
            )]));
            let _offer = client.receive();
            client.send(&Value::Map(vec![
                (frame::text("pubkey"), frame::text(&pubkey)),
                (frame::text("device"), frame::text("Jhen's Vision Pro")),
            ]));
            let done = client.receive();
            assert_eq!(frame::map_get(&done, "ok"), Some(&Value::Bool(true)));
        });

        let outcome = run(&listener, &config, &|_| true, &|_| {});
        client_thread.join().unwrap();
        assert!(matches!(outcome, BindOutcome::Enrolled { .. }));
    }

    #[test]
    fn declining_ends_the_session_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let spub = config.spub;
        let token = config.token;
        let pubkey = client_pubkey();

        let client_thread = std::thread::spawn(move || {
            let mut client = Client::connect(port, spub);
            client.send(&Value::Map(vec![(
                frame::text("proof"),
                Value::Bytes(token.to_vec()),
            )]));
            let _offer = client.receive();
            client.send(&Value::Map(vec![
                (frame::text("pubkey"), frame::text(&pubkey)),
                (frame::text("device"), frame::text("Stranger")),
            ]));
            let done = client.receive();
            assert_eq!(frame::map_get(&done, "ok"), Some(&Value::Bool(false)));
        });

        let outcome = run(&listener, &config, &|_| false, &|_| {});
        client_thread.join().unwrap();
        assert_eq!(outcome, BindOutcome::Declined);
        assert!(!dir.path().join("authorized_keys").exists());
    }
}
