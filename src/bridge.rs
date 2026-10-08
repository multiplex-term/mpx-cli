//! `mpx bridge` — the host end of Multiplex's agent browser.
//!
//! The Multiplex app starts this over its own SSH connection (a shell
//! channel without a PTY), so the bridge's stdin/stdout ARE the app. It then
//! serves a unix socket that agents on this machine reach through
//! `mpx browser …`. Nothing listens on TCP, and nothing needs sshd's port
//! forwarding: the socket lives in a 0700 directory, so only this user's
//! processes can drive the browser — the same trust boundary as their tmux
//! server.
//!
//! Wire (newline-delimited JSON, both legs):
//! - bridge → app, once: `{"mpx":"browser-bridge","v":1,…}` — the app skips
//!   anything before it (a login shell's rc files may print).
//! - bridge → app: `{"id":N,"method":"…","params":{…},"t":ms,"ttl":ms}` —
//!   `t` on the bridge's monotonic clock, `ttl` the client's timeout
//! - app → bridge: `{"id":N,"result":…}` or `{"id":N,"error":{…}}`
//! - app → bridge: `{"ping":N}`, answered `{"pong":N,"t":ms}` — how the app
//!   notices a dead SSH channel, and how it learns the bridge clock so a
//!   request read after a suspension can be judged stale by `t` + `ttl`.
//! - bridge → app: `{"cancel":N}` once request N timed out here, so an app
//!   that was suspended does not act on it late.
//! - client → bridge: `{"method":"…","params":{…},"timeout_ms":N}`, answered
//!   with `{"result":…}` or `{"error":{…}}`; several per connection.
//!
//! The bridge ends when its stdin does: the app closed the channel, went to
//! sleep long enough for the connection to drop, or was quit. The socket goes
//! with it, unless a newer bridge for the same device already replaced it.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const PROTOCOL_VERSION: u64 = 1;
pub const HELLO_TAG: &str = "browser-bridge";
/// How long a request waits for the app when the client names no timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// Ceiling on any client-requested timeout.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(600);

/// Longest line a client may send (a request is small; `fill` text and
/// `eval` source are the big ones).
pub const MAX_CLIENT_LINE: usize = 1 << 20;
/// Longest line the app may send — above its own 16 MiB answer cap.
pub const MAX_APP_LINE: usize = 24 << 20;
/// Clients served at once; more are turned away.
pub const MAX_CLIENTS: usize = 16;

pub fn socket_path(dir: &Path, device_slug: &str) -> PathBuf {
    dir.join(format!("browser-{device_slug}.sock"))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn error_value(code: &str, message: &str) -> Value {
    json!({ "code": code, "message": message })
}

struct Shared {
    device: String,
    slug: String,
    started_ms: u64,
    /// The bridge's monotonic clock, stamped on requests (`t`) and pongs
    /// (`t`) so the app can tell a request's age across its own suspension.
    clock: std::time::Instant,
    waiting: Mutex<HashMap<u64, mpsc::Sender<Value>>>,
    app: Mutex<Box<dyn Write + Send>>,
    next_id: AtomicU64,
}

impl Shared {
    /// The waiting clients by request id. A panicked holder cannot have
    /// left the map half-updated, so a poisoned lock is still usable.
    fn pending(&self) -> MutexGuard<'_, HashMap<u64, mpsc::Sender<Value>>> {
        self.waiting.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn write_app(&self, value: &Value) -> std::io::Result<()> {
        let mut app = self.app.lock().unwrap_or_else(|e| e.into_inner());
        crate::runtime::write_json_line(&mut *app, value)
    }

    fn clock_ms(&self) -> u64 {
        self.clock.elapsed().as_millis() as u64
    }

    fn info(&self, socket: &Path) -> Value {
        json!({
            "device": self.device,
            "slug": self.slug,
            "pid": std::process::id(),
            "started_ms": self.started_ms,
            "socket": socket.display().to_string(),
            "v": PROTOCOL_VERSION,
        })
    }

    /// One client request → the app, and the app's answer back. Returns the
    /// client-facing response object.
    fn forward(&self, method: &str, params: Value, timeout: Duration) -> Value {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        self.pending().insert(id, tx);
        let request = json!({
            "id": id,
            "method": method,
            "params": params,
            "t": self.clock_ms(),
            "ttl": timeout.as_millis() as u64,
        });
        if self.write_app(&request).is_err() {
            self.pending().remove(&id);
            return json!({ "error": error_value("disconnected", "Multiplex closed the bridge") });
        }
        match rx.recv_timeout(timeout) {
            Ok(mut answer) => match answer.get_mut("error").map(Value::take) {
                Some(error) => json!({ "error": error }),
                None => {
                    json!({ "result": answer.get_mut("result").map(Value::take).unwrap_or(Value::Null) })
                }
            },
            Err(_) => {
                self.pending().remove(&id);
                // A suspended app reads this request when it wakes; without
                // the cancel it would still run it then (a stale click).
                let _ = self.write_app(&json!({ "cancel": id }));
                json!({ "error": error_value(
                    "timeout",
                    &format!(
                        "Multiplex did not answer within {}s — the app may be in the background, \
                         locked, or asleep. Bring it to the front and retry.",
                        timeout.as_secs()
                    ),
                ) })
            }
        }
    }
}

/// Routes one line from the app. Pure enough to test: replies (pongs) go
/// through `shared.write_app`, answers to their waiting client.
fn handle_app_line(shared: &Shared, line: &str) {
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return;
    };
    if let Some(ping) = value.get("ping") {
        let _ = shared.write_app(&json!({ "pong": ping, "t": shared.clock_ms() }));
        return;
    }
    let Some(id) = value.get("id").and_then(Value::as_u64) else {
        return;
    };
    let waiter = shared.pending().remove(&id);
    if let Some(tx) = waiter {
        let _ = tx.send(value);
    }
}

fn write_client(writer: &mut UnixStream, response: &Value) -> bool {
    crate::runtime::write_json_line(writer, response).is_ok()
}

fn serve_client(shared: Arc<Shared>, stream: UnixStream, socket: PathBuf) {
    // The directory already keeps other users out; this is the second lock.
    if crate::runtime::peer_uid(&stream).ok() != Some(crate::runtime::current_uid()) {
        return;
    }
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;
    loop {
        let line = match crate::runtime::read_line_bounded(&mut reader, MAX_CLIENT_LINE) {
            Ok(Some(bytes)) => String::from_utf8_lossy(&bytes).into_owned(),
            Ok(None) => break,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                let error = error_value("too_large", "request line over 1 MiB");
                if !write_client(&mut writer, &json!({ "error": error })) {
                    break;
                }
                continue;
            }
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Err(e) => json!({ "error": error_value("bad_request", &format!("not JSON: {e}")) }),
            Ok(request) => {
                let method = request.get("method").and_then(Value::as_str).unwrap_or("");
                let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
                let timeout = request
                    .get("timeout_ms")
                    .and_then(Value::as_u64)
                    .map(Duration::from_millis)
                    .unwrap_or(DEFAULT_TIMEOUT)
                    .min(MAX_TIMEOUT);
                match method {
                    "" => json!({ "error": error_value("bad_request", "missing method") }),
                    "bridge.info" => json!({ "result": shared.info(&socket) }),
                    _ => shared.forward(method, params, timeout),
                }
            }
        };
        if !write_client(&mut writer, &response) {
            break;
        }
    }
}

/// Removes the socket only while it is still ours — a newer bridge for the
/// same device may have replaced it, and that one is live.
fn remove_if_ours(path: &Path, inode: u64) {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.ino() == inode {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub struct BridgeConfig {
    pub device: String,
    /// The app's install id; part of the socket name when present.
    pub id: Option<String>,
    pub runtime_dir: PathBuf,
}

/// The socket's name for a device: its name's slug, plus its install id
/// when it sent one (iOS reports generic names — two iPads are both "iPad"
/// — and a shared name would make the newer bridge evict the older).
pub fn device_slug(device: &str, id: Option<&str>) -> String {
    let base = crate::util::device_slug(device);
    match id.filter(|id| (4..=16).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        Some(id) => format!("{base}-{}", id.to_ascii_lowercase()),
        None => base,
    }
}

/// SIGTERM/SIGINT/SIGHUP: unlink our socket (if it is still ours) and exit.
/// Only async-signal-safe calls: lstat, unlink, _exit.
mod cleanup {
    use std::ffi::CString;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;

    static PATH: OnceLock<CString> = OnceLock::new();
    static INODE: AtomicU64 = AtomicU64::new(0);

    extern "C" fn handle(_signal: libc::c_int) {
        if let Some(path) = PATH.get() {
            // SAFETY: lstat/unlink/_exit are async-signal-safe; `stat` is a
            // stack value; `path` was fully initialised before install.
            unsafe {
                let mut stat: libc::stat = std::mem::zeroed();
                if libc::lstat(path.as_ptr(), &mut stat) == 0
                    && stat.st_ino as u64 == INODE.load(Ordering::SeqCst)
                {
                    libc::unlink(path.as_ptr());
                }
            }
        }
        // SAFETY: _exit is async-signal-safe.
        unsafe { libc::_exit(0) }
    }

    pub fn install(path: &std::path::Path, inode: u64) {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
            return;
        };
        if PATH.set(c_path).is_err() {
            return;
        }
        INODE.store(inode, Ordering::SeqCst);
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            // SAFETY: `handle` only makes async-signal-safe calls.
            unsafe {
                libc::signal(signal, handle as *const () as libc::sighandler_t);
            }
        }
    }
}

/// Runs until `app_in` reaches EOF. Returns the process exit code.
pub fn run(
    config: BridgeConfig,
    app_in: Box<dyn BufRead + Send>,
    app_out: Box<dyn Write + Send>,
) -> i32 {
    let slug = device_slug(&config.device, config.id.as_deref());
    if let Err(e) = crate::runtime::ensure_private_dir(&config.runtime_dir) {
        eprintln!(
            "mpx bridge: cannot create {}: {e}",
            config.runtime_dir.display()
        );
        return 1;
    }
    let path = socket_path(&config.runtime_dir, &slug);
    // A previous bridge for this device whose SSH channel is half-dead still
    // holds the name. The app only starts a new one when it has given up on
    // the old, so the newcomer takes over; the old one exits on its own EOF
    // and leaves the replaced path alone (`remove_if_ours`).
    let _ = std::fs::remove_file(&path);
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("mpx bridge: cannot listen on {}: {e}", path.display());
            return 1;
        }
    };
    // The 0700 directory already guards it; a socket that cannot be made
    // owner-only is still not served.
    if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
        eprintln!("mpx bridge: cannot restrict {}: {e}", path.display());
        let _ = std::fs::remove_file(&path);
        return 1;
    }
    let inode = std::fs::symlink_metadata(&path)
        .map(|m| m.ino())
        .unwrap_or(0);
    // A bridge killed by a signal (sshd hanging up, `kill`) takes its
    // socket with it, like one that saw EOF.
    cleanup::install(&path, inode);

    let shared = Arc::new(Shared {
        device: config.device.clone(),
        slug,
        started_ms: now_ms(),
        clock: std::time::Instant::now(),
        waiting: Mutex::new(HashMap::new()),
        app: Mutex::new(app_out),
        next_id: AtomicU64::new(1),
    });

    let hello = json!({
        "mpx": HELLO_TAG,
        "v": PROTOCOL_VERSION,
        "version": env!("CARGO_PKG_VERSION"),
        "socket": path.display().to_string(),
    });
    if shared.write_app(&hello).is_err() {
        remove_if_ours(&path, inode);
        return 1;
    }

    let accept_shared = Arc::clone(&shared);
    let accept_path = path.clone();
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            if active.fetch_add(1, Ordering::SeqCst) >= MAX_CLIENTS {
                active.fetch_sub(1, Ordering::SeqCst);
                let error = error_value("busy", "too many mpx browser clients at once");
                let _ = write_client(&mut stream, &json!({ "error": error }));
                continue;
            }
            let shared = Arc::clone(&accept_shared);
            let socket = accept_path.clone();
            let active = Arc::clone(&active);
            std::thread::spawn(move || {
                serve_client(shared, stream, socket);
                active.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });

    let mut app_in = app_in;
    loop {
        match crate::runtime::read_line_bounded(&mut app_in, MAX_APP_LINE) {
            Ok(Some(bytes)) => handle_app_line(&shared, &String::from_utf8_lossy(&bytes)),
            Ok(None) => break,
            // An over-long answer is dropped; its client times out.
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => continue,
            Err(_) => break,
        }
    }

    // The app is gone: fail every waiting client now instead of letting each
    // sit out its timeout.
    let waiters: Vec<_> = shared.pending().drain().collect();
    for (_, tx) in waiters {
        let _ =
            tx.send(json!({ "error": error_value("disconnected", "Multiplex closed the bridge") }));
    }
    remove_if_ours(&path, inode);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared_with_sink() -> (Arc<Shared>, Arc<Mutex<Vec<u8>>>) {
        struct Sink(Arc<Mutex<Vec<u8>>>);
        impl Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::new(Shared {
            device: "Test Pad".into(),
            slug: "test-pad".into(),
            started_ms: 0,
            clock: std::time::Instant::now(),
            waiting: Mutex::new(HashMap::new()),
            app: Mutex::new(Box::new(Sink(Arc::clone(&bytes)))),
            next_id: AtomicU64::new(1),
        });
        (shared, bytes)
    }

    #[test]
    fn pings_are_answered_with_the_same_token() {
        let (shared, bytes) = shared_with_sink();
        handle_app_line(&shared, r#"{"ping":7}"#);
        let sent = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        let pong: Value = serde_json::from_str(sent.trim_end()).unwrap();
        assert_eq!(pong["pong"], 7);
        assert!(pong["t"].is_u64());
    }

    #[test]
    fn answers_reach_their_waiter_and_unknown_ids_are_dropped() {
        let (shared, _) = shared_with_sink();
        let (tx, rx) = mpsc::channel();
        shared.pending().insert(3, tx);
        handle_app_line(&shared, r#"{"id":9,"result":1}"#);
        handle_app_line(&shared, "not json");
        handle_app_line(&shared, r#"{"id":3,"result":{"ok":true}}"#);
        let got = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(got["result"]["ok"], true);
        assert!(shared.pending().is_empty());
    }

    #[test]
    fn forward_times_out_with_an_actionable_message() {
        let (shared, bytes) = shared_with_sink();
        let response = shared.forward("tabs", json!({}), Duration::from_millis(20));
        assert_eq!(response["error"]["code"], "timeout");
        assert!(shared.pending().is_empty());
        let sent = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert!(sent.contains("\"method\":\"tabs\""));
        assert!(sent.contains("\"ttl\":20"));
        assert!(sent.ends_with("{\"cancel\":1}\n"), "{sent}");
    }

    #[test]
    fn same_named_devices_get_separate_sockets() {
        assert_eq!(device_slug("iPad", Some("3F2A9C1E")), "ipad-3f2a9c1e");
        assert_ne!(
            device_slug("iPad", Some("3f2a9c1e")),
            device_slug("iPad", Some("77aa00bb"))
        );
        assert_eq!(device_slug("iPad", None), "ipad");
        assert_eq!(
            device_slug("iPad", Some("not-hex!")),
            "ipad",
            "a malformed id is ignored"
        );
    }

    #[test]
    fn socket_names_are_per_device() {
        let dir = Path::new("/r");
        assert_eq!(
            socket_path(dir, "jhen-s-ipad"),
            PathBuf::from("/r/browser-jhen-s-ipad.sock")
        );
    }
}
