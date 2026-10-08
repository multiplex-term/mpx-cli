//! `mpx browser …` — the agent's side of Multiplex's agent browser.
//!
//! Finds the bridge a Multiplex device is running on this machine (see
//! `bridge.rs`), sends one request, and prints the answer in a form an agent
//! can read: snapshots as an indented outline with `[ref=eN]` handles,
//! screenshots as a PNG path, everything else as short text. `--json` prints
//! the raw result instead.

use serde_json::{json, Value};
use std::io::{BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A bridge that answered `bridge.info`.
#[derive(Debug, Clone)]
pub struct LiveBridge {
    pub socket: PathBuf,
    pub device: String,
    pub slug: String,
    pub started_ms: u64,
}

#[derive(Debug)]
pub struct ClientError {
    pub code: String,
    pub message: String,
}

impl ClientError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// One request/response over a connected bridge socket.
pub fn call(
    socket: &Path,
    method: &str,
    params: Value,
    timeout: Duration,
) -> Result<Value, ClientError> {
    let stream = UnixStream::connect(socket).map_err(|e| {
        ClientError::new(
            "unreachable",
            format!("cannot reach {}: {e}", socket.display()),
        )
    })?;
    // A socket served by another user is not this user's bridge, whatever
    // its name — it could read every `fill` and answer anything.
    if crate::runtime::peer_uid(&stream).ok() != Some(crate::runtime::current_uid()) {
        return Err(ClientError::new(
            "unreachable",
            format!(
                "{} is served by another user — ignoring it",
                socket.display()
            ),
        ));
    }
    // The bridge enforces the app-side timeout; the socket timeout only has
    // to outlast it, so a wedged bridge still cannot hang the agent forever.
    // `bridge.info` is answered by the bridge itself: no margin, so a stale
    // socket costs its probe one second, not six.
    let margin = if method == "bridge.info" {
        Duration::ZERO
    } else {
        Duration::from_secs(5)
    };
    let _ = stream.set_read_timeout(Some(timeout + margin));
    let mut writer = stream
        .try_clone()
        .map_err(|e| ClientError::new("unreachable", e.to_string()))?;
    let request =
        json!({ "method": method, "params": params, "timeout_ms": timeout.as_millis() as u64 });
    crate::runtime::write_json_line(&mut writer, &request)
        .map_err(|e| ClientError::new("unreachable", e.to_string()))?;
    let mut reader = BufReader::new(stream);
    let answer = crate::runtime::read_line_bounded(&mut reader, crate::bridge::MAX_APP_LINE)
        .map_err(|e| ClientError::new("timeout", format!("no answer from the bridge: {e}")))?
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    if answer.trim().is_empty() {
        return Err(ClientError::new(
            "disconnected",
            "the bridge closed without answering",
        ));
    }
    let mut value: Value = serde_json::from_str(&answer)
        .map_err(|e| ClientError::new("bad_response", format!("unreadable answer: {e}")))?;
    if let Some(error) = value.get("error") {
        return Err(ClientError::new(
            error.get("code").and_then(Value::as_str).unwrap_or("error"),
            error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("request failed")
                .to_string(),
        ));
    }
    Ok(value
        .get_mut("result")
        .map(Value::take)
        .unwrap_or(Value::Null))
}

/// Every bridge socket in the runtime directory that answers right now.
/// Stale sockets (a bridge killed without cleanup) are skipped, not removed:
/// they may belong to a bridge that is merely slow.
pub fn live_bridges(dir: &Path) -> Vec<LiveBridge> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut bridges: Vec<LiveBridge> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("browser-") && n.ends_with(".sock"))
        })
        .filter_map(|socket| {
            let info = call(&socket, "bridge.info", json!({}), Duration::from_secs(1)).ok()?;
            Some(LiveBridge {
                device: info.get("device")?.as_str()?.to_string(),
                slug: info.get("slug")?.as_str()?.to_string(),
                started_ms: info.get("started_ms").and_then(Value::as_u64).unwrap_or(0),
                socket,
            })
        })
        .collect();
    bridges.sort_by_key(|bridge| std::cmp::Reverse(bridge.started_ms));
    bridges
}

/// Picks the bridge to talk to. A `wanted` device matches by slug or by a
/// case-insensitive substring of the device name. With several devices and
/// no choice, the most recently connected wins — the device someone just
/// picked up — and the caller says so on stderr.
pub fn choose(
    bridges: &[LiveBridge],
    wanted: Option<&str>,
) -> Result<(LiveBridge, bool), ClientError> {
    if bridges.is_empty() {
        return Err(ClientError::new(
            "no_device",
            "no Multiplex device is serving a browser on this machine. In Multiplex, turn on \
             Host Settings ▸ Agent Browser for this host and keep the app open.",
        ));
    }
    if let Some(wanted) = wanted.filter(|w| !w.is_empty()) {
        let needle = wanted.to_lowercase();
        let listing = || {
            bridges
                .iter()
                .map(|b| format!("{} ({})", b.device, b.slug))
                .collect::<Vec<_>>()
                .join(", ")
        };
        // An exact slug wins; otherwise a name or slug substring must name
        // exactly one device — two iPads both answer to "ipad".
        if let Some(exact) = bridges.iter().find(|b| b.slug == needle) {
            return Ok((exact.clone(), false));
        }
        let matches: Vec<_> = bridges
            .iter()
            .filter(|b| b.slug.contains(&needle) || b.device.to_lowercase().contains(&needle))
            .collect();
        return match matches.as_slice() {
            [only] => Ok(((*only).clone(), false)),
            [] => Err(ClientError::new(
                "no_device",
                format!("no device matches '{wanted}' (have: {})", listing()),
            )),
            _ => Err(ClientError::new(
                "ambiguous_device",
                format!(
                    "'{wanted}' matches several devices — pass a slug: {}",
                    listing()
                ),
            )),
        };
    }
    Ok((bridges[0].clone(), bridges.len() > 1))
}

/// The session this agent runs in, so the app can dock the browser beside
/// that session's terminal. tmux only: `$TMUX` names the server the session
/// lives on, and `display-message` reads the client's own session.
pub fn current_session() -> Option<(String, &'static str)> {
    std::env::var_os("TMUX")?;
    let output = std::process::Command::new("tmux")
        .args(["display-message", "-p", "#S"])
        .output()
        .ok()?;
    let name = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (output.status.success() && !name.is_empty()).then_some((name, "tmux"))
}

// MARK: Output

/// Renders a result for an agent's eyes. Methods without a special shape
/// fall back to compact JSON.
pub fn render(method: &str, result: &Value) -> String {
    match method {
        "snapshot" => {
            let mut out = String::new();
            let title = result.get("title").and_then(Value::as_str).unwrap_or("");
            let url = result.get("url").and_then(Value::as_str).unwrap_or("");
            out.push_str(&format!("# {title} — {url}\n"));
            out.push_str(result.get("text").and_then(Value::as_str).unwrap_or(""));
            if result.get("truncated").and_then(Value::as_bool) == Some(true) {
                out.push_str("\n… (truncated — pass --full for the whole page)");
            }
            out
        }
        "tabs" => {
            let tabs = result
                .get("tabs")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if tabs.is_empty() {
                return "no agent tabs — `mpx browser open <url>` starts one".into();
            }
            tabs.iter()
                .map(|tab| {
                    let id = tab.get("tab").and_then(Value::as_str).unwrap_or("?");
                    let url = tab.get("url").and_then(Value::as_str).unwrap_or("");
                    let title = tab.get("title").and_then(Value::as_str).unwrap_or("");
                    let mut flags = Vec::new();
                    if tab.get("active").and_then(Value::as_bool) == Some(true) {
                        flags.push("active");
                    }
                    if tab.get("visible").and_then(Value::as_bool) == Some(false) {
                        flags.push("hidden");
                    }
                    if tab.get("loading").and_then(Value::as_bool) == Some(true) {
                        flags.push("loading");
                    }
                    let flags = if flags.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", flags.join(", "))
                    };
                    format!("{id}  {url}  {title}{flags}")
                })
                .chain(forwards_line(result))
                .collect::<Vec<_>>()
                .join("\n")
        }
        "forward" => forwards_line(result).unwrap_or_else(|| "ok".into()),
        "console" => {
            let entries = result
                .get("entries")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if entries.is_empty() {
                return "(no console output)".into();
            }
            entries
                .iter()
                .map(|e| {
                    format!(
                        "[{}] {}",
                        e.get("level").and_then(Value::as_str).unwrap_or("log"),
                        e.get("text").and_then(Value::as_str).unwrap_or("")
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
        "eval" => match result.get("value") {
            Some(Value::String(s)) => s.clone(),
            Some(other) => serde_json::to_string_pretty(other).unwrap_or_default(),
            None => "undefined".into(),
        },
        _ => {
            let tab = result.get("tab").and_then(Value::as_str);
            let url = result.get("url").and_then(Value::as_str);
            let title = result.get("title").and_then(Value::as_str);
            match (tab, url) {
                (Some(tab), Some(url)) => {
                    let title = title
                        .filter(|t| !t.is_empty())
                        .map(|t| format!("  {t}"))
                        .unwrap_or_default();
                    let mut line = format!("{tab}  {url}{title}");
                    for key in ["loadError", "focusRefused"] {
                        if let Some(note) = result.get(key).and_then(Value::as_str) {
                            line.push_str(&format!("\nnote: {note}"));
                        }
                    }
                    line
                }
                _ if result.is_null() || result == &json!({}) => "ok".into(),
                _ => match result.as_object() {
                    // Action receipts: one `key: value` per line, strings bare.
                    Some(fields) => fields
                        .iter()
                        .map(|(k, v)| match v {
                            Value::String(s) => format!("{k}: {s}"),
                            other => format!("{k}: {other}"),
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                    None => result.to_string(),
                },
            }
        }
    }
}

/// `forwards: localhost:5173, :8000` when the device forwards any of this
/// machine's localhost ports.
fn forwards_line(result: &Value) -> Option<String> {
    let open: Vec<u64> = result
        .get("open")
        .and_then(Value::as_array)
        .map(|ports| ports.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default();
    let ports: Vec<String> = result
        .get("forwards")?
        .as_array()?
        .iter()
        .filter_map(Value::as_u64)
        .map(|port| {
            if open.contains(&port) {
                format!(":{port} (open)")
            } else {
                format!(":{port}")
            }
        })
        .collect();
    (!ports.is_empty()).then(|| format!("forwards: localhost{}", ports.join(", ")))
}

/// Writes a screenshot result's PNG and returns where it went.
pub fn save_png(result: &Value, out: Option<PathBuf>) -> Result<PathBuf, ClientError> {
    use base64::Engine as _;
    let encoded = result
        .get("png")
        .and_then(Value::as_str)
        .ok_or_else(|| ClientError::new("bad_response", "screenshot carried no image"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| ClientError::new("bad_response", format!("screenshot was not base64: {e}")))?;
    let out_is_default = out.is_none();
    let path = match out {
        Some(path) => path,
        None => {
            // ~/.mpx/shots (0700), not the shared temp directory.
            let dir = crate::runtime::private_dir("shots")
                .and_then(|dir| crate::runtime::ensure_private_dir(&dir).map(|_| dir))
                .map_err(|e| {
                    ClientError::new("io", format!("no private place for screenshots: {e}"))
                })?;
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            dir.join(format!(
                "mpx-browser-{stamp}-{}.png",
                crate::util::random_hex(8)
            ))
        }
    };
    write_private(&path, &bytes, out_is_default)
        .map_err(|e| ClientError::new("io", format!("cannot write {}: {e}", path.display())))?;
    Ok(path)
}

/// A capture is page content — possibly a logged-in page — so it is
/// written owner-only and never through a symlink. A default name is also
/// unguessable and must not exist yet (`create_private`: 0600, O_EXCL).
fn write_private(path: &Path, bytes: &[u8], fresh: bool) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = if fresh {
        crate::authkeys::create_private(path)?
    } else {
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?
    };
    file.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridge(device: &str, slug: &str, started: u64) -> LiveBridge {
        LiveBridge {
            socket: PathBuf::from(format!("/r/browser-{slug}.sock")),
            device: device.into(),
            slug: slug.into(),
            started_ms: started,
        }
    }

    #[test]
    fn choose_prefers_the_named_device_then_the_newest() {
        let list = vec![
            bridge("Jhen's Vision Pro", "jhen-s-vision-pro", 20),
            bridge("Jhen's iPad", "jhen-s-ipad", 10),
        ];
        let (picked, ambiguous) = choose(&list, None).unwrap();
        assert_eq!(picked.slug, "jhen-s-vision-pro");
        assert!(ambiguous);
        let (picked, ambiguous) = choose(&list, Some("ipad")).unwrap();
        assert_eq!(picked.slug, "jhen-s-ipad");
        assert!(!ambiguous);
        assert_eq!(choose(&list, Some("phone")).unwrap_err().code, "no_device");
        let twins = vec![
            bridge("iPad", "ipad-3f2a9c1e", 20),
            bridge("iPad", "ipad-77aa00bb", 10),
        ];
        assert_eq!(
            choose(&twins, Some("ipad")).unwrap_err().code,
            "ambiguous_device"
        );
        assert_eq!(
            choose(&twins, Some("ipad-77aa00bb")).unwrap().0.started_ms,
            10
        );
        assert_eq!(choose(&twins, Some("77aa")).unwrap().0.started_ms, 10);
        assert_eq!(choose(&[], None).unwrap_err().code, "no_device");
    }

    #[test]
    fn snapshot_renders_header_and_truncation_note() {
        let text = render(
            "snapshot",
            &json!({"title": "Docs", "url": "http://devbox:3000/", "text": "- link \"Home\" [ref=e1]", "truncated": true}),
        );
        assert!(text.starts_with("# Docs — http://devbox:3000/\n- link"));
        assert!(text.ends_with("--full for the whole page)"));
    }

    #[test]
    fn plain_results_render_tab_and_url() {
        assert_eq!(
            render(
                "open",
                &json!({"tab": "t1", "url": "http://x/", "title": "X"})
            ),
            "t1  http://x/  X"
        );
        assert_eq!(render("click", &json!({})), "ok");
        assert_eq!(
            render("forward", &json!({"forwards": [5173, 8000]})),
            "forwards: localhost:5173, :8000"
        );
        assert_eq!(
            render(
                "forward",
                &json!({"forwards": [5173, 8000], "open": [8000]})
            ),
            "forwards: localhost:5173, :8000 (open)"
        );
        assert_eq!(
            render(
                "open",
                &json!({"tab": "t1", "url": "http://x/", "title": "", "focusRefused": "The user is typing."})
            ),
            "t1  http://x/\nnote: The user is typing."
        );
        assert_eq!(render("eval", &json!({"value": 3})), "3");
        assert_eq!(render("eval", &json!({"value": "hi"})), "hi");
    }
}
