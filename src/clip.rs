//! Clipboard delivery. Local sessions use the platform tool; SSH sessions
//! use OSC 52 so the payload lands on the *local* terminal's clipboard —
//! which Universal Clipboard then carries to the user's iPad/iPhone/Vision
//! Pro. Inside tmux the sequence is DCS-passthrough wrapped (needs
//! `allow-passthrough on`, tmux ≥ 3.3 default off — we print a hint).

use crate::util::b64std;
use std::io::Write;
use std::process::{Command, Stdio};

pub enum CopyOutcome {
    Copied(&'static str),
    Failed,
}

pub fn copy(payload: &str) -> CopyOutcome {
    let over_ssh =
        std::env::var_os("SSH_TTY").is_some() || std::env::var_os("SSH_CONNECTION").is_some();
    if !over_ssh {
        if let Some(tool) = local_tool() {
            if pipe_to(tool, payload) {
                return CopyOutcome::Copied(tool.0);
            }
        }
    }
    if osc52(payload) {
        CopyOutcome::Copied(if over_ssh {
            "OSC 52 → your local terminal"
        } else {
            "OSC 52"
        })
    } else {
        CopyOutcome::Failed
    }
}

fn local_tool() -> Option<(&'static str, &'static [&'static str])> {
    if cfg!(target_os = "macos") {
        return Some(("pbcopy", &[]));
    }
    if std::env::var_os("WAYLAND_DISPLAY").is_some() && which("wl-copy") {
        return Some(("wl-copy", &[]));
    }
    if std::env::var_os("DISPLAY").is_some() {
        if which("xclip") {
            return Some(("xclip", &["-selection", "clipboard"]));
        }
        if which("xsel") {
            return Some((
                "xsel",
                "--clipboard --input".split(' ').collect::<Vec<_>>().leak(),
            ));
        }
    }
    None
}

fn which(binary: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(binary).is_file()))
        .unwrap_or(false)
}

fn pipe_to(tool: (&'static str, &'static [&'static str]), payload: &str) -> bool {
    let Ok(mut child) = Command::new(tool.0)
        .args(tool.1)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(stdin) = child.stdin.as_mut() {
        if stdin.write_all(payload.as_bytes()).is_err() {
            return false;
        }
    }
    child.wait().map(|status| status.success()).unwrap_or(false)
}

/// Writes the OSC 52 clipboard-set sequence to the controlling terminal.
fn osc52(payload: &str) -> bool {
    let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") else {
        return false;
    };
    let sequence = format!("\x1b]52;c;{}\x07", b64std(payload.as_bytes()));
    let wrapped = if std::env::var_os("TMUX").is_some() {
        // tmux swallows unknown escapes unless passthrough-wrapped, with
        // inner ESC bytes doubled.
        format!("\x1bPtmux;{}\x1b\\", sequence.replace('\x1b', "\x1b\x1b"))
    } else {
        sequence
    };
    tty.write_all(wrapped.as_bytes())
        .and_then(|_| tty.flush())
        .is_ok()
}

pub fn tmux_passthrough_hint() -> Option<&'static str> {
    if std::env::var_os("TMUX").is_some() {
        Some("inside tmux, OSC 52 needs `set -g allow-passthrough on` in the host's tmux.conf")
    } else {
        None
    }
}
