//! Small shared helpers: base64url, hex, ANSI voice, slugs.

use base64::engine::general_purpose::STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use std::io::IsTerminal;

pub fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.as_bytes()).ok()
}

pub fn b64std(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decodes lowercase or uppercase hex, rejecting anything else.
///
/// Deliberately byte-oriented: slicing the `&str` at every second *byte*
/// panics the moment a multi-byte character straddles the boundary, so
/// `hex_decode("€€")` aborted the process where it was supposed to return
/// `None`. Nothing here needs character semantics — a hex digit is an ASCII
/// byte or it is not a hex digit.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| {
            let hi = char::from(pair[0]).to_digit(16)?;
            let lo = char::from(pair[1]).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

/// The comment-field slug for authorized_keys markers: lowercase alnum and
/// dashes only, never empty, capped so the line stays scannable.
pub fn device_slug(display: &str) -> String {
    let mut slug = String::new();
    let mut last_dash = true;
    for ch in display.chars() {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            slug.push(lower);
            last_dash = false;
        } else if !last_dash {
            slug.push('-');
            last_dash = true;
        }
        if slug.len() >= 24 {
            break;
        }
    }
    let trimmed = slug.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "device".into()
    } else {
        trimmed
    }
}

// ANSI voice — dim/status coloring only when stdout is a terminal.
fn styled() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

pub fn ok(msg: &str) {
    if styled() {
        println!("\x1b[32m✓\x1b[0m {msg}");
    } else {
        println!("+ {msg}");
    }
}

pub fn note(msg: &str) {
    if styled() {
        println!("\x1b[2m{msg}\x1b[0m");
    } else {
        println!("{msg}");
    }
}

pub fn warn(msg: &str) {
    if styled() {
        eprintln!("\x1b[33m!\x1b[0m {msg}");
    } else {
        eprintln!("! {msg}");
    }
}

pub fn wait(msg: &str) {
    if styled() {
        println!("\x1b[33m◌\x1b[0m {msg}");
    } else {
        println!("~ {msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs() {
        assert_eq!(device_slug("Jhen's Vision Pro"), "jhen-s-vision-pro");
        assert_eq!(device_slug("  ---  "), "device");
        assert_eq!(device_slug(""), "device");
        assert_eq!(
            device_slug("A very long device display name here"),
            "a-very-long-device-displ"
        );
        assert_eq!(device_slug("iPad Pro 13\""), "ipad-pro-13");
    }

    #[test]
    fn hex_roundtrip() {
        let data = [0u8, 1, 0xab, 0xff];
        assert_eq!(hex_decode(&hex(&data)).unwrap(), data);
        assert_eq!(hex_decode("AB").unwrap(), [0xab]);
        assert!(hex_decode("abc").is_none());
    }

    /// Multi-byte characters must be rejected, not indexed into. Every one
    /// of these used to panic: the slice landed mid-character.
    #[test]
    fn hex_rejects_multibyte_input_without_panicking() {
        for bad in ["€€", "ab€€", "😀", "ππ", "\u{0}\u{0}"] {
            assert!(hex_decode(bad).is_none(), "{bad:?} should not decode");
        }
    }
}
