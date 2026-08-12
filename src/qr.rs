//! Terminal QR rendering — unicode half-blocks, two modules per character
//! row. Block characters draw the LIGHT modules (terminal foreground on the
//! prevailing dark background), which is the orientation phone scanners
//! read reliably from a terminal.
//!
//! Half-blocks are what keep modules square: a terminal cell is about twice
//! as tall as it is wide, so packing two module rows into one cell makes each
//! module roughly square. Packing 2×2 per cell (quadrant glyphs) would halve
//! the width again but leave every module 1:2, which phone scanners read
//! badly — so the way to a smaller QR is fewer bytes, not denser glyphs.
//!
//! Error correction stays at **L**: the code is being read off a lit screen
//! from a few inches away, not off a scuffed parcel, and L is the difference
//! between a 45-column and a 53-column block.

use qrcode::render::unicode;
use qrcode::{EcLevel, QrCode};

pub fn render(payload: &str) -> Option<String> {
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::L).ok()?;
    Some(
        code.render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Light)
            .light_color(unicode::Dense1x2::Dark)
            .quiet_zone(true)
            .build(),
    )
}

/// Display width of the rendered block, in terminal columns — the caller
/// decides whether the PIN panel fits beside it or has to go underneath.
pub fn width(art: &str) -> usize {
    art.lines()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_plausible_block() {
        let art = render("multiplex://b/abc").unwrap();
        assert!(art.lines().count() > 10);
        assert!(art.contains('█'));
    }

    /// A real handshake payload has to draw inside a plain 80×24 terminal.
    /// The old CBOR payload rendered 97×49 and this is the regression that
    /// keeps it from creeping back.
    #[test]
    fn a_handshake_payload_fits_a_plain_terminal() {
        let url = crate::payload::Payload {
            addrs: vec!["192.168.1.24".parse().unwrap()],
            port: 41337,
            spub: [3; 32],
            token: [7; 16],
            name: "devbox".into(),
            offline: None,
        }
        .to_url();
        let art = render(&url).unwrap();
        assert!(width(&art) <= 80, "QR was {} columns wide", width(&art));
        assert!(
            art.lines().count() <= 24,
            "QR was {} rows tall",
            art.lines().count()
        );
    }
}
