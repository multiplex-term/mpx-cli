//! The handshake channel: X25519 → HKDF-SHA256 → ChaCha20-Poly1305, with
//! 4-byte big-endian length-prefixed frames. One key per direction, nonce =
//! 4 zero bytes ‖ BE64(per-direction sequence). The first client frame (the
//! intro carrying the ephemeral public key) is the only cleartext frame.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ciborium::value::Value;
use hkdf::Hkdf;
use sha2::Sha256;
use std::io::{Read, Write};

pub const SALT: &[u8] = b"multiplex-bind-v1";
pub const PIN_INFO: &[u8] = b"multiplex-bind-pin";
/// Frames above this are not protocol traffic; refuse before allocating.
pub const MAX_FRAME: usize = 64 * 1024;

#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    TooLarge(usize),
    Crypto,
    Malformed,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(err) => write!(f, "connection error: {err}"),
            FrameError::TooLarge(n) => write!(f, "oversized frame ({n} bytes)"),
            FrameError::Crypto => write!(f, "frame failed authentication"),
            FrameError::Malformed => write!(f, "malformed frame"),
        }
    }
}

impl From<std::io::Error> for FrameError {
    fn from(err: std::io::Error) -> Self {
        FrameError::Io(err)
    }
}

/// Directional keys + sequence counters for one handshake connection.
pub struct Channel {
    c2s: ChaCha20Poly1305,
    s2c: ChaCha20Poly1305,
    seq_c2s: u64,
    seq_s2c: u64,
}

impl Channel {
    /// Both sides derive the same channel from the X25519 shared secret and
    /// the two public keys (client ephemeral first — the transcript binding).
    pub fn derive(shared: &[u8; 32], epub: &[u8; 32], spub: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(SALT), shared);
        let mut info = Vec::with_capacity(64);
        info.extend_from_slice(epub);
        info.extend_from_slice(spub);
        let mut okm = [0u8; 64];
        hk.expand(&info, &mut okm)
            .expect("64 bytes is a valid HKDF-SHA256 output length");
        Channel {
            c2s: ChaCha20Poly1305::new(Key::from_slice(&okm[..32])),
            s2c: ChaCha20Poly1305::new(Key::from_slice(&okm[32..])),
            seq_c2s: 0,
            seq_s2c: 0,
        }
    }

    fn nonce(seq: u64) -> Nonce {
        let mut bytes = [0u8; 12];
        bytes[4..].copy_from_slice(&seq.to_be_bytes());
        *Nonce::from_slice(&bytes)
    }

    pub fn seal_s2c(&mut self, plain: &[u8]) -> Vec<u8> {
        let sealed = self
            .s2c
            .encrypt(&Self::nonce(self.seq_s2c), plain)
            .expect("ChaCha20-Poly1305 encryption cannot fail");
        self.seq_s2c += 1;
        sealed
    }

    pub fn open_c2s(&mut self, sealed: &[u8]) -> Result<Vec<u8>, FrameError> {
        let plain = self
            .c2s
            .decrypt(&Self::nonce(self.seq_c2s), sealed)
            .map_err(|_| FrameError::Crypto)?;
        self.seq_c2s += 1;
        Ok(plain)
    }

    /// Client-side halves — used by tests and the vector generator so the
    /// same code exercises both ends of the wire.
    pub fn seal_c2s(&mut self, plain: &[u8]) -> Vec<u8> {
        let sealed = self
            .c2s
            .encrypt(&Self::nonce(self.seq_c2s), plain)
            .expect("ChaCha20-Poly1305 encryption cannot fail");
        self.seq_c2s += 1;
        sealed
    }

    pub fn open_s2c(&mut self, sealed: &[u8]) -> Result<Vec<u8>, FrameError> {
        let plain = self
            .s2c
            .decrypt(&Self::nonce(self.seq_s2c), sealed)
            .map_err(|_| FrameError::Crypto)?;
        self.seq_s2c += 1;
        Ok(plain)
    }
}

/// The discovery path's PIN proof: HKDF(salt = epub‖spub, ikm = PIN digits,
/// info = "multiplex-bind-pin"). Binding the proof to both public keys means
/// a relayed proof is useless on any other connection.
pub fn pin_proof(pin: &str, epub: &[u8; 32], spub: &[u8; 32]) -> [u8; 32] {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(epub);
    salt.extend_from_slice(spub);
    let hk = Hkdf::<Sha256>::new(Some(&salt), pin.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(PIN_INFO, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

pub fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, FrameError> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut frame = vec![0u8; len];
    stream.read_exact(&mut frame)?;
    Ok(frame)
}

pub fn write_frame(stream: &mut impl Write, frame: &[u8]) -> Result<(), FrameError> {
    stream.write_all(&u32::try_from(frame.len()).unwrap().to_be_bytes())?;
    stream.write_all(frame)?;
    stream.flush()?;
    Ok(())
}

// -- message bodies (CBOR maps, spec key order) --

pub fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out)
        .expect("CBOR encoding of an in-memory value cannot fail");
    out
}

pub fn decode(bytes: &[u8]) -> Result<Value, FrameError> {
    ciborium::de::from_reader(bytes).map_err(|_| FrameError::Malformed)
}

pub fn map_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Map(entries) => entries.iter().find_map(|(k, v)| match k {
            Value::Text(t) if t == key => Some(v),
            _ => None,
        }),
        _ => None,
    }
}

pub fn get_text(value: &Value, key: &str) -> Option<String> {
    match map_get(value, key)? {
        Value::Text(t) => Some(t.clone()),
        _ => None,
    }
}

pub fn get_bytes(value: &Value, key: &str) -> Option<Vec<u8>> {
    match map_get(value, key)? {
        Value::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_roundtrip_and_sequencing() {
        let shared = [9u8; 32];
        let epub = [1u8; 32];
        let spub = [2u8; 32];
        let mut client = Channel::derive(&shared, &epub, &spub);
        let mut server = Channel::derive(&shared, &epub, &spub);

        let hello = client.seal_c2s(b"hello");
        assert_eq!(server.open_c2s(&hello).unwrap(), b"hello");
        let offer = server.seal_s2c(b"offer");
        assert_eq!(client.open_s2c(&offer).unwrap(), b"offer");

        // Same plaintext, next sequence — ciphertext must differ, and a
        // replayed first frame must fail against the advanced counter.
        let hello2 = client.seal_c2s(b"hello");
        assert_ne!(hello, hello2);
        assert!(server.open_c2s(&hello).is_err());
    }

    #[test]
    fn pin_proof_binds_to_transcript() {
        let a = pin_proof("482163", &[1; 32], &[2; 32]);
        let b = pin_proof("482163", &[1; 32], &[3; 32]);
        let c = pin_proof("482164", &[1; 32], &[2; 32]);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, pin_proof("482163", &[1; 32], &[2; 32]));
    }

    #[test]
    fn frame_io_caps_length() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"abc").unwrap();
        assert_eq!(buf, [0, 0, 0, 3, b'a', b'b', b'c']);
        let mut oversized = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        oversized.extend_from_slice(&[0; 8]);
        assert!(matches!(
            read_frame(&mut oversized.as_slice()),
            Err(FrameError::TooLarge(_))
        ));
    }
}
