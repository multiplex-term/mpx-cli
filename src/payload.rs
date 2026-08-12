//! The bind payload — the one string QR and clipboard both carry:
//! `multiplex://b/<base64url>`.
//!
//! It is deliberately the SMALLEST thing that can reach and authenticate the
//! machine, because it has to survive being drawn as a QR code in an 80×24
//! terminal. Everything merely *descriptive* — the SSH user, the host key
//! fingerprints the app pins — arrives a moment later inside the sealed
//! OFFER, which is authenticated and unbounded. An earlier CBOR format
//! carried all of it up front and rendered 97 columns wide (host key
//! fingerprints alone were 186 of its 393 bytes); this one is 65 bytes.
//!
//! Offline payloads are the exception: there is no handshake to carry the
//! record, so they append the SSH user, port, and the 32-byte key seed.

use crate::util::{b64url, b64url_decode};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const VERSION: u8 = 2;
pub const URL_PREFIX: &str = "multiplex://b/";
/// Longer names cost QR modules and the app re-learns the real one from the
/// OFFER anyway (or, offline, shows what fits).
pub const MAX_NAME: usize = 32;
/// More candidates cost modules for addresses the app will never try; the
/// first reachable one wins.
pub const MAX_ADDRS: usize = 3;

const FLAG_OFFLINE: u8 = 1 << 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineKey {
    pub ssh_user: String,
    pub ssh_port: u16,
    /// Raw ed25519 private seed. Both sides derive the identical OpenSSH key
    /// from it, so armoring it into the payload was ~370 wasted bytes.
    pub seed: [u8; 32],
    /// A non-default authorized_keys the CLI enrolled into, so the app's
    /// rotation edits the file the sshd actually reads.
    pub authorized_keys: Option<String>,
    /// Raw SHA-256 digest of the ed25519 host key. An offline bind has no
    /// OFFER to carry pins in, and dropping them to save bytes would quietly
    /// retract a security promise — so it rides as 32 raw bytes rather than
    /// the 50-character display form.
    pub hostkey_sha256: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub addrs: Vec<IpAddr>,
    /// Handshake TCP listener. 0 in offline payloads (there is no listener).
    pub port: u16,
    pub spub: [u8; 32],
    pub token: [u8; 16],
    pub name: String,
    pub offline: Option<OfflineKey>,
}

impl Payload {
    pub fn to_url(&self) -> String {
        format!("{URL_PREFIX}{}", b64url(&self.encode()))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.push(VERSION);
        out.push(if self.offline.is_some() {
            FLAG_OFFLINE
        } else {
            0
        });
        out.extend_from_slice(&self.spub);
        out.extend_from_slice(&self.token);
        out.extend_from_slice(&self.port.to_be_bytes());

        let addrs: Vec<&IpAddr> = self.addrs.iter().take(MAX_ADDRS).collect();
        out.push(addrs.len() as u8);
        for addr in addrs {
            match addr {
                IpAddr::V4(v4) => {
                    out.push(4);
                    out.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    out.push(6);
                    out.extend_from_slice(&v6.octets());
                }
            }
        }

        let name: Vec<u8> = truncated_name(&self.name);
        out.push(name.len() as u8);
        out.extend_from_slice(&name);

        if let Some(offline) = &self.offline {
            let user = offline.ssh_user.as_bytes();
            out.push(user.len().min(255) as u8);
            out.extend_from_slice(&user[..user.len().min(255)]);
            out.extend_from_slice(&offline.ssh_port.to_be_bytes());
            out.extend_from_slice(&offline.seed);
            let path = offline
                .authorized_keys
                .as_deref()
                .unwrap_or_default()
                .as_bytes();
            out.push(path.len().min(255) as u8);
            out.extend_from_slice(&path[..path.len().min(255)]);
            match &offline.hostkey_sha256 {
                Some(digest) => {
                    out.push(32);
                    out.extend_from_slice(digest);
                }
                None => out.push(0),
            }
        }
        out
    }

    pub fn from_url(url: &str) -> Option<Self> {
        let data = url.strip_prefix(URL_PREFIX)?;
        Self::decode(&b64url_decode(data)?)
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader { bytes, index: 0 };
        if reader.u8()? != VERSION {
            return None;
        }
        let flags = reader.u8()?;
        let spub: [u8; 32] = reader.take(32)?.try_into().ok()?;
        let token: [u8; 16] = reader.take(16)?.try_into().ok()?;
        let port = reader.u16()?;

        let count = reader.u8()? as usize;
        if count > MAX_ADDRS {
            return None;
        }
        let mut addrs = Vec::with_capacity(count);
        for _ in 0..count {
            addrs.push(match reader.u8()? {
                4 => {
                    let octets: [u8; 4] = reader.take(4)?.try_into().ok()?;
                    IpAddr::V4(Ipv4Addr::from(octets))
                }
                6 => {
                    let octets: [u8; 16] = reader.take(16)?.try_into().ok()?;
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
                _ => return None,
            });
        }

        let name_len = reader.u8()? as usize;
        let name = String::from_utf8(reader.take(name_len)?.to_vec()).ok()?;

        let offline = if flags & FLAG_OFFLINE != 0 {
            let user_len = reader.u8()? as usize;
            let ssh_user = String::from_utf8(reader.take(user_len)?.to_vec()).ok()?;
            let ssh_port = reader.u16()?;
            let seed: [u8; 32] = reader.take(32)?.try_into().ok()?;
            let path_len = reader.u8()? as usize;
            let path = String::from_utf8(reader.take(path_len)?.to_vec()).ok()?;
            let hostkey_sha256 = match reader.u8()? {
                0 => None,
                32 => Some(reader.take(32)?.try_into().ok()?),
                _ => return None,
            };
            Some(OfflineKey {
                ssh_user,
                ssh_port,
                seed,
                authorized_keys: if path.is_empty() { None } else { Some(path) },
                hostkey_sha256,
            })
        } else {
            None
        };

        Some(Payload {
            addrs,
            port,
            spub,
            token,
            name,
            offline,
        })
    }
}

/// Truncate on a character boundary — a name cut mid-UTF-8 would not decode.
fn truncated_name(name: &str) -> Vec<u8> {
    let mut end = name.len().min(MAX_NAME);
    while end > 0 && !name.is_char_boundary(end) {
        end -= 1;
    }
    name.as_bytes()[..end].to_vec()
}

struct Reader<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.index.checked_add(count)?;
        let slice = self.bytes.get(self.index..end)?;
        self.index = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(offline: Option<OfflineKey>) -> Payload {
        Payload {
            addrs: vec![
                "192.168.1.24".parse().unwrap(),
                "fda1:5a14:3df6:49c1::1".parse().unwrap(),
            ],
            port: 41337,
            spub: [3; 32],
            token: [7; 16],
            name: "devbox".into(),
            offline,
        }
    }

    #[test]
    fn url_roundtrip() {
        let handshake = sample(None);
        assert_eq!(Payload::from_url(&handshake.to_url()).unwrap(), handshake);

        let offline = sample(Some(OfflineKey {
            ssh_user: "jhen".into(),
            ssh_port: 22,
            seed: [9; 32],
            authorized_keys: Some("/etc/ssh/keys/ak".into()),
            hostkey_sha256: Some([4; 32]),
        }));
        assert_eq!(Payload::from_url(&offline.to_url()).unwrap(), offline);
    }

    /// The whole point of the format: a handshake payload has to fit a QR a
    /// terminal can draw. 65 bytes for one IPv4 candidate; the old CBOR
    /// format was 393 on a real Mac.
    #[test]
    fn handshake_payload_stays_small() {
        let mut payload = sample(None);
        payload.addrs = vec!["192.168.1.24".parse().unwrap()];
        assert_eq!(payload.encode().len(), 65);
        assert!(
            payload.to_url().len() <= 106,
            "url was {} chars — a QR version 5 at EC level L holds 106",
            payload.to_url().len()
        );
    }

    #[test]
    fn rejects_other_versions_and_truncation() {
        let good = sample(None).encode();
        assert!(Payload::decode(&good).is_some());

        let mut wrong_version = good.clone();
        wrong_version[0] = 1;
        assert!(Payload::decode(&wrong_version).is_none());

        for cut in 1..good.len() {
            assert!(
                Payload::decode(&good[..cut]).is_none(),
                "a payload truncated to {cut} bytes must not decode"
            );
        }
        assert!(Payload::from_url("multiplex://b/!!!").is_none());
        assert!(Payload::from_url("https://example.com").is_none());
        assert!(Payload::from_url("multiplex://open?host=devbox").is_none());
    }

    #[test]
    fn caps_addresses_and_name() {
        let mut payload = sample(None);
        payload.addrs = vec![
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            "10.0.0.3".parse().unwrap(),
            "10.0.0.4".parse().unwrap(),
        ];
        payload.name = "a".repeat(80);
        let decoded = Payload::decode(&payload.encode()).unwrap();
        assert_eq!(decoded.addrs.len(), MAX_ADDRS);
        assert_eq!(decoded.name.len(), MAX_NAME);
    }

    /// A multi-byte name must never be cut mid-character.
    #[test]
    fn truncates_names_on_character_boundaries() {
        let payload = Payload {
            name: "π".repeat(30),
            ..sample(None)
        };
        let decoded = Payload::decode(&payload.encode()).unwrap();
        assert!(decoded.name.chars().all(|c| c == 'π'));
        assert!(decoded.name.len() <= MAX_NAME);
    }
}
