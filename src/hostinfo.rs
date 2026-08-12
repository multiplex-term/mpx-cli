//! What this machine tells the app about itself: name, candidate addresses,
//! and its SSH host key fingerprints (which the app pins — bind-enrolled
//! hosts arrive with TOFU data on day one).

use ssh_key::{HashAlg, PublicKey};
use std::net::IpAddr;
use std::path::Path;

pub fn machine_name() -> String {
    hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .map(|name| name.trim_end_matches(".local").to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "host".into())
}

/// Non-loopback, non-link-local addresses, private IPv4 first (the LAN case
/// binding exists for), capped so payloads stay QR-sized.
pub fn local_addrs() -> Vec<String> {
    let Ok(interfaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    let mut v4_private = Vec::new();
    let mut v4_public = Vec::new();
    let mut v6 = Vec::new();
    for interface in interfaces {
        let ip = interface.ip();
        if ip.is_loopback() {
            continue;
        }
        match ip {
            IpAddr::V4(addr) => {
                if addr.is_link_local() {
                    continue;
                }
                if addr.is_private() {
                    v4_private.push(addr.to_string());
                } else {
                    v4_public.push(addr.to_string());
                }
            }
            IpAddr::V6(addr) => {
                // fe80::/10 needs a scope id to be dialable; skip it.
                if (addr.segments()[0] & 0xffc0) == 0xfe80 {
                    continue;
                }
                v6.push(addr.to_string());
            }
        }
    }
    let mut addrs: Vec<String> = v4_private.into_iter().chain(v4_public).chain(v6).collect();
    addrs.dedup();
    addrs.truncate(6);
    addrs
}

/// `"<key type> <SHA256:fp>"` for each host public key readable under
/// `/etc/ssh`, ed25519 first. Missing/unreadable files just narrow the list.
pub fn host_key_fingerprints(ssh_dir: &Path) -> Vec<String> {
    let mut fingerprints = Vec::new();
    let Ok(entries) = std::fs::read_dir(ssh_dir) else {
        return fingerprints;
    };
    let mut names: Vec<_> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("ssh_host_") && n.ends_with("_key.pub"))
                .unwrap_or(false)
        })
        .collect();
    names.sort();
    for path in names {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(key) = PublicKey::from_openssh(content.trim()) else {
            continue;
        };
        let entry = format!(
            "{} {}",
            key.algorithm().as_str(),
            key.fingerprint(HashAlg::Sha256)
        );
        if key.algorithm().as_str().contains("ed25519") {
            fingerprints.insert(0, entry);
        } else {
            fingerprints.push(entry);
        }
    }
    fingerprints
}

/// The ed25519 host key's raw SHA-256 digest. Offline payloads carry this
/// instead of the 50-character `SHA256:…` display form, because they have no
/// OFFER to deliver pins in and every byte is a QR module. The app renders
/// the display form itself.
pub fn ed25519_host_key_digest(ssh_dir: &Path) -> Option<[u8; 32]> {
    let content = std::fs::read_to_string(ssh_dir.join("ssh_host_ed25519_key.pub")).ok()?;
    let key = PublicKey::from_openssh(content.trim()).ok()?;
    key.fingerprint(HashAlg::Sha256).as_bytes().try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_read_generated_keys() {
        let dir = tempfile::tempdir().unwrap();
        let mut rng = rand_core::OsRng;
        let key = ssh_key::PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519).unwrap();
        std::fs::write(
            dir.path().join("ssh_host_ed25519_key.pub"),
            key.public_key().to_openssh().unwrap(),
        )
        .unwrap();
        std::fs::write(dir.path().join("ssh_host_bogus_key.pub"), "not a key").unwrap();

        let fps = host_key_fingerprints(dir.path());
        assert_eq!(fps.len(), 1);
        assert!(fps[0].starts_with("ssh-ed25519 SHA256:"), "{}", fps[0]);
    }

    #[test]
    fn machine_name_is_never_empty() {
        assert!(!machine_name().is_empty());
    }
}
