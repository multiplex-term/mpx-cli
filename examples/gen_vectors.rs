//! Regenerates the shared cross-implementation test vectors:
//!
//!     cargo run --example gen_vectors > bind-v1.json
//!
//! The Multiplex app vendors the same file (MultiplexTests/Fixtures) so the
//! Swift client and this Rust server can never drift apart silently. Every
//! input is fixed; every output is a pure function of the protocol.

use ciborium::value::Value;
use mpx::frame::{self, pin_proof, Channel};
use mpx::payload::{OfflineKey, Payload};
use mpx::util::hex;
use x25519_dalek::{PublicKey, StaticSecret};

/// Deterministic CryptoRng for the fixed ed25519 enroll key — a keystream
/// this predictable is exactly the point of a test vector.
struct FixedRng(u64);

impl rand_core::RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        // xorshift64* — stable across platforms, good enough to make a key.
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for FixedRng {}

fn main() {
    let session_seed = [0x11u8; 32];
    let eph_seed = [0x22u8; 32];
    let token = [0x33u8; 16];
    let pin = "482163";

    let session = StaticSecret::from(session_seed);
    let spub = PublicKey::from(&session).to_bytes();
    let eph = StaticSecret::from(eph_seed);
    let epub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(spub));

    let record = Payload {
        addrs: vec!["192.168.1.24".parse().unwrap(), "10.0.5.2".parse().unwrap()],
        port: 41337,
        spub,
        token,
        name: "devbox".into(),
        offline: None,
    };

    // What the sealed OFFER carries — the descriptive record that used to
    // ride the payload and blow the QR up.
    let offer_name = "devbox";
    let offer_addrs = vec!["192.168.1.24", "10.0.5.2"];
    let offer_user = "jhen";
    let offer_port: u16 = 2222;
    let offer_hostkeys = vec!["ssh-ed25519 SHA256:8LKW2AiTswwLnvmMmLGyU5DjLYPGwCauTAdSSlpFy1Y"];

    let mut rng = FixedRng(0x6D70782D62696E64); // "mpx-bind"
    let enroll_key = ssh_key::PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519).unwrap();
    let enroll_pub = enroll_key.public_key().to_openssh().unwrap();

    // Client-authored frames (the Swift side must produce these bytes).
    let intro = Value::Map(vec![
        (frame::text("v"), Value::Integer(1.into())),
        (frame::text("epub"), Value::Bytes(epub.to_vec())),
        (frame::text("mode"), frame::text("token")),
    ]);
    let intro_bytes = frame::encode(&intro);

    let mut client = Channel::derive(shared.as_bytes(), &epub, &spub);
    let hello = Value::Map(vec![(frame::text("proof"), Value::Bytes(token.to_vec()))]);
    let hello_sealed = client.seal_c2s(&frame::encode(&hello));

    // Server-authored frames (the Swift side must open these bytes).
    let mut server = Channel::derive(shared.as_bytes(), &epub, &spub);
    server.open_c2s(&hello_sealed).unwrap();
    let offer = Value::Map(vec![
        (frame::text("name"), frame::text(offer_name)),
        (
            frame::text("addrs"),
            Value::Array(offer_addrs.iter().map(|a| frame::text(a)).collect()),
        ),
        (
            frame::text("ssh"),
            Value::Map(vec![
                (frame::text("user"), frame::text(offer_user)),
                (frame::text("port"), Value::Integer(offer_port.into())),
                (
                    frame::text("hostkeys"),
                    Value::Array(offer_hostkeys.iter().map(|k| frame::text(k)).collect()),
                ),
            ]),
        ),
    ]);
    let offer_sealed = server.seal_s2c(&frame::encode(&offer));

    let enroll = Value::Map(vec![
        (frame::text("pubkey"), frame::text(&enroll_pub)),
        (frame::text("device"), frame::text("Jhen's Vision Pro")),
    ]);
    let enroll_sealed = client.seal_c2s(&frame::encode(&enroll));
    server.open_c2s(&enroll_sealed).unwrap();

    let done = Value::Map(vec![
        (frame::text("ok"), Value::Bool(true)),
        (
            frame::text("comment"),
            frame::text("multiplex:bind:9f3a1c2e:jhen-s-vision-pro"),
        ),
    ]);
    let done_sealed = server.seal_s2c(&frame::encode(&done));

    let offline = Payload {
        port: 0,
        spub: [0; 32],
        token: [0; 16],
        offline: Some(OfflineKey {
            ssh_user: "jhen".into(),
            ssh_port: 2222,
            seed: [0x55; 32],
            authorized_keys: None,
            hostkey_sha256: Some([0x66; 32]),
        }),
        ..record.clone()
    };

    let json = serde_json::json!({
        "spec": "bind-v1",
        "inputs": {
            "session_seed_hex": hex(&session_seed),
            "eph_seed_hex": hex(&eph_seed),
            "token_hex": hex(&token),
            "pin": pin,
            "enroll_pubkey": enroll_pub,
            "device": "Jhen's Vision Pro",
        },
        "record": {
            "name": offer_name,
            "addrs": offer_addrs,
            "port": record.port,
            "ssh_user": offer_user,
            "ssh_port": offer_port,
            "hostkeys": offer_hostkeys,
        },
        "derived": {
            "spub_hex": hex(&spub),
            "epub_hex": hex(&epub),
            "shared_hex": hex(shared.as_bytes()),
            "pin_proof_hex": hex(&pin_proof(pin, &epub, &spub)),
        },
        "payload": {
            "url": record.to_url(),
            "bytes_hex": hex(&record.encode()),
        },
        "payload_offline": {
            "url": offline.to_url(),
            "bytes_hex": hex(&offline.encode()),
            "seed_hex": hex(&[0x55u8; 32]),
            "hostkey_sha256_hex": hex(&[0x66u8; 32]),
        },
        "frames": {
            "intro_hex": hex(&intro_bytes),
            "hello_sealed_hex": hex(&hello_sealed),
            "offer_sealed_hex": hex(&offer_sealed),
            "enroll_sealed_hex": hex(&enroll_sealed),
            "done_sealed_hex": hex(&done_sealed),
        },
    });
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}
