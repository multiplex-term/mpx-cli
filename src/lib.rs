//! mpx — companion CLI for Multiplex.
//!
//! `mpx bind` runs on the machine being added to the app: it publishes a
//! short-lived bind offer (QR + clipboard + Bonjour), then completes an
//! encrypted TCP handshake in which the app enrolls ITS public key into this
//! machine's authorized_keys. The default handshake never moves a private
//! key; `--offline` inverts that for hosts the device can only reach over
//! SSH itself (the app retires the transported key on first connect).
//!
//! The Multiplex client tests against the same cross-implementation
//! vectors this crate generates (`cargo run --example gen_vectors`), so
//! the two sides cannot drift apart silently.

pub mod announce;
pub mod authkeys;
pub mod cancel;
pub mod clip;
pub mod frame;
pub mod hostinfo;
pub mod payload;
pub mod qr;
pub mod server;
pub mod util;
