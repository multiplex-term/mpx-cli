//! Ctrl-C that still says goodbye.
//!
//! `mpx bind` prints "(Ctrl-C cancels)", and until now that was literally
//! true and practically wrong: the default SIGINT disposition kills the
//! process where it stands, so `Announcer::stop()` never runs and no mDNS
//! goodbye goes out. Every device browsing for `_multiplex-bind._tcp` then
//! keeps a dead offer in its list until its own cache expires — Multiplex
//! showed a machine still asking for a PIN that nothing was listening for,
//! and its resolution kept succeeding the whole time, so the app could not
//! tell the difference from the outside.
//!
//! The handler therefore does the only thing that is async-signal-safe: it
//! sets a flag. `server::run` already polls its non-blocking accept every
//! 100 ms to enforce the deadline, so it notices within a tick and returns
//! through the ordinary path — which unregisters the service, waits out the
//! goodbye, and shuts the daemon down like any other ending.
//!
//! SIGTERM gets the same treatment (a closed terminal, a `kill`, a service
//! manager stopping the unit). SIGKILL and a crash still cannot say goodbye;
//! nothing running in this process can fix those.

use std::sync::atomic::{AtomicBool, Ordering};

static CANCELED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle(_signal: libc::c_int) {
    // Async-signal-safe: a relaxed atomic store and nothing else. No
    // allocation, no I/O, no locks.
    CANCELED.store(true, Ordering::SeqCst);
}

/// Installs the handler for SIGINT and SIGTERM. Idempotent and best effort:
/// if installation fails the CLI still works, it just goes back to dying
/// abruptly, which is where it started.
pub fn install() {
    for signal in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: `handle` is async-signal-safe (one atomic store), and this
        // runs before any thread that could race the disposition.
        unsafe {
            libc::signal(signal, handle as *const () as libc::sighandler_t);
        }
    }
}

/// Whether a cancel signal has arrived. Polled by the accept loop.
pub fn requested() -> bool {
    CANCELED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The flag has to survive being read repeatedly — the accept loop polls
    /// it ten times a second and must keep seeing the cancel, not consume it.
    #[test]
    fn the_flag_latches_once_raised() {
        CANCELED.store(false, Ordering::SeqCst);
        assert!(!requested());
        handle(libc::SIGINT);
        assert!(requested());
        assert!(requested());
        CANCELED.store(false, Ordering::SeqCst);
    }
}
