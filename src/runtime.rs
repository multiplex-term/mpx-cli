//! The bridge's private runtime directory, and who may talk across it.
//!
//! A unix socket is only as private as the directory chain above it: a
//! writable ancestor owned by someone else lets that someone swap the
//! directory and serve their own socket under the expected name. So the
//! directory is created owner-only, and every ancestor must belong to this
//! user or root, with any other-writable one root-owned and sticky (`/tmp`'s
//! shape). Both ends of a connection then check the peer's uid — the bridge
//! refuses other users' clients, and the client refuses a socket another
//! user is serving.

use std::io::{self, BufRead};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

pub fn current_uid() -> u32 {
    // SAFETY: getuid cannot fail and touches no memory.
    unsafe { libc::getuid() }
}

pub fn home() -> io::Result<PathBuf> {
    match std::env::var_os("HOME").map(PathBuf::from) {
        Some(home) if home.is_absolute() => Ok(home),
        _ => Err(io::Error::other(
            "HOME is not set to an absolute path — refusing to pick a shared directory instead",
        )),
    }
}

/// `~/.mpx/<leaf>` — never a shared fallback like `/tmp`.
pub fn private_dir(leaf: &str) -> io::Result<PathBuf> {
    Ok(home()?.join(".mpx").join(leaf))
}

/// Where bridges put their sockets: `$MPX_RUNTIME_DIR` (tests, unusual
/// homes) or `~/.mpx/run`.
pub fn runtime_dir() -> io::Result<PathBuf> {
    match std::env::var_os("MPX_RUNTIME_DIR") {
        Some(dir) => Ok(PathBuf::from(dir)),
        None => private_dir("run"),
    }
}

/// One JSON value as one `\n`-terminated line, flushed — the framing on
/// both sides of the bridge.
pub fn write_json_line(writer: &mut impl io::Write, value: &serde_json::Value) -> io::Result<()> {
    let mut line = serde_json::to_vec(value).expect("JSON values always serialize");
    line.push(b'\n');
    writer.write_all(&line)?;
    writer.flush()
}

/// Creates `dir` owner-only (0700) and proves the chain above it safe.
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let uid = current_uid();
    let meta = std::fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(io::Error::other(format!(
            "{} is not a plain directory",
            dir.display()
        )));
    }
    if meta.uid() != uid {
        return Err(io::Error::other(format!(
            "{} belongs to uid {}, not you",
            dir.display(),
            meta.uid()
        )));
    }
    if meta.mode() & 0o777 != 0o700 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    check_ancestry(&std::fs::canonicalize(dir)?, uid)
}

/// Every ancestor of `dir` (canonical) owned by `uid` or root; one that
/// others can write must be root's and sticky.
fn check_ancestry(dir: &Path, uid: u32) -> io::Result<()> {
    for ancestor in dir.ancestors().skip(1) {
        let meta = std::fs::metadata(ancestor)?;
        let owner_ok = meta.uid() == uid || meta.uid() == 0;
        let others_write = meta.mode() & 0o022 != 0;
        let sticky_root = meta.uid() == 0 && meta.mode() & 0o1000 != 0;
        if !owner_ok || (others_write && !sticky_root) {
            return Err(io::Error::other(format!(
                "{} is writable by other users — refusing to keep a socket under it",
                ancestor.display()
            )));
        }
    }
    Ok(())
}

/// The uid on the other end of a connected unix socket.
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let fd = stream.as_raw_fd();
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred`/`len` are valid for writes of the sizes passed.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut libc::ucred as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.uid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: both out-pointers are valid for one write each.
        let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }
}

/// Reads one `\n`-terminated line of at most `max` bytes (newline
/// excluded). `Ok(None)` at EOF; an over-long line is an `InvalidData`
/// error after it has been consumed up to its newline, so a caller may skip
/// it and keep reading.
pub fn read_line_bounded<R: BufRead>(reader: &mut R, max: usize) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let mut oversized = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() && !oversized {
                Ok(None)
            } else if oversized {
                Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"))
            } else {
                Ok(Some(line))
            };
        }
        let (chunk, done) = match available.iter().position(|&b| b == b'\n') {
            Some(i) => (&available[..i], i + 1),
            None => (available, available.len()),
        };
        if !oversized {
            if line.len() + chunk.len() > max {
                oversized = true;
                line.clear();
            } else {
                line.extend_from_slice(chunk);
            }
        }
        let found_newline = done > chunk.len();
        reader.consume(done);
        if found_newline {
            return if oversized {
                Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"))
            } else {
                Ok(Some(line))
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn bounded_lines_skip_oversized_ones_and_keep_reading() {
        let mut input = Cursor::new(b"ok\nTOO-LONG-LINE\nnext\nlast".to_vec());
        assert_eq!(
            read_line_bounded(&mut input, 8).unwrap(),
            Some(b"ok".to_vec())
        );
        assert_eq!(
            read_line_bounded(&mut input, 8).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            read_line_bounded(&mut input, 8).unwrap(),
            Some(b"next".to_vec())
        );
        assert_eq!(
            read_line_bounded(&mut input, 8).unwrap(),
            Some(b"last".to_vec())
        );
        assert_eq!(read_line_bounded(&mut input, 8).unwrap(), None);
    }

    #[test]
    fn private_dirs_are_created_owner_only_and_tightened() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("a").join("run");
        ensure_private_dir(&dir).unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&dir).unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn a_symlinked_runtime_dir_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.path().join("run");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(ensure_private_dir(&link).is_err());
    }

    #[test]
    fn an_other_writable_ancestor_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let open = base.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = ensure_private_dir(&open.join("run")).unwrap_err();
        assert!(err.to_string().contains("writable by other users"), "{err}");
    }

    #[test]
    fn peer_uid_is_our_own_on_a_socketpair() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), current_uid());
    }
}
