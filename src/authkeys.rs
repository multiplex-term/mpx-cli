//! authorized_keys editing. Every line mpx writes carries its marker in the
//! key line's own comment field — `multiplex:bind:<uuid8>:<device-slug>` —
//! never a separate `#` line, so the marker travels with the key and unbind
//! can match it exactly. Writes are atomic (tempfile + rename in the same
//! directory) with 700/600 permissions ensured.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const MARKER_PREFIX: &str = "multiplex:bind:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkedKey {
    pub id: String,
    pub device: String,
    pub key_type: String,
    pub line: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AddOutcome {
    Added,
    /// The same public key was already enrolled; its existing line (and
    /// comment) was kept — idempotent re-binds don't multiply lines.
    AlreadyPresent {
        comment: String,
    },
}

pub fn default_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".ssh").join("authorized_keys")
}

/// Splits an authorized_keys line into (key type, key material, comment).
/// Lines mpx wrote never have an options field, but files mpx *edits* may —
/// never mangle them.
///
/// The key cannot be located by scanning for the first field that *looks*
/// like a key type: an option's quoted value can contain one verbatim
/// (`command="echo ssh-rsa hi" ssh-ed25519 …`), and a scan lands inside the
/// quotes, taking `ssh-rsa` as the type and pushing the real key into the
/// comment. That line's `multiplex:bind:` marker then stops being visible to
/// `marked_keys`, so `mpx unbind` cannot revoke a key it enrolled. Walk the
/// quoting instead: the options field, when present, is field one and ends at
/// the first *unquoted* space.
fn parse_line(line: &str) -> Option<(String, String, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let mut fields = skip_options(trimmed).split_whitespace();
    let key_type = fields.next()?.to_string();
    let key_b64 = fields.next()?.to_string();
    let comment = fields.collect::<Vec<_>>().join(" ");
    Some((key_type, key_b64, comment))
}

fn is_key_type(field: &str) -> bool {
    field.starts_with("ssh-") || field.starts_with("ecdsa-") || field.starts_with("sk-")
}

/// Returns the line from its key type onward, dropping a leading options
/// field if there is one. Quotes (and backslash escapes inside them, which
/// sshd honours) hide the spaces within an option value.
fn skip_options(line: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (index, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                return if is_key_type(&line[..index]) {
                    line
                } else {
                    line[index..].trim_start()
                };
            }
            _ => {}
        }
    }
    line
}

/// Reads the file, treating "it isn't there yet" as empty and *every other*
/// failure as a failure.
///
/// `read_to_string(path).unwrap_or_default()` collapsed a permissions error,
/// a bad disk, and a single non-UTF-8 byte anywhere in the file into "the
/// file is empty" — and the callers act on that by renaming a rebuilt file
/// over the original. One `latin-1` comment in someone's authorized_keys was
/// enough for a bind to replace every key in it with the one being enrolled.
/// A file we cannot read is a file we must not rewrite.
fn read_existing(path: &Path) -> std::io::Result<String> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(content),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(err) => Err(err),
    }
}

pub fn marked_keys(path: &Path) -> std::io::Result<Vec<MarkedKey>> {
    Ok(read_existing(path)?
        .lines()
        .filter_map(|line| {
            let (key_type, _, comment) = parse_line(line)?;
            let rest = comment.strip_prefix(MARKER_PREFIX)?;
            let mut parts = rest.splitn(2, ':');
            let id = parts.next()?.to_string();
            let device = parts.next().unwrap_or("").to_string();
            Some(MarkedKey {
                id,
                device,
                key_type,
                line: line.trim().to_string(),
            })
        })
        .collect())
}

/// Appends `<key_type> <key_b64> <comment>`, creating `~/.ssh` (700) and the
/// file (600) when absent. If the same key material is already present under
/// any comment, the file is left untouched.
pub fn ensure_line(
    path: &Path,
    key_type: &str,
    key_b64: &str,
    comment: &str,
) -> std::io::Result<AddOutcome> {
    let content = read_existing(path)?;
    for line in content.lines() {
        if let Some((_, existing_b64, existing_comment)) = parse_line(line) {
            if existing_b64 == key_b64 {
                return Ok(AddOutcome::AlreadyPresent {
                    comment: existing_comment,
                });
            }
        }
    }
    let mut updated = content;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&format!("{key_type} {key_b64} {comment}\n"));
    write_atomically(path, &updated)?;
    Ok(AddOutcome::Added)
}

/// Removes marked lines selected by `filter` (by uuid8 id); returns them.
pub fn remove_marked(
    path: &Path,
    filter: impl Fn(&MarkedKey) -> bool,
) -> std::io::Result<Vec<MarkedKey>> {
    let content = read_existing(path)?;
    let mut removed = Vec::new();
    let mut kept = String::new();
    for line in content.lines() {
        let marked = parse_line(line).and_then(|(key_type, _, comment)| {
            let rest = comment.strip_prefix(MARKER_PREFIX)?;
            let mut parts = rest.splitn(2, ':');
            Some(MarkedKey {
                id: parts.next()?.to_string(),
                device: parts.next().unwrap_or("").to_string(),
                key_type,
                line: line.trim().to_string(),
            })
        });
        match marked {
            Some(key) if filter(&key) => removed.push(key),
            _ => {
                kept.push_str(line);
                kept.push('\n');
            }
        }
    }
    if !removed.is_empty() {
        write_atomically(path, &kept)?;
    }
    Ok(removed)
}

fn write_atomically(path: &Path, content: &str) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        set_mode(dir, 0o700)?;
    }
    // Per-process temp name: two `mpx` runs sharing a directory must not
    // write the same scratch file and hand each other a half-written one.
    let tmp = dir.join(format!(
        ".{}.mpx-{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("authorized_keys"),
        std::process::id()
    ));
    // Only a leftover from a killed run of *this* pid can be here; clear it
    // so the exclusive create below succeeds.
    let _ = fs::remove_file(&tmp);
    let mut file = create_private(&tmp)?;
    let written = file
        .write_all(content.as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(err) = written.and_then(|()| fs::rename(&tmp, path)) {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    Ok(())
}

/// Creates the scratch file at 0600 *in the open(2) call*. Creating it first
/// and chmod-ing after leaves a window where the umask's permissions apply —
/// and on a shared machine that window is enough to read a file in `~/.ssh`.
/// O_EXCL is what makes it safe to use a predictable name: a symlink planted
/// at that path makes the create fail rather than redirect the write.
#[cfg(unix)]
fn create_private(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh").join("authorized_keys");
        (dir, path)
    }

    #[test]
    fn append_is_idempotent_and_atomic() {
        let (_dir, path) = temp_file();
        let outcome = ensure_line(
            &path,
            "ssh-ed25519",
            "AAAAKEY",
            "multiplex:bind:9f3a1c2e:visionpro",
        )
        .unwrap();
        assert_eq!(outcome, AddOutcome::Added);
        let again = ensure_line(
            &path,
            "ssh-ed25519",
            "AAAAKEY",
            "multiplex:bind:deadbeef:other",
        )
        .unwrap();
        assert!(
            matches!(again, AddOutcome::AlreadyPresent { comment } if comment == "multiplex:bind:9f3a1c2e:visionpro")
        );
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 1);
    }

    #[test]
    fn preserves_foreign_lines_and_removes_only_marked() {
        let (_dir, path) = temp_file();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            "# a comment\ncommand=\"echo hi\" ssh-rsa FOREIGN user@laptop\n",
        )
        .unwrap();
        ensure_line(
            &path,
            "ssh-ed25519",
            "MINE",
            "multiplex:bind:9f3a1c2e:visionpro",
        )
        .unwrap();
        ensure_line(
            &path,
            "ssh-ed25519",
            "MINE2",
            "multiplex:bind:11223344:ipad",
        )
        .unwrap();

        let listed = marked_keys(&path).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, "9f3a1c2e");
        assert_eq!(listed[0].device, "visionpro");

        let removed = remove_marked(&path, |k| k.id == "9f3a1c2e").unwrap();
        assert_eq!(removed.len(), 1);
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("# a comment"));
        assert!(content.contains("FOREIGN"));
        assert!(content.contains("MINE2"));
        assert!(!content.contains("MINE "));
    }

    /// An option value may contain something that reads exactly like a key
    /// type. Scanning for the first such field lands inside the quotes, and
    /// the marker then rides in what the parser calls "key material" — so
    /// unbind stops seeing a key it enrolled, and the key cannot be revoked.
    #[test]
    fn key_fields_survive_options_that_quote_a_key_type() {
        let line = r#"command="echo ssh-rsa hi",no-pty ssh-ed25519 AAAAREAL multiplex:bind:9f3a1c2e:visionpro"#;
        assert_eq!(
            parse_line(line),
            Some((
                "ssh-ed25519".into(),
                "AAAAREAL".into(),
                "multiplex:bind:9f3a1c2e:visionpro".into()
            ))
        );

        let (_dir, path) = temp_file();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, format!("{line}\n")).unwrap();

        let listed = marked_keys(&path).unwrap();
        assert_eq!(listed.len(), 1, "an optioned line must still be revocable");
        assert_eq!(listed[0].id, "9f3a1c2e");
        assert_eq!(listed[0].key_type, "ssh-ed25519");

        // And the key material is seen, so re-binding it stays a no-op
        // instead of appending a second line for the same key.
        let again = ensure_line(
            &path,
            "ssh-ed25519",
            "AAAAREAL",
            "multiplex:bind:deadbeef:x",
        )
        .unwrap();
        assert!(matches!(again, AddOutcome::AlreadyPresent { .. }));

        assert_eq!(
            remove_marked(&path, |k| k.id == "9f3a1c2e").unwrap().len(),
            1
        );
        assert_eq!(fs::read_to_string(&path).unwrap().trim(), "");
    }

    /// One stray non-UTF-8 byte used to make the whole file read as empty,
    /// and enrolling then renamed a one-line file over it — every existing
    /// key gone. A file we cannot read is a file we must not rewrite.
    #[test]
    fn an_unreadable_file_is_never_rewritten() {
        let (_dir, path) = temp_file();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original: &[u8] = b"ssh-ed25519 AAAAREAL someone@laptop\n\xff\xfe not utf-8\n";
        fs::write(&path, original).unwrap();

        let err = ensure_line(&path, "ssh-ed25519", "NEW", "multiplex:bind:9f3a1c2e:box")
            .expect_err("enrolling into an unreadable file must fail, not truncate it");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(fs::read(&path).unwrap(), original, "the file was rewritten");

        // The same file must not read as "nothing enrolled" either — that
        // answer is indistinguishable from a successful revocation.
        assert!(marked_keys(&path).is_err());
        assert!(remove_marked(&path, |_| true).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    /// A missing file is still the ordinary first-bind case, not an error.
    #[test]
    fn a_missing_file_is_empty_not_an_error() {
        let (_dir, path) = temp_file();
        assert_eq!(marked_keys(&path).unwrap(), vec![]);
        assert_eq!(remove_marked(&path, |_| true).unwrap(), vec![]);
        assert_eq!(
            ensure_line(&path, "ssh-ed25519", "AAAA", "multiplex:bind:9f3a1c2e:box").unwrap(),
            AddOutcome::Added
        );
    }

    /// A backslash-escaped quote inside an option must not end the field.
    #[test]
    fn options_tolerate_escaped_quotes() {
        let line = r#"command="echo \"hi\" there" ssh-ed25519 AAAAB3 tag"#;
        assert_eq!(
            parse_line(line),
            Some(("ssh-ed25519".into(), "AAAAB3".into(), "tag".into()))
        );
    }

    /// The file must never exist at the umask's permissions, not even for the
    /// instant between create and chmod.
    #[cfg(unix)]
    #[test]
    fn the_written_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path) = temp_file();
        ensure_line(
            &path,
            "ssh-ed25519",
            "AAAAKEY",
            "multiplex:bind:9f3a1c2e:box",
        )
        .unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "authorized_keys was {mode:o}");
        let dir_mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "the .ssh directory was {dir_mode:o}");
        // No scratch file survives a successful write.
        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("mpx-"))
            .collect();
        assert!(leftovers.is_empty(), "temp file left behind");
    }

    /// A symlink squatting on the scratch path must never redirect the write
    /// into whatever it points at — the link is what gets replaced.
    #[cfg(unix)]
    #[test]
    fn a_planted_scratch_symlink_cannot_redirect_the_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authorized_keys");
        let victim = dir.path().join("victim");
        fs::write(&victim, "untouched\n").unwrap();
        let tmp = dir
            .path()
            .join(format!(".authorized_keys.mpx-{}.tmp", std::process::id()));
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();

        write_atomically(&path, "ssh-ed25519 AAAA marker\n").unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "untouched\n");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "ssh-ed25519 AAAA marker\n"
        );
    }
}
