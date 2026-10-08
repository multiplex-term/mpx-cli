//! `mpx skill` — ships the `multiplex` agent skill with the binary, so the
//! instructions an agent reads always match the `mpx browser` it calls.
//!
//! One source: `plugin/skills/multiplex/SKILL.md` is both what this embeds
//! and the skill of the Claude Code plugin this repository publishes
//! (`.claude-plugin/marketplace.json` → `plugin/`).

use std::path::{Path, PathBuf};

pub const SKILL_NAME: &str = "multiplex";
pub const SKILL_MD: &str = include_str!("../plugin/skills/multiplex/SKILL.md");

/// Where a skill directory goes for each agent this knows about. Claude Code
/// honours `CLAUDE_CONFIG_DIR` (a relocated config root keeps its skills
/// there too); Codex honours `CODEX_HOME`.
pub fn default_skills_dir(agent: &str) -> Option<PathBuf> {
    let home = crate::runtime::home().ok()?;
    match agent {
        "claude" => Some(
            std::env::var_os("CLAUDE_CONFIG_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".claude"))
                .join("skills"),
        ),
        "codex" => Some(
            std::env::var_os("CODEX_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".codex"))
                .join("skills"),
        ),
        _ => None,
    }
}

/// Writes `<skills_dir>/multiplex/SKILL.md`, replacing an older copy.
/// Returns the file written. The new copy is written beside the old one and
/// renamed over it, so a symlink planted at either name is replaced, never
/// written through; a symlinked skill directory is refused.
pub fn install(skills_dir: &Path) -> std::io::Result<PathBuf> {
    let dir = skills_dir.join(SKILL_NAME);
    if std::fs::symlink_metadata(&dir).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(std::io::Error::other(format!(
            "{} is a symlink — remove it first",
            dir.display()
        )));
    }
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("SKILL.md");
    crate::authkeys::write_atomically(&path, SKILL_MD)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_skill_carries_frontmatter_an_agent_can_index() {
        assert!(SKILL_MD.starts_with("---\nname: multiplex\ndescription: "));
        assert!(SKILL_MD.contains("mpx browser snapshot"));
    }

    /// The plugin's version moves with the crate's, so a release that
    /// changes `mpx browser` also ships the skill update to plugin users.
    #[test]
    fn the_plugin_version_tracks_the_crate() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../plugin/.claude-plugin/plugin.json")).unwrap();
        assert_eq!(manifest["name"], SKILL_NAME);
        assert_eq!(manifest["version"], env!("CARGO_PKG_VERSION"));
        let marketplace: serde_json::Value =
            serde_json::from_str(include_str!("../.claude-plugin/marketplace.json")).unwrap();
        assert_eq!(marketplace["plugins"][0]["name"], SKILL_NAME);
        assert_eq!(marketplace["plugins"][0]["source"], "./plugin");
    }

    #[test]
    fn install_replaces_a_planted_symlink_instead_of_following_it() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, "keep").unwrap();
        std::fs::create_dir_all(dir.path().join("multiplex")).unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join("multiplex").join("SKILL.md")).unwrap();
        install(dir.path()).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("multiplex").join("SKILL.md")).unwrap(),
            SKILL_MD
        );
    }

    #[test]
    fn install_writes_into_a_named_skill_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = install(dir.path()).unwrap();
        assert_eq!(path, dir.path().join("multiplex").join("SKILL.md"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), SKILL_MD);
    }
}
