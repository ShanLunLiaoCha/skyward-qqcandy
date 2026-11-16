//! Select only a mode the running kernel advertises. This keeps real suspend
//! available without assuming a Qualcomm-specific s2idle policy on MTK.
use anyhow::{ensure, Context, Result};
use std::path::Path;

pub fn choose(text: &str) -> Result<Option<&'static str>> {
    let words: Vec<_> = text.split_whitespace().collect();
    ensure!(!words.is_empty(), "mem_sleep advertises no modes");
    let active: Vec<_> = words.iter().filter(|word| word.starts_with('[') && word.ends_with(']')).collect();
    ensure!(active.len() == 1, "mem_sleep must identify exactly one active mode");
    let has_s2idle = words.iter().any(|word| word.trim_matches(['[', ']']) == "s2idle");
    if has_s2idle && *active[0] != "[s2idle]" { Ok(Some("s2idle")) } else { Ok(None) }
}

/// None means keep the kernel's selected mode. A missing selector is normal on
/// kernels whose /sys/power/state directly implements suspend; it is not a
/// reason to disable the sleep worker. Permission and format errors propagate.
pub fn configure(path: &Path) -> Result<()> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    if let Some(mode) = choose(&text)? {
        std::fs::write(path, mode).with_context(|| format!("select supported {mode} at {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn supported_s2idle_is_preferred_but_deep_only_is_preserved() {
        assert_eq!(choose("s2idle [deep]\n").unwrap(), Some("s2idle"));
        assert_eq!(choose("[s2idle] deep\n").unwrap(), None);
        assert_eq!(choose("[deep]\n").unwrap(), None);
        assert_eq!(choose("[shallow] deep\n").unwrap(), None);
    }
    #[test]
    fn selector_can_be_absent_without_disabling_the_sleep_worker() {
        let root = std::env::temp_dir().join(format!("skyward-suspend-mode-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("mem_sleep");
        configure(&file).unwrap();
        assert!(!file.exists());
        std::fs::write(&file, "[deep]\n").unwrap();
        configure(&file).unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "[deep]\n");
        std::fs::write(&file, "s2idle [deep]\n").unwrap();
        configure(&file).unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "s2idle");
        // This exact fixed test file was created above; no computed recursive delete.
        std::fs::remove_file(&file).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }
    #[test]
    fn malformed_modes_are_not_silently_assumed_supported() {
        for value in ["", "deep", "[deep] [s2idle]"] { assert!(choose(value).is_err()); }
    }
}
