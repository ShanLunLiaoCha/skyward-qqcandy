//! Installed APEX locations across recovery mount layouts.
use std::path::{Path, PathBuf};
pub const DIRECTORIES: [&str; 6] = [
    "/system_ext/apex", "/mnt/system_ext/apex", "/mnt/system/system/apex",
    "/product/apex", "/mnt/product/apex", "/vendor/apex",
];
pub fn find(name: &str, roots: impl IntoIterator<Item=impl AsRef<Path>>) -> Option<PathBuf> {
    roots.into_iter().map(|root| root.as_ref().join(format!("{name}.apex"))).find(|file| file.is_file())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_system_ext_mount_is_not_assumed_to_live_under_mnt() {
        assert!(DIRECTORIES.contains(&"/system_ext/apex"));
        let temp=tempfile::tempdir().unwrap();
        let actual=temp.path().join("system_ext/apex");std::fs::create_dir_all(&actual).unwrap();
        let apex=actual.join("com.android.vndk.v31.apex");std::fs::write(&apex,b"APEX fixture").unwrap();
        assert_eq!(find("com.android.vndk.v31",[temp.path().join("mnt/system_ext/apex"),actual]),Some(apex));
    }
    #[test]
    fn missing_bundle_does_not_invent_a_path() {
        let temp=tempfile::tempdir().unwrap();
        assert_eq!(find("com.android.vndk.v31",[temp.path()]),None);
    }
}
