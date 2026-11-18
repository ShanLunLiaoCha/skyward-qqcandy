//! Installed APEX locations across recovery mount layouts.
use anyhow::{Context, Result, bail, ensure};
use std::path::{Path, PathBuf};

const VNDK_CURRENT: &str = "/mnt/system/system/apex/com.android.vndk.current.apex";
pub const MANIFEST_LIMIT: usize = 4096;
pub const DIRECTORIES: [&str; 6] = [
    "/system_ext/apex", "/mnt/system_ext/apex", "/mnt/system/system/apex",
    "/product/apex", "/mnt/product/apex", "/vendor/apex",
];
pub fn find(name: &str, roots: impl IntoIterator<Item=impl AsRef<Path>>) -> Option<PathBuf> {
    roots.into_iter().map(|root| root.as_ref().join(format!("{name}.apex"))).find(|file| file.is_file())
}
/// Prefer the exact versioned name in the normal search order. A present
/// but invalid versioned object is an error, not a reason to fall back.
/// The second result marks `current` so the caller must check its manifest.
pub fn find_vndk(name: &str) -> Result<Option<(PathBuf, bool)>> {
    select_vndk(name, DIRECTORIES.map(Path::new), Path::new(VNDK_CURRENT))
}

fn select_vndk<'a>(name: &str, roots: impl IntoIterator<Item = &'a Path>, current: &Path) -> Result<Option<(PathBuf, bool)>> {
    let regular = |path: &Path| -> Result<bool> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                ensure!(meta.is_file(), "VNDK bundle {} is not a regular file", path.display());
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error).with_context(|| format!("inspect VNDK bundle {}", path.display())),
        }
    };
    for root in roots {
        let path = root.join(format!("{name}.apex"));
        if regular(&path)? { return Ok(Some((path, false))); }
    }
    Ok(regular(current)?.then(|| (current.to_owned(), true)))
}

fn varint(input: &mut &[u8]) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = input.split_first().context("truncated protobuf varint")?;
        *input = rest;
        ensure!(shift != 63 || byte <= 1, "protobuf varint overflow");
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            ensure!(shift == 0 || byte != 0, "overlong protobuf varint");
            return Ok(value);
        }
    }
    bail!("protobuf varint overflow")
}

fn consume<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    let (field, rest) = input.split_at_checked(len).context("truncated protobuf field")?;
    *input = rest;
    Ok(field)
}

/// Check the entire bounded ApexManifest message. In particular, a matching
/// prefix cannot conceal a second field 1 (protobuf readers may take the last).
pub fn verify_manifest_name(mut input: &[u8], expected: &str) -> Result<()> {
    ensure!(input.len() <= MANIFEST_LIMIT, "APEX manifest exceeds {MANIFEST_LIMIT} bytes");
    let mut name = None;
    while !input.is_empty() {
        let key = varint(&mut input)?;
        let (number, wire) = (key >> 3, key & 7);
        ensure!((1..=(1 << 29) - 1).contains(&number), "invalid protobuf field number");
        if number == 1 {
            ensure!(wire == 2 && name.is_none(), "invalid or duplicate APEX manifest name field");
        }
        match wire {
            0 => { varint(&mut input)?; }
            1 => { consume(&mut input, 8)?; }
            2 => {
                let len = usize::try_from(varint(&mut input)?).context("protobuf field length overflows")?;
                let field = consume(&mut input, len)?;
                if number == 1 { name = Some(std::str::from_utf8(field).context("invalid APEX manifest name encoding")?); }
            }
            5 => { consume(&mut input, 4)?; }
            _ => bail!("unsupported protobuf wire type {wire}"),
        }
    }
    ensure!(name == Some(expected), "APEX manifest name {name:?} does not match {expected}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const V31: &str = "com.android.vndk.v31";
    const A16_MANIFEST: &[u8] = b"\x0a\x14com.android.vndk.v31\x10\x01";

    #[test]
    fn parses_complete_a16_manifest_and_allows_other_well_formed_fields() {
        assert!(verify_manifest_name(A16_MANIFEST, V31).is_ok());
        let mut reordered = vec![0x10, 0x01];
        reordered.extend_from_slice(&A16_MANIFEST[..22]);
        reordered.extend_from_slice(&[0x1a, 3, 0x0a, 0x01, b'x']);
        assert!(verify_manifest_name(&reordered, V31).is_ok());
    }

    #[test]
    fn refuses_wrong_missing_or_duplicate_name() {
        assert!(verify_manifest_name(A16_MANIFEST, "com.android.vndk.v30").is_err());
        assert!(verify_manifest_name(&[0x10, 1], V31).is_err());
        let mut duplicate = A16_MANIFEST.to_vec();
        duplicate.extend_from_slice(&A16_MANIFEST[..22]);
        assert!(verify_manifest_name(&duplicate, V31).is_err());
        assert!(verify_manifest_name(&[0x08, 1], V31).is_err());
    }

    #[test]
    fn refuses_malformed_suffix_lengths_tags_and_oversize() {
        for tail in [&[0x18][..], &[0x1a, 1], &[0x00], &[0x1b], &[0x19, 1], &[0x18, 0x81, 0], &[0x18, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2]] {
            let mut bytes = A16_MANIFEST.to_vec();
            bytes.extend_from_slice(tail);
            assert!(verify_manifest_name(&bytes, V31).is_err(), "accepted malformed tail {tail:x?}");
        }
        assert!(verify_manifest_name(&A16_MANIFEST[..20], V31).is_err());
        assert!(verify_manifest_name(&vec![0; MANIFEST_LIMIT + 1], V31).is_err());
    }

    #[test]
    fn exact_version_precedes_current_and_v30_is_never_substituted() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let current = root.join("com.android.vndk.current.apex");
        let versioned = root.join(format!("{V31}.apex"));
        std::fs::write(root.join("com.android.vndk.v30.apex"), b"wrong").unwrap();
        assert_eq!(select_vndk(V31, [root], &current).unwrap(), None);
        std::fs::write(&current, b"current").unwrap();
        assert_eq!(select_vndk(V31, [root], &current).unwrap(), Some((current.clone(), true)));
        std::fs::create_dir(&versioned).unwrap();
        assert!(select_vndk(V31, [root], &current).is_err());
        std::fs::remove_dir(&versioned).unwrap();
        std::fs::write(&versioned, b"v31").unwrap();
        assert_eq!(select_vndk(V31, [root], &current).unwrap(), Some((versioned, false)));
    }

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
