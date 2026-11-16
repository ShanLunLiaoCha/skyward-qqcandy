//! Metadata encryption as Android's fs_mgr/vold interprets the phone's
//! own fstab. `keydirectory` enables metadata encryption; the optional
//! `metadata_encryption` value overrides vold's defaults.

use anyhow::{ensure, Context, Result};
use skyward_block::dm::Target;
use skyward_block::fstab::Entry;
use std::path::{Path, PathBuf};

const KEY_DIR: &str = "key";
// AOSP android-12.0.0_r34 / android-15.0.0_r1 MetadataCrypt.cpp:
// an empty cipher selects supported_crypto_types[0], AES-256-XTS.
const CIPHERS: [(&str, &str, usize); 2] = [
    ("aes-256-xts", "aes-xts-plain64", 64),
    ("adiantum", "xchacha12,aes-adiantum-plain64", 32),
];
const SECTORS_PER_UNIT: u64 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encryption {
    pub cipher: String,
    pub wrapped: bool,
}

impl Encryption {
    /// The modern dm-default-key options format (v2), not a legacy-v1
    /// compatibility guess. Android runtime callers must first validate
    /// the installed system's options-format property/API level.
    pub fn of(entry: &Entry) -> Result<Encryption> {
        let said = match entry.extra("metadata_encryption") {
            Some(value) => value,
            None => {
                let directory = entry.extra("keydirectory").unwrap_or_default();
                ensure!(!directory.is_empty(), "the phone enables no metadata encryption key directory");
                ""
            }
        };
        let parts: Vec<_> = said.split(':').collect();
        ensure!(parts.len() <= 2, "invalid metadata encryption options: {said}");
        let name = if parts[0].is_empty() { "aes-256-xts" } else { parts[0] };
        let cipher = CIPHERS.iter().find_map(|(theirs, kernels, _)| (*theirs == name).then_some(*kernels))
            .with_context(|| format!("no cipher here is the {name} the phone names"))?;
        let wrapped = match parts.get(1) {
            None => false,
            Some(&"wrappedkey_v0") => true,
            Some(flag) => anyhow::bail!("unsupported metadata encryption flag: {flag}"),
        };
        Ok(Encryption { cipher: cipher.to_string(), wrapped })
    }

    /// Validate the plaintext key size before sending it to the kernel.
    /// Hardware-wrapped storage keys are opaque and have no plaintext-size
    /// assertion here; only KeyMint/kernel can validate those.
    pub fn validate_key(&self, key: &[u8]) -> Result<()> {
        ensure!(!key.is_empty(), "metadata storage key is empty");
        if !self.wrapped {
            let size = CIPHERS.iter().find_map(|(_, kernel, size)| (*kernel == self.cipher).then_some(*size))
                .context("unsupported metadata kernel cipher")?;
            ensure!(key.len() == size, "metadata storage key length {} does not match cipher length {size}", key.len());
        }
        Ok(())
    }
}

/// Resolve Android's options format without silently mapping a legacy or
/// unknown target as modern. AOSP defaults to v1 for launch API <=29, v2
/// for newer devices. Missing/malformed launch API is not enough evidence.
pub fn modern_format(explicit: Option<&str>, first_api: Option<&str>) -> Result<()> {
    let version = match explicit {
        Some(value) => value.parse::<u32>().context("invalid dm-default-key options format")?,
        None => {
            let api = first_api.context("no installed first API level to select metadata options format")?
                .parse::<u32>().context("invalid installed first API level")?;
            ensure!(api != 0, "unknown installed first API level");
            if api <= 29 { 1 } else { 2 }
        }
    };
    ensure!(version == 2, "dm-default-key options format {version} is not supported by this recovery (requires v2)");
    Ok(())
}

pub fn key_dir(entry: &Entry) -> Result<PathBuf> {
    let dir = entry.extra("keydirectory").context("the phone says where the key for its data partition is not")?;
    let path = Path::new(dir);
    ensure!(path.is_absolute() && path.components().all(|p| matches!(p, std::path::Component::RootDir | std::path::Component::Normal(_))), "metadata keydirectory is not a plain absolute path");
    Ok(path.join(KEY_DIR))
}

pub fn target(device: &str, sectors: u64, key: &[u8], encryption: &Encryption) -> Target {
    Target::DefaultKey {
        sectors: sectors - sectors % SECTORS_PER_UNIT,
        device: device.to_string(), cipher: encryption.cipher.clone(),
        key: hex::encode(key), wrapped: encryption.wrapped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(extras: &str) -> Entry {
        Entry { device: "/dev/block/by-name/userdata".into(), mount_point: "/data".into(),
            filesystem: "f2fs".into(), options: vec!["noatime".into(), "inlinecrypt".into()],
            extras: extras.split(',').map(str::to_string).collect() }
    }
    #[test]
    fn explicit_ciphers_and_wrapped_key() {
        assert_eq!(Encryption::of(&entry("metadata_encryption=aes-256-xts:wrappedkey_v0")).unwrap(),
            Encryption { cipher: "aes-xts-plain64".into(), wrapped: true });
        assert_eq!(Encryption::of(&entry("metadata_encryption=adiantum")).unwrap(),
            Encryption { cipher: "xchacha12,aes-adiantum-plain64".into(), wrapped: false });
    }
    #[test]
    fn pgz110_keydirectory_enables_default_aes_without_wrapping() {
        let e = entry("wait,check,fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized,keydirectory=/metadata/vold/metadata_encryption,fsverity,fscompress");
        let encryption = Encryption::of(&e).unwrap();
        assert_eq!(encryption, Encryption { cipher: "aes-xts-plain64".into(), wrapped: false });
        assert_eq!(key_dir(&e).unwrap(), Path::new("/metadata/vold/metadata_encryption/key"));
        encryption.validate_key(&[0x42; 64]).unwrap();
        assert!(encryption.validate_key(&[0x42; 32]).is_err());
    }
    #[test]
    fn empty_cipher_matches_vold_default_but_unknown_flags_fail() {
        assert_eq!(Encryption::of(&entry("metadata_encryption=")).unwrap().cipher, "aes-xts-plain64");
        assert!(Encryption::of(&entry("metadata_encryption=:wrappedkey_v0")).unwrap().wrapped);
        for extras in ["quota", "keydirectory=", "metadata_encryption=rot13", "metadata_encryption=aes-256-xts:",
            "metadata_encryption=aes-256-xts:wrappedkey_v1", "metadata_encryption=aes-256-xts:wrappedkey_v0:extra"] {
            assert!(Encryption::of(&entry(extras)).is_err(), "{extras}");
        }
    }
    #[test]
    fn metadata_key_path_is_absolute_and_plain() {
        assert!(key_dir(&entry("quota")).is_err());
        for dir in ["", "relative", "/metadata/../data"] {
            assert!(key_dir(&entry(&format!("keydirectory={dir}"))).is_err());
        }
    }
    #[test]
    fn format_defaults_follow_launch_api_and_fail_closed_for_legacy() {
        modern_format(None, Some("31")).unwrap();
        modern_format(None, Some("35")).unwrap();
        modern_format(Some("2"), None).unwrap();
        for (explicit, api) in [(None, Some("29")), (None, None), (None, Some("0")),
            (None, Some("garbage")), (Some("1"), Some("31")), (Some("3"), Some("35")), (Some("garbage"), None)] {
            assert!(modern_format(explicit, api).is_err());
        }
    }
    #[test]
    fn target_rounds_to_whole_4096_byte_units() {
        let e = Encryption { cipher: "aes-xts-plain64".into(), wrapped: true };
        let t = target("/dev/block/by-name/userdata", 969_825_751, &[0xAB, 0x01], &e);
        let Target::DefaultKey { sectors, key, cipher, device, wrapped } = t else { panic!("wrong target") };
        assert_eq!(sectors, 969_825_744); assert_eq!(key, "ab01");
        assert_eq!(cipher, "aes-xts-plain64"); assert_eq!(device, "/dev/block/by-name/userdata"); assert!(wrapped);
    }
}
