//! Allowlisted PGZ110 recovery-ramdisk targets for factory-reset planning.
//! This parses trusted stock text; the caller still verifies the live block
//! devices and update state before making any destructive changes.
use anyhow::{bail, ensure, Context, Result};
use skyward_block::fstab::Entry;

pub struct ResetEntries {
    pub data: Entry,
    pub metadata: Entry,
    pub cache: Option<Entry>,
}

const USERDATA: &str = "/dev/block/by-name/userdata";
const METADATA: &str = "/dev/block/by-name/metadata";
const CACHE: &str = "/dev/block/by-name/oplusreserve2";
const FBE: &str = "fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized";
const KEY_DIR: &str = "keydirectory=/metadata/vold/metadata_encryption";

const META_OPTIONS: &[&str] = &["noatime", "nosuid", "nodev", "discard"];
const META_EXTRAS: &[&str] = &["wait", "check", "formattable", "first_stage_mount"];
const CACHE_OPTIONS: &[&str] = &["noatime", "nosuid", "nodev", "noauto_da_alloc", "discard"];
const DATA_OPTIONS: &[&str] = &[
    "noatime", "nosuid", "nodev", "discard", "noflush_merge", "fsync_mode=nobarrier",
    "reserve_root=134217", "resgid=1065", "inlinecrypt",
];
const DATA_EXTRAS: &[&str] = &[
    "wait", "check", "formattable", "quota", "latemount", "resize", "reservedsize=128m",
    "checkpoint=fs", FBE, KEY_DIR, "fsverity", "fscompress",
];

fn flags(text: &str, allowed: &[&str]) -> Result<Vec<String>> {
    let mut result = Vec::new();
    for flag in text.split(',') {
        ensure!(allowed.contains(&flag), "unaudited reset fstab flag {flag:?}");
        ensure!(!result.iter().any(|seen| seen == flag), "duplicate reset fstab flag {flag:?}");
        result.push(flag.to_owned());
    }
    Ok(result)
}

// Find relevant rows before parsing the five columns. In particular, a
// malformed or aliased row naming one of these devices must not be dropped
// by a permissive general-purpose fstab parser.
fn relevant(fields: &[&str]) -> bool {
    fields.iter().any(|word| {
        let name = word.trim_end_matches('/').rsplit('/').next().unwrap_or_default();
        let unslotted = name.strip_suffix("_a").or_else(|| name.strip_suffix("_b")).unwrap_or(name);
        // Other canonical by-name entries (including reserve2) aren't these
        // targets; a bare name or bootdevice/platform alias of a target is.
        matches!(unslotted, "userdata" | "metadata" | "oplusreserve2" | "opporeserve" | "data" | "cache")
    })
}

/// Parse the audited PGZ110 targets from the original recovery.fstab. Unknown
/// options (including slot mapping or filesystem layout overrides) are not
/// accepted by this narrow parser. Unrelated fstab rows are not used.
pub fn parse(text: &str) -> Result<ResetEntries> {
    ensure!(!text.contains('\0'), "NUL in recovery fstab");
    let (mut data, mut metadata, mut cache) = (None, None, None);
    let mut oem_alias_seen = false;
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if !relevant(&fields) {
            continue;
        }
        let row = (|| -> Result<()> {
            let [device, at, fs, options, extras] = fields.as_slice() else {
                bail!("malformed reset-relevant fstab row (expected five columns)");
            };
            // Both sampled stock versions list this secondary mount of
            // oplusreserve2. It is never a separate wipe target. Accept only
            // the specific audited alias, once; reject other aliases.
            if *at == "/opporeserve" {
                ensure!(!oem_alias_seen && *device == CACHE && *fs == "ext4"
                    && *options == "rw,seclabel,nosuid,nodev,noatime,data=ordered" && *extras == "wait",
                    "unexpected or duplicate OEM cache alias");
                oem_alias_seen = true;
                return Ok(());
            }
            let (target, expected_dev, expected_fs, allowed_options, allowed_extras) = match *at {
                "/data" => (&mut data, USERDATA, "f2fs", DATA_OPTIONS, DATA_EXTRAS),
                "/metadata" => (&mut metadata, METADATA, "ext4", META_OPTIONS, META_EXTRAS),
                "/cache" => (&mut cache, CACHE, "ext4", CACHE_OPTIONS, META_EXTRAS),
                _ => bail!("unexpected mount point or alias for a reset-relevant row: {at}"),
            };
            ensure!(target.is_none(), "duplicate reset target {at}");
            ensure!(*device == expected_dev && *fs == expected_fs, "unexpected device or filesystem for {at}");
            let options = flags(options, allowed_options)?;
            let extras = flags(extras, allowed_extras)?;
            ensure!(extras.iter().any(|flag| flag == "formattable"), "{at} is not formattable");
            if *at == "/data" {
                ensure!(options.iter().any(|flag| flag == "inlinecrypt")
                    && [FBE, KEY_DIR].into_iter().all(|required| extras.iter().any(|flag| flag.as_str() == required)),
                    "unexpected data encryption configuration");
            }
            *target = Some(Entry { device: (*device).into(), mount_point: (*at).into(),
                filesystem: (*fs).into(), options, extras });
            Ok(())
        })();
        row.with_context(|| format!("recovery fstab line {}", number + 1))?;
    }
    Ok(ResetEntries { data: data.context("missing active /data row")?,
        metadata: metadata.context("missing active /metadata row")?, cache })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA_ROW: &str = "/dev/block/by-name/userdata /data f2fs noatime,nosuid,nodev,discard,noflush_merge,fsync_mode=nobarrier,reserve_root=134217,resgid=1065,inlinecrypt wait,check,formattable,quota,latemount,resize,reservedsize=128m,checkpoint=fs,fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized,keydirectory=/metadata/vold/metadata_encryption,fsverity,fscompress";
    const META_ROW: &str = "/dev/block/by-name/metadata /metadata ext4 noatime,nosuid,nodev,discard wait,check,formattable,first_stage_mount";
    const CACHE_ROW: &str = "/dev/block/by-name/oplusreserve2 /cache ext4 noatime,nosuid,nodev,noauto_da_alloc,discard wait,check,formattable,first_stage_mount";
    const OEM_ALIAS: &str = "/dev/block/by-name/oplusreserve2 /opporeserve ext4 rw,seclabel,nosuid,nodev,noatime,data=ordered wait";
    fn table() -> String { format!("{DATA_ROW}\n{META_ROW}\n{CACHE_ROW}\n{OEM_ALIAS}\n") }

    #[test]
    fn validates_supplied_stock_tables() {
        // Integration fixtures are extracted read-only from local OEM images;
        // no proprietary filesystem images need to be checked into the repo.
        if let Some(paths) = std::env::var_os("SKYWARD_PGZ110_FSTAB_FIXTURES") {
            for path in std::env::split_paths(&paths) {
                let text = std::fs::read_to_string(&path).unwrap();
                let entries = parse(&text).unwrap_or_else(|error| panic!("{}: {error:#}", path.display()));
                assert_eq!(entries.data.device, USERDATA);
                assert_eq!(entries.metadata.device, METADATA);
            }
        }
    }

    #[test]
    fn accepts_stock_layouts_with_or_without_fscompress() {
        for text in [table(), table().replace(",fscompress", "")] {
            let parsed = parse(&format!("# /dev/block/by-name/userdata /data f2fs invalid\n\
                system /system erofs ro wait,logical,slotselect\n{text}")).unwrap();
            assert_eq!(parsed.data.extra("keydirectory"), Some("/metadata/vold/metadata_encryption"));
            assert_eq!(parsed.metadata.device, METADATA);
            assert_eq!(parsed.cache.unwrap().device, CACHE);
            assert_eq!(parsed.data.extras.iter().any(|f| f == "fscompress"), text.contains("fscompress"));
        }
    }

    #[test]
    fn cache_may_be_absent_but_data_and_metadata_may_not() {
        assert!(parse(&format!("{DATA_ROW}\n{META_ROW}\n# {CACHE_ROW}")).unwrap().cache.is_none());
        assert!(parse(DATA_ROW).is_err());
        assert!(parse(META_ROW).is_err());
    }

    #[test]
    fn rejects_duplicates_wrong_devices_aliases_and_malformed_rows() {
        for extra in [DATA_ROW, META_ROW, CACHE_ROW, OEM_ALIAS,
            "/dev/block/by-name/userdata /other f2fs inlinecrypt formattable",
            "/dev/block/by-name/oplusreserve2 /other ext4 noatime formattable",
            "/dev/block/by-name/metadata",
            "/wrong /data",
            "/wrong /cache/ ext4 noatime formattable"] {
            assert!(parse(&format!("{}{extra}\n", table())).is_err(), "accepted {extra}");
        }
        for text in [table().replace(USERDATA, "/dev/block/bootdevice/by-name/userdata"),
            table().replace("/data f2fs", "/data ext4"), table().replace("/metadata ext4", "/metadata f2fs"),
            table().replace("/cache ext4", "/cache f2fs"), table().replace(",formattable", "")] {
            assert!(parse(&text).is_err(), "accepted {text}");
        }
    }

    #[test]
    fn rejects_unsupported_mapping_layout_and_encryption() {
        for flag in ["logical", "slotselect", "slotselect_other", "length=-4096", "eraseblk=8192",
            "logicalblk=4096", "metadata_encryption=aes-256-xts", "noinlinecrypt", "wait"] {
            for extra in [format!("{DATA_ROW},{flag}"), DATA_ROW.replace("inlinecrypt wait", &format!("inlinecrypt,{flag} wait"))] {
                assert!(parse(&table().replace(DATA_ROW, &extra)).is_err(), "accepted {flag}");
            }
        }
        for text in [table().replace(FBE, "fileencryption=aes-256-xts:aes-256-cts:v1"),
            table().replace(KEY_DIR, "keydirectory=/metadata/other"),
            table().replace(",inlinecrypt wait", " wait")] {
            assert!(parse(&text).is_err(), "accepted {text}");
        }
    }
}
