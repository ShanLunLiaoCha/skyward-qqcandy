//! Pure admission check for preparing a PGZ110 single-A factory candidate.
//! A successful check neither verifies operation bytes nor authorizes flashing.
use crate::payload_plan;
use anyhow::{Context, Result, ensure};
use skyward_lp::{HEADER_FLAG_VIRTUAL_AB_DEVICE, Metadata, single_a};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Read-only diagnostic of direct kernel consumers. A nonempty result
/// forbids a whole-device overwrite, even when mounts are lazily detached.
/// An empty result is only a point-in-time observation, not authorization.
pub fn kernel_super_holders(sys_dev_block: &Path, device: (u32, u32)) -> Result<BTreeSet<String>> {
    let at = sys_dev_block.join(format!("{}:{}", device.0, device.1)).join("holders");
    let mut holders = BTreeSet::new();
    for item in std::fs::read_dir(&at).with_context(|| format!("read kernel holders at {}", at.display()))? {
        let item = item?;
        let name = item.file_name().into_string().map_err(|_| anyhow::anyhow!("non-UTF8 kernel holder name"))?;
        ensure!(name.len() <= 255 && !name.is_empty() && name.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.')),
            "unknown kernel holder name");
        ensure!(holders.len() < 4096, "excessive number of kernel holders");
        holders.insert(name);
    }
    Ok(holders)
}

/// A partial Virtual A/B package is either restored by the dedicated path or
/// refused: on this profile it never falls through to the OEM engine, which
/// was observed writing a B layout over live A data. `local` and `resume`
/// describe how the package reached Recovery; `executor` says the interactive
/// restore page is available.
pub fn admit_partial_vab_restore(local: bool, wipe: bool, resume: bool, executor: bool) -> Result<()> {
    ensure!(local && !wipe && !resume && executor,
        "this partial Virtual A/B package needs a confirmed local restore without a data wipe; the OEM fallback is disabled");
    Ok(())
}

/// Point-in-time prerequisites that can be observed without preparing a ZIP
/// or opening writable handles. Each result is independent; none transfers
/// authority to the actual installer.
#[cfg(target_os = "android")]
#[derive(Debug)]
pub struct RestoreAvailability {
    pub physical_super_bytes: Result<u64>,
    pub kernel_super_holders: Result<BTreeSet<String>>,
    pub snapshot_metadata_idle: Result<()>,
    pub super_exclusive_readonly: Result<()>,
    pub preloader_mappings: Result<()>,
}

#[cfg(target_os = "android")]
pub fn observe_restore_availability() -> RestoreAvailability {
    let path = Path::new(skyward_block::BY_NAME).join("super");
    RestoreAvailability {
        physical_super_bytes: skyward_block::size_bytes(&path),
        kernel_super_holders: skyward_block::devnum(&path)
            .and_then(|id| kernel_super_holders(Path::new("/sys/dev/block"), id)),
        snapshot_metadata_idle: audit_restore_metadata(),
        super_exclusive_readonly: crate::with_exclusive_super_for_audit(|_| Ok(())),
        preloader_mappings: crate::factory_preloader::audit_pgz110_211(),
    }
}

/// Early metadata-only preflight. The actual writer independently checks
/// BootControl and holds a fresh metadata lock across the write transaction.
#[cfg(target_os = "android")]
pub fn audit_restore_metadata() -> Result<()> {
    crate::factory_snapshot::lock_metadata().map(drop)
}

const REPLACEMENTS: [&str; 2] = ["my_company", "my_preload"];
const BOOT_CHAIN: [&str; 4] = ["boot", "dtbo", "vendor_boot", "vbmeta"];

/// An independently trusted target-specific roster. Do not derive these lists
/// from the untrusted payload itself or from the currently installed slots.
/// `logical` is exact for the result; only explicitly supplied replacements
/// may be absent from the target group. `physical` lists required non-logical
/// payload images. Extra physical images are not included in the result.
#[derive(Clone, Copy, Debug)]
pub struct RequiredRoster<'a> {
    pub logical: &'a [&'a str],
    pub physical: &'a [&'a str],
}

/// Independently reviewed inventory of the specified .211 OTA. The digest
/// selects an exact manifest, not a trusted key, and these names do not
/// establish that the OTA can restore all firmware used by the phone.
pub fn reviewed_roster(metadata_hash: &[u8; 32]) -> Result<RequiredRoster<'static>> {
    const OTA_211: [u8; 32] = [0xd3, 0x02, 0x07, 0xea, 0x42, 0x53, 0x44, 0xab, 0x79, 0xa8, 0xea, 0x19, 0xec, 0xc7, 0xff, 0xf4,
        0xe7, 0x6e, 0x64, 0x61, 0x36, 0x04, 0x96, 0x44, 0xa0, 0xc9, 0x50, 0x11, 0xd1, 0xd9, 0xc5, 0x03];
    ensure!(*metadata_hash == OTA_211, "no reviewed single-A restore inventory for this exact OTA manifest");
    Ok(pgz211_layout(true, true))
}

fn pgz211_layout(vendor_dlkm: bool, odm_dlkm: bool) -> RequiredRoster<'static> {
    const LOGICAL: &[&str] = &["system", "system_ext", "vendor", "product", "my_product", "odm", "my_engineering",
        "my_stock", "my_heytap", "my_carrier", "my_region", "my_bigball", "my_manifest", "my_company", "my_preload"];
    const LOGICAL_WITH_DLKM: &[&str] = &["system", "system_ext", "vendor", "product", "my_product", "odm", "my_engineering",
        "my_stock", "my_heytap", "my_carrier", "my_region", "my_bigball", "my_manifest", "my_company", "my_preload", "vendor_dlkm",
        "odm_dlkm"];
    RequiredRoster {
        logical: if vendor_dlkm { LOGICAL_WITH_DLKM } else { LOGICAL },
        physical: &["apusys", "audio_dsp", "boot", "ccu", "cdt_engineering", "dpm", "dtbo", "gpueb", "gz", "lk",
            "mcf_ota", "mcupm", "md1img", "mvpu_algo", "pi_img", "preloader_raw", "scp", "spmfw", "sspm", "tee",
            "vbmeta", "vbmeta_system", "vbmeta_vendor", "vcp", "vendor_boot"],
    }
}

/// Select a supported PGZ110 layout from a signed, already parsed payload.
/// No reliance on version, container size, or a single manifest hash. Only
/// the fixed device target profile is accepted: its destinations are not
/// inferred from payload entries. Replacement names may be omitted only.
pub(crate) fn compatible_pgz_roster(plan: &payload_plan::Plan) -> Result<RequiredRoster<'static>> {
    let dynamic = plan.dynamic.as_ref().context("missing target Virtual A/B layout")?;
    let [group] = dynamic.groups.as_slice() else { anyhow::bail!("requires exactly one target dynamic group"); };
    ensure!(plan.partial_update && dynamic.snapshot_enabled && group.name == "main", "not a supported partial Virtual A/B layout");
    // The inventory is taken from the package itself: PGZ110 and PGJM10
    // builds differ in which partitions are dynamic, so nothing here is a
    // fixed list any more. What stays checked are the things whose absence
    // would produce an unbootable target: the boot chain, the preloader
    // bounds and duplicate names.
    ensure!(!group.partitions.is_empty(), "package has an empty dynamic group");
    let group_set: BTreeSet<&str> = group.partitions.iter().map(String::as_str).collect();
    ensure!(group_set.len() == group.partitions.len(), "duplicate dynamic partitions in the package");
    let mut all_names = BTreeSet::new();
    for part in &plan.partitions {
        ensure!(all_names.insert(part.name.as_str()), "duplicate payload partitions");
    }
    for required in ["boot", "dtbo", "vendor_boot", "vbmeta"] {
        ensure!(all_names.contains(required), "{required} is missing from the package");
    }
    let leak = |names: Vec<&str>| -> &'static [&'static str] {
        let owned: Vec<&'static str> = names.into_iter()
            .map(|name| &*Box::leak(name.to_owned().into_boxed_str())).collect();
        Box::leak(owned.into_boxed_slice())
    };
    let mut logical_names: Vec<&str> = group.partitions.iter().map(String::as_str).collect();
    // my_company and my_preload always have a destination: their content is
    // carried inside vendor_boot and written into slot A every time.
    for name in REPLACEMENTS { if !logical_names.contains(&name) { logical_names.push(name); } }
    let logical = leak(logical_names);
    let physical: Vec<&str> = plan.partitions.iter().map(|part| part.name.as_str())
        .filter(|name| !group_set.contains(name)).collect();
    if !physical.iter().any(|name| *name == "vendor_boot") {
        anyhow::bail!("vendor_boot is dynamic in this package; not supported");
    }
    let roster = RequiredRoster { logical, physical: leak(physical) };
    let preloader = plan.partitions.iter().find(|part| part.name == "preloader_raw").context("missing preloader image")?;
    crate::factory_preloader::check_image_bounds(preloader.size, &preloader.sha256)?;
    Ok(roster)
}

/// Expanded sizes, as determined by inspecting both replacement files.
/// This gate does not authenticate replacement contents or establish their AVB compatibility.
#[derive(Clone, Copy, Debug)]
pub struct ReplacementSizes {
    pub my_company: u64,
    pub my_preload: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeclaredImage {
    pub bytes: u64,
    pub sha256: [u8; 32],
}

/// Permission to prepare a regular candidate file only. Source images and
/// replacements still need to be staged and checked. Not flash authorization.
#[derive(Debug)]
pub struct Candidate {
    /// Original payload declarations for the trusted required roster. Entries
    /// are absent only for replacements not supplied by the official package.
    pub original_images: BTreeMap<String, DeclaredImage>,
    pub effective_a_sizes: BTreeMap<String, u64>,
    /// Externally supplied replacements with no original declaration. Even a
    /// replacement *with* an original declaration is not bound to its hash.
    pub replacements_without_original: BTreeSet<String>,
    pub allocated_end: u64,
    /// The OTA engine's partial-update marker is descriptive; the trusted
    /// roster and self-contained operations determine candidate completeness.
    pub partial_update: bool,
}

fn names<'a>(names: &'a [&'a str]) -> Result<BTreeSet<&'a str>> {
    let mut set = BTreeSet::new();
    for &name in names {
        ensure!(!name.is_empty() && name.len() <= 33 && !name.ends_with("_a") && !name.ends_with("_b")
            && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "invalid target roster entry {name:?}");
        ensure!(set.insert(name), "duplicate target roster entry {name}");
    }
    Ok(set)
}

/// The caller must supply a `Plan` parsed from the ZIP it intends to install.
/// `authenticated` records whether that ZIP's package signature was actually
/// checked against this device's keys; when the caller deliberately installs
/// without that check, every structural, capacity and roster test below still
/// applies. No filesystem or device access occurs here.
pub fn check(
    plan: &payload_plan::Plan, authenticated: bool, reference: &Metadata, actual_bytes: u64,
    roster: RequiredRoster<'_>, replacements: ReplacementSizes,
) -> Result<Candidate> {
    #[cfg(target_os = "android")]
    let _ = skyward_sys::kmsg(if authenticated {
        "factory restore: package signature verified"
    } else {
        "factory restore: package signature not checked"
    });
    // Plan's parser rejects old partition info and source-dependent operations.
    // A nonzero minor version or the OTA engine's partial_update flag alone
    // does not require any source bytes (the official .211 package is an example).
    let [device] = reference.block_devices.as_slice() else { anyhow::bail!("expected one physical super device") };
    ensure!(reference.damaged.is_empty() && reference.header_flags == HEADER_FLAG_VIRTUAL_AB_DEVICE
        && reference.major_version == 10 && reference.minor_version == 2
        && device.partition_name == "super" && device.size == actual_bytes
        && plan.block_size.is_power_of_two() && (512..=65536).contains(&plan.block_size)
        && plan.block_size == u64::from(reference.geometry.logical_block_size),
        "unsupported Virtual A/B super reference or mismatched physical geometry");
    let dynamic = plan.dynamic.as_ref().context("missing target dynamic partition metadata")?;
    let [group] = dynamic.groups.as_slice() else { anyhow::bail!("expected one target dynamic group") };
    ensure!(dynamic.snapshot_enabled && group.name == "main", "unsupported target Virtual A/B group");
    let limit = group.maximum_size.filter(|&n| n > 0).context("missing target group limit")?;
    let logical = names(roster.logical)?;
    let physical = names(roster.physical)?;
    ensure!(REPLACEMENTS.iter().all(|n| logical.contains(n)), "target roster lacks a required replacement destination");
    ensure!(BOOT_CHAIN.iter().all(|n| physical.contains(n)), "target roster lacks a required boot-chain destination");
    ensure!(logical.is_disjoint(&physical), "target roster places a partition in both logical and physical sets");
    let members: BTreeSet<_> = group.partitions.iter().map(String::as_str).collect();
    ensure!(members.len() == group.partitions.len(), "duplicate member in target dynamic group");
    let missing: Vec<_> = logical.difference(&members).filter(|name| !REPLACEMENTS.contains(*name)).collect();
    ensure!(missing.is_empty() && members.is_subset(&logical),
        "target dynamic group differs from the required roster (missing {missing:?}; unexpected {:?})",
        members.difference(&logical).collect::<Vec<_>>());
    let mut payload = BTreeMap::new();
    for p in &plan.partitions {
        ensure!(payload.insert(p.name.as_str(), p).is_none(), "duplicate payload image {}", p.name);
    }
    let mut original_images = BTreeMap::new();
    let mut replacements_without_original = BTreeSet::new();
    for &name in logical.union(&physical) {
        let Some(p) = payload.get(name) else {
            ensure!(REPLACEMENTS.contains(&name), "package omits required image {name}");
            replacements_without_original.insert(name.to_owned());
            continue;
        };
        ensure!(!logical.contains(name) || members.contains(name),
            "payload image {name} is not assigned to its required dynamic group");
        ensure!(p.size > 0 && p.size % plan.block_size == 0 && p.sha256 != [0;32] && !p.operations.is_empty(),
            "invalid or incomplete payload image declaration for {name}");
        original_images.insert(name.to_owned(), DeclaredImage { bytes: p.size, sha256: p.sha256 });
    }
    let original_total = logical.iter().filter_map(|name| original_images.get(*name))
        .try_fold(0u64, |total, image| total.checked_add(image.bytes)).context("original logical image sizes overflow")?;
    ensure!(original_total <= limit, "original logical images exceed target group limit");
    let effective_a_sizes = logical.into_iter().map(|name| {
        let bytes = match name {
            "my_company" => replacements.my_company,
            "my_preload" => replacements.my_preload,
            _ => original_images[name].bytes,
        };
        (name.to_owned(), bytes)
    }).collect();
    let layout = single_a::build(reference.geometry, device, limit, &effective_a_sizes)
        .context("target does not fit the supported single-A layout")?;
    Ok(Candidate { original_images, effective_a_sizes, replacements_without_original,
        allocated_end: layout.used_end, partial_update: plan.partial_update })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload_plan::{DynamicGroup, DynamicMetadata, Kind, Operation, Partition, Plan};
    use skyward_lp::{BlockDevice, Geometry};

    const LOGICAL: &[&str] = &["system", "vendor", "my_company", "my_preload"];
    const PHYSICAL: &[&str] = &["boot", "dtbo", "vendor_boot", "vbmeta"];
    const ROSTER: RequiredRoster<'static> = RequiredRoster { logical: LOGICAL, physical: PHYSICAL };
    const SIZES: ReplacementSizes = ReplacementSizes { my_company: 8192, my_preload: 4096 };
    const SUPER: u64 = 8 << 20;

    #[test]
    fn kernel_holders_are_reported_even_without_mounts() {
        let sys = tempfile::tempdir().unwrap();
        let dir = sys.path().join("8:79/holders");
        assert!(kernel_super_holders(sys.path(), (8,79)).is_err());
        std::fs::create_dir_all(&dir).unwrap();
        assert!(kernel_super_holders(sys.path(), (8,79)).unwrap().is_empty());
        std::os::unix::fs::symlink("../../dm-11", dir.join("dm-11")).unwrap();
        assert_eq!(kernel_super_holders(sys.path(), (8,79)).unwrap(), BTreeSet::from(["dm-11".into()]));
    }

    #[test]
    fn a_partial_vab_package_is_restored_locally_or_refused() {
        assert!(admit_partial_vab_restore(true, false, false, true).is_ok());
        for (local, wipe, resume, executor) in [
            (false, false, false, true), (true, true, false, true),
            (true, false, true, true), (true, false, false, false),
        ] {
            assert!(admit_partial_vab_restore(local, wipe, resume, executor).is_err());
        }
    }

    #[test]
    fn signed_layout_variants_do_not_borrow_missing_partitions() {
        for dlkm in [false, true] {
            let expected = pgz211_layout(dlkm, true);
            let mut candidate = plan();
            candidate.partial_update = true;
            let logical: Vec<_> = expected.logical.iter().copied().filter(|name| !REPLACEMENTS.contains(name)).collect();
            candidate.dynamic.as_mut().unwrap().groups[0].partitions = logical.iter().map(|n| (*n).into()).collect();
            let template = candidate.partitions[0].operations[0].output_size;
            candidate.partitions = logical.into_iter().chain(expected.physical.iter().copied()).map(|name| {
                let (size, sha256) = if name == "preloader_raw" {
                    (crate::factory_preloader::IMAGE_211_BYTES, crate::factory_preloader::IMAGE_211_SHA256)
                } else { (template, [9; 32]) };
                Partition { name: name.into(), size, sha256, operations: vec![] }
            }).collect();
            let roster = compatible_pgz_roster(&candidate).unwrap();
            assert_eq!(roster.logical.contains(&"vendor_dlkm"), dlkm);
            let image = candidate.partitions.iter_mut().find(|p| p.name == "preloader_raw").unwrap();
            image.sha256[0] ^= 1;
            image.size += 512;
            assert!(compatible_pgz_roster(&candidate).is_ok());
            candidate.partitions.iter_mut().find(|p| p.name == "preloader_raw").unwrap().size = crate::factory_preloader::MAPPED_BYTES + 512;
            assert!(compatible_pgz_roster(&candidate).is_err());
            candidate.partitions.retain(|p| p.name != "boot");
            assert!(compatible_pgz_roster(&candidate).is_err());
        }
    }

    fn plan() -> Plan {
        Plan { block_size: 4096, minor_version: 0, partial_update: false, dynamic: Some(DynamicMetadata {
            snapshot_enabled: true, vabc_enabled: false, groups: vec![DynamicGroup { name: "main".into(),
                maximum_size: Some(4 << 20), partitions: LOGICAL.iter().map(|n| (*n).into()).collect() }],
        }), partitions: LOGICAL.iter().chain(PHYSICAL).enumerate().map(|(i, name)| Partition {
            name: (*name).into(), size: 4096, sha256: [i as u8 + 1;32],
            operations: vec![Operation { kind: Kind::Zero, data: None, targets: vec![0..4096], output_size:4096 }],
        }).collect() }
    }

    fn reference() -> Metadata {
        Metadata { geometry: Geometry { metadata_max_size: 65536, metadata_slot_count: 3, logical_block_size: 4096 },
            major_version: 10, minor_version: 2, header_flags: HEADER_FLAG_VIRTUAL_AB_DEVICE,
            partitions: vec![], groups: vec![], damaged: vec![], block_devices: vec![BlockDevice {
                partition_name: "super".into(), first_logical_sector: 2048, alignment: 1 << 20,
                alignment_offset: 0, size: SUPER,
            }], }
    }

    #[test]
    fn official_full_candidate_preserves_hashes_and_uses_replacement_sizes() {
        let p = plan();
        let result = check(&p, true, &reference(), SUPER, ROSTER, SIZES).unwrap();
        assert_eq!(result.original_images["my_company"], DeclaredImage { bytes:4096, sha256:[3;32] });
        assert_eq!(result.effective_a_sizes["my_company"], 8192);
        assert_eq!(result.effective_a_sizes.len(), LOGICAL.len());
        assert!(!result.effective_a_sizes.contains_key("vendor_dlkm"));
        assert!(result.allocated_end <= SUPER);
    }

    #[test]
    fn unauthenticated_admission_keeps_every_structural_check() {
        // The install page runs without a package-signature verdict; every
        // roster, geometry and capacity check still applies.
        assert!(check(&plan(), false, &reference(), SUPER, ROSTER, SIZES).is_ok());
        let mut missing = plan();
        missing.partitions.retain(|entry| entry.name != "boot");
        assert!(check(&missing, false, &reference(), SUPER, ROSTER, SIZES).is_err());
        assert!(check(&plan(), false, &reference(), SUPER - 4096, ROSTER, SIZES).is_err());
    }

    #[test]
    fn self_contained_partial_marker_and_minor_seven_are_not_omissions() {
        let mut p = plan();
        p.partial_update = true;
        p.minor_version = 7;
        let result = check(&p, true, &reference(), SUPER, ROSTER, SIZES).unwrap();
        assert!(result.partial_update);
        assert!(result.replacements_without_original.is_empty());
        p.partitions.retain(|entry| !REPLACEMENTS.contains(&entry.name.as_str()));
        p.dynamic.as_mut().unwrap().groups[0].partitions.retain(|entry| !REPLACEMENTS.contains(&entry.as_str()));
        let result = check(&p, true, &reference(), SUPER, ROSTER, SIZES).unwrap();
        assert_eq!(result.replacements_without_original, REPLACEMENTS.map(str::to_owned).into_iter().collect());
        assert!(!result.original_images.contains_key("my_company"));
        assert_eq!(result.effective_a_sizes["my_company"], SIZES.my_company);
        p.partitions.retain(|entry| entry.name != "system");
        assert!(check(&p, true, &reference(), SUPER, ROSTER, SIZES).is_err());
    }

    #[test]
    fn omissions_and_layout_drift_do_not_borrow_from_the_running_slot() {
        for omitted in ["boot", "vbmeta", "vendor"] {
            let mut p = plan();
            p.partitions.retain(|entry| entry.name != omitted);
            assert!(check(&p, true, &reference(), SUPER, ROSTER, SIZES).is_err());
        }
        let mut p = plan();
        p.dynamic.as_mut().unwrap().groups[0].partitions.push("vendor_dlkm".into());
        assert!(check(&p, true, &reference(), SUPER, ROSTER, SIZES).is_err());
        assert!(check(&plan(), true, &reference(), SUPER,
            RequiredRoster { logical: LOGICAL, physical: &[] }, SIZES).is_err());
    }

    #[test]
    fn runs_the_real_single_a_geometry_and_quota_checks() {
        assert!(check(&plan(), true, &reference(), SUPER - 4096, ROSTER, SIZES).is_err());
        let mut r = reference();
        r.block_devices[0].alignment_offset = 4096;
        assert!(check(&plan(), true, &r, SUPER, ROSTER, SIZES).is_err());
        r.block_devices[0].alignment_offset = 0;
        r.geometry.metadata_slot_count = 4;
        assert!(check(&plan(), true, &r, SUPER, ROSTER, SIZES).is_err());
        assert!(check(&plan(), true, &reference(), SUPER, ROSTER,
            ReplacementSizes { my_company: 4 << 20, ..SIZES }).is_err());
    }
}
