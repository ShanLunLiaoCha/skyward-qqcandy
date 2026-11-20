//! Stage all reviewed .211 payload images, with a single-A super, atomically.
//! No device is opened, flashed or activated. Staged full payload coverage is
//! NOT authorization to flash a complete device or bypass its boot policy.
use crate::{factory_execute::{Image, Target}, factory_preflight, payload_plan, payload_preflight,
    payload_stage, retention, signature, super_image, super_replacement, vendor_boot};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use skyward_vab::Slot;
use std::{collections::BTreeMap, ffi::CString, fs::{self, File, OpenOptions},
    io::{BufReader, Read, Write}, os::{fd::AsRawFd, unix::{ffi::OsStrExt,
    fs::{MetadataExt, OpenOptionsExt}}}, path::{Path, PathBuf}};

const CORE_PAYLOAD: [(&str, Target, u64); 4] = [
    ("boot", Target::BootA, 128 << 20), ("dtbo", Target::DtboA, 32 << 20),
    ("vbmeta_system", Target::VbmetaSystemA, 1 << 20),
    ("vbmeta_vendor", Target::VbmetaVendorA, 1 << 20),
];

/// A verified original payload image staged as a regular file. Names here are
/// inventory identifiers, never raw disk or device destination paths.
#[derive(Debug)]
pub struct StagedPhysical {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug)]
pub struct Bundle {
    pub directory: PathBuf,
    pub paths: BTreeMap<Target, PathBuf>,
    pub images: Vec<Image>,
    /// Original non-core physical payload images, including preloader_raw.
    /// Their verified files are not instructions to write any block device.
    pub extra_physical: BTreeMap<String, StagedPhysical>,
    /// Entries not staged. This is empty only after all reviewed physical
    /// declarations have been reconstructed and checked successfully.
    pub remaining_physical: Vec<String>,
    /// Staged inventory with no supported device target mapping. A nonempty
    /// list prevents treating this bundle as an executable full restore.
    pub unmapped_physical: Vec<String>,
    pub avb_off: bool,
}

impl Bundle {
    /// Return descriptors for the core and regular GPT firmware targets.
    /// The preloader is checked separately as a specific OEM DM mapping.
    pub fn supported_images(&self) -> Result<Vec<Image>> {
        use crate::factory_execute::FirmwarePartition;
        let mut supported = self.images.clone();
        for firmware in FirmwarePartition::ALL {
            let name = firmware.base_name();
            let image = self.extra_physical.get(name).with_context(|| format!("missing staged firmware {name}"))?;
            ensure!(image.bytes > 0 && image.bytes <= firmware.maximum_image_bytes(), "firmware {name} exceeds target size bound");
            supported.push(Image { target: Target::Firmware(firmware), bytes: image.bytes, sha256: image.sha256 });
        }
        Ok(supported)
    }

    /// Return the fixed destination roster only when no reviewed physical
    /// image is left unstaged or lacks a device mapping. This is not AVB
    /// acceptance, exclusive ownership, or permission to run a restore.
    pub fn execution_plan(&self) -> Result<crate::factory_execute::Plan> {
        crate::factory_execute::Plan::full(&self.execution_images_a()?)
    }

    fn execution_images_a(&self) -> Result<Vec<Image>> {
        use crate::factory_execute::FirmwarePartition;
        ensure!(self.remaining_physical.is_empty(), "unstaged payload images: {:?}", self.remaining_physical);
        let unsupported: Vec<_> = self.extra_physical.keys().filter(|name| name.as_str() != "preloader_raw"
            && !FirmwarePartition::ALL.iter().any(|firmware| firmware.base_name() == name.as_str())).collect();
        ensure!(self.unmapped_physical.is_empty() && unsupported.is_empty(),
            "no verified write mapping for staged physical images: {:?} {:?}", self.unmapped_physical, unsupported);
        let preloader = self.extra_physical.get("preloader_raw").context("missing staged preloader_raw")?;
        let mut images = self.supported_images()?;
        images.push(Image { target: Target::PreloaderA, bytes: preloader.bytes, sha256: preloader.sha256 });
        Ok(images)
    }

    /// Describe both slots' physical writes using the same verified staged
    /// bytes. The shared super image is still the single-A layout. A physical
    /// B boot chain does not establish that B has a bootable logical system.
    pub fn execution_plan_ab(&self) -> Result<crate::factory_execute::Plan> {
        Ok(self.physical_ab()?.0)
    }

    /// Map each A and B physical target to its verified staged source. Each
    /// pair intentionally shares a path; the executor opens and verifies an
    /// independent source descriptor for each target. No B files are created.
    pub fn execution_sources_ab(&self) -> Result<BTreeMap<Target, PathBuf>> {
        Ok(self.physical_ab()?.1)
    }

    /// Read-only, point-in-time target audit for both slots and shared super.
    #[cfg(target_os = "android")]
    pub fn audit_targets_ab(&self) -> Result<usize> {
        let (plan, paths) = self.physical_ab()?;
        crate::factory_backend::audit_staged_io(&paths, plan.images())
    }

    fn physical_ab(&self) -> Result<(crate::factory_execute::Plan, BTreeMap<Target, PathBuf>)> {
        use crate::factory_execute::Plan;
        let mut images = self.execution_images_a()?;
        Plan::full(&images)?;
        let mut sources = self.execution_sources_a(&images)?;
        let mut slot_b = Vec::with_capacity(25);
        for image in &images {
            let target = match image.target {
                Target::Firmware(firmware) => Target::FirmwareB(firmware),
                Target::BootA => Target::BootB,
                Target::DtboA => Target::DtboB,
                Target::VendorBootA => Target::VendorBootB,
                Target::VbmetaSystemA => Target::VbmetaSystemB,
                Target::VbmetaVendorA => Target::VbmetaVendorB,
                Target::PreloaderA => Target::PreloaderB,
                Target::VbmetaA => Target::VbmetaB,
                Target::Super => continue,
                other => anyhow::bail!("unexpected slot in staged sources: {other:?}"),
            };
            let path = sources.get(&image.target).context("missing verified A source")?.clone();
            ensure!(sources.insert(target, path).is_none(), "duplicate physical B source mapping");
            slot_b.push(Image { target, ..*image });
        }
        images.extend(slot_b);
        ensure!(sources.len() == 51, "source roster differs from the physical A/B plan");
        Ok((Plan::physical_ab(&images)?, sources))
    }

    /// Explicit development-only executor. No fallback and no implicit OTA
    /// invocation. Caller must establish a quiescent, unlocked Recovery and
    /// provide the same verified OEM BootControl owner in both callbacks.
    #[cfg(target_os = "android")]
    pub fn execute_ab_test(&self,
        ready: impl FnMut(&std::collections::BTreeSet<(u32, u32)>) -> Result<skyward_vab::MergeStatus>,
        activate_a: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.execute_physical_ab(ready, activate_a, || false, || {})
    }

    /// Execute a verified bundle with cancellation and a first-write notice.
    #[cfg(target_os = "android")]
    pub fn execute_physical_ab(&self,
        ready: impl FnMut(&std::collections::BTreeSet<(u32, u32)>) -> Result<skyward_vab::MergeStatus>,
        activate_a: impl FnMut() -> Result<()>, cancelled: impl Fn() -> bool, first_write: impl Fn(),
    ) -> Result<()> {
        let (plan, sources) = self.physical_ab()?;
        let mut backend = crate::factory_backend::DeviceBackend::new(sources, cancelled, ready, activate_a);
        crate::factory_execute::execute_observed(&plan, &mut backend, first_write)
    }

    /// Check live target identity, capacity, holders and exclusive access.
    /// This is a point-in-time diagnostic, not an installation capability.
    #[cfg(target_os = "android")]
    pub fn audit_targets(&self) -> Result<usize> {
        crate::factory_targets::audit_full_plan(&self.execution_plan()?)
    }

    /// Build the descriptor-to-source mapping from this in-memory verified
    /// bundle, not by trusting or parsing the diagnostic manifest text.
    pub fn execution_sources(&self) -> Result<BTreeMap<Target, PathBuf>> {
        let images = self.execution_images_a()?;
        crate::factory_execute::Plan::full(&images)?;
        self.execution_sources_a(&images)
    }

    fn execution_sources_a(&self, images: &[Image]) -> Result<BTreeMap<Target, PathBuf>> {
        let mut paths = self.paths.clone();
        for firmware in crate::factory_execute::FirmwarePartition::ALL {
            ensure!(paths.insert(Target::Firmware(firmware), self.extra_physical[firmware.base_name()].path.clone()).is_none(),
                "duplicate staged firmware source");
        }
        ensure!(paths.insert(Target::PreloaderA, self.extra_physical["preloader_raw"].path.clone()).is_none(),
            "duplicate staged preloader source");
        ensure!(paths.len() == 26, "source roster differs from the full .211 plan");
        for (&target, path) in &paths {
            let expected = match target {
                Target::Firmware(firmware) => format!("{}.img", firmware.base_name()),
                Target::PreloaderA => "preloader_raw.img".into(),
                _ => filename(target),
            };
            ensure!(*path == self.directory.join(expected), "staged source path differs for {}", target.display_name());
        }
        Ok(paths)
    }
}

fn open_regular(path: &Path, limit: u64) -> Result<(File, fs::Metadata)> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let meta = file.metadata()?;
    ensure!(meta.is_file() && (1..=limit).contains(&meta.len()), "need a bounded regular input: {}", path.display());
    Ok((file, meta))
}

fn unchanged(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev() && before.ino() == after.ino() && before.len() == after.len()
        && before.mtime() == after.mtime() && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec()
}

fn filename(target: Target) -> String {
    format!("{}.img", target.display_name())
}

fn put(dir: &Path, target: Target, bytes: &[u8]) -> Result<Image> {
    let path = dir.join(filename(target));
    let mut file = OpenOptions::new().write(true).create_new(true).custom_flags(libc::O_NOFOLLOW).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(Image {target, bytes:bytes.len() as u64, sha256:Sha256::digest(bytes).into()})
}

fn physical_filename(name: &str, bytes: u64) -> Result<String> {
    ensure!(!name.is_empty() && name.len() <= 33 && !name.ends_with("_a") && !name.ends_with("_b")
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
        "invalid physical payload inventory name {name:?}");
    ensure!((1..=128 << 20).contains(&bytes) && bytes % 512 == 0,
        "physical payload image {name} exceeds bounds or is unaligned");
    ensure!(!matches!(name, "sda" | "sdb" | "sdc") && name != "super" && !matches!(name, "boot" | "dtbo" | "vbmeta_system" | "vbmeta_vendor" | "vbmeta"),
        "physical payload image {name} collides with a staged core image");
    // vendor_boot is handled by the verified repack, not copied as stock.
    ensure!(name != "vendor_boot", "physical payload image vendor_boot collides with its staged repack");
    Ok(format!("{name}.img"))
}

fn put_physical(dir: &Path, name: &str, partition: &payload_plan::Partition, bytes: &[u8]) -> Result<(u64, [u8; 32])> {
    ensure!(name == partition.name, "physical payload identity changed during staging");
    let filename = physical_filename(name, partition.size)?;
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    ensure!(bytes.len() as u64 == partition.size && digest == partition.sha256,
        "physical payload image {name} differs from new_partition_info");
    let path = dir.join(filename);
    let mut file = OpenOptions::new().write(true).create_new(true).custom_flags(libc::O_NOFOLLOW).open(&path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    ensure!(hash_file(&path)? == (partition.size, digest), "physical staged file {name} changed");
    Ok((partition.size, digest))
}

fn note(message: &str) {
    #[cfg(target_os = "android")]
    let _ = skyward_sys::kmsg(&format!("factory restore: {message}"));
    #[cfg(not(target_os = "android"))]
    let _ = message;
}

fn step(step: crate::FactoryStep) {
    crate::progress::report(step);
}

fn hash_file(path: &Path) -> Result<(u64, [u8;32])> {
    let (mut file, before) = open_regular(path, 128 << 30)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 256 << 10];
    let mut left = before.len();
    let mut told = before.len();
    let total = before.len();
    while left != 0 {
        let n = left.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..n])?;
        hash.update(&buffer[..n]); left -= n as u64;
        // A 12 GB image takes minutes to hash; report roughly every 2 GiB.
        if told.saturating_sub(left) >= (2 << 30) {
            told = left;
            note(&format!("hashing {} : {}% done", path.file_name().map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(), (total - left) * 100 / total.max(1)));
            step(crate::FactoryStep::HashingSuper { percent: (((total - left) * 100 / total.max(1)) as u32).min(100) });
        }
    }
    ensure!(file.read(&mut [0])? == 0 && unchanged(&before, &file.metadata()?), "staged file changed while hashing");
    Ok((before.len(),hash.finalize().into()))
}

fn checked_replacement(path: &Path, expected: &str) -> Result<(u64,[u8;32])> {
    let (size, digest) = hash_file(path)?;
    ensure!(size <= 2 << 30 && format!("{:x}",DigestDisplay(digest)) == expected,
        "replacement does not match the explicitly supplied .211 file: {}",path.display());
    Ok((size,digest))
}

fn partition<'a>(plan: &'a payload_plan::Plan, name: &str) -> Result<&'a payload_plan::Partition> {
    let mut matches = plan.partitions.iter().filter(|p| p.name == name);
    let p = matches.next().with_context(|| format!("missing core image {name}"))?;
    ensure!(matches.next().is_none(), "duplicate core image {name}");
    Ok(p)
}

/// Prepare the seven core images and every other reviewed physical payload
/// image, using trusted certificates from outside the incoming OTA. All
/// validation/assembly finishes before the destination appears. `avb_off`
/// changes top-level flags and invalidates its OEM signature; it does NOT
/// prove that any bootloader accepts the modified boot chain.
#[allow(clippy::too_many_arguments)]
pub fn prepare(ota: &Path, trusted_certs: Option<&Path>, reference: &skyward_lp::Metadata,
    actual_size: u64, company: &Path, preload: &Path, program: &[u8],
    assets: &[(&str,&[u8])], avb_off: bool, destination: &Path) -> Result<Bundle> {
    let (file, original_meta) = open_regular(ota, 128 << 30)?;
    note("reading payload manifest");
    step(crate::FactoryStep::ReadingPackage);
    let mut input = BufReader::new(file);
    let plan = payload_preflight::read_zip(&mut input)?;
    // `None` means the caller installs without checking the package
    // signature. Structure, roster and capacity are still enforced below.
    let authenticated = match trusted_certs {
        Some(certs) => {
            let (certs, _) = open_regular(certs, 8 << 20)?;
            let keys = signature::keys(BufReader::new(certs))?;
            let verdict = signature::verify(&mut input, original_meta.len(), &keys, |_, _| true)?;
            ensure!(verdict == signature::Verdict::Signed, "official OTA signature is not established: {verdict:?}");
            true
        }
        None => false,
    };
    let roster = factory_preflight::compatible_pgz_roster(&plan)?;
    let sizes = factory_preflight::ReplacementSizes {
        my_company:super_replacement::inspect(company)?, my_preload:super_replacement::inspect(preload)?,
    };
    let company_hash = checked_replacement(company, "55941734cc82ffa44a812583bf7b3fbe3b8bfa1c1d8b7931a812135458de66bf")?;
    let preload_hash = checked_replacement(preload, "a5f578d470231315485c2323fb180d90a3e9ae5a6ff9699d59a38999d8218364")?;
    let checked = factory_preflight::check(&plan, authenticated, reference, actual_size, roster, sizes)?;
    // Full-payload staging cannot silently drop an undeclared physical image.
    let dynamic_names: std::collections::BTreeSet<_> = plan.dynamic.as_ref().context("missing dynamic metadata")?
        .groups.iter().flat_map(|group| group.partitions.iter().map(String::as_str)).collect();
    let actual_physical: std::collections::BTreeSet<_> = plan.partitions.iter().map(|p| p.name.as_str())
        .filter(|name| !dynamic_names.contains(name)).collect();
    let reviewed_physical: std::collections::BTreeSet<_> = roster.physical.iter().copied().collect();
    ensure!(actual_physical == reviewed_physical, "physical payload inventory differs from the reviewed full-payload roster");
    let base = retention::SlotTarget::from_payload(&plan, Slot::A)?.stage_from_payload(&mut input, &plan)?;
    note("repacking vendor_boot with the supplied Recovery program");
    step(crate::FactoryStep::RepackingVendorBoot);
    let pair = if avb_off {
        base.prepare_a_avb_off(program, assets)?
    } else {
        ensure!(base.audit_repack(program, assets)? == vendor_boot::parent_avb::ParentBinding::MatchesCandidate,
            "repacked vendor_boot does not match unchanged parent AVB; no bundle published");
        let stock = payload_stage::reconstruct(&mut input, partition(&plan,"vendor_boot")?,64 << 20)?;
        retention::OfflineAvbPair {
            vendor_boot:vendor_boot::repack(&stock,program,assets)?,
            vbmeta:payload_stage::reconstruct(&mut input,partition(&plan,"vbmeta")?,1 << 20)?,
        }
    };
    let raw_parent = destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let parent = fs::canonicalize(raw_parent)?;
    let name = destination.file_name().context("missing bundle directory name")?;
    ensure!(name != "." && name != "..", "invalid destination directory name");
    let final_path = parent.join(name);
    match fs::symlink_metadata(&final_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
        Ok(_) => anyhow::bail!("refusing to replace existing bundle {}", final_path.display()),
    }
    let parent_fd = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_DIRECTORY).open(&parent)?;
    let parent_meta = parent_fd.metadata()?;
    let staged = tempfile::Builder::new().prefix(".skyward-core-bundle-").tempdir_in(&parent)?;
    let mut images = Vec::new();
    note("staging core boot-chain images");
    step(crate::FactoryStep::CoreImages);
    for (name,target,max) in CORE_PAYLOAD {
        let bytes = payload_stage::reconstruct(&mut input,partition(&plan,name)?,max)?;
        images.push(put(staged.path(),target,&bytes)?);
    }
    images.push(put(staged.path(),Target::VendorBootA,&pair.vendor_boot)?);
    images.push(put(staged.path(),Target::VbmetaA,&pair.vbmeta)?);
    let super_path = staged.path().join(filename(Target::Super));
    note(&format!("building the A-only super image ({actual_size} bytes)"));
    super_image::build_a_observed(&mut input, &plan, reference, actual_size, company, preload, &super_path,
        &mut |name, index, total| {
            #[cfg(target_os = "android")]
            let _ = skyward_sys::kmsg(&format!("factory restore: staging A logical volume {index}/{total} {name}"));
            step(crate::FactoryStep::LogicalVolume { index, count: total, name: name.to_owned() });
            #[cfg(not(target_os = "android"))]
            let _ = (name, index, total);
            Ok(())
        })?;
    note("super image written; computing its SHA-256 (this reads the whole file)");
    let (bytes,sha256) = hash_file(&super_path)?;
    note("super image hashed");
    images.push(Image {target:Target::Super,bytes,sha256});
    crate::factory_execute::Plan::core(&images)?;
    // Replacement inputs are pinned exact user files; ensure neither changed
    // while the super was being assembled from them.
    ensure!(hash_file(company)? == company_hash, "company replacement changed during bundle assembly");
    ensure!(hash_file(preload)? == preload_hash, "preload replacement changed during bundle assembly");
    ensure!(unchanged(&original_meta,&input.get_ref().metadata()?), "OTA file changed during bundle preparation");
    let core_names = ["boot","dtbo","vendor_boot","vbmeta_system","vbmeta_vendor","vbmeta"];
    let mut extra_physical = BTreeMap::new();
    let mut remaining_physical: Vec<_> = roster.physical.iter().filter(|n| !core_names.contains(n)).map(|s| (*s).to_owned()).collect();
    remaining_physical.sort();
    let physical_total = remaining_physical.len();
    for (position, name) in remaining_physical.iter().enumerate() {
        let image = partition(&plan, name)?;
        physical_filename(name, image.size)?;
        note(&format!("staging physical firmware image {name} ({} bytes)", image.size));
        step(crate::FactoryStep::Physical { index: position + 1, count: physical_total, name: name.clone() });
        let bytes = payload_stage::reconstruct(&mut input, image, 128 << 20)
            .with_context(|| format!("reconstruct physical payload image {name}"))?;
        let (bytes, sha256) = put_physical(staged.path(), name, image, &bytes)?;
        ensure!(extra_physical.insert(name.clone(), StagedPhysical {
            path: final_path.join(physical_filename(name, bytes)?), bytes, sha256,
        }).is_none(), "duplicate physical staged image {name}");
    }
    ensure!(extra_physical.len() + core_names.len() == reviewed_physical.len(), "incomplete staged physical payload");
    remaining_physical.clear();
    let supported_firmware: std::collections::BTreeSet<_> = crate::factory_execute::FirmwarePartition::ALL
        .into_iter().map(|firmware| firmware.base_name()).collect();
    // The preloader has a fixed A-only target, but its live DM mapping
    // must still be proven by the Android claims layer before writing.
    let unmapped_physical: Vec<_> = extra_physical.keys().filter(|name|
        name.as_str() != "preloader_raw" && !supported_firmware.contains(name.as_str())).cloned().collect();
    // Extra extraction can take time too; recheck the same source descriptor
    // before publishing instead of considering an earlier check final.
    ensure!(unchanged(&original_meta,&input.get_ref().metadata()?), "OTA file changed during physical staging");
    let mut report = String::from("STAGED FULL PAYLOAD; not complete-device or bootloader authorization. No device writes.\n");
    report.push_str(&format!("avb_off={avb_off}; modified parent signature invalid={avb_off}; A allocation end={}\n",checked.allocated_end));
    for image in &images { report.push_str(&format!("{:x}  {}  {}\n",DigestDisplay(image.sha256),filename(image.target),image.bytes)); }
    for (name, image) in &extra_physical {
        report.push_str(&format!("{:x}  {}  {}\n", DigestDisplay(image.sha256),physical_filename(name,image.bytes)?,image.bytes));
    }
    report.push_str("remaining_physical=\n");
    report.push_str(&format!("unmapped_physical={}\n", unmapped_physical.join(",")));
    let mut marker = OpenOptions::new().write(true).create_new(true).open(staged.path().join("FULL-PAYLOAD-STAGED.txt"))?;
    marker.write_all(report.as_bytes())?; marker.sync_all()?;
    File::open(staged.path())?.sync_all()?;
    let current_parent = fs::metadata(&parent)?;
    ensure!(current_parent.dev()==parent_meta.dev() && current_parent.ino()==parent_meta.ino(), "destination parent changed");
    note("publishing the staged bundle");
    step(crate::FactoryStep::Publishing);
    publish_no_replace(&parent_fd,staged.path().file_name().context("missing staging basename")?,name)?;
    // The directory has moved. Suppress cleanup of the obsolete pathname.
    let _old_name = staged.keep();
    parent_fd.sync_all()?;
    let paths = images.iter().map(|i| (i.target,final_path.join(filename(i.target)))).collect();
    Ok(Bundle {directory:final_path,paths,images,extra_physical,remaining_physical,unmapped_physical,avb_off})
}

struct DigestDisplay([u8;32]);
impl std::fmt::LowerHex for DigestDisplay {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        for byte in self.0 { write!(f,"{byte:02x}")?; } Ok(())
    }
}

fn publish_no_replace(parent:&File, from:&std::ffi::OsStr, to:&std::ffi::OsStr)->Result<()> {
    let from=CString::new(from.as_bytes())?; let to=CString::new(to.as_bytes())?;
    #[cfg(any(target_os="linux",target_os="android"))]
    {
        // SAFETY: both names are live NUL-terminated basenames relative to
        // the same live directory FD. RENAME_NOREPLACE forbids races/clobbering.
        let rc=unsafe {libc::syscall(libc::SYS_renameat2,parent.as_raw_fd(),from.as_ptr(),parent.as_raw_fd(),to.as_ptr(),1u32)};
        if rc!=0 {return Err(std::io::Error::last_os_error()).context("publish core bundle without overwrite")}
        Ok(())
    }
    #[cfg(not(any(target_os="linux",target_os="android")))]
    { let _=(parent,from,to); anyhow::bail!("atomic no-replace publish unavailable on this host") }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact call the install page makes, against the real package: no
    /// signature, real captured LP metadata, real Recovery repack inputs.
    /// Requires the 7 GB ZIP and about 14 GB of scratch space.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the real .211 ZIP, captured LP metadata, Recovery assets and about 25 GB scratch"]
    fn install_page_prepare_stages_a_complete_a_only_ab_roster() -> Result<()> {
        let var = |name: &str| std::env::var_os(name).map(PathBuf::from)
            .with_context(|| format!("set {name}"));
        let (ota, lp, assets) = (var("SKYWARD_OTA_211")?, var("SKYWARD_SUPER_LP")?, var("SKYWARD_RECOVERY_ASSETS")?);
        let (company, preload) = (var("SKYWARD_MY_COMPANY")?, var("SKYWARD_MY_PRELOAD")?);
        let reference = skyward_lp::read_image(&lp)?;
        let actual = reference.block_devices[0].size;
        let program = std::fs::read(assets.join("recovery"))?;
        let mut owned = Vec::new();
        for (inside, file) in [("skyward/device.toml", "device.toml"), ("skyward/MiSansVF.ttf", "MiSansVF.ttf"),
            ("skyward/KirkMono-Regular.ttf", "KirkMono-Regular.ttf"),
            ("skyward/KirkMono-OFL.txt", "KirkMono-OFL.txt"), ("system/etc/init/skyward-mtp.rc", "skyward-mtp.rc")] {
            owned.push((inside, std::fs::read(assets.join(file))?));
        }
        let borrowed: Vec<_> = owned.iter().map(|(name, bytes)| (*name, bytes.as_slice())).collect();
        let scratch = tempfile::tempdir()?;
        let bundle = prepare(&ota, None, &reference, actual, &company, &preload,
            &program, &borrowed, true, scratch.path().join("bundle").as_path())?;
        assert!(bundle.remaining_physical.is_empty(), "every reviewed physical image was staged");
        assert!(bundle.unmapped_physical.is_empty(), "no staged image lacks a fixed target");
        let plan = bundle.execution_plan_ab()?;
        let sources = bundle.execution_sources_ab()?;
        assert_eq!(sources.len(), 51);
        assert_eq!(plan.images().len(), 51);
        assert_eq!(sources.values().filter(|path| **path == *bundle.paths.get(&Target::Super).unwrap()).count(), 1,
            "one shared super is written");
        let super_image = bundle.images.iter().find(|image| image.target == Target::Super).context("staged super")?;
        assert_eq!(super_image.bytes, actual);
        let super_path = bundle.paths.get(&Target::Super).context("staged super path")?;
        let written = skyward_lp::read(super_path, 0)?;
        assert!(written.damaged.is_empty());
        assert!(written.partition("my_company_a").is_some() && written.partition("my_preload_a").is_some());
        // B keeps placeholder records so the Virtual A/B layout stays valid,
        // but none of them maps physical super: no second system is stored.
        for part in written.partitions.iter().filter(|part| part.name.ends_with("_b")) {
            let mapped: u64 = part.extents.iter().filter_map(|extent| match extent {
                skyward_lp::Extent::Linear { sectors, .. } => Some(*sectors),
                skyward_lp::Extent::Zero { .. } => None,
            }).sum();
            assert_eq!(mapped, 0, "{} maps physical super sectors for slot B", part.name);
        }
        crate::factory_simulation::replay_staged_ab(&bundle, scratch.path())
    }

    #[test]
    fn a_staged_preloader_does_not_authorize_an_incomplete_bundle() {
        let mut bundle = Bundle { directory: PathBuf::new(), paths:BTreeMap::new(), images:Vec::new(),
            extra_physical:BTreeMap::from([("preloader_raw".into(), StagedPhysical {
                path: PathBuf::from("preloader_raw.img"), bytes: 507904, sha256: [1;32],
            })]), remaining_physical:Vec::new(), unmapped_physical:Vec::new(), avb_off:true };
        // Even a missing diagnostic entry must not bypass the fixed roster.
        let error = bundle.execution_plan().unwrap_err().to_string();
        assert!(error.contains("missing staged firmware"), "{error}");
        bundle.extra_physical.insert("sda".into(), StagedPhysical {
            path: PathBuf::from("sda.img"), bytes: 4096, sha256: [2;32],
        });
        let error = bundle.execution_plan().unwrap_err().to_string();
        assert!(error.contains("no verified write mapping") && error.contains("sda"));
        bundle.remaining_physical.push("lk".into());
        assert!(bundle.execution_plan().unwrap_err().to_string().contains("unstaged payload images"));
    }

    #[test]
    fn full_bundle_maps_each_source_to_a_fixed_target() {
        use crate::factory_execute::FirmwarePartition;
        let directory = PathBuf::from("/staged");
        let core = [Target::BootA, Target::DtboA, Target::VendorBootA, Target::VbmetaSystemA,
            Target::VbmetaVendorA, Target::Super, Target::VbmetaA];
        let mut bundle = Bundle {
            directory: directory.clone(),
            paths: core.into_iter().map(|target| (target, directory.join(filename(target)))).collect(),
            images: core.into_iter().map(|target| Image { target, bytes: 4096, sha256: [3;32] }).collect(),
            extra_physical: FirmwarePartition::ALL.into_iter().map(|firmware| {
                let base = firmware.base_name();
                (base.into(), StagedPhysical { path:directory.join(format!("{base}.img")), bytes:4096, sha256:[4;32] })
            }).collect(),
            remaining_physical:Vec::new(), unmapped_physical:Vec::new(), avb_off:true,
        };
        assert!(bundle.execution_plan().is_err());
        bundle.extra_physical.insert("preloader_raw".into(), StagedPhysical {
            path: directory.join("preloader_raw.img"), bytes:crate::factory_preloader::IMAGE_211_BYTES,
            sha256:crate::factory_preloader::IMAGE_211_SHA256,
        });
        let sources = bundle.execution_sources().unwrap();
        assert_eq!(sources.len(), 26);
        assert_eq!(sources[&Target::PreloaderA], directory.join("preloader_raw.img"));
        let ab = bundle.execution_sources_ab().unwrap();
        assert_eq!(ab.len(), 51);
        assert_eq!(ab[&Target::PreloaderB], ab[&Target::PreloaderA]);
        assert_eq!(ab[&Target::VendorBootB], ab[&Target::VendorBootA]);
        assert_eq!(ab[&Target::Super], directory.join("super.img"));
        bundle.extra_physical.get_mut("preloader_raw").unwrap().path = directory.join("other.img");
        assert!(bundle.execution_sources().is_err());
        bundle.extra_physical.get_mut("preloader_raw").unwrap().bytes = crate::factory_preloader::MAPPED_BYTES + 512;
        assert!(bundle.execution_plan().is_err());
    }

    #[test]
    fn physical_inventory_names_are_safe_and_never_core_or_whole_disk() {
        assert_eq!(physical_filename("md1img", 69_967_872).unwrap(),"md1img.img");
        for bad in ["", "sda", "super", "boot", "vendor_boot", "vbmeta", "system_a", "../x", "UPPER"] {
            assert!(physical_filename(bad, 4096).is_err(), "accepted {bad:?}");
        }
        assert!(physical_filename("preloader_raw", 0).is_err());
        assert!(physical_filename("preloader_raw", 4097).is_err());
        assert!(physical_filename("huge", (128u64 << 20) + 512).is_err());
    }

    #[test]
    fn publish_is_atomic_and_never_overwrites_an_existing_directory() {
        let dir=tempfile::tempdir().unwrap();
        let parent=File::open(dir.path()).unwrap();
        fs::create_dir(dir.path().join("stage")).unwrap();
        fs::write(dir.path().join("stage/CORE-COMPLETE.txt"),b"done").unwrap();
        publish_no_replace(&parent,std::ffi::OsStr::new("stage"),std::ffi::OsStr::new("final")).unwrap();
        assert_eq!(fs::read(dir.path().join("final/CORE-COMPLETE.txt")).unwrap(),b"done");
        fs::create_dir(dir.path().join("second")).unwrap();
        assert!(publish_no_replace(&parent,std::ffi::OsStr::new("second"),std::ffi::OsStr::new("final")).is_err());
        assert!(dir.path().join("second").is_dir());
    }
    #[test]
    fn extra_physical_bytes_must_match_the_payload_declaration() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = vec![0x45; 4096];
        let mut declaration = payload_plan::Partition {
            name: "preloader_raw".into(), size: 4096, sha256: Sha256::digest(&bytes).into(), operations: Vec::new(),
        };
        assert!(put_physical(dir.path(), "lk", &declaration, &bytes).is_err());
        declaration.sha256 = [0; 32];
        assert!(put_physical(dir.path(), "preloader_raw", &declaration, &bytes).is_err());
        assert!(!dir.path().join("preloader_raw.img").exists());
        declaration.sha256 = Sha256::digest(&bytes).into();
        let staged = put_physical(dir.path(), "preloader_raw", &declaration, &bytes).unwrap();
        assert_eq!(staged, (4096, declaration.sha256));
        assert_eq!(std::fs::read(dir.path().join("preloader_raw.img")).unwrap(), bytes);
        assert!(put_physical(dir.path(), "preloader_raw", &declaration, &bytes).is_err());
    }

    #[test]
    fn replacement_hash_pin_rejects_a_renamed_or_altered_file() {
        let dir=tempfile::tempdir().unwrap();
        let company=dir.path().join("renamed-company.img");
        std::fs::write(&company,[1,2,3,4]).unwrap();
        let expected=format!("{:x}",DigestDisplay(Sha256::digest([1,2,3,4]).into()));
        assert_eq!(checked_replacement(&company,&expected).unwrap(),(4,Sha256::digest([1,2,3,4]).into()));
        assert!(checked_replacement(&company,"00").is_err());
        std::fs::write(&company,[1,2,3,5]).unwrap();
        assert!(checked_replacement(&company,&expected).is_err());
    }
    #[test]
    fn source_open_rejects_symlinks_and_hash_descriptor_is_exact() {
        let dir=tempfile::tempdir().unwrap();let target=dir.path().join("source");
        fs::write(&target,b"bytes").unwrap();
        let link=dir.path().join("link");std::os::unix::fs::symlink(&target,&link).unwrap();
        assert!(open_regular(&link,64).is_err());assert!(open_regular(&target,4).is_err());
        let image=put(dir.path(),Target::BootA,b"bytes").unwrap();
        assert_eq!(image.sha256,Sha256::digest(b"bytes").as_slice());
        assert_eq!(hash_file(&dir.path().join("boot_a.img")).unwrap(),(5,image.sha256));
    }
}
