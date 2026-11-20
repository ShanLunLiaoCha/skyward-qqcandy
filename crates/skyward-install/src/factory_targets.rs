//! Android-only exclusive claims for the fixed single-A restore targets.
//! This layer does not authorize a restore, open whole disks, or switch slots.
use crate::factory_execute::{Image, Target};
use anyhow::{Context, Result, ensure};
#[cfg(target_os = "android")]
use std::collections::{BTreeMap, BTreeSet};

fn partition(target: Target) -> &'static str {
    target.display_name()
}

fn unique_field<'a>(text: &'a str, field: &str) -> Result<&'a str> {
    let mut values = text.lines().filter_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key == field).then_some(value)
    });
    let value = values.next().with_context(|| format!("missing kernel {field}"))?;
    ensure!(!value.is_empty() && values.next().is_none(), "ambiguous kernel {field}");
    Ok(value)
}

fn check_partition_event(event: &str, target: Target, id: (u32,u32)) -> Result<()> {
    ensure!(!matches!(target, Target::PreloaderA | Target::PreloaderB), "preloader must use the dedicated DM audit, not a kernel partition");
    ensure!(unique_field(event, "DEVTYPE")? == "partition", "target is not a kernel partition");
    ensure!(unique_field(event, "PARTNAME")? == partition(target), "kernel partition label differs from the requested target {}", partition(target));
    ensure!(unique_field(event, "MAJOR")?.parse::<u32>()? == id.0
        && unique_field(event, "MINOR")?.parse::<u32>()? == id.1, "kernel device number differs from the descriptor");
    Ok(())
}

fn check_capacity(image: &Image, capacity: u64) -> Result<()> {
    ensure!(image.bytes != 0 && image.bytes % 512 == 0 && capacity % 512 == 0 && capacity >= image.bytes,
        "target {} capacity {capacity} does not fit {} bytes", partition(image.target), image.bytes);
    if let Target::Firmware(firmware) | Target::FirmwareB(firmware) = image.target {
        ensure!(image.bytes <= firmware.maximum_image_bytes(), "firmware {} exceeds its reviewed bound", firmware.base_name());
    }
    if matches!(image.target, Target::PreloaderA | Target::PreloaderB) {
        crate::factory_preloader::check_image_bounds(image.bytes, &image.sha256)?;
        ensure!(capacity == crate::factory_preloader::MAPPED_BYTES, "unexpected preloader mapping capacity");
    }
    if matches!(image.target, Target::Super | Target::VendorBootA | Target::VendorBootB) {
        ensure!(capacity == image.bytes, "{} requires a full-size staged image", partition(image.target));
    }
    Ok(())
}

#[cfg(target_os = "android")]
#[derive(Debug)]
struct Claimed {
    fd: std::fs::File,
    id: (u32, u32),
    image: Image,
    preloader: Option<crate::factory_preloader::ObservedMapping>,
}

/// Claims are held until the owner drops this entire set. No caller can open
/// a package-provided filename as a destination. The preloader can only use
/// the independently audited OEM A mapping, not its raw backing device.
#[cfg(target_os = "android")]
pub(crate) struct Claims(BTreeMap<Target, Claimed>);

#[cfg(target_os = "android")]
impl Claims {
    pub(crate) fn acquire(images: &[Image]) -> Result<Self> {
        Self::claim_set(images, true)
    }

    pub(crate) fn claim_set(images: &[Image], writable: bool) -> Result<Self> {
        let mut ids = BTreeSet::new();
        let mut claims = BTreeMap::new();
        for (index, image) in images.iter().enumerate() {
            let access = if writable { "write" } else { "read-only" };
            let _ = skyward_sys::kmsg(&format!("factory restore: exclusive {access} claim {}/{} {}", index + 1, images.len(), image.target.display_name()));
            if writable {
                crate::progress::report(crate::FactoryStep::Claiming {
                    index: index + 1, count: images.len(), name: image.target.display_name().to_owned() });
            }
            ensure!(!claims.contains_key(&image.target), "duplicate target {}", partition(image.target));
            let entry = claim(*image, writable).with_context(|| format!("claim {} before any writes", partition(image.target)))?;
            ensure!(ids.insert(entry.id), "restore targets alias the same block device");
            if let Some(dm) = &entry.preloader {
                ensure!(ids.insert(dm.backing), "restore target aliases the preloader backing LUN");
            }
            claims.insert(image.target, entry);
        }
        Ok(Self(claims))
    }

    pub(crate) fn identities(&self) -> BTreeSet<(u32,u32)> {
        self.0.values().flat_map(|entry| std::iter::once(entry.id)
            .chain(entry.preloader.as_ref().map(|dm| dm.backing))).collect()
    }

    pub(crate) fn copy(&mut self, image: &Image, source: &mut impl std::io::Read) -> Result<()> {
        use std::io::{Seek, SeekFrom};
        let entry = self.0.get_mut(&image.target).context("destination was not claimed")?;
        ensure!(entry.image == *image, "staged descriptor changed since claiming target");
        if let Some(mapping) = &entry.preloader {
            // Verify all bootloader bytes before the first write (unlike big
            // images, every fitting preloader fits a small bounded buffer).
            use std::io::Write;
            let bytes = read_preloader_image(source, image)?;
            recheck_preloader(&entry.fd, mapping, image)?;
            entry.fd.seek(SeekFrom::Start(0))?;
            entry.fd.write_all(&bytes)?;
            return recheck_preloader(&entry.fd, mapping, image);
        }
        entry.fd.seek(SeekFrom::Start(0))?;
        crate::factory_execute::copy_checked(source, &mut entry.fd, image)
    }

    pub(crate) fn sync(&self, target: Target) -> Result<()> {
        let entry = self.0.get(&target).context("destination was not claimed")?;
        entry.fd.sync_all()?;
        if let Some(mapping) = &entry.preloader {
            recheck_preloader(&entry.fd, mapping, &entry.image)?;
        }
        Ok(())
    }
}

#[cfg(any(target_os = "android", test))]
fn read_preloader_image(source: &mut impl std::io::Read, image: &Image) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256};
    crate::factory_preloader::check_image_bounds(image.bytes, &image.sha256)?;
    let mut bytes = vec![0; image.bytes as usize];
    source.read_exact(&mut bytes).context("read staged .211 preloader")?;
    ensure!(source.read(&mut [0])? == 0, "staged preloader has trailing bytes");
    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    ensure!(hash == image.sha256, "staged preloader differs from the payload's declared hash");
    Ok(bytes)
}

#[cfg(target_os = "android")]
fn recheck_preloader(fd: &std::fs::File, expected: &crate::factory_preloader::ObservedMapping, image: &Image) -> Result<()> {
    use std::path::Path;
    let id = block_identity(&fd.metadata()?)?;
    ensure!(expected.target == id && observe_preloader(image.target)? == *expected,
        "claimed preloader DM identity or table changed");
    ensure!(crate::factory_preflight::kernel_super_holders(Path::new("/sys/dev/block"), id)?.is_empty()
        && skyward_block::mount::points_of(id)?.is_empty(), "preloader DM target is in use");
    check_fd_capacity(fd, image)
}

#[cfg(target_os = "android")]
fn block_identity(meta: &std::fs::Metadata) -> Result<(u32,u32)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    ensure!(meta.file_type().is_block_device(), "restore target is not a block device");
    let rdev = meta.rdev() as libc::dev_t;
    Ok((libc::major(rdev) as u32, libc::minor(rdev) as u32))
}

#[cfg(target_os = "android")]
fn observe_preloader(target: Target) -> Result<crate::factory_preloader::ObservedMapping> {
    match target {
        Target::PreloaderA => crate::factory_preloader::observe_a(),
        Target::PreloaderB => crate::factory_preloader::observe_b(),
        _ => anyhow::bail!("target is not a dedicated preloader mapping"),
    }
}

#[cfg(target_os = "android")]
fn claim_preloader(image: Image, writable: bool) -> Result<Claimed> {
    use std::{fs::OpenOptions, os::{fd::AsRawFd, unix::fs::OpenOptionsExt}};
    crate::factory_preloader::check_image_bounds(image.bytes, &image.sha256)?;
    let mapping = observe_preloader(image.target)?;
    // Pin the audited DM inode without opening the block device for I/O.
    // Reopen that same object through procfs, not a re-resolved by-name path.
    let pin = OpenOptions::new().read(true).custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&mapping.node)?;
    ensure!(block_identity(&pin.metadata()?)? == mapping.target
        && observe_preloader(image.target)? == mapping, "preloader DM target changed before claim");
    let fd = OpenOptions::new().read(!writable).write(writable).custom_flags(libc::O_EXCL | libc::O_CLOEXEC)
        .open(format!("/proc/self/fd/{}", pin.as_raw_fd())).context("exclusive open of pinned A preloader mapping")?;
    recheck_preloader(&fd, &mapping, &image)?;
    Ok(Claimed {fd, id:mapping.target, image, preloader:Some(mapping)})
}

#[cfg(target_os = "android")]
fn claim(image: Image, writable: bool) -> Result<Claimed> {
    if matches!(image.target, Target::PreloaderA | Target::PreloaderB) { return claim_preloader(image, writable); }
    let (fd, id) = claim_gpt_partition(image.target, writable)?;
    check_fd_capacity(&fd, &image)?;
    Ok(Claimed {fd, id, image, preloader:None})
}

/// Simultaneously hold all plan targets read-only and exclusively. No writes,
/// service calls, durable authorization, or slot changes are performed.
#[cfg(target_os = "android")]
pub(crate) fn audit_full_plan(plan: &crate::factory_execute::Plan) -> Result<usize> {
    let claims = Claims::claim_set(plan.images(), false)?;
    // Ordinary claims do not protect against a privileged DM table reload.
    for entry in claims.0.values() {
        if let Some(mapping) = &entry.preloader {
            recheck_preloader(&entry.fd, mapping, &entry.image)?;
        }
    }
    Ok(claims.0.len())
}

/// Keep an exclusive read-only super FD live across the diagnostic. The
/// callback receives its identity, never the descriptor or a write handle.
#[cfg(target_os = "android")]
pub fn with_exclusive_super_for_audit<T>(audit: impl FnOnce((u32, u32)) -> Result<T>) -> Result<T> {
    let (lease, id) = claim_gpt_partition(Target::Super, false)?;
    let result = audit(id);
    drop(lease);
    result
}

#[cfg(target_os = "android")]
pub(crate) fn claim_gpt_partition(target: Target, writable: bool) -> Result<(std::fs::File, (u32, u32))> {
    use std::{fs::{self, OpenOptions}, io::Read, os::{fd::AsRawFd, unix::fs::OpenOptionsExt}, path::Path};
    let by_name = Path::new(skyward_block::BY_NAME).join(partition(target));
    let real = fs::canonicalize(&by_name)?;
    ensure!(real.starts_with("/dev/block") && !real.starts_with(skyward_block::BY_NAME), "unexpected block target path");
    // Even for an ordinary partition, inspect its identity before taking a
    // write handle: a stale by-name symlink must never open a whole disk RW.
    let pin = OpenOptions::new().read(true).custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&real)?;
    let id = block_identity(&pin.metadata()?)?;
    let sys = Path::new("/sys/dev/block");
    let at = sys.join(format!("{}:{}", id.0,id.1));
    let verify_event = || -> Result<()> {
        let mut event = String::new();
        fs::File::open(at.join("uevent"))?.take(4097).read_to_string(&mut event)?;
        ensure!(event.len() <= 4096, "kernel partition event is too large");
        check_partition_event(&event, target, id)
    };
    verify_event()?;
    ensure!(fs::canonicalize(&by_name)? == real, "block target changed before claiming");
    let fd = OpenOptions::new().read(true).write(writable).custom_flags(libc::O_EXCL | libc::O_CLOEXEC)
        .open(format!("/proc/self/fd/{}", pin.as_raw_fd()))?;
    ensure!(block_identity(&fd.metadata()?)? == id && fs::canonicalize(&by_name)? == real,
        "block target changed while claiming");
    verify_event()?;
    ensure!(crate::factory_preflight::kernel_super_holders(sys, id)?.is_empty(), "kernel still holds target {}", partition(target));
    ensure!(skyward_block::mount::points_of(id)?.is_empty(), "target {} is mounted", partition(target));
    Ok((fd, id))
}

#[cfg(target_os = "android")]
fn check_fd_capacity(fd: &std::fs::File, image: &Image) -> Result<()> {
    use std::os::fd::AsRawFd;
    let mut capacity = 0u64;
    let mut readonly = 1i32;
    // SAFETY: both calls use a live block FD and appropriately sized outputs.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), 0x80081272u32 as libc::c_int, &mut capacity) };
    if rc != 0 { return Err(std::io::Error::last_os_error()).context("BLKGETSIZE64 on claimed target"); }
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), 0x125e, &mut readonly) };
    if rc != 0 { return Err(std::io::Error::last_os_error()).context("BLKROGET on claimed target"); }
    ensure!(readonly == 0, "claimed target is read-only");
    check_capacity(image, capacity)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_whole_disk_wrong_partition_duplicate_and_wrong_device() {
        let valid = "MAJOR=8\nMINOR=79\nDEVTYPE=partition\nPARTNAME=super\n";
        assert!(check_partition_event(valid, Target::Super, (8,79)).is_ok());
        assert!(check_partition_event(valid, Target::BootA, (8,79)).is_err());
        assert!(check_partition_event(valid, Target::Super, (8,80)).is_err());
        assert!(check_partition_event(&valid.replace("partition", "disk"), Target::Super, (8,79)).is_err());
        assert!(check_partition_event(&format!("{valid}PARTNAME=super\n"), Target::Super, (8,79)).is_err());
        assert!(check_partition_event("MAJOR=253\nMINOR=0\nDEVTYPE=disk\nDM_NAME=pl_a\n", Target::Super, (253,0)).is_err());
    }
    #[test]
    fn firmware_targets_are_fixed_a_partitions_with_explicit_bounds() {
        for firmware in crate::factory_execute::FirmwarePartition::ALL {
            let target = Target::Firmware(firmware);
            let name = partition(target);
            assert!(name.ends_with("_a") && !name.contains("preloader"));
            let image = Image { target, bytes: 4096, sha256: [1; 32] };
            assert!(check_capacity(&image, 8192).is_ok(), "{name} is not required to fill its partition");
            assert!(check_capacity(&image, 4095).is_err());
            let oversized = Image { bytes: firmware.maximum_image_bytes() + 512, ..image };
            assert!(check_capacity(&oversized, oversized.bytes).is_err());
        }
        assert!(check_partition_event("MAJOR=8\nMINOR=1\nDEVTYPE=partition\nPARTNAME=gz_a\n", Target::Firmware(crate::factory_execute::FirmwarePartition::Gz), (8,1)).is_ok());
        assert!(check_partition_event("MAJOR=8\nMINOR=1\nDEVTYPE=partition\nPARTNAME=gz\n", Target::Firmware(crate::factory_execute::FirmwarePartition::Gz), (8,1)).is_err());
    }
    #[test]
    fn preloader_requires_oem_dm_capacity_and_rejects_damaged_source_bytes() {
        use crate::factory_preloader::{IMAGE_211_BYTES, IMAGE_211_SHA256, MAPPED_BYTES};
        use std::io::Read;
        let image = Image {target:Target::PreloaderA, bytes:IMAGE_211_BYTES, sha256:IMAGE_211_SHA256};
        assert!(check_capacity(&image, MAPPED_BYTES).is_ok());
        assert!(check_capacity(&image, IMAGE_211_BYTES).is_err());
        assert!(check_capacity(&image, 4 << 20).is_err());
        assert!(check_partition_event("MAJOR=8\nMINOR=0\nDEVTYPE=partition\nPARTNAME=preloader_raw_a\n", image.target, (8,0)).is_err());
        assert!(read_preloader_image(&mut std::io::repeat(0).take(IMAGE_211_BYTES), &image).is_err());
        assert!(read_preloader_image(&mut std::io::repeat(0).take(IMAGE_211_BYTES-1), &image).is_err());
        assert!(read_preloader_image(&mut std::io::repeat(0).take(IMAGE_211_BYTES+1), &image).is_err());
    }
    #[test]
    fn full_size_is_required_for_super_and_vendor_boot() {
        for target in [Target::Super, Target::VendorBootA, Target::VbmetaA] {
            let image = Image {target, bytes:4096, sha256:[1;32]};
            assert!(check_capacity(&image, 4096).is_ok());
            assert!(check_capacity(&image, 2048).is_err());
            assert_eq!(check_capacity(&image, 8192).is_ok(), target == Target::VbmetaA);
        }
    }
}
