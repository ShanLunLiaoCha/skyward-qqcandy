//! Android-only, current-slot writer for the mobile porter. No slot switch,
//! reboot, unmount, or writes to raw disks. The APK must separately obtain
//! consent and retain the original backups before invoking this helper.
use anyhow::Result;
use std::ffi::OsString;

#[cfg(not(target_os = "android"))]
pub fn flash(_args: &[OsString]) -> Result<()> {
    anyhow::bail!("mobile porter flashing is only available on Android")
}

#[cfg(target_os = "android")]
pub fn flash(args: &[OsString]) -> Result<()> {
    android::run(args)
}

#[cfg(any(target_os = "android", test))]
fn parse_sha256(value: &str) -> Result<[u8; 32]> {
    anyhow::ensure!(value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()), "expected a 64-digit SHA-256");
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)?;
    }
    Ok(out)
}

#[cfg(any(target_os = "android", test))]
fn is_boot_id(value: &str) -> bool {
    value.len() == 36 && value.bytes().enumerate().all(|(i, b)| {
        if matches!(i, 8 | 13 | 18 | 23) { b == b'-' }
        else { b.is_ascii_digit() || matches!(b, b'a'..=b'f') }
    })
}

#[cfg(any(target_os = "android", test))]
fn validate_vbmeta_edit(stock: &[u8], candidate: &[u8]) -> Result<()> {
    use anyhow::ensure;
    // Only the top-level header's big-endian flags are permitted to change.
    // Preserve every other byte, including the rest of the partition.
    ensure!(stock.len() == candidate.len() && stock.len() >= 256 && stock.starts_with(b"AVB0"),
        "unexpected original top-level vbmeta layout");
    let flag_bytes = &stock[120..124];
    let flags = u32::from_be_bytes(flag_bytes.try_into()?);
    ensure!(flags & !3 == 0 && candidate[120..124] == (flags | 3).to_be_bytes()
        && stock[..120] == candidate[..120] && stock[124..] == candidate[124..],
        "candidate vbmeta must change only the known hashtree/verification flags");
    Ok(())
}

#[cfg(target_os = "android")]
mod android {
    use super::*;
    use anyhow::{Context, ensure};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File, OpenOptions},
        io::{self, Read},
        os::{fd::AsRawFd, unix::fs::{FileExt, FileTypeExt, MetadataExt, OpenOptionsExt}},
        path::{Path, PathBuf},
        process::Command,
    };

    const VENDOR_BYTES: usize = 64 << 20;
    const VBMETA_BYTES: usize = 8 << 20;
    const CHUNK: usize = 1 << 20;
    const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";

    pub(super) fn run(args: &[OsString]) -> Result<()> {
        // SAFETY: geteuid/getuid take no arguments and have no memory side effects.
        ensure!(unsafe { libc::geteuid() == 0 && libc::getuid() == 0 }, "flash requires Android Root");
        let [slot, boot_id, vendor_node, vbmeta_node, stock_vendor, stock_vbmeta,
            new_vendor, new_vbmeta, candidate_vendor, candidate_vbmeta] = args else {
            anyhow::bail!("expected slot, boot ID, two canonical nodes, two original hashes, two candidate files and two candidate hashes");
        };
        let slot = slot.to_str().context("slot is not UTF-8")?;
        let number = match slot { "_a" => "0", "_b" => "1", _ => anyhow::bail!("invalid slot") };
        let boot_id = boot_id.to_str().context("boot ID is not UTF-8")?;
        ensure!(is_boot_id(boot_id), "invalid boot ID");
        let expected = |value: &OsString| parse_sha256(value.to_str().context("invalid digest argument")?);
        let stock_vendor = expected(stock_vendor)?;
        let stock_vbmeta = expected(stock_vbmeta)?;
        let candidate_vendor = expected(candidate_vendor)?;
        let candidate_vbmeta = expected(candidate_vbmeta)?;
        readiness(slot, number, boot_id).context("check current-slot and bootloader state")?;

        // Load both exact verified images into private process memory. Reusing
        // a modifiable path after hashing it would allow a replacement race.
        let new_vendor = image(Path::new(new_vendor), VENDOR_BYTES, &candidate_vendor)
            .context("verify candidate vendor_boot")?;
        let new_vbmeta = image(Path::new(new_vbmeta), VBMETA_BYTES, &candidate_vbmeta)
            .context("verify candidate vbmeta")?;
        ensure!(new_vendor.starts_with(b"VNDRBOOT") && &new_vendor[VENDOR_BYTES - 64..VENDOR_BYTES - 60] == b"AVBf",
            "candidate vendor_boot header or AVB footer is missing");

        let vendor = Target::claim(&format!("vendor_boot{slot}"), Path::new(vendor_node), VENDOR_BYTES)
            .context("exclusively claim current vendor_boot")?;
        let vbmeta = Target::claim(&format!("vbmeta{slot}"), Path::new(vbmeta_node), VBMETA_BYTES)
            .context("exclusively claim current vbmeta")?;
        ensure!(vendor.id != vbmeta.id, "both targets alias the same block device");
        ensure!(hash_partition(&vendor.file, VENDOR_BYTES)? == stock_vendor,
            "current vendor_boot no longer matches its backup");
        let mut original_vbmeta = vec![0u8; VBMETA_BYTES];
        vbmeta.file.read_exact_at(&mut original_vbmeta, 0).context("read current vbmeta")?;
        ensure!(sha256(&original_vbmeta) == stock_vbmeta, "current vbmeta no longer matches its backup");
        validate_vbmeta_edit(&original_vbmeta, &new_vbmeta)?;
        drop(original_vbmeta);
        readiness(slot, number, boot_id).context("recheck boot state before writing")?;
        vendor.recheck()?;
        vbmeta.recheck()?;
        println!("Both current-slot partitions verified and exclusively held; beginning confirmed write.");

        // Do not change vendor_boot while a stock vbmeta still binds the old
        // image to it. This is not an atomic two-partition transaction.
        vbmeta.write_and_verify(&new_vbmeta, candidate_vbmeta)
            .context("vbmeta may be partially written; vendor_boot write not attempted")?;
        vendor.recheck().context("vbmeta was written; vendor_boot write not attempted")?;
        vendor.write_and_verify(&new_vendor, candidate_vendor)
            .context("vbmeta was written; vendor_boot may be partially written")?;
        println!("Both current-slot writes synced and read back. No reboot or slot change was requested.");
        Ok(())
    }

    fn readiness(slot: &str, number: &str, boot_id: &str) -> Result<()> {
        ensure!(fs::read_to_string(BOOT_ID)?.trim() == boot_id, "device rebooted after preparation");
        ensure!(skyward_sys::prop("ro.boot.slot_suffix").as_deref() == Some(slot), "booted slot changed");
        // The caller decided to write; unlock state is not re-judged here.
        // bootctl is absent on some 13.x builds; the snapshot directory is
        // then the evidence that no merge is pending.
        let snapshots = fs::read_dir("/metadata/ota/snapshots").map(|dir| dir.count()).unwrap_or(0);
        ensure!(snapshots == 0, "virtual A/B snapshot state is not idle");
        let bootctl = Path::new("/system/bin/bootctl");
        let checks: &[(&str, &str)] = if bootctl.exists() {
            &[("get-current-slot", number), ("get-active-boot-slot", number), ("get-snapshot-merge-status", "none")]
        } else {
            &[]
        };
        for (verb, expected) in checks.iter().copied() {
            let output = Command::new(bootctl).arg(verb).output()
                .with_context(|| format!("run bootctl {verb}"))?;
            ensure!(output.status.success() && std::str::from_utf8(&output.stdout)?.trim() == expected,
                "bootctl {verb} does not confirm the current slot and idle snapshots");
        }
        ensure!(fs::read_to_string(BOOT_ID)?.trim() == boot_id, "device rebooted during boot checks");
        Ok(())
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] { Sha256::digest(bytes).into() }

    fn image(path: &Path, bytes: usize, digest: &[u8; 32]) -> Result<Vec<u8>> {
        let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path).with_context(|| format!("open {}", path.display()))?;
        let info = file.metadata()?;
        ensure!(info.is_file() && info.len() == bytes as u64, "candidate is not a regular file of the exact partition size");
        let mut data = Vec::with_capacity(bytes);
        file.take(bytes as u64 + 1).read_to_end(&mut data)?;
        ensure!(data.len() == bytes && sha256(&data) == *digest, "candidate length or SHA-256 changed");
        Ok(data)
    }

    fn hash_partition(file: &File, bytes: usize) -> Result<[u8; 32]> {
        let mut buffer = vec![0u8; CHUNK.min(bytes)];
        let mut hash = Sha256::new();
        for offset in (0..bytes).step_by(CHUNK) {
            let chunk = &mut buffer[..(bytes - offset).min(CHUNK)];
            file.read_exact_at(chunk, offset as u64)?;
            hash.update(chunk);
        }
        Ok(hash.finalize().into())
    }

    fn identity(file: &File) -> Result<(u32, u32)> {
        let meta = file.metadata()?;
        ensure!(meta.file_type().is_block_device(), "target is not a block partition");
        let id = meta.rdev() as libc::dev_t;
        Ok((libc::major(id) as u32, libc::minor(id) as u32))
    }

    fn check_kernel(name: &str, node: &Path, id: (u32, u32)) -> Result<()> {
        let sys = PathBuf::from(format!("/sys/dev/block/{}:{}", id.0, id.1));
        let mut event = String::new();
        File::open(sys.join("uevent"))?.take(4097).read_to_string(&mut event)?;
        ensure!(event.len() <= 4096, "unexpected kernel partition metadata length");
        let dev = node.file_name().and_then(|n| n.to_str()).context("invalid canonical node")?;
        let major = id.0.to_string();
        let minor = id.1.to_string();
        for (key, value) in [("DEVTYPE", "partition"), ("PARTNAME", name), ("DEVNAME", dev), ("MAJOR", &major), ("MINOR", &minor)] {
            let mut values = event.lines().filter_map(|line| line.split_once('='))
                .filter(|(k, _)| *k == key).map(|(_, v)| v);
            ensure!(values.next() == Some(value) && values.next().is_none(), "kernel partition {name} has an unexpected {key}");
        }
        ensure!(fs::read_dir(sys.join("holders"))?.next().transpose()?.is_none(), "{name} has block holders");
        ensure!(skyward_block::mount::points_of(id)?.is_empty(), "{name} is mounted");
        Ok(())
    }

    fn check_capacity(file: &File, expected: usize) -> Result<()> {
        let mut capacity = 0u64;
        let mut readonly = 1i32;
        // SAFETY: these ioctls only query the open block partition and the
        // destination buffers match the Linux/Android argument ABI.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), 0x80081272u32 as libc::c_int, &mut capacity) };
        if rc != 0 { return Err(io::Error::last_os_error()).context("read partition capacity"); }
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), 0x125e, &mut readonly) };
        if rc != 0 { return Err(io::Error::last_os_error()).context("read partition write protection"); }
        ensure!(capacity == expected as u64 && readonly == 0, "unexpected partition capacity or read-only state");
        Ok(())
    }

    struct Target {
        file: File,
        id: (u32, u32),
        node: PathBuf,
        alias: PathBuf,
        name: String,
        bytes: usize,
    }

    impl Target {
        fn claim(name: &str, node: &Path, bytes: usize) -> Result<Self> {
            ensure!(node.parent() == Some(Path::new("/dev/block"))
                && node.file_name().and_then(|v| v.to_str()).is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric())),
                "canonical node must be a direct physical /dev/block child");
            let alias = Path::new(skyward_block::BY_NAME).join(name);
            ensure!(fs::canonicalize(&alias)? == node, "the by-name link for {name} no longer matches");
            let pin = OpenOptions::new().read(true).custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC).open(node)?;
            let id = identity(&pin)?;
            check_kernel(name, node, id)?;
            ensure!(fs::canonicalize(&alias)? == node, "the by-name link changed before claiming");
            let file = OpenOptions::new().read(true).write(true).custom_flags(libc::O_EXCL | libc::O_CLOEXEC)
                .open(format!("/proc/self/fd/{}", pin.as_raw_fd()))?;
            let result = Self { file, id, node: node.into(), alias, name: name.into(), bytes };
            result.recheck()?;
            Ok(result)
        }

        fn recheck(&self) -> Result<()> {
            ensure!(fs::canonicalize(&self.alias)? == self.node && identity(&self.file)? == self.id,
                "physical identity of {} changed", self.name);
            let now = OpenOptions::new().read(true).custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&self.node)?;
            ensure!(identity(&now)? == self.id, "canonical node for {} changed", self.name);
            check_kernel(&self.name, &self.node, self.id)?;
            check_capacity(&self.file, self.bytes)
        }

        fn write_and_verify(&self, data: &[u8], digest: [u8; 32]) -> Result<()> {
            ensure!(data.len() == self.bytes, "candidate size no longer matches target");
            println!("Writing {} ({} bytes)", self.name, self.bytes);
            for (i, chunk) in data.chunks(CHUNK).enumerate() {
                self.file.write_all_at(chunk, (i * CHUNK) as u64).with_context(|| format!("write {} at byte {}", self.name, i * CHUNK))?;
            }
            self.file.sync_all().with_context(|| format!("sync {}", self.name))?;
            ensure!(hash_partition(&self.file, self.bytes)? == digest, "{} readback SHA-256 mismatch", self.name);
            println!("{} synced and read back", self.name);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_hash_and_boot_id_shapes() {
        assert_eq!(parse_sha256(&"a5".repeat(32)).unwrap(), [0xa5; 32]);
        assert!(parse_sha256(&"x5".repeat(32)).is_err());
        assert!(parse_sha256("a5").is_err());
        assert!(is_boot_id("00b52fa0-382f-4c55-babf-23d2ac2862bf"));
        assert!(!is_boot_id("00b52fa0_382f-4c55-babf-23d2ac2862bf"));
    }

    #[test]
    fn only_the_two_vbmeta_flags_are_editable() {
        let mut original = vec![0; 512];
        original[..4].copy_from_slice(b"AVB0");
        let mut candidate = original.clone();
        candidate[123] = 3;
        assert!(validate_vbmeta_edit(&original, &candidate).is_ok());
        assert!(validate_vbmeta_edit(&original, &original).is_err());
        candidate[500] = 1;
        assert!(validate_vbmeta_edit(&original, &candidate).is_err());
        candidate[500] = 0;
        original[123] = 4;
        assert!(validate_vbmeta_edit(&original, &candidate).is_err());
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn host_cannot_flash() {
        assert!(flash(&[]).is_err());
    }
}
