//! Pre-write checks for preparing a PGZ110 recovery for a concrete slot.
//! This module never opens block devices itself, writes, changes AVB, or activates
//! a slot. A payload metadata hash is not an OEM signature and neither is an
//! on-disk parent descriptor match a complete AVB trust-chain check.
use crate::{payload_plan, vendor_boot};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use skyward_vab::Slot;
use std::io::{Read, Seek};

const SPECS: [(&str, u64); 4] = [("boot", 128 << 20), ("dtbo", 32 << 20), ("vendor_boot", 64 << 20), ("vbmeta", 1 << 20)];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Target {
    name: &'static str,
    bytes: u64,
    sha256: [u8; 32],
}

#[derive(Debug)]
pub struct SlotTarget {
    slot: Slot,
    targets: [Target; SPECS.len()],
}

impl SlotTarget {
    /// Capture payload-declared targets *before* an installation, separately
    /// for each slot actually written by that package. Omission is a failure,
    /// not permission to borrow the corresponding image from the other slot.
    pub fn from_payload(plan: &payload_plan::Plan, slot: Slot) -> Result<Self> {
        let mut targets = Vec::new();
        for (name, bound) in SPECS {
            let mut matches = plan.partitions.iter().filter(|p| p.name == name);
            let p = matches.next().with_context(|| format!("payload has no target declaration for {name}"))?;
            ensure!(matches.next().is_none(), "multiple declarations for {name}");
            ensure!(p.size > 0 && p.size <= bound && (name != "vendor_boot" || p.size == bound), "invalid target size for {name}");
            targets.push(Target {name, bytes:p.size, sha256:p.sha256});
        }
        let targets = targets.try_into().map_err(|_| anyhow::anyhow!("incomplete boot-chain targets"))?;
        Ok(Self {slot, targets})
    }

    /// Reconstruct the four matching boot-chain images from one payload;
    /// operation blobs and final hashes are checked during reconstruction.
    /// Only vendor_boot and its parent survive in memory after each check.
    pub fn stage_from_payload<R: Read + Seek>(&self, source: &mut R, plan: &payload_plan::Plan) -> Result<PreparedBase> {
        let mut vendor_boot = Vec::new();
        let mut parent = Vec::new();
        for ((name, bound), target) in SPECS.into_iter().zip(self.targets) {
            let mut partitions = plan.partitions.iter().filter(|p| p.name == name);
            let p = partitions.next().context("staging target disappeared")?;
            ensure!(partitions.next().is_none() && p.size == target.bytes && p.sha256 == target.sha256,
                "staging plan changed for {name}{}", self.slot.suffix());
            let image = crate::payload_stage::reconstruct(source, p, bound)
                .with_context(|| format!("stage {name}{}", self.slot.suffix()))?;
            match name {
                "vendor_boot" => vendor_boot = image,
                "vbmeta" => parent = image,
                _ => (),
            }
        }
        Ok(PreparedBase {slot:self.slot, vendor_boot, parent})
    }

    /// `open` supplies staged stock image data for the specified slot;
    /// the hash domain is exactly the payload's target image size (not padding).
    /// Verify all staged partners before repacking. No post-flash read-back.
    pub fn validate_sources<R: Read>(&self, mut open: impl FnMut(Slot, &str) -> Result<(R, u64)>) -> Result<PreparedBase> {
        let mut vendor_boot = Vec::new();
        let mut parent = Vec::new();
        for item in self.targets {
            let (mut file, capacity) = open(self.slot, item.name).with_context(|| format!("open slot {} {}", self.slot.suffix(), item.name))?;
            ensure!(capacity >= item.bytes && (item.name != "vendor_boot" || capacity == item.bytes), "capacity disagrees with target for {}{}", item.name, self.slot.suffix());
            let mut hash = Sha256::new();
            let mut bytes_left = item.bytes;
            let mut buffer = vec![0u8; 256 << 10];
            while bytes_left != 0 {
                let take = buffer.len().min(bytes_left as usize);
                let data = &mut buffer[..take];
                file.read_exact(data).with_context(|| format!("read staged {}{}", item.name, self.slot.suffix()))?;
                hash.update(&*data);
                match item.name {
                    "vendor_boot" => vendor_boot.extend_from_slice(data),
                    "vbmeta" => parent.extend_from_slice(data),
                    _ => (),
                }
                bytes_left -= take as u64;
            }
            let actual: [u8; 32] = hash.finalize().into();
            ensure!(actual == item.sha256, "staged source hash differs from target for {}{}", item.name, self.slot.suffix());
        }
        Ok(PreparedBase {slot:self.slot, vendor_boot, parent})
    }
}

pub struct PreparedBase {
    slot: Slot,
    vendor_boot: Vec<u8>,
    parent: Vec<u8>,
}

/// A deliberately unsigned-as-modified development pair, never a flash authorization.
pub struct OfflineAvbPair {
    pub vendor_boot: Vec<u8>,
    pub vbmeta: Vec<u8>,
}

impl PreparedBase {
    /// Explicit opt-in for staged A-slot files. The caller authenticates the OTA.
    /// Changing the top-level flags invalidates its original signature.
    pub fn prepare_a_avb_off(&self, program: &[u8], assets: &[(&str, &[u8])]) -> Result<OfflineAvbPair> {
        use vendor_boot::parent_avb::{assess, ParentBinding};
        ensure!(self.slot == Slot::A, "single-A recovery candidate requires A-slot sources");
        let vendor_boot = vendor_boot::repack(&self.vendor_boot, program, assets)?;
        ensure!(assess(&self.parent, &self.vendor_boot, &vendor_boot)? == ParentBinding::RejectsCandidate,
            "expected a supported, enabled stock parent binding that rejects the repacked image");
        let mut vbmeta = self.parent.clone();
        let flags = vbmeta.get_mut(120..124).context("missing top-level AVB flags")?;
        ensure!(flags == [0; 4], "expected flags zero in original top-level vbmeta");
        // AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED | VERIFICATION_DISABLED.
        flags.copy_from_slice(&3u32.to_be_bytes());
        Ok(OfflineAvbPair {vendor_boot, vbmeta})
    }

    pub fn slot(&self) -> Slot { self.slot }

    /// Repack its exact target stock image (not the running slot) and
    /// check the parent descriptor. The caller cannot interpret this as an
    /// automatic flash authorization: the OEM chain is not authenticated here.
    pub fn audit_repack(&self, program: &[u8], assets: &[(&str, &[u8])]) -> Result<vendor_boot::parent_avb::ParentBinding> {
        let local = vendor_boot::repack(&self.vendor_boot, program, assets)?;
        vendor_boot::parent_avb::assess(&self.parent, &self.vendor_boot, &local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Seek, SeekFrom};

    const PUBLIC_211_DIGEST: [u8;32] = [0xd3, 0x02, 0x07, 0xea, 0x42, 0x53, 0x44, 0xab, 0x79, 0xa8, 0xea, 0x19, 0xec, 0xc7, 0xff, 0xf4,
                         0xe7, 0x6e, 0x64, 0x61, 0x36, 0x04, 0x96, 0x44, 0xa0, 0xc9, 0x50, 0x11, 0xd1, 0xd9, 0xc5, 0x03];
    const PUBLIC_211_PAYLOAD_BYTES: u64 = 7_084_991_019;

    #[test]
    fn public_211_native_staging_reconstructs_and_checks_boot_chain() {
        let (Some(path), Some(dir)) = (std::env::var_os("SKYWARD_OTA211_NATIVE_PAYLOAD"), std::env::var_os("SKYWARD_OTA211_STAGED")) else { return };
        let dir = std::path::PathBuf::from(dir);
        let mut input = std::fs::File::open(path).unwrap();
        let payload = payload_plan::read(&mut input, 0, PUBLIC_211_PAYLOAD_BYTES, &PUBLIC_211_DIGEST).unwrap();
        let mut prepared = SlotTarget::from_payload(&payload, Slot::A).unwrap().stage_from_payload(&mut input, &payload).unwrap();
        assert_eq!(prepared.slot(), Slot::A);
        assert_eq!(prepared.vendor_boot, std::fs::read(dir.join("vendor_boot.img")).unwrap());
        assert_eq!(prepared.parent, std::fs::read(dir.join("vbmeta.img")).unwrap());
        if let (Some(donor), Some(mtp)) = (std::env::var_os("SKYWARD_TEST_REPACK_DONOR"), std::env::var_os("SKYWARD_TEST_REPACK_MTP")) {
            use vendor_boot::parent_avb::ParentBinding;
            let donor = std::path::PathBuf::from(donor);
            let program = std::fs::read(donor.join("system/bin/recovery")).unwrap();
            let mut owned = Vec::new();
            for path in ["skyward/device.toml", "skyward/MiSansVF.ttf", "skyward/KirkMono-Regular.ttf", "skyward/KirkMono-OFL.txt"] {
                owned.push((path, std::fs::read(donor.join(path)).unwrap()));
            }
            owned.push(("system/etc/init/skyward-mtp.rc", std::fs::read(mtp).unwrap()));
            let assets: Vec<_> = owned.iter().map(|(name, data)| (*name, data.as_slice())).collect();
            let pair = prepared.prepare_a_avb_off(&program, &assets).unwrap();
            assert_eq!(vendor_boot::parent_avb::assess(&prepared.parent, &prepared.vendor_boot, &pair.vendor_boot).unwrap(), ParentBinding::RejectsCandidate);
            assert_eq!(pair.vbmeta, std::fs::read(dir.join("PGZ110-211-vbmeta-AVB-OFF-UNTESTED.img")).unwrap());
            assert_eq!(pair.vendor_boot.len(), 64 << 20);
            let mut wrong_slot = prepared;
            wrong_slot.slot = Slot::B;
            assert!(wrong_slot.prepare_a_avb_off(&program, &assets).is_err());
            wrong_slot.slot = Slot::A;
            prepared = wrong_slot;
        }
        if let Some(candidate) = std::env::var_os("SKYWARD_PARENT_CANDIDATE") {
            use vendor_boot::parent_avb::ParentBinding;
            assert_eq!(vendor_boot::parent_avb::assess(&prepared.parent, &prepared.vendor_boot,
                &std::fs::read(candidate).unwrap()).unwrap(), ParentBinding::RejectsCandidate);
        }
    }

    #[test]
    fn public_211_staged_boot_chain_matches_payload() {
        let Some(dir) = std::env::var_os("SKYWARD_OTA211_STAGED") else { return };
        let dir = std::path::PathBuf::from(dir);
        struct Head(Cursor<Vec<u8>>);
        impl Read for Head {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> { self.0.read(buf) }
        }
        impl Seek for Head {
            fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
                match from { SeekFrom::End(0) => Ok(7_084_991_019), from => self.0.seek(from) }
            }
        }
        let mut header = Head(Cursor::new(std::fs::read(dir.join("payload-header.bin")).unwrap()));
        let expected = [0xd3, 0x02, 0x07, 0xea, 0x42, 0x53, 0x44, 0xab, 0x79, 0xa8, 0xea, 0x19, 0xec, 0xc7, 0xff, 0xf4,
                         0xe7, 0x6e, 0x64, 0x61, 0x36, 0x04, 0x96, 0x44, 0xa0, 0xc9, 0x50, 0x11, 0xd1, 0xd9, 0xc5, 0x03];
        let payload = payload_plan::read(&mut header, 0, 7_084_991_019, &expected).unwrap();
        let target = SlotTarget::from_payload(&payload, Slot::B).unwrap();
        let prepared = target.validate_sources(|slot, name| {
            assert_eq!(slot, Slot::B);
            let file = std::fs::File::open(dir.join(format!("{name}.img")))?;
            let bytes = file.metadata()?.len();
            Ok((file, bytes))
        }).unwrap();
        assert_eq!(prepared.slot(), Slot::B);
        assert_eq!(prepared.vendor_boot.len(), 64 << 20);
    }

    #[test]
    fn absence_and_duplicate_targets_are_rejected_before_install() {
        let mut plan = payload_plan::Plan { block_size: 4096, minor_version: 7, partial_update: true, dynamic: None, partitions: Vec::new() };
        assert!(SlotTarget::from_payload(&plan, Slot::A).is_err());
        for (name, _) in SPECS {
            plan.partitions.push(payload_plan::Partition { name: name.into(), size: if name == "vendor_boot" {64 << 20} else {4096}, sha256: [0;32], operations:Vec::new() });
        }
        assert!(SlotTarget::from_payload(&plan, Slot::A).is_ok());
        plan.partitions.push(payload_plan::Partition { name:"vbmeta".into(), size:4096, sha256:[0;32], operations:Vec::new() });
        assert!(SlotTarget::from_payload(&plan, Slot::B).is_err());
    }

    #[test]
    fn checks_requested_slot_prefix_and_rejects_inconsistent_staged_input() {
        let make = |slot| SlotTarget { slot, targets:SPECS.map(|(name,_)| Target { name, bytes:3, sha256:Sha256::digest(b"abc").into() }) };
        let b = make(Slot::B);
        let after = b.validate_sources(|slot, name| {
            assert_eq!(slot, Slot::B);
            Ok((Cursor::new(b"abc!"), if name == "vendor_boot" {3} else {4}))
        }).unwrap();
        assert_eq!(after.slot(), Slot::B);
        assert_eq!(after.vendor_boot, b"abc");
        assert!(make(Slot::A).validate_sources(|_, name| Ok((Cursor::new(if name == "dtbo" {b"bad"} else {b"abc"}),3))).is_err());
        assert!(make(Slot::A).validate_sources(|_, _| Ok((Cursor::new(b"ab"),3))).is_err());
        assert!(make(Slot::A).validate_sources(|_, _| Ok((Cursor::new(b"abc"),4))).is_err());
    }
}
