//! Combine package metadata and target layout, without writing any device.
use crate::{package, payload_plan, super_plan};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};

pub struct Geometry {
    pub device_size: u64,
    pub data_start: u64,
    pub alignment: u64,
    pub alignment_offset: u64,
    pub logical_block: u64,
}

pub struct Preview {
    pub only_a: super_plan::Capacity,
    pub two_copies: super_plan::Capacity,
    pub group_limit: Option<u64>,
    pub partial: bool,
    pub snapshot_enabled: bool,
    pub physical_payload_names: Vec<String>,
}

pub(crate) fn metadata_hash(properties: &str) -> Result<[u8;32]> {
    const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut fields = properties.lines().filter_map(|line| line.trim().strip_prefix("METADATA_HASH="));
    let input = fields.next().context("payload property METADATA_HASH missing")?.as_bytes();
    ensure!(fields.next().is_none() && input.len() == 44 && input[43] == b'=', "invalid or duplicate METADATA_HASH");
    let mut output = Vec::with_capacity(32);
    let (mut bits, mut word) = (0, 0u32);
    for byte in &input[..43] {
        let symbol = BASE64.iter().position(|c| c == byte).context("invalid Base64 METADATA_HASH")?;
        word = (word << 6) | symbol as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((word >> bits) as u8);
            word &= (1 << bits) - 1;
        }
    }
    ensure!(word == 0, "noncanonical base64 METADATA_HASH");
    output.try_into().map_err(|_| anyhow::anyhow!("METADATA_HASH is not SHA-256"))
}

pub fn read_zip(file: &mut (impl Read + Seek)) -> Result<payload_plan::Plan> {
    Ok(read_zip_with_digest(file)?.0)
}

/// The digest identifies the exact manifest for a reviewed inventory; it is
/// not the ZIP signature or proof that its payload data has been read.
pub fn read_zip_with_digest(file: &mut (impl Read + Seek)) -> Result<(payload_plan::Plan, [u8; 32])> {
    file.seek(SeekFrom::Start(0))?;
    let package::Package::Update(update) = package::identify(&mut *file)? else { anyhow::bail!("expected a stored Android OTA payload ZIP"); };
    let digest = metadata_hash(&update.properties)?;
    let plan = payload_plan::read(file, update.payload_offset, update.payload_size, &digest)?;
    Ok((plan, digest))
}

/// Identify the PGZ110 partial Virtual A/B package class, independent of
/// release, ZIP length, operation representation or the reviewed roster.
/// This is routing, not whole-ZIP trust or authority to write.
#[cfg(any(target_os = "android", test))]
pub(crate) fn pgz_partial_vab<R: Read + Seek>(
    config: &skyward_config::DeviceConfig,
    update: &package::Update,
    open: impl FnOnce() -> Result<R>,
) -> Result<bool> {
    if config.device.codename != "OP5911"
        || config.device.recovery_partition != skyward_config::RecoveryPartition::VendorBoot {
        return Ok(false);
    }
    let digest = metadata_hash(&update.properties)?;
    payload_plan::is_partial_vab(&mut open()?, update.payload_offset, update.payload_size, &digest)
}

/// Preview only the logical partition roster declared by the target payload,
/// plus two explicitly requested partitions. Kept physical payload names are
/// reported separately; this is not proof that the complete target has no
/// other omitted partitions, or that replacements pass its AVB policy.
pub fn preview(p: &payload_plan::Plan, g: Geometry, company: u64, preload: u64) -> Result<Preview> {
    let dynamic = p.dynamic.as_ref().context("payload has no dynamic partition layout")?;
    let [group] = dynamic.groups.as_slice() else { anyhow::bail!("preflight currently requires one declared target dynamic group"); };
    let mut names: BTreeSet<_> = group.partitions.iter().cloned().collect();
    ensure!(names.len() == group.partitions.len(), "duplicate logical partition name");
    let mut ota = BTreeMap::new();
    let mut physical_payload_names = Vec::new();
    for part in &p.partitions {
        if names.contains(&part.name) {
            ensure!(ota.insert(part.name.clone(), part.size).is_none(), "duplicate logical payload partition");
        } else { physical_payload_names.push(part.name.clone()); }
    }
    let replacements = BTreeMap::from([("my_company".into(),company),("my_preload".into(),preload)]);
    names.extend(replacements.keys().cloned());
    let empty = BTreeMap::new();
    let budget = |slots| super_plan::plan(g.device_size, g.data_start, g.alignment, g.alignment_offset,
        g.logical_block, &names, slots, [&empty,&empty], &ota, &replacements);
    let only_a = budget([true,false])?;
    let two_copies = budget([true,true])?;
    Ok(Preview {only_a,two_copies,group_limit:group.maximum_size,partial:p.partial_update,
        snapshot_enabled:dynamic.snapshot_enabled,physical_payload_names})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_otas_are_not_routed_to_factory_restore() {
        let config = |device| skyward_config::DeviceConfig::parse(&format!(
            "[device]\ncodename='{device}'\nrecovery_partition='vendor_boot'\n")).unwrap();
        for (partial, snapshot, extra, digest, wanted) in [
            (1, 1, false, "oF91DEPnI6MJ1bYKHoJ3gGVrz9RpK+wcLhmBwId8a6Y=", true),
            (0, 1, false, "zNFqNLF7j7B5xqbmq//3G8+7bvbnwTHF89uKdaAbVDc=", false),
            (1, 0, false, "LOAuaM3waE6l1STP2utEXyPPViAcZh2MGS5+ItuDVX0=", false),
            (1, 1, true, "I70NODoA1lcbGz6mOJQ6haEAhU1swOi6TNwDQYhetDo=", true),
        ] {
            let mut manifest = vec![0x7a, 2, 0x10, snapshot, 0x80, 1, partial];
            if extra { manifest.extend([0x6a, 1, 0]); }
            let mut raw = b"CrAU".to_vec();
            raw.extend(2u64.to_be_bytes());
            raw.extend((manifest.len() as u64).to_be_bytes());
            raw.extend([0; 4]);
            raw.extend(manifest);
            let update = package::Update { payload_offset: 0, payload_size: raw.len() as u64,
                properties: format!("METADATA_HASH={digest}\n"), metadata: package::Metadata::default() };
            let not_open = || -> Result<std::io::Cursor<Vec<u8>>> { panic!("other model must not be reparsed") };
            assert!(!pgz_partial_vab(&config("other"), &update, not_open).unwrap());
            assert_eq!(pgz_partial_vab(&config("OP5911"), &update, || Ok(std::io::Cursor::new(raw))).unwrap(), wanted);
            assert!(pgz_partial_vab(&config("OP5911"), &update, || Ok(std::io::Cursor::new(vec![]))).is_err());
        }
    }

    #[test]
    fn exact_metadata_hash_or_refusal() {
        assert_eq!(metadata_hash("METADATA_HASH=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n").unwrap(),[0;32]);
        assert!(metadata_hash("METADATA_HASH=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=\n").is_err());
        assert!(metadata_hash("METADATA_HASH=bad\nMETADATA_HASH=bad\n").is_err());
    }
}
