//! Read-only capacity preflight. A feasibility result is not a flash plan or
//! authorization: contents, LP metadata and the AVB chains are separate checks.
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Origin { Payload, Replacement, Retained }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    pub name: String,
    pub bytes: u64,
    pub origin: Origin,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Capacity {
    pub slot: [Vec<Entry>; 2],
    pub device_size: u64,
    pub data_start: u64,
    pub partition_bytes: [u64; 2],
    pub aligned_end: u64,
}

impl Capacity {
    pub fn fits(&self) -> bool { self.aligned_end <= self.device_size }
}

fn valid_base(name: &str) -> bool {
    !name.is_empty() && name.len() <= 33 && !name.ends_with("_a") && !name.ends_with("_b")
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Compare the two logical slot images against one physical super device.
/// For each slot, omitted base partitions are kept in the budget, with their
/// actual expanded sizes. The caller must separately prove retained bytes are
/// the right baseline before treating them as usable images.
pub fn plan(
    device_size: u64, data_start: u64, alignment: u64, alignment_offset: u64, logical_block: u64,
    target_names: &BTreeSet<String>, materialize: [bool; 2], slot_base: [&BTreeMap<String, u64>; 2],
    ota: &BTreeMap<String, u64>, overrides: &BTreeMap<String, u64>,
) -> Result<Capacity> {
    ensure!(logical_block.is_power_of_two() && logical_block >= 512 && device_size % logical_block == 0,
        "invalid physical super geometry");
    ensure!(data_start != 0 && data_start < device_size && data_start % logical_block == 0,
        "invalid first logical byte of super");
    ensure!(alignment.is_power_of_two() && alignment >= logical_block && alignment_offset < alignment
        && alignment_offset % logical_block == 0, "invalid super alignment");
    ensure!(materialize.iter().any(|&used| used) && !target_names.is_empty(), "empty target super layout");
    ensure!(target_names.iter().all(|name| valid_base(name)), "invalid name in target super layout");
    for (name, size) in ota.iter().chain(overrides) {
        ensure!(target_names.contains(name) && *size != 0 && size % logical_block == 0,
            "partition {name} is absent from the target layout or has an invalid size");
    }
    let mut slot = [Vec::new(), Vec::new()];
    let mut partition_bytes = [0u64; 2];
    let mut cursor = data_start;
    for i in 0..2 {
        if !materialize[i] { continue; }
        for name in target_names {
            let (bytes, origin) = if let Some(&n) = overrides.get(name) { (n, Origin::Replacement) }
                else if let Some(&n) = ota.get(name) { (n, Origin::Payload) }
                else { (*slot_base[i].get(name).with_context(|| format!("slot {} is missing required target partition {name}", i))?, Origin::Retained) };
            ensure!(bytes != 0 && bytes % logical_block == 0, "empty or unaligned target LP partition {name}");
            let rem = cursor.checked_add(alignment_offset).context("super alignment overflow")? % alignment;
            cursor = cursor.checked_add((alignment - rem) % alignment).and_then(|p| p.checked_add(bytes))
                .context("super offset overflow")?;
            partition_bytes[i] = partition_bytes[i].checked_add(bytes).context("super slot size overflow")?;
            slot[i].push(Entry {name: name.clone(), bytes, origin});
        }
    }
    Ok(Capacity { slot, device_size, data_start, partition_bytes, aligned_end: cursor })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sizes(inputs: &[(&str,u64)]) -> BTreeMap<String,u64> {
        inputs.iter().map(|&(name,n)| (name.to_owned(), n*4096)).collect()
    }
    #[test]
    fn old_target_never_inherits_vendor_dlkm_and_detects_dual_slot_overflow() {
        let a = sizes(&[("system", 8), ("my_company", 3), ("my_preload", 2), ("vendor_dlkm", 1)]);
        let b = sizes(&[]);
        let ota = sizes(&[("system", 10)]);
        let overrides = sizes(&[("my_company", 2), ("my_preload", 1)]);
        let names = ota.keys().chain(overrides.keys()).cloned().collect();
        let p = plan(25*4096, 4096, 4096, 0, 4096, &names, [true,true], [&a,&b], &ota,&overrides).unwrap();
        assert_eq!(p.partition_bytes,[13*4096,13*4096]);
        assert_eq!(p.aligned_end,27*4096);
        assert!(!p.fits());
        assert!(!p.slot[0].iter().any(|e| e.name=="vendor_dlkm"));
        let p = plan(25*4096, 4096, 4096, 0, 4096, &names, [true,false], [&a,&b], &ota,&overrides).unwrap();
        assert_eq!(p.partition_bytes,[13*4096,0]);
        assert!(p.fits());
    }
    #[test]
    fn counts_alignment_and_rejects_unproven_replacement_destinations() {
        let empty = sizes(&[]);
        let ota = sizes(&[("system", 1)]);
        let names: BTreeSet<_> = ota.keys().cloned().collect();
        let p = plan(8*4096, 4096, 8192, 0, 4096, &names, [true,true], [&empty,&empty], &ota,&empty).unwrap();
        assert_eq!(p.aligned_end, 5*4096);
        assert!(p.fits());
        assert!(plan(8*4096, 4096, 8192, 0, 4096, &names, [true,true], [&empty,&empty], &ota,&sizes(&[("my_company",1)])).is_err());
        assert!(plan(8*4096, 4096, 8192, 0, 4096, &names, [true,true], [&empty,&empty], &sizes(&[("system_a",1)]),&empty).is_err());
        let names = ["system".into(), "my_preload".into()].into_iter().collect();
        assert!(plan(8*4096, 4096, 8192, 0, 4096, &names, [true,false], [&empty,&empty], &ota,&empty).is_err());
    }
}
