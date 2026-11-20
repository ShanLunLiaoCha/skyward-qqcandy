//! Pure classification of the one observed PGZ110 .211 failed-OTA residue.
//! A match is not write authorization. Callers must verify the device,
//! guarantee the observations are complete and contemporaneous, and retain
//! appropriate locks while revalidating evidence before any separate action.
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use skyward_vab::{MergeStatus, Slot};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Presence {
    /// Absence established across all relevant sources, not just one query.
    Absent,
    Present,
    /// Includes inaccessible, incomplete or ambiguous results.
    Unknown,
}

pub(crate) struct Evidence<'a> {
    /// Exact contents of the *present* regular global state file. Do not
    /// supply an empty slice for a missing, unverified or unreadable file.
    pub(crate) state: &'a [u8],
    pub(crate) current_slot: Option<Slot>,
    pub(crate) next_slot: Option<Slot>,
    pub(crate) merge_status: Option<MergeStatus>,
    /// Actual B/COW allocation or residency: validated LP copies, backing
    /// storage and mappings must all be covered. Requested sizes in the
    /// captured protobufs do not themselves establish allocated space.
    pub(crate) b_or_cow_residency: Presence,
    /// All relevant live DM/snapshot evidence; failed enumeration is unknown.
    pub(crate) live_snapshots: Presence,
    /// Full LP metadata region (geometry and six table copies), not an
    /// arbitrary super prefix, a digest supplied by the caller or a summary.
    pub(crate) lp_prefix: &'a [u8],
    /// All entries from the active snapshot directory, not a filtered subset.
    /// Caller must already have rejected symlinks and non-regular files.
    pub(crate) records: &'a BTreeMap<String, Vec<u8>>,
}

const LP_PREFIX_BYTES: usize = 405_504;
// SHA-256 of the exact complete LP region in the before/after comparison.
const LP_PREFIX_SHA256: &str = "993d6c6a63ce48e60d46b9845a8d6bc7316b04153b30340f3e3704874a660c90";

// Independently decoded from the raw hexdump in the device capture, and
// cross-checked against decoded-snapshot-status.json. Match exact bytes,
// not merely parsed protobuf names/state (which would allow unknown fields,
// alternate values, duplicate fields or a different OTA with this roster).
const RECORDS: [(&str, usize, &str); 15] = [
    ("my_bigball_b", 46, "854abc382d9a9b634265bc7b78dfe1003fbc8b74da99ebc950620348557701d6"),
    ("my_carrier_b", 38, "03feaca0fde8092e9b2358e937540b1108197bb0dba8b12e4694812cd45b5aed"),
    ("my_engineering_b", 42, "b3933ff073ad4a2fc4887bfef69f0aa0ff960eeabdb0d3435247fc717dd85d0e"),
    ("my_heytap_b", 45, "95d4c5000287c032f7437511199ac9427e5a8da0cf55dcf3ffde90a931ba6e04"),
    ("my_manifest_b", 39, "69c5092d9ec86d377b4eb6ec701ba67521ff234272535fb9c367b20bfbe844ed"),
    ("my_product_b", 46, "d6065798cc16b251f39be2672113525167746d8471a96b2aa8109e9b2725a6e6"),
    ("my_region_b", 41, "0654d38f039709984ec581c0c07bb1087e2e2b405cca9f0477db21b7561e5bab"),
    ("my_stock_b", 50, "f1ee7d07b6f574497aa66e2a2888a34bf24950d2351d45d3789ba62a32027c20"),
    ("odm_b", 39, "ae16cd990f9f3ef13fe6c12db2950e2d6b92e08beb0272cd13c3e2e7278f693f"),
    ("odm_dlkm_b", 36, "9ab5205f930f5b35d1c16f6867c6fcd750d6701f3a327ab05e36d31ee1328bf1"),
    ("product_b", 36, "006c45124f6417aff175fdb62bf3eab483919926551ce1231f863ab9a921d3c4"),
    ("system_b", 42, "db8f1661ec94225ffcdb55578366dd745c17f0033a388b29335ba5d59ecbfa7a"),
    ("system_ext_b", 46, "31ed6a9679a94beba54b7fd5752f53fd6db70445f5e38dd5cf41d06680a20142"),
    ("vendor_b", 42, "7f2919b3ec36fd7d4f983fbc24e5bd8a6a00b18ac7c3d592084d5a97118dd747"),
    ("vendor_dlkm_b", 43, "d2a7d218359090608975f0240f855f08e4729ca88877825a694ccd858c0a7a16"),
];

pub(crate) fn classify(e: &Evidence<'_>) -> Result<()> {
    check_snapshot_evidence(e)?;
    check_prefix(e.lp_prefix)
}

fn check_prefix(prefix: &[u8]) -> Result<()> {
    ensure!(prefix.len() == LP_PREFIX_BYTES && sha_matches(prefix, LP_PREFIX_SHA256),
        "LP metadata differs from the exact PGZ110 .211 failure capture");
    Ok(())
}

/// Identify this exact incident before leaving the normal UI. This is *not*
/// the maintenance proof and does not establish that any write is safe.
pub(crate) fn matches_handoff_candidate(prefix: &[u8], state: &[u8], records: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    check_prefix(prefix)?;
    ensure!(state.is_empty(), "global OTA state is not exactly empty");
    check_record_roster(records)
}

fn check_snapshot_evidence(e: &Evidence<'_>) -> Result<()> {
    ensure!(e.state.is_empty(), "global OTA state is not exactly empty");
    ensure!(e.current_slot == Some(Slot::A) && e.next_slot == Some(Slot::A),
        "current and next boot slots must both be known A");
    ensure!(e.merge_status == Some(MergeStatus::None), "OEM merge state is not known None");
    ensure!(e.b_or_cow_residency == Presence::Absent, "B-slot or COW residency is present or unknown");
    ensure!(e.live_snapshots == Presence::Absent, "live snapshot evidence is present or unknown");
    check_record_roster(e.records)
}

fn check_record_roster(records: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    ensure!(records.len() == RECORDS.len(), "snapshot count differs from the observed 15-record set");
    for (name, len, sha256) in RECORDS {
        let bytes = records.get(name).with_context(|| format!("missing exact snapshot record {name}"))?;
        ensure!(bytes.len() == len && sha_matches(bytes, sha256),
            "snapshot record {name} differs from the observed bytes");
    }
    Ok(())
}

fn sha_matches(bytes: &[u8], hex: &str) -> bool {
    format!("{:x}", Sha256::digest(bytes)) == hex
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exact raw payloads, independently useful for exercising the hash roster
    // and for detecting a typo without any external device or fixture path.
    fn captured_records() -> BTreeMap<String, Vec<u8>> {
        let bodies = [
            "0a0c6d795f62696762616c6c5f621001188080dfa903208080dfa9032880a0b4ab035080a083d9025a046e6f6e65",
            "0a0c6d795f636172726965725f6210011880c0142080c014288080155080c0145a046e6f6e65",
            "0a106d795f656e67696e656572696e675f6210011880c0142080c014288080155080c0145a046e6f6e65",
            "0a0b6d795f6865797461705f6210011880e0c592052080e0c592052880c08f9505508080f0ed035a046e6f6e65",
            "0a0d6d795f6d616e69666573745f6210011880801d2080801d2880c01d5080a01a5a046e6f6e65",
            "0a0c6d795f70726f647563745f6210011880c08881022080c08881022880c08982025080a0f49b015a046e6f6e65",
            "0a0b6d795f726567696f6e5f6210011880a0e2012080a0e2012880c0e3015080a0a6015a046e6f6e65",
            "0a0a6d795f73746f636b5f6210011880e0d7b3082080e0d7b30828808080b405308080f283035080a0d69f065a046e6f6e65",
            "0a056f646d5f621001188080fad004208080fad0043080e0a2d304508080dda9045a046e6f6e65",
            "0a0a6f646d5f646c6b6d5f6210011880a0152080a0153080e0155080a0155a046e6f6e65",
            "0a0970726f647563745f6210011880c06a2080c06a3080a06b5080e096015a046e6f6e65",
            "0a0873797374656d5f6210011880a08481032080a08481033080a0c58203508080fced025a046e6f6e65",
            "0a0c73797374656d5f6578745f6210011880e0f2ed032080e0f2ed03308080eaef035080e080c1035a046e6f6e65",
            "0a0876656e646f725f621001188080b3aa04208080b3aa043080c0c8ac045080a09f9f045a046e6f6e65",
            "0a0d76656e646f725f646c6b6d5f62100118808099192080809919308080a6195080a0f11b5a046e6f6e65",
        ];
        RECORDS.into_iter().zip(bodies).map(|((name, _, _), hex)| {
            let bytes = (0..hex.len()).step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
            (name.to_owned(), bytes)
        }).collect()
    }

    fn evidence(records: &BTreeMap<String, Vec<u8>>) -> Evidence<'_> {
        Evidence { state: &[], current_slot: Some(Slot::A), next_slot: Some(Slot::A),
            merge_status: Some(MergeStatus::None), b_or_cow_residency: Presence::Absent,
            live_snapshots: Presence::Absent, lp_prefix: &[], records }
    }

    #[test]
    fn rejects_changes_to_captured_wire_bytes_and_names() {
        let records = captured_records();
        check_snapshot_evidence(&evidence(&records)).unwrap();
        let mut changed = records.clone();
        changed.get_mut("vendor_b").unwrap()[30] ^= 1;
        assert!(check_snapshot_evidence(&evidence(&changed)).is_err());
        let wrong_name = changed.remove("vendor_b").unwrap();
        changed.insert("vendor_a".into(), wrong_name);
        assert!(check_snapshot_evidence(&evidence(&changed)).is_err());
        changed.insert("vendor_b".into(), records["vendor_b"].clone());
        assert!(check_snapshot_evidence(&evidence(&changed)).is_err());
        changed = records.clone();
        changed.get_mut("vendor_b").unwrap().extend_from_slice(&[0x78, 0]);
        assert!(check_snapshot_evidence(&evidence(&changed)).is_err());
        changed.remove("vendor_b");
        assert!(check_snapshot_evidence(&evidence(&changed)).is_err());
    }

    #[test]
    fn refuses_unknown_or_non_idle_observations() {
        let records = captured_records();
        let ok = || evidence(&records);
        for state in [b"\0".as_slice(), b"none", b"merging"] {
            assert!(check_snapshot_evidence(&Evidence { state, ..ok() }).is_err());
        }
        for slot in [None, Some(Slot::B)] {
            assert!(check_snapshot_evidence(&Evidence { current_slot: slot, ..ok() }).is_err());
            assert!(check_snapshot_evidence(&Evidence { next_slot: slot, ..ok() }).is_err());
        }
        for merge_status in [None, Some(MergeStatus::Unknown), Some(MergeStatus::Snapshotted),
            Some(MergeStatus::Merging), Some(MergeStatus::Cancelled)] {
            assert!(check_snapshot_evidence(&Evidence { merge_status, ..ok() }).is_err());
        }
        for status in [Presence::Present, Presence::Unknown] {
            assert!(check_snapshot_evidence(&Evidence { b_or_cow_residency: status, ..ok() }).is_err());
            assert!(check_snapshot_evidence(&Evidence { live_snapshots: status, ..ok() }).is_err());
        }
    }

    #[test]
    fn captured_failure_replays_as_archive_and_lp_patch_on_host() {
        use crate::{lp_orphan_archive as archive, lp_orphan_evidence::read_ota_records};
        let Some(path) = std::env::var_os("SKYWARD_ORPHAN_LP_CAPTURE") else { return; };
        let capture = std::fs::read(path).unwrap();
        let prefix = &capture[..LP_PREFIX_BYTES];
        let actual = 12_348_030_976;
        let repair = skyward_lp::capacity::repair(prefix, actual).unwrap();
        assert_eq!(repair.len(), 6);
        let sandbox = tempfile::tempdir().unwrap();
        let ota = sandbox.path().join("ota");
        let snapshots = ota.join("snapshots");
        std::fs::create_dir_all(&snapshots).unwrap();
        std::fs::write(ota.join("state"), []).unwrap();
        let records = captured_records();
        for (name, bytes) in &records { std::fs::write(snapshots.join(name), bytes).unwrap(); }
        archive::begin(sandbox.path()).unwrap();
        let dest = archive::quarantine(sandbox.path(), prefix, || {
            let observed = read_ota_records(sandbox.path())?;
            classify(&Evidence { state: &observed.state, lp_prefix: prefix, ..evidence(&observed.records) })
        }).unwrap();
        let mut virtual_super = prefix.to_vec();
        for (offset, bytes) in repair {
            let offset = offset as usize;
            virtual_super[offset..offset + bytes.len()].copy_from_slice(&bytes);
        }
        assert!(skyward_lp::capacity::repair(&virtual_super, actual).unwrap().is_empty());
        assert!(std::fs::read_dir(&snapshots).unwrap().next().is_none());
        assert_eq!(std::fs::read(dest.join("super-lp-original.bin")).unwrap(), prefix);
        for (name, bytes) in records { assert_eq!(std::fs::read(dest.join("snapshots").join(name)).unwrap(), bytes); }
        assert!(archive::check_idle(sandbox.path()).is_err());
    }

    #[test]
    fn rejects_unknown_or_changed_lp_prefix() {
        let records = captured_records();
        assert!(classify(&evidence(&records)).is_err());
        let mut prefix = vec![0; LP_PREFIX_BYTES];
        assert!(classify(&Evidence { lp_prefix: &prefix, ..evidence(&records) }).is_err());
        if let Some(path) = std::env::var_os("SKYWARD_ORPHAN_LP_CAPTURE") {
            let capture = std::fs::read(path).unwrap();
            prefix.copy_from_slice(&capture[..LP_PREFIX_BYTES]);
            classify(&Evidence { lp_prefix: &prefix, ..evidence(&records) }).unwrap();
            matches_handoff_candidate(&prefix, &[], &records).unwrap();
            assert!(matches_handoff_candidate(&prefix, b"none", &records).is_err());
            let mut changed_records = records.clone();
            changed_records.remove("vendor_b");
            assert!(matches_handoff_candidate(&prefix, &[], &changed_records).is_err());
            prefix[LP_PREFIX_BYTES - 1] ^= 1;
            assert!(matches_handoff_candidate(&prefix, &[], &records).is_err());
            assert!(classify(&Evidence { lp_prefix: &prefix, ..evidence(&records) }).is_err());
            assert!(classify(&Evidence { lp_prefix: &capture[..LP_PREFIX_BYTES + 1], ..evidence(&records) }).is_err());
        }
    }
}
