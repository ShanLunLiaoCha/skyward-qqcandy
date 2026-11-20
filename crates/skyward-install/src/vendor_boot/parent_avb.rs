//! Read-only inspection of a parent AVB hash descriptor. No signature, OEM
//! trust anchor, rollback state, slot acceptance or boot policy is verified.
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

const HEADER: usize = 256;
const MAX_PARENT: usize = 1024 * 1024;
const MAX_IMAGE: usize = 64 * 1024 * 1024;
const SHA256_RSA2048: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParentBinding {
    /// The candidate matches the descriptor in the supplied bytes; this
    /// does not establish trust in those bytes or authorize a flash.
    MatchesCandidate,
    /// The descriptor matches the stock bytes but not the candidate bytes.
    RejectsCandidate,
    /// No supported, unambiguous binding was established.
    Unproven,
}

fn word(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(bytes.get(at..at+4).context("short AVB field")?.try_into()?))
}
fn wide(bytes: &[u8], at: usize) -> Result<usize> {
    Ok(u64::from_be_bytes(bytes.get(at..at+8).context("short AVB field")?.try_into()?).try_into()?)
}
fn span(bytes: &[u8], at: usize, len: usize) -> Result<&[u8]> {
    let end = at.checked_add(len).context("AVB span overflow")?;
    bytes.get(at..end).context("AVB range outside its block")
}
fn ranges(header: &[u8], block: &[u8], fields: &[usize]) -> Result<()> {
    let mut used = Vec::new();
    for &field in fields {
        let (at, len) = (wide(header, field)?, wide(header, field+8)?);
        span(block, at, len)?;
        if len != 0 { used.push((at, at + len)); }
    }
    used.sort_unstable();
    ensure!(used.windows(2).all(|p| p[0].1 <= p[1].0), "overlapping AVB block ranges");
    Ok(())
}
fn payload(descriptor: &[u8], fixed: usize, name: usize, extra: usize) -> Result<&[u8]> {
    ensure!(name != 0 && name <= 128, "invalid AVB partition name length");
    let len = name.checked_add(extra).context("AVB descriptor length overflow")?;
    span(descriptor, fixed, len)?;
    let used = fixed + len;
    ensure!(descriptor.len() - used < 8 && descriptor[used..].iter().all(|&b| b == 0), "invalid AVB descriptor padding");
    let name = &descriptor[fixed..fixed+name];
    ensure!(name.iter().all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(b)), "invalid AVB partition name");
    Ok(name)
}
fn related(name: &[u8]) -> bool { matches!(name, b"vendor_boot" | b"vendor_boot_a" | b"vendor_boot_b") }

/// Compare only the direct, flags-zero SHA-256 `vendor_boot` descriptor in
/// top-level vbmeta with the prefix of each image that the descriptor names.
/// Unsupported modes (including disabled verification) never prove a binding.
/// A supported direct descriptor that cannot bind the provided stock is an
/// input error, not a claim about the candidate. Unrelated chains are not read.
pub fn assess(parent: &[u8], stock: &[u8], candidate: &[u8]) -> Result<ParentBinding> {
    ensure!((HEADER..=MAX_PARENT).contains(&parent.len()) && parent.starts_with(b"AVB0"), "invalid parent vbmeta magic or size");
    ensure!(stock.len() <= MAX_IMAGE && candidate.len() <= MAX_IMAGE, "vendor_boot input exceeds PGZ110 partition size");
    let h = &parent[..HEADER];
    let (auth_len, aux_len) = (wide(h, 12)?, wide(h, 20)?);
    ensure!(auth_len % 64 == 0 && aux_len % 64 == 0, "unaligned vbmeta blocks");
    let auth = span(parent, HEADER, auth_len)?;
    let aux = span(parent, HEADER+auth_len, aux_len)?;
    ensure!(parent[HEADER+auth_len+aux_len..].iter().all(|&b| b == 0), "nonzero data after parent vbmeta blocks");
    ranges(h, auth, &[32, 48])?; // digest and signature
    ranges(h, aux, &[64, 80, 96])?; // public key, key metadata, descriptors
    let mut unproven = word(h, 4)? != 1 || word(h, 8)? > 2 || word(h, 120)? != 0;
    if word(h, 28)? == SHA256_RSA2048 {
        ensure!(wide(h, 40)? == 32 && wide(h, 56)? == 256 && wide(h, 72)? == 520, "invalid SHA256_RSA2048 field sizes");
        ensure!(word(span(aux, wide(h, 64)?, 520)?, 0)? == 2048, "invalid RSA2048 key width");
    } else {
        unproven = true;
    }
    let len = wide(h, 104)?;
    let offset = wide(h, 96)?;
    ensure!(len % 8 == 0 && offset % 8 == 0, "unaligned AVB descriptor table");
    let mut table = span(aux, offset, len)?;
    let mut descriptor = None;
    let mut related_seen = false;
    while !table.is_empty() {
        let tag = wide(table, 0)?;
        let body_len = wide(table, 8)?;
        ensure!(body_len % 8 == 0, "unaligned AVB descriptor");
        let item = span(table, 0, 16usize.checked_add(body_len).context("AVB descriptor overflow")?)?;
        table = &table[item.len()..];
        let mark_related = |seen: &mut bool| -> Result<()> {
            ensure!(!*seen, "duplicate or ambiguous vendor_boot descriptors");
            *seen = true;
            Ok(())
        };
        match tag {
            2 => {
                const FIXED: usize = 132;
                let (n, s, d) = (word(item, 56)? as usize, word(item, 60)? as usize, word(item, 64)? as usize);
                let extra = s.checked_add(d).context("AVB hash descriptor length overflow")?;
                let name = payload(item, FIXED, n, extra)?;
                ensure!(item[72..FIXED].iter().all(|&b| b == 0), "invalid hash descriptor reserved fields");
                if !related(name) { continue; }
                mark_related(&mut related_seen)?;
                let sha256 = item[24..56].strip_prefix(b"sha256").is_some_and(|p| p.iter().all(|&b| b == 0));
                if name != b"vendor_boot" || !sha256 || word(item, 68)? != 0 || d == 0 || s > 64 {
                    unproven = true;
                    continue;
                }
                ensure!(d == 32, "invalid SHA-256 vendor_boot digest length");
                let size = wide(item, 16)?;
                ensure!(size != 0 && size <= MAX_IMAGE, "invalid vendor_boot hash image size");
                let at = FIXED + n;
                descriptor = Some((size, &item[at..at+s], &item[at+s..at+s+d]));
            }
            4 => {
                let name = payload(item, 92, word(item, 20)? as usize, word(item, 24)? as usize)?;
                if related(name) { mark_related(&mut related_seen)?; unproven = true; }
            }
            1 => {
                let extra = (word(item, 108)? as usize).checked_add(word(item, 112)? as usize).context("AVB hashtree descriptor length overflow")?;
                let name = payload(item, 180, word(item, 104)? as usize, extra)?;
                if related(name) { mark_related(&mut related_seen)?; unproven = true; }
            }
            0 | 3 => (), // Properties and kernel cmdlines are not bindings.
            _ => unproven = true,
        }
    }
    if unproven { return Ok(ParentBinding::Unproven); }
    let Some((size, salt, digest)) = descriptor else { return Ok(ParentBinding::Unproven) };
    let matches = |image: &[u8]| image.get(..size).is_some_and(|prefix| {
        Sha256::new().chain_update(salt).chain_update(prefix).finalize()[..] == *digest
    });
    ensure!(matches(stock), "parent vbmeta does not bind the supplied stock vendor_boot");
    Ok(if matches(candidate) { ParentBinding::MatchesCandidate } else { ParentBinding::RejectsCandidate })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put32(b: &mut [u8], at: usize, v: u32) { b[at..at+4].copy_from_slice(&v.to_be_bytes()); }
    fn put64(b: &mut [u8], at: usize, v: usize) { b[at..at+8].copy_from_slice(&(v as u64).to_be_bytes()); }
    fn hash(name: &[u8], stock: &[u8]) -> Vec<u8> {
        let salt = b"testing";
        let mut d = vec![0; (132+name.len()+salt.len()+32+7)&!7];
        let len = d.len();
        put64(&mut d, 0, 2); put64(&mut d, 8, len-16); put64(&mut d, 16, stock.len());
        d[24..30].copy_from_slice(b"sha256");
        put32(&mut d, 56, name.len() as u32); put32(&mut d, 60, salt.len() as u32); put32(&mut d, 64, 32);
        d[132..132+name.len()].copy_from_slice(name);
        let at = 132+name.len();
        d[at..at+salt.len()].copy_from_slice(salt);
        d[at+salt.len()..at+salt.len()+32].copy_from_slice(&Sha256::new().chain_update(salt).chain_update(stock).finalize());
        d
    }
    fn parent(descriptors: &[u8]) -> Vec<u8> {
        let aux = (520 + descriptors.len() + 63) & !63;
        let mut p = vec![0; HEADER + 320 + aux];
        p[..4].copy_from_slice(b"AVB0");
        put32(&mut p, 4, 1); put32(&mut p, 28, SHA256_RSA2048);
        put64(&mut p, 12, 320); put64(&mut p, 20, aux);
        put64(&mut p, 40, 32); put64(&mut p, 48, 32); put64(&mut p, 56, 256);
        put64(&mut p, 64, descriptors.len()); put64(&mut p, 72, 520); put64(&mut p, 104, descriptors.len());
        p[576..576+descriptors.len()].copy_from_slice(descriptors);
        put32(&mut p, 576+descriptors.len(), 2048);
        p
    }
    #[test]
    fn verifies_only_the_salted_stock_prefix() {
        let p = parent(&hash(b"vendor_boot", b"stock"));
        assert_eq!(assess(&p, b"stock A", b"stock B").unwrap(), ParentBinding::MatchesCandidate);
        assert_eq!(assess(&p, b"stock", b"rotck").unwrap(), ParentBinding::RejectsCandidate);
        assert_eq!(assess(&p, b"stock", b"s").unwrap(), ParentBinding::RejectsCandidate);
        assert!(assess(&p, b"other", b"stock").is_err());
    }
    #[test]
    fn absences_flags_and_nonstandard_names_do_not_prove_binding() {
        for name in [b"boot".as_slice(), b"vendor_boot_a"] {
            assert_eq!(assess(&parent(&hash(name, b"stock")), b"stock", b"stock").unwrap(), ParentBinding::Unproven);
        }
        let mut d = hash(b"vendor_boot", b"stock");
        put32(&mut d, 68, 1);
        assert_eq!(assess(&parent(&d), b"stock", b"stock").unwrap(), ParentBinding::Unproven);
        put32(&mut d, 68, 0);
        let mut p = parent(&d);
        for flags in [1,2,3,4] {
            put32(&mut p, 120, flags);
            assert_eq!(assess(&p, b"stock", b"stock").unwrap(), ParentBinding::Unproven);
        }
    }
    #[test]
    fn refuses_duplicates_bad_geometry_and_truncation() {
        let d = hash(b"vendor_boot", b"stock");
        assert!(assess(&parent(&[d.clone(), d.clone()].concat()), b"stock", b"stock").is_err());
        let mut p = parent(&d);
        assert!(assess(&p[..p.len()-1], b"stock", b"stock").is_err());
        put64(&mut p, 48, 16);
        assert!(assess(&p, b"stock", b"stock").is_err());
        let mut p = parent(&d);
        p[584..592].fill(255);
        assert!(assess(&p, b"stock", b"stock").is_err());
    }
    #[test]
    fn optional_real_pg211_binding() {
        let (Some(parent), Some(stock), Some(candidate)) = (std::env::var_os("SKYWARD_PARENT_AVB"), std::env::var_os("SKYWARD_PARENT_STOCK"), std::env::var_os("SKYWARD_PARENT_CANDIDATE")) else { return; };
        let (p,s,c) = (std::fs::read(parent).unwrap(), std::fs::read(stock).unwrap(), std::fs::read(candidate).unwrap());
        assert_eq!(assess(&p, &s, &s).unwrap(), ParentBinding::MatchesCandidate);
        assert_eq!(assess(&p, &s, &c).unwrap(), ParentBinding::RejectsCandidate);
    }
}
