//! Verify the audited stock hash footer and build a new unsigned footer.
//! Integrity is not AVB authorization: a parent vbmeta may pin or sign hashes.
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

const FOOTER: usize = 64;
const HEADER: usize = 256;
const HASH_FIXED: usize = 132;
const NAME: &[u8] = b"vendor_boot";
const FINGERPRINT: &[u8] = b"com.android.build.vendor_boot.fingerprint";

fn big32(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(b.get(at..at+4).context("short AVB field")?.try_into()?))
}
fn big64(b: &[u8], at: usize) -> Result<usize> {
    Ok(u64::from_be_bytes(b.get(at..at+8).context("short AVB field")?.try_into()?).try_into()?)
}
fn wr32(b: &mut [u8], at: usize, n: u32) { b[at..at+4].copy_from_slice(&n.to_be_bytes()); }
fn wr64(b: &mut [u8], at: usize, n: usize) { b[at..at+8].copy_from_slice(&(n as u64).to_be_bytes()); }
fn round(n: usize, by: usize) -> usize { (n + by - 1) & !(by - 1) }

pub(super) fn verify(image: &[u8], payload: usize, stock: bool) -> Result<()> {
    let f = image.len().checked_sub(FOOTER).context("missing AVB footer")?;
    let footer = &image[f..];
    ensure!(&footer[..4] == b"AVBf" && big32(footer, 4)? == 1 && big32(footer, 8)? == 0
        && footer[36..].iter().all(|&v| v == 0), "invalid AVB footer");
    ensure!(big64(footer, 12)? == payload && big64(footer, 20)? == payload, "unexpected AVB payload offset");
    let size = big64(footer, 28)?;
    ensure!((HEADER..=4096).contains(&size) && payload.checked_add(size).is_some_and(|end| end <= f), "invalid AVB vbmeta geometry");
    ensure!(image[payload+size..f].iter().all(|&v| v == 0), "unexpected trailing vendor_boot data");
    let v = &image[payload..payload+size];
    ensure!(&v[..4] == b"AVB0" && big32(v, 4)? == 1 && big32(v, 8)? == 0 && big64(v, 12)? == 0 && big32(v, 28)? == 0, "unrecognized vendor_boot vbmeta algorithm or version");
    ensure!(v[32..64].iter().all(|&n| n == 0) && v[112..128].iter().all(|&n| n == 0), "unexpected vbmeta authentication or rollback properties");
    let auxiliary = big64(v, 20)?;
    ensure!(auxiliary == size - HEADER && auxiliary % 64 == 0 && big64(v, 96)? == 0, "invalid vbmeta auxiliary block");
    let desc_len = big64(v, 104)?;
    ensure!(desc_len <= auxiliary && desc_len % 8 == 0, "invalid AVB descriptor bounds");
    // avbtool places zero-length stock key fields at the end of the descriptor
    // array. Accept only that audited offset or the canonical zero, never data.
    for (offset, size) in [(64, 72), (80, 88)] {
        let at = big64(v, offset)?;
        ensure!(big64(v, size)? == 0 && (at == 0 || (stock && at == desc_len)), "unexpected vbmeta public key or key metadata");
    }
    ensure!(v[HEADER+desc_len..].iter().all(|&v| v == 0), "nonzero AVB auxiliary padding");
    let mut descriptors = &v[HEADER..HEADER+desc_len];
    let (mut seen_hash, mut seen_fingerprint) = (false, false);
    while !descriptors.is_empty() {
        let tag = big64(descriptors, 0)?;
        let following = big64(descriptors, 8)?;
        ensure!(following % 8 == 0, "unaligned AVB descriptor");
        let (desc, rest) = descriptors.split_at_checked(16usize.checked_add(following).context("AVB descriptor overflow")?).context("truncated AVB descriptor")?;
        descriptors = rest;
        match tag {
            2 => {
                ensure!(!seen_hash && desc.len() >= HASH_FIXED, "invalid or duplicate hash descriptor");
                seen_hash = true;
                ensure!(big64(desc, 16)? == payload && desc[24..56].strip_prefix(b"sha256").is_some_and(|padding| padding.iter().all(|v| *v == 0))
                    && big32(desc, 56)? as usize == NAME.len() && big32(desc, 64)? == 32 && desc[68..132].iter().all(|&v| v == 0), "invalid vendor_boot hash settings");
                let salt = big32(desc, 60)? as usize;
                ensure!(salt <= 64 && desc.len() == round(HASH_FIXED + NAME.len() + salt + 32, 8), "bad vendor_boot salt or digest size");
                let at = HASH_FIXED + NAME.len();
                ensure!(&desc[HASH_FIXED..at] == NAME && desc[at+salt+32..].iter().all(|&n| n == 0), "wrong AVB partition name or padding");
                let mut sha = Sha256::new();
                sha.update(&desc[at..at+salt]);
                sha.update(&image[..payload]);
                ensure!(sha.finalize()[..] == desc[at+salt..at+salt+32], "vendor_boot AVB hash mismatch");
            }
            0 if stock => {
                ensure!(!seen_fingerprint && big64(desc, 16)? == FINGERPRINT.len(), "unexpected or duplicate AVB property");
                seen_fingerprint = true;
                let value = big64(desc, 24)?;
                let key_end = 32 + FINGERPRINT.len();
                ensure!((1..=256).contains(&value) && desc.len() == round(key_end + value + 2, 8), "bad stock AVB fingerprint size");
                ensure!(&desc[32..key_end] == FINGERPRINT && desc[key_end] == 0 && !desc[key_end+1..key_end+1+value].contains(&0)
                    && desc[key_end+1+value..].iter().all(|&n| n == 0), "invalid stock AVB fingerprint");
            }
            _ => anyhow::bail!("unsupported AVB descriptor tag {tag}"),
        }
    }
    ensure!(seen_hash && seen_fingerprint == stock, "missing expected AVB descriptors");
    Ok(())
}

pub(super) fn attach(mut image: Vec<u8>, capacity: usize, page: usize) -> Result<Vec<u8>> {
    let payload = image.len();
    let desc_size = round(HASH_FIXED + NAME.len() + 32, 8);
    let aux = round(desc_size, 64);
    let vbmeta_size = HEADER + aux;
    ensure!(payload % page == 0 && payload + round(vbmeta_size, page) + page <= capacity, "not enough space for AVB metadata");
    let digest = Sha256::digest(&image);
    image.resize(capacity, 0);
    let v = &mut image[payload..payload+vbmeta_size];
    v[..4].copy_from_slice(b"AVB0");
    wr32(v, 4, 1);
    wr64(v, 20, aux);
    wr64(v, 104, desc_size);
    v[128..135].copy_from_slice(b"Skyward");
    let desc = &mut v[HEADER..HEADER+desc_size];
    wr64(desc, 0, 2);
    wr64(desc, 8, desc_size - 16);
    wr64(desc, 16, payload);
    desc[24..30].copy_from_slice(b"sha256");
    wr32(desc, 56, NAME.len() as u32);
    wr32(desc, 64, 32);
    desc[HASH_FIXED..HASH_FIXED+NAME.len()].copy_from_slice(NAME);
    desc[HASH_FIXED+NAME.len()..HASH_FIXED+NAME.len()+32].copy_from_slice(&digest);
    let footer = &mut image[capacity-FOOTER..];
    footer[..4].copy_from_slice(b"AVBf");
    wr32(footer, 4, 1);
    wr64(footer, 12, payload);
    wr64(footer, 20, payload);
    wr64(footer, 28, vbmeta_size);
    verify(&image, payload, false)?;
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsigned_footer_hash_roundtrip_and_tampering() {
        let mut image = attach(vec![0x77; 4096], 16384, 4096).unwrap();
        assert!(verify(&image, 4096, true).is_err(), "generated footer is not accepted as stock");
        image[250] ^= 1;
        assert!(verify(&image, 4096, false).is_err());
    }
}
