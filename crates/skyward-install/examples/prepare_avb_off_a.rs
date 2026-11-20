//! Host exercise of the native A-slot development pair. Ordinary files only.
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use skyward_install::{factory_preflight, payload_preflight, retention, signature};
use skyward_vab::Slot;
use std::{fs::{self, File, OpenOptions}, io::{BufReader, Read, Write}, os::unix::fs::OpenOptionsExt, path::Path};

fn regular(path: &Path, limit: u64) -> Result<(File, u64)> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let meta = file.metadata()?;
    ensure!(meta.is_file() && (1..=limit).contains(&meta.len()), "need a bounded regular file: {}", path.display());
    Ok((file, meta.len()))
}

fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let (file, len) = regular(path, limit)?;
    let mut bytes = Vec::new();
    file.take(len + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 == len, "input size changed: {}", path.display());
    Ok(bytes)
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [ota, certs, program, assets_dir, mtp, dest] = &args[..] else {
        anyhow::bail!("usage: prepare_avb_off_a OTA.zip TRUSTED_CERTS.zip ELF DONOR_DIR MTP.rc NEW_DIRECTORY");
    };
    let (zip, size) = regular(Path::new(ota), 128 << 30)?;
    let mut zip = BufReader::new(zip);
    let (plan, digest) = payload_preflight::read_zip_with_digest(&mut zip)?;
    factory_preflight::reviewed_roster(&digest)?;
    let keys = signature::keys(BufReader::new(regular(Path::new(certs), 8 << 20)?.0))?;
    let verdict = signature::verify(&mut zip, size, &keys, |_, _| true)?;
    ensure!(verdict == signature::Verdict::Signed, "trusted OTA signature not established: {verdict:?}");
    println!("Whole-ZIP signature: {verdict:?}");
    let program = read(Path::new(program), 32 << 20)?;
    let mut inputs = Vec::new();
    for name in ["skyward/device.toml", "skyward/MiSansVF.ttf", "skyward/KirkMono-Regular.ttf", "skyward/KirkMono-OFL.txt"] {
        inputs.push((name, read(&Path::new(assets_dir).join(name), 32 << 20)?));
    }
    inputs.push(("system/etc/init/skyward-mtp.rc", read(Path::new(mtp), 64 << 10)?));
    let assets: Vec<_> = inputs.iter().map(|(name, data)| (*name, data.as_slice())).collect();
    let base = retention::SlotTarget::from_payload(&plan, Slot::A)?.stage_from_payload(&mut zip, &plan)?;
    let pair = base.prepare_a_avb_off(&program, &assets)?;
    let dest = Path::new(dest);
    fs::create_dir(dest)?;
    let mut sums = String::new();
    for (name, data) in [("vendor_boot_a-UNTESTED.img", pair.vendor_boot), ("vbmeta_a-AVB-OFF-UNTESTED.img", pair.vbmeta)] {
        let mut file = OpenOptions::new().write(true).create_new(true).open(dest.join(name))?;
        file.write_all(&data)?;
        file.sync_all()?;
        sums.push_str(&format!("{:x}  {name}\n", Sha256::digest(&data)));
    }
    let mut marker = OpenOptions::new().write(true).create_new(true).open(dest.join("SHA256SUMS.txt"))?;
    marker.write_all(sums.as_bytes())?;
    marker.sync_all()?;
    print!("{sums}");
    Ok(())
}
