//! Offline exercise of the same native packer intended for Recovery.
//! The output must be a new regular file; never opens a partition for writing.
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let meta = file.metadata()?;
    ensure!(meta.is_file() && meta.len() <= limit, "need a regular file of <= {limit} bytes: {}", path.display());
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 == meta.len(), "input size changed: {}", path.display());
    Ok(bytes)
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [stock, donor, mtp, output] = &args[..] else {
        anyhow::bail!("usage: repack_vendor_boot STOCK.img DONOR_DIR MTP.rc NEW.img");
    };
    let donor = Path::new(donor);
    let stock = read(Path::new(stock), 64 << 20)?;
    let elf = read(&donor.join("system/bin/recovery"), 32 << 20)?;
    let mut assets = Vec::new();
    for path in ["skyward/device.toml", "skyward/MiSansVF.ttf", "skyward/KirkMono-Regular.ttf", "skyward/KirkMono-OFL.txt"] {
        assets.push((path, read(&donor.join(path), 32 << 20)?));
    }
    assets.push(("system/etc/init/skyward-mtp.rc", read(Path::new(mtp), 64 << 10)?));
    let borrowed: Vec<_> = assets.iter().map(|(p, b)| (*p, b.as_slice())).collect();
    let output_bytes = skyward_install::vendor_boot::repack(&stock, &elf, &borrowed)?;
    let mut dst = OpenOptions::new().write(true).create_new(true).open(output)?;
    dst.write_all(&output_bytes)?;
    dst.sync_all()?;
    println!("{:x}  {}", Sha256::digest(&output_bytes), Path::new(output).display());
    Ok(())
}
