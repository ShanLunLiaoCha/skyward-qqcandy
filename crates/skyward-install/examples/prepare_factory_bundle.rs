//! Run Recovery's core bundle preparation on ordinary host files; no flashing.
use anyhow::{Result,ensure};
use std::{fs::OpenOptions,io::Read,os::unix::fs::OpenOptionsExt,path::Path};
fn read(path:&Path,limit:u64)->Result<Vec<u8>> {
 let f=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK).open(path)?;
 let m=f.metadata()?;ensure!(m.is_file()&&m.len()<=limit,"need bounded regular input");
 let mut b=Vec::new();f.take(limit+1).read_to_end(&mut b)?;ensure!(b.len() as u64==m.len(),"input size changed");Ok(b)
}
fn main()->Result<()> {
 let a:Vec<_>=std::env::args_os().skip(1).collect();
 let [ota,certs,reference,company,preload,elf,donor,mtp,dest]=&a[..] else {anyhow::bail!("usage: prepare_factory_bundle OTA CERTS OEM_SUPER_META COMPANY PRELOAD ELF DONOR MTP NEW_DIRECTORY")};
 read(Path::new(reference),8<<20)?;
 let meta=skyward_lp::read_image(Path::new(reference))?;
 let [device]=meta.block_devices.as_slice() else {anyhow::bail!("one super required")};
 let elf=read(Path::new(elf),32<<20)?;
 let mut own=Vec::new();for n in ["skyward/device.toml","skyward/MiSansVF.ttf","skyward/KirkMono-Regular.ttf","skyward/KirkMono-OFL.txt"] {own.push((n,read(&Path::new(donor).join(n),32<<20)?));}
 own.push(("system/etc/init/skyward-mtp.rc",read(Path::new(mtp),64<<10)?));
 let assets:Vec<_>=own.iter().map(|(n,b)|(*n,b.as_slice())).collect();
 let result=skyward_install::factory_bundle::prepare(Path::new(ota),Path::new(certs),&meta,device.size,Path::new(company),Path::new(preload),&elf,&assets,true,Path::new(dest))?;
 println!("Core staged at {}; {} verified files; remaining physical={:?}; no device writes",result.directory.display(),result.images.len(),result.remaining_physical);Ok(())
}
