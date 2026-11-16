//! Recovery-only remembered WLAN credentials. Never metadata or Android's
//! own Wi-Fi store. Contents are secret: deliberately no Debug implementation.
use anyhow::{ensure, Context, Result};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
const NOFOLLOW: i32 = 0x20000; // Linux O_NOFOLLOW, including Android and host tests.
const LIMIT: usize = 32 * 1024;
const MAGIC: &[u8] = b"SKYWIFI1";
#[derive(Clone)]
pub struct Profile { pub ssid: Vec<u8>, pub security: u8, pub password: String }
fn encode(profiles: &[Profile]) -> Result<Vec<u8>> {
    ensure!(profiles.len() <= 16, "too many recovery WLAN profiles");
    let mut out=MAGIC.to_vec();out.push(profiles.len() as u8);
    for p in profiles {
        ensure!(!p.ssid.is_empty() && p.ssid.len()<=32 && p.password.len()<=256 && p.security<=4,"invalid recovery WLAN profile");
        out.push(p.ssid.len() as u8);out.push(p.security);out.extend_from_slice(&(p.password.len() as u16).to_le_bytes());out.extend_from_slice(&p.ssid);out.extend_from_slice(p.password.as_bytes());
    }
    ensure!(out.len()<=LIMIT,"WLAN profile store too large");Ok(out)
}
fn decode(bytes: &[u8]) -> Result<Vec<Profile>> {
    ensure!(bytes.len()<=LIMIT && bytes.starts_with(MAGIC) && bytes.len()>MAGIC.len(),"invalid recovery WLAN store");
    let mut at=MAGIC.len();let count=bytes[at] as usize;at+=1;ensure!(count<=16,"too many WLAN profiles");
    let mut profiles=Vec::new();
    for _ in 0..count {
        ensure!(at+4<=bytes.len(),"truncated WLAN profile");
        let n=bytes[at] as usize;let security=bytes[at+1];let p=u16::from_le_bytes([bytes[at+2],bytes[at+3]]) as usize;at+=4;
        ensure!(n>0 && n<=32 && p<=256 && security<=4 && at+n+p<=bytes.len(),"invalid WLAN profile bounds");
        let ssid=bytes[at..at+n].to_vec();at+=n;let password=String::from_utf8(bytes[at..at+p].to_vec()).context("invalid WLAN credential encoding")?;at+=p;
        profiles.push(Profile{ssid,security,password});
    }
    ensure!(at==bytes.len(),"trailing WLAN credential bytes");Ok(profiles)
}
fn checked(path: &Path, uid:u32, directory:bool) -> Result<()> {
    let m=fs::symlink_metadata(path)?;
    ensure!(!m.file_type().is_symlink() && m.uid()==uid && (directory || m.nlink()==1),"unsafe recovery WLAN store owner or link");
    ensure!(if directory {m.is_dir() && m.mode()&0o777==0o700} else {m.is_file() && m.mode()&0o777==0o600},"unsafe recovery WLAN store permissions");Ok(())
}
fn load_at(dir:&Path,uid:u32)->Result<Vec<Profile>> {
    if !dir.exists(){return Ok(Vec::new())}checked(dir,uid,true)?;
    let path=dir.join("wifi.conf");
    let file=match OpenOptions::new().read(true).custom_flags(NOFOLLOW).open(&path){Ok(f)=>f,Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(Vec::new()),Err(e)=>return Err(e.into())};
    checked(&path,uid,false)?;
    let meta=file.metadata()?;
    ensure!(meta.is_file() && meta.uid()==uid && meta.nlink()==1 && meta.mode()&0o777==0o600,"unsafe opened WLAN credential file");
    ensure!(meta.len()<=LIMIT as u64,"WLAN store too large");
    let mut bytes=Vec::new();file.take((LIMIT+1) as u64).read_to_end(&mut bytes)?;decode(&bytes)
}
fn save_at(dir:&Path,uid:u32,profiles:&[Profile])->Result<()> {
    let bytes=encode(profiles)?;
    match fs::DirBuilder::new().mode(0o700).create(dir){Ok(())=>{},Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists=>{},Err(e)=>return Err(e.into())};
    checked(dir,uid,true)?;let target=dir.join("wifi.conf");
    if fs::symlink_metadata(&target).is_ok(){checked(&target,uid,false)?;}
    let temp=dir.join(format!(".wifi-{}.tmp",std::process::id()));
    let mut created=false;
    let result=(||->Result<()> {
        let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(NOFOLLOW).open(&temp)?;
        created=true;
        file.write_all(&bytes)?;file.sync_all()?;drop(file);checked(&temp,uid,false)?;
        fs::rename(&temp,&target)?;fs::File::open(dir)?.sync_all()?;Ok(())
    })();
    // Never remove someone else's pre-existing temporary object.
    if created && result.is_err() && fs::symlink_metadata(&temp).is_ok_and(|m|m.uid()==uid && m.is_file() && m.nlink()==1 && m.mode()&0o777==0o600){let _=fs::remove_file(&temp);}
    result
}
#[cfg(target_os="android")]
fn directory()->Result<&'static Path> {
    // /data must be an actual mounted decrypted filesystem, not an empty
    // rootfs directory. Read-only mounts cannot accept remembered credentials.
    ensure!(skyward_block::mount::is_mount_point(Path::new("/data"))?,"data is not open; WLAN credentials remain temporary");
    let mounts=fs::read_to_string("/proc/mounts")?;
    ensure!(mounts.lines().any(|l|{let f:Vec<_>=l.split_whitespace().collect();f.len()>3 && f[1]=="/data" && f[3].split(',').any(|o|o=="rw")}),"data is read-only; WLAN credentials remain temporary");
    for p in ["/data","/data/vendor"] {let m=fs::symlink_metadata(p)?;ensure!(m.is_dir()&&!m.file_type().is_symlink(),"unsafe WLAN parent path");}
    Ok(Path::new("/data/vendor/skyward-recovery"))
}
#[cfg(target_os="android")]
pub fn load()->Result<Vec<Profile>> {load_at(directory()?,0)}
#[cfg(target_os="android")]
pub fn remember(profile:Profile)->Result<()> {
    let dir=directory()?;let mut all=load_at(dir,0)?;
    all.retain(|p|p.ssid!=profile.ssid || p.security!=profile.security);all.insert(0,profile);all.truncate(16);save_at(dir,0,&all)
}
#[cfg(target_os="android")]
pub fn forget(ssid:&[u8],security:u8)->Result<()> {let dir=directory()?;let mut all=load_at(dir,0)?;all.retain(|p|p.ssid!=ssid||p.security!=security);save_at(dir,0,&all)}
#[cfg(test)]
mod tests {
 use super::*;
 fn sample()->Profile {Profile{ssid:b"test".to_vec(),security:2,password:"not-a-real-credential".into()}}
 #[test]fn roundtrip_and_bounds(){let p=decode(&encode(&[sample()]).unwrap()).unwrap();assert_eq!(p[0].ssid,b"test");assert_eq!(p[0].password,"not-a-real-credential");for b in [&b""[..],&b"SKYWIFI1\xff"[..],&b"SKYWIFI1\x01"[..]]{assert!(decode(b).is_err());}}
 #[test]fn private_atomic_store(){let temp=tempfile::tempdir().unwrap();let dir=temp.path().join("private");let uid=fs::metadata(temp.path()).unwrap().uid();save_at(&dir,uid,&[sample()]).unwrap();assert_eq!(fs::metadata(dir.join("wifi.conf")).unwrap().mode()&0o777,0o600);assert_eq!(fs::metadata(&dir).unwrap().mode()&0o777,0o700);assert_eq!(load_at(&dir,uid).unwrap().len(),1);save_at(&dir,uid,&[]).unwrap();assert!(load_at(&dir,uid).unwrap().is_empty());}
 #[test]fn preexisting_temp_is_never_removed(){let t=tempfile::tempdir().unwrap();let d=t.path().join("d");let uid=fs::metadata(t.path()).unwrap().uid();save_at(&d,uid,&[sample()]).unwrap();let temp=d.join(format!(".wifi-{}.tmp",std::process::id()));fs::write(&temp,b"owned elsewhere").unwrap();assert!(save_at(&d,uid,&[]).is_err());assert_eq!(fs::read(&temp).unwrap(),b"owned elsewhere");assert_eq!(load_at(&d,uid).unwrap().len(),1);}
 #[test]fn refuses_unsafe_permissions_and_symlinks(){use std::os::unix::fs::{symlink,PermissionsExt};let t=tempfile::tempdir().unwrap();let uid=fs::metadata(t.path()).unwrap().uid();let d=t.path().join("d");save_at(&d,uid,&[sample()]).unwrap();fs::set_permissions(d.join("wifi.conf"),fs::Permissions::from_mode(0o644)).unwrap();assert!(load_at(&d,uid).is_err());assert!(save_at(&d,uid,&[]).is_err());let link=t.path().join("link");symlink(&d,&link).unwrap();assert!(load_at(&link,uid).is_err());}
}
