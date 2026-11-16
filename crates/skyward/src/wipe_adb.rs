//! Temporarily pause only a verified init-owned adbd which holds userdata.
//! Killing its PID is insufficient: init restarts it and reopens /data logs.
#[cfg(target_os="android")]
use anyhow::Result;
pub fn needs_pause(running: bool, holds_data: bool) -> bool { running && holds_data }
#[cfg(target_os="android")]
pub struct Pause { restore: bool }
#[cfg(target_os="android")]
impl Pause {
 pub fn for_data_holders()->Result<Self>{
  use anyhow::{ensure,Context};use std::path::Path;
  let mut guard=Self{restore:false};
  let Some(data)=skyward_block::mount::visible(Path::new("/data"))? else{return Ok(guard)};
  let state=skyward_sys::prop("init.svc.adbd");
  if matches!(state.as_deref(),None|Some("stopped")){return Ok(guard)}
  ensure!(state.as_deref()==Some("running"),"adbd is transitioning; wait for it to settle before factory reset");
  let raw=skyward_sys::prop("init.svc_debug_pid.adbd").context("init gives no adbd PID")?;
  let pid:u32=raw.parse().context("invalid init adbd PID")?;ensure!(pid>1,"invalid adbd PID");
  let holders=skyward_block::mount::holding(data.device)?;
  if !needs_pause(true,holders.iter().any(|(id,_)|*id==pid as i32)){return Ok(guard)}
  let process=procfs::process::Process::new(pid as i32)?;
  ensure!(process.stat()?.ppid==1 && process.exe()?==Path::new("/system/bin/adbd"),"data holder is not the audited init adbd; refusing to stop unknown process");
  ensure!(skyward_sys::prop("init.svc_debug_pid.adbd").as_deref()==Some(raw.as_str()),"adbd changed during identity check");
  use std::os::fd::{FromRawFd,AsRawFd};
  let fd=unsafe{libc::syscall(libc::SYS_pidfd_open,pid as libc::pid_t,0)};
  ensure!(fd>=0,"cannot hold verified adbd process identity; refusing factory reset");
  let pidfd=unsafe{std::os::fd::OwnedFd::from_raw_fd(fd as i32)};
  ensure!(skyward_sys::prop("init.svc_debug_pid.adbd").as_deref()==Some(raw.as_str()),"adbd changed before pause");
  skyward_sys::kmsg("factory reset pauses init-owned adbd because its logs hold data; ADB will temporarily disconnect")?;
  skyward_sys::set_prop("ctl.stop","adbd")?;guard.restore=true;
  skyward_sys::wait_prop("init.svc.adbd","stopped",std::time::Duration::from_secs(5))?;
  let mut exit=libc::pollfd{fd:pidfd.as_raw_fd(),events:libc::POLLIN,revents:0};
  let until=std::time::Instant::now()+std::time::Duration::from_secs(5);
  loop {
   let result=unsafe{libc::poll(&mut exit,1,100)};
   if result>0 && exit.revents&libc::POLLIN!=0 {break;}
   if result<0 {let error=std::io::Error::last_os_error();if error.kind()!=std::io::ErrorKind::Interrupted{return Err(error.into());}}
   ensure!(std::time::Instant::now()<until,"adbd did not fully exit after init stop; refusing factory reset");
  }
  ensure!(crate::services::running("/system/bin/adbd").is_none(),"adbd still runs after init stop; refusing factory reset");
  Ok(guard)
 }
}
#[cfg(target_os="android")]
impl Drop for Pause {
 fn drop(&mut self){if self.restore {
  // Restarting the daemon does not open/mount userdata on Recovery's behalf.
  // Do not force another start if somebody already started it meanwhile.
  if skyward_sys::prop("init.svc.adbd").as_deref()!=Some("running"){
   if let Err(error)=skyward_sys::set_prop("ctl.start","adbd"){let _=skyward_sys::kmsg(&format!("could not restore adbd after reset attempt: {error:#}"));}
  }
 }}
}

/// Non-destructive host model used to regress the ordering contract.
#[cfg(test)]mod tests{
 #[test]fn stop_is_needed_only_for_running_init_daemon_with_data_reference(){
  assert!(super::needs_pause(true,true));assert!(!super::needs_pause(false,true));assert!(!super::needs_pause(true,false));assert!(!super::needs_pause(false,false));
 }
}
