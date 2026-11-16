//! Owned secure-service runtime. Partition operations quiesce it instead of
//! disabling Recovery features or leaving immortal restart threads behind.
use anyhow::Result;
#[derive(Default)]
pub struct Runtime {
    pub services: crate::services::ServiceGroup,
    pub tee: Option<crate::trustonic::DaemonGuard>,
}
impl Runtime {
    pub fn stop(&mut self) -> Result<()> {
        // HALs/directories depend on TEE: cancel restarts and reap them first.
        self.services.stop()?;
        if let Some(daemon) = &mut self.tee { daemon.stop_checked()?; }
        self.tee = None;
        Ok(())
    }
}
impl Drop for Runtime {
    fn drop(&mut self) { if let Err(error)=self.stop() { let _=skyward_sys::kmsg(&format!("secure runtime shutdown failed: {error:#}")); } }
}
