//! UI effects that require services after a partition transaction.
//! Pure policy shared by Android dispatch and host regression tests.
use skyward_ui::app::{Effect,FsAction};
pub fn needs_restored_services(effect:&Effect)->bool {
    matches!(effect, Effect::OpenData | Effect::Unlock{..} | Effect::ReadSlots | Effect::SetSlot(_) |
        Effect::Filesystem{action:FsAction::Repair,..} | Effect::Wlan(true))
}
pub fn needs_wlan_worker(effect:&Effect)->bool {
    matches!(effect,Effect::Wlan(_) | Effect::ScanWlan | Effect::JoinWlan{..} | Effect::LeaveWlan)
}
pub fn auto_scan_ready(on:bool,worker_exists:bool)->bool {on && worker_exists}
#[cfg(test)]mod tests {
 use super::*;
 #[test]fn read_slots_must_restore_the_stopped_directory() {
  assert!(needs_restored_services(&Effect::ReadSlots));
  assert!(needs_restored_services(&Effect::Wlan(true)));
  assert!(!needs_restored_services(&Effect::ScanWlan));
 }
 #[test]fn stale_scan_is_guarded_without_starting_services_during_install() {
  assert!(needs_wlan_worker(&Effect::ScanWlan));
  assert!(needs_wlan_worker(&Effect::LeaveWlan));
  assert!(!auto_scan_ready(true,false));
  assert!(!auto_scan_ready(false,true));
  assert!(auto_scan_ready(true,true));
 }
}
