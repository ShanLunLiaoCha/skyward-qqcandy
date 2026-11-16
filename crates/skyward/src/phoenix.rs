//! PGZ110 original Phoenix command protocol. Keep the daemon/watchdog intact;
//! acknowledge successful UI startup instead of letting its default reboot timer
//! expire. The third underscore-separated field is a command sequence number.
use anyhow::{ensure, Context, Result};

pub const PROPERTY: &str = "vendor.oplus.phoenix.recovery.cmd";

#[derive(Debug, PartialEq, Eq)]
pub enum ReadyCommand {
    Write(String),
    AlreadyDone,
    // An install/wipe or a caller explicitly chose another watchdog command.
    // Startup must never cancel that operation's protection.
    Preserve,
}

pub fn ready_command(current: Option<&str>) -> Result<ReadyCommand> {
    let Some(current) = current.filter(|value| !value.is_empty()) else {
        return Ok(ReadyCommand::Write("done_0_0".into()));
    };
    let fields: Vec<_> = current.split('_').collect();
    ensure!(fields.len() == 3, "Phoenix command is not the audited three-field protocol");
    let sequence: i32 = fields[2].parse().context("invalid Phoenix command sequence")?;
    ensure!(sequence >= 0, "negative Phoenix command sequence");
    if fields[0] == "done" && fields[1] == "0" { return Ok(ReadyCommand::AlreadyDone); }
    if fields[0] != "reboot" || fields[1] != "300" { return Ok(ReadyCommand::Preserve); }
    let next = sequence.checked_add(1).context("Phoenix command sequence exhausted")?;
    Ok(ReadyCommand::Write(format!("done_0_{next}")))
}

#[cfg(target_os = "android")]
pub fn acknowledge_ui_ready(cfg: &skyward_config::DeviceConfig) -> Result<bool> {
    if cfg.device.codename != "OP5911" || cfg.device.recovery_partition != skyward_config::RecoveryPartition::VendorBoot {
        return Ok(true);
    }
    if skyward_sys::prop("init.svc.phoenix_recovery").as_deref() != Some("running") {
        return Ok(false); // Late init service startup: retry after a later real frame.
    }
    let current = skyward_sys::prop(PROPERTY);
    match ready_command(current.as_deref())? {
        ReadyCommand::AlreadyDone => Ok(true),
        ReadyCommand::Preserve => {
            skyward_sys::kmsg("Phoenix startup acknowledgement preserves an existing non-startup watchdog command")?;
            Ok(true)
        }
        ReadyCommand::Write(command) => {
            if current.as_deref().is_none_or(|value| value.is_empty()) {
                // init marks a service running before its main() has read the
                // command. Wait for Phoenix to publish its default rather than
                // racing its startup write with a synthetic sequence zero.
                return Ok(false);
            }
            // Do not overwrite a command changed since planning the write.
            ensure!(skyward_sys::prop(PROPERTY) == current, "Phoenix command changed during startup acknowledgement; retry safely");
            skyward_sys::set_prop(PROPERTY, &command)?;
            ensure!(skyward_sys::prop(PROPERTY).as_deref() == Some(command.as_str()), "Phoenix startup acknowledgement was not stored");
            skyward_sys::kmsg(&format!("Phoenix notified after first completed UI frame: {command}; original daemon remains active"))?;
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_default_timer_requires_an_incremented_sequence() {
        assert_eq!(ready_command(Some("reboot_300_0")).unwrap(), ReadyCommand::Write("done_0_1".into()));
        assert_eq!(ready_command(Some("reboot_300_42")).unwrap(), ReadyCommand::Write("done_0_43".into()));
        assert_eq!(ready_command(None).unwrap(), ReadyCommand::Write("done_0_0".into()));
    }
    #[test]
    fn do_not_reset_other_operations_or_repeat_done() {
        assert_eq!(ready_command(Some("done_0_1")).unwrap(), ReadyCommand::AlreadyDone);
        for value in ["update_1500_3", "wipe_1000_4", "reboot_60_5"] {
            assert_eq!(ready_command(Some(value)).unwrap(), ReadyCommand::Preserve);
        }
    }
    #[test]
    fn malformed_or_overflowing_sequence_is_never_guessed() {
        for value in ["reboot_300", "reboot_300_nan", "reboot_300_-1", "reboot_300_2147483647", "reboot_300_1_extra"] {
            assert!(ready_command(Some(value)).is_err(), "{value}");
        }
    }
}
