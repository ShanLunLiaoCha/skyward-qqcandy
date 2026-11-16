//! Bounded LED motor command planning; hardware writes remain in haptics.rs.
use anyhow::{ensure,Result};
pub fn plan(cfg:&skyward_config::LedHaptics,ticks:bool,strength:f32)->Result<(u32,u8)> {
 let duration=if ticks {cfg.ticks_ms}else{cfg.click_ms};
 ensure!((1..=80).contains(&duration) && (1..=128).contains(&cfg.max_gain),"unsafe LED motor limits");
 ensure!(strength.is_finite(),"invalid motor strength");
 let gain=(strength.clamp(0.0,1.0)*f32::from(cfg.max_gain)).round() as u8;
 Ok((duration,gain))
}
#[cfg(test)]mod tests {
 use super::*;
 fn cfg()->skyward_config::LedHaptics{skyward_config::LedHaptics{path:"/sys/class/leds/vibrator".into(),click_ms:18,ticks_ms:30,max_gain:128}}
 #[test]fn short_motor_commands_stay_bounded(){assert_eq!(plan(&cfg(),false,0.5).unwrap(),(18,64));assert_eq!(plan(&cfg(),true,2.0).unwrap(),(30,128));assert_eq!(plan(&cfg(),false,-1.0).unwrap().1,0);}
 #[test]fn rejects_unbounded_duration_and_nonfinite_gain(){let mut c=cfg();c.click_ms=0;assert!(plan(&c,false,0.5).is_err());c.click_ms=81;assert!(plan(&c,false,0.5).is_err());assert!(plan(&cfg(),false,f32::NAN).is_err());}
}
