//! Device-opt-in display resume mode selection, independent of DRM ioctls.
//! A cached mode is updated only after its corresponding atomic commit succeeds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ResumeMode {
    #[default]
    PreferredThenFastest,
    Running,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResumePlan<T> {
    pub mode: T,
    pub speed_up_after: bool,
}

pub struct ResumeState<T> {
    policy: ResumeMode,
    preferred: T,
    fastest: Option<T>,
    running: T,
}

impl<T: Copy + PartialEq> ResumeState<T> {
    /// Construct only after the initial preferred-mode commit succeeded.
    pub fn new(policy: ResumeMode, preferred: T, fastest: Option<T>) -> Self {
        Self { policy, preferred, fastest, running: preferred }
    }

    pub fn plan(&self) -> ResumePlan<T> {
        match self.policy {
            ResumeMode::PreferredThenFastest => ResumePlan {
                mode: self.preferred,
                speed_up_after: self.fastest.is_some_and(|fastest| fastest != self.preferred),
            },
            ResumeMode::Running => ResumePlan { mode: self.running, speed_up_after: false },
        }
    }

    /// Call only after the hardware accepted this mode's atomic commit.
    pub fn committed(&mut self, mode: T) { self.running = mode; }

    pub fn running(&self) -> T { self.running }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_keeps_the_preferred_then_fastest_quirk() {
        let mut state = ResumeState::new(ResumeMode::default(), 60, Some(120));
        state.committed(120);
        assert_eq!(state.plan(), ResumePlan { mode: 60, speed_up_after: true });
    }
    #[test]
    fn explicit_running_restores_last_success_without_a_second_modeset() {
        let mut state = ResumeState::new(ResumeMode::Running, 60, Some(120));
        state.committed(120);
        assert_eq!(state.plan(), ResumePlan { mode: 120, speed_up_after: false });
        state.committed(state.plan().mode);
        assert_eq!(state.plan(), ResumePlan { mode: 120, speed_up_after: false });
    }
    #[test]
    fn failed_commit_cannot_change_the_cached_mode() {
        let mut state = ResumeState::new(ResumeMode::Running, 60, Some(120));
        let result: Result<(), ()> = Err(());
        if result.is_ok() { state.committed(120); }
        assert_eq!(state.running(), 60);
        assert_eq!(state.plan(), ResumePlan { mode: 60, speed_up_after: false });
        state.committed(120);
        let requested = state.plan();
        let result: Result<(), ()> = Err(());
        if result.is_ok() { state.committed(requested.mode); }
        assert_eq!(state.running(), 120);
    }
    #[test]
    fn same_mode_needs_no_followup() {
        let state = ResumeState::new(ResumeMode::PreferredThenFastest, 120, None);
        assert_eq!(state.plan(), ResumePlan { mode: 120, speed_up_after: false });
    }
}
