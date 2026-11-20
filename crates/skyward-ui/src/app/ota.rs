//! Model/ColorOS/version catalogue and its independent download state.
use super::*;
use crate::ota_catalog::GROUPS;

pub const OTA_DIRECTORY: &str = "/data/ota_package";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtaDownload {
    pub model: usize,
    pub generation: usize,
    pub package: usize,
    pub downloaded: u64,
    pub total: Option<u64>,
    pub status: OtaStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OtaStatus {
    Downloading,
    Cancelling,
    Cancelled,
    Failed(String),
    Ready(String),
}

impl OtaDownload {
    pub(super) fn active(&self) -> bool {
        matches!(self.status, OtaStatus::Downloading | OtaStatus::Cancelling)
    }
}

impl App {
    fn ota_preconditions(&mut self, now: u64) -> Result<(), Vec<Effect>> {
        if !self.state.data.storage_open() {
            self.open(Screen::Decrypt);
            return Err(self.arrive_at(Screen::Decrypt));
        }
        if self.state.wlan.is_some() && !self.state.online() {
            self.open(Screen::Wlan);
            return Err(self.arrive_at(Screen::Wlan));
        }
        if !matches!(self.state.install, Install::Idle | Install::Finished { .. }) {
            self.say(self.state.lang.pick(INSTALL_UNFINISHED), now);
            return Err(Vec::new());
        }
        Ok(())
    }

    pub(super) fn select_ota(&mut self, package: usize, now: u64) -> Vec<Effect> {
        let Screen::OtaVersions(model, generation) = self.screen() else { return Vec::new() };
        if GROUPS.get(model).and_then(|m| m.generations.get(generation))
            .and_then(|g| g.packages.get(package)).is_none() || self.state.ota_download.as_ref().is_some_and(OtaDownload::active) {
            return Vec::new();
        }
        if self.state.ota_download.as_ref().is_some_and(|job| (job.model, job.generation, job.package) == (model, generation, package)) {
            self.open(Screen::OtaDownload);
            return Vec::new();
        }
        if let Err(effects) = self.ota_preconditions(now) { return effects; }
        self.open(Screen::OtaDownload);
        self.start_ota(model, generation, package)
    }

    fn start_ota(&mut self, model: usize, generation: usize, package: usize) -> Vec<Effect> {
        self.state.ota_download = Some(OtaDownload { model, generation, package, downloaded: 0, total: None, status: OtaStatus::Downloading });
        self.refresh();
        vec![Effect::DownloadOta { model, generation, package }]
    }

    pub(super) fn retry_ota(&mut self, now: u64) -> Vec<Effect> {
        if self.screen() != Screen::OtaDownload { return Vec::new(); }
        let Some(job) = self.state.ota_download.as_ref().filter(|job| matches!(job.status, OtaStatus::Cancelled | OtaStatus::Failed(_))) else { return Vec::new() };
        let (model, generation, package) = (job.model, job.generation, job.package);
        if let Err(effects) = self.ota_preconditions(now) { return effects; }
        self.start_ota(model, generation, package)
    }

    pub(super) fn cancel_ota(&mut self) -> Vec<Effect> {
        if self.screen() != Screen::OtaDownload { return Vec::new(); }
        let Some(job) = self.state.ota_download.as_mut().filter(|job| job.status == OtaStatus::Downloading) else { return Vec::new() };
        job.status = OtaStatus::Cancelling;
        self.refresh();
        vec![Effect::CancelOtaDownload]
    }

    pub(super) fn install_ota(&mut self, now: u64) -> Vec<Effect> {
        if self.screen() != Screen::OtaDownload { return Vec::new(); }
        let Some(OtaDownload { status: OtaStatus::Ready(path), downloaded, .. }) = self.state.ota_download.as_ref() else { return Vec::new() };
        let (path, size) = (path.clone(), *downloaded);
        if !self.state.data.storage_open() {
            self.open(Screen::Decrypt);
            return self.arrive_at(Screen::Decrypt);
        }
        self.install_opened(path, size, now)
    }

    /// Byte count for the current job. `total` is absent until known.
    pub fn ota_download_progress(&mut self, downloaded: u64, total: Option<u64>) {
        let Some(job) = self.state.ota_download.as_mut().filter(|job| job.status == OtaStatus::Downloading) else { return };
        job.downloaded = downloaded;
        job.total = total.filter(|n| *n != 0);
        self.refresh();
    }

    /// The worker has exited. `Ok` names the published ZIP; it does not install it.
    pub fn ota_download_finished(&mut self, result: Result<String, String>) {
        let Some(job) = self.state.ota_download.as_mut().filter(|job| job.active()) else { return };
        job.status = match result {
            Ok(path) => OtaStatus::Ready(path),
            Err(why) => OtaStatus::Failed(why),
        };
        self.refresh();
    }

    /// The worker acknowledged cancellation and can now be retried.
    pub fn ota_download_cancelled(&mut self) {
        let Some(job) = self.state.ota_download.as_mut().filter(|job| job.active()) else { return };
        job.status = OtaStatus::Cancelled;
        self.refresh();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::testing::*;

    #[test]
    fn catalogue_download_waits_for_cancel_and_success_requires_install_action() {
        let (f, i) = (fonts(), info());
        let mut app = opened(Screen::Install, &f, &i);
        app.data_waiting(None);
        for page in [Screen::OtaModels, Screen::OtaGenerations(0), Screen::OtaVersions(0, 0)] {
            assert!(tap(&mut app, &f, &i, Action::Open(page)).is_empty());
            assert_eq!(app.screen(), page);
        }
        let download = Effect::DownloadOta { model: 0, generation: 0, package: 0 };
        assert_eq!(tap(&mut app, &f, &i, Action::SelectOta(0)), vec![download.clone()]);
        assert_eq!(app.screen(), Screen::OtaDownload);
        assert!(app.key(Key::Back, 1000).is_empty());
        assert_eq!(app.screen(), Screen::OtaDownload);
        app.ota_download_progress(20, Some(100));
        assert_eq!(app.state.ota_download.as_ref().unwrap().downloaded, 20);
        assert_eq!(tap(&mut app, &f, &i, Action::CancelOta), vec![Effect::CancelOtaDownload]);
        assert!(app.act(Action::RetryOta, 0).is_empty());
        app.ota_download_cancelled();
        assert_eq!(tap(&mut app, &f, &i, Action::RetryOta), vec![download.clone()]);
        app.ota_download_finished(Err("network unavailable".into()));
        assert_eq!(tap(&mut app, &f, &i, Action::RetryOta), vec![download]);
        app.ota_download_progress(100, Some(100));
        let path = format!("{OTA_DIRECTORY}/model-hash.zip");
        app.ota_download_finished(Ok(path.clone()));
        assert_eq!(app.screen(), Screen::OtaDownload);
        assert_eq!(app.state.install, Install::Idle);
        assert_eq!(tap(&mut app, &f, &i, Action::InstallOta), vec![Effect::InstallPath(path)]);
        assert_eq!(app.screen(), Screen::Installing);
    }

    #[test]
    fn download_selection_without_open_data_requests_decryption() {
        let (f, i) = (fonts(), info());
        let mut app = opened(Screen::Install, &f, &i);
        app.act(Action::Open(Screen::OtaVersions(0, 0)), 0);
        let effects = app.act(Action::SelectOta(0), 0);
        assert_eq!(app.screen(), Screen::Decrypt);
        assert!(!effects.iter().any(|effect| matches!(effect, Effect::DownloadOta { .. })));
        assert!(app.state.ota_download.is_none());
    }
}
