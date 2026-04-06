use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    errors::AppResult,
    models::PinnedKeySettings,
};

#[derive(Default)]
pub struct PinnedSettingsService;

impl PinnedSettingsService {
    pub fn load(&self, config_dir: &Path) -> AppResult<PinnedKeySettings> {
        let path = self.settings_path(config_dir);
        if !path.exists() {
            return Ok(PinnedKeySettings::default());
        }

        let content = fs::read_to_string(path)?;
        let settings = serde_json::from_str::<PinnedKeySettings>(&content).unwrap_or_default();
        Ok(settings)
    }

    pub fn save(&self, config_dir: &Path, settings: &PinnedKeySettings) -> AppResult<()> {
        fs::create_dir_all(config_dir)?;
        let path = self.settings_path(config_dir);
        let payload = serde_json::to_string_pretty(settings)?;
        fs::write(path, payload)?;
        Ok(())
    }

    fn settings_path(&self, config_dir: &Path) -> PathBuf {
        config_dir.join("pinned-key-settings.json")
    }
}
