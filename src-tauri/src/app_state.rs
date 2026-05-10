use std::sync::RwLock;

use crate::services::{
    archive_service::ArchiveService, crypto_service::CryptoService, key_manager::KeyManager,
    pinned_settings_service::PinnedSettingsService, secure_temp::SecureTempManager,
    session_manager::SessionManager, vault_service::VaultService,
};

pub struct AppState {
    pub session: RwLock<SessionManager>,
    pub keys: RwLock<KeyManager>,
    pub vault: RwLock<VaultService>,
    pub crypto: CryptoService,
    pub pinned_settings: PinnedSettingsService,
    pub archives: ArchiveService,
    pub secure_temp: SecureTempManager,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            session: RwLock::new(SessionManager::default()),
            keys: RwLock::new(KeyManager::default()),
            vault: RwLock::new(VaultService::default()),
            crypto: CryptoService::default(),
            pinned_settings: PinnedSettingsService,
            archives: ArchiveService::default(),
            secure_temp: SecureTempManager::default(),
        }
    }
}
