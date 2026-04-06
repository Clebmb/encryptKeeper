use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::errors::{AppError, AppResult};

pub struct SessionManager {
    unlocked: bool,
    passphrase: Option<Zeroizing<String>>,
    last_activity: Option<Instant>,
    inactivity_timeout: Duration,
    auto_save: bool,
    recursive_scan: bool,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self {
            unlocked: false,
            passphrase: None,
            last_activity: None,
            inactivity_timeout: Duration::from_secs(0),
            auto_save: false,
            recursive_scan: true,
        }
    }
}

impl SessionManager {
    pub fn unlock(&mut self, passphrase: String) {
        self.unlocked = true;
        self.passphrase = Some(Zeroizing::new(passphrase));
        self.last_activity = Some(Instant::now());
    }

    pub fn lock(&mut self) {
        self.unlocked = false;
        self.passphrase = None;
        self.last_activity = None;
    }

    pub fn ensure_unlocked(&mut self) -> AppResult<&str> {
        self.expire_if_idle();
        if !self.unlocked {
            return Err(AppError::SessionLocked);
        }
        self.touch();
        self.passphrase
            .as_deref()
            .ok_or(AppError::SessionLocked)
            .map(|value| value.as_str())
    }

    pub fn touch(&mut self) {
        self.last_activity = Some(Instant::now());
    }

    pub fn is_unlocked(&mut self) -> bool {
        self.expire_if_idle();
        self.unlocked
    }

    pub fn set_timeout_secs(&mut self, secs: u64) {
        self.inactivity_timeout = Duration::from_secs(if secs == 0 { 0 } else { secs.max(60) });
    }

    pub fn timeout_secs(&self) -> u64 {
        self.inactivity_timeout.as_secs()
    }

    pub fn remaining_timeout_secs(&mut self) -> Option<u64> {
        self.expire_if_idle();
        if !self.unlocked || self.inactivity_timeout.is_zero() {
            return None;
        }

        self.last_activity.map(|last_activity| {
            self.inactivity_timeout
                .saturating_sub(last_activity.elapsed())
                .as_secs()
        })
    }

    pub fn set_auto_save(&mut self, enabled: bool) {
        self.auto_save = enabled;
    }

    pub fn auto_save(&self) -> bool {
        self.auto_save
    }

    pub fn set_recursive_scan(&mut self, recursive: bool) {
        self.recursive_scan = recursive;
    }

    pub fn recursive_scan(&self) -> bool {
        self.recursive_scan
    }

    fn expire_if_idle(&mut self) {
        if !self.unlocked {
            return;
        }
        if self.inactivity_timeout.is_zero() {
            return;
        }
        if let Some(last_activity) = self.last_activity {
            if last_activity.elapsed() >= self.inactivity_timeout {
                self.lock();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SessionManager;

    #[test]
    fn unlock_and_lock_cycle() {
        let mut session = SessionManager::default();
        session.unlock("secret".into());
        assert!(session.is_unlocked());
        session.lock();
        assert!(!session.is_unlocked());
    }
}
