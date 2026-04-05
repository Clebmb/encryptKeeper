use std::collections::HashSet;

use crate::{errors::AppResult, models::KeySummary};

#[derive(Default)]
pub struct KeyManager {
    selected_private_key: Option<String>,
    selected_recipients: HashSet<String>,
}

impl KeyManager {
    pub fn selected_private_key(&self) -> Option<String> {
        self.selected_private_key.clone()
    }

    pub fn selected_recipients(&self) -> Vec<String> {
        let mut recipients = self.selected_recipients.iter().cloned().collect::<Vec<_>>();
        recipients.sort();
        recipients
    }

    pub fn select_private_key(&mut self, fingerprint: String) {
        self.selected_private_key = Some(fingerprint);
    }

    pub fn set_recipients(&mut self, fingerprints: Vec<String>) -> AppResult<()> {
        self.selected_recipients = fingerprints.into_iter().collect();
        Ok(())
    }

    pub fn remove_key(&mut self, fingerprint: &str) {
        if self.selected_private_key.as_deref() == Some(fingerprint) {
            self.selected_private_key = None;
        }
        self.selected_recipients.remove(fingerprint);
    }

    pub fn map_keys(&self, mut keys: Vec<KeySummary>) -> Vec<KeySummary> {
        for key in &mut keys {
            key.is_selected_private = self
                .selected_private_key
                .as_ref()
                .is_some_and(|value| value == &key.fingerprint);
            key.is_selected_recipient = self.selected_recipients.contains(&key.fingerprint);
        }
        keys
    }
}
