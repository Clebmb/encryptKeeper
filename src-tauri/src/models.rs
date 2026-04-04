use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteSummary {
    pub id: String,
    pub name: String,
    pub relative_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenNoteResult {
    pub note: NoteSummary,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySummary {
    pub fingerprint: String,
    pub user_ids: Vec<String>,
    pub has_secret: bool,
    pub is_selected_private: bool,
    pub is_selected_recipient: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatus {
    pub vault_kind: String,
    pub vault_path: Option<String>,
    pub archive_unlocked: bool,
    pub session_unlocked: bool,
    pub selected_private_key: Option<String>,
    pub selected_recipients: Vec<String>,
    pub inactivity_timeout_secs: u64,
    pub recursive_scan: bool,
    pub auto_save: bool,
}
