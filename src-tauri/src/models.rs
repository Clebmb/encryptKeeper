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
pub struct ClipboardNoteContent {
    pub content: String,
    pub was_decrypted: bool,
    pub signature: Option<NoteSignatureStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PinnedKeySettings {
    pub private_key_fingerprint: Option<String>,
    pub recipient_fingerprints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteRecipientInfo {
    pub key_id: String,
    pub fingerprint: Option<String>,
    pub label: String,
    pub has_secret: bool,
    pub is_selected_private: bool,
    pub is_selected_recipient: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteEncryptionStatus {
    pub recipients: Vec<NoteRecipientInfo>,
    pub can_decrypt_with_selected_key: bool,
    pub matches_selected_recipients: bool,
    pub signature: NoteSignatureStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteSignatureStatus {
    pub state: String,
    pub signer_key_id: Option<String>,
    pub signer_fingerprint: Option<String>,
    pub signer_label: Option<String>,
    pub summary: String,
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
    pub remaining_auto_lock_secs: Option<u64>,
    pub recursive_scan: bool,
    pub auto_save: bool,
}
