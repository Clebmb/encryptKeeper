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
    pub key_id: String,
    pub fingerprint: String,
    pub user_ids: Vec<String>,
    pub has_secret: bool,
    pub algorithm: String,
    pub bits: u32,
    pub created_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub trust: String,
    pub capabilities: Vec<String>,
    pub is_selected_private: bool,
    pub is_selected_recipient: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySubkey {
    pub fingerprint: String,
    pub key_id: String,
    pub algorithm: String,
    pub bits: u32,
    pub created_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub capabilities: Vec<String>,
    pub has_secret: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDetails {
    pub summary: KeySummary,
    pub subkeys: Vec<KeySubkey>,
    pub certifications: Vec<KeyCertification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyCertification {
    pub signer_key_id: String,
    pub signer_fingerprint: Option<String>,
    pub signer_label: String,
    pub subject_user_id: Option<String>,
    pub created_at: Option<u64>,
    pub kind: String,
    pub is_self_signature: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperationResult {
    pub input_path: String,
    pub output_path: String,
    pub operation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportKeyResult {
    pub imported: u32,
    pub unchanged: u32,
    pub secret_imported: u32,
    pub fingerprints: Vec<String>,
    pub imported_fingerprints: Vec<String>,
    pub unchanged_fingerprints: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyActionResult {
    pub fingerprint: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X509CertificateSummary {
    pub fingerprint: String,
    pub key_id: String,
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub validity: String,
    pub algorithm: String,
    pub bits: u32,
    pub created_at: Option<String>,
    pub expires_at: Option<String>,
    pub has_secret: bool,
    pub is_trusted_root: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartcardStatus {
    pub available: bool,
    pub summary: String,
    pub reader: Option<String>,
    pub serial_number: Option<String>,
    pub application_id: Option<String>,
    pub manufacturer: Option<String>,
    pub cardholder: Option<String>,
    pub signature_key: Option<String>,
    pub encryption_key: Option<String>,
    pub authentication_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyserverSearchResult {
    pub fingerprint: String,
    pub algorithm: String,
    pub bits: u32,
    pub created_at: Option<u64>,
    pub user_ids: Vec<String>,
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
