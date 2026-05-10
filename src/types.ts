export type VaultKind = "none" | "folder" | "archive";

export interface KeySummary {
  key_id: string;
  fingerprint: string;
  user_ids: string[];
  has_secret: boolean;
  algorithm: string;
  bits: number;
  created_at: number | null;
  expires_at: number | null;
  trust: string;
  capabilities: string[];
  is_selected_private: boolean;
  is_selected_recipient: boolean;
}

export interface KeySubkey {
  fingerprint: string;
  key_id: string;
  algorithm: string;
  bits: number;
  created_at: number | null;
  expires_at: number | null;
  capabilities: string[];
  has_secret: boolean;
}

export interface KeyDetails {
  summary: KeySummary;
  subkeys: KeySubkey[];
  certifications: KeyCertification[];
}

export interface KeyCertification {
  signer_key_id: string;
  signer_fingerprint: string | null;
  signer_label: string;
  subject_user_id: string | null;
  created_at: number | null;
  kind: string;
  is_self_signature: boolean;
}

export interface NoteSummary {
  id: string;
  name: string;
  relative_path: string;
}

export interface SessionStatus {
  vault_kind: VaultKind;
  vault_path: string | null;
  archive_unlocked: boolean;
  session_unlocked: boolean;
  selected_private_key: string | null;
  selected_recipients: string[];
  inactivity_timeout_secs: number;
  remaining_auto_lock_secs: number | null;
  recursive_scan: boolean;
  auto_save: boolean;
}

export interface OpenNoteResult {
  note: NoteSummary;
  content: string;
}

export interface ClipboardNoteContent {
  content: string;
  was_decrypted: boolean;
  signature: NoteSignatureStatus | null;
}

export interface PinnedKeySettings {
  private_key_fingerprint: string | null;
  recipient_fingerprints: string[];
}

export interface NoteRecipientInfo {
  key_id: string;
  fingerprint: string | null;
  label: string;
  has_secret: boolean;
  is_selected_private: boolean;
  is_selected_recipient: boolean;
}

export interface NoteEncryptionStatus {
  recipients: NoteRecipientInfo[];
  can_decrypt_with_selected_key: boolean;
  matches_selected_recipients: boolean;
  signature: NoteSignatureStatus;
}

export interface NoteSignatureStatus {
  state: "none" | "good" | "bad" | "unknown";
  signer_key_id: string | null;
  signer_fingerprint: string | null;
  signer_label: string | null;
  summary: string;
}

export interface FileOperationResult {
  input_path: string;
  output_path: string;
  operation: string;
}

export interface ImportKeyResult {
  imported: number;
  unchanged: number;
  secret_imported: number;
  fingerprints: string[];
  imported_fingerprints: string[];
  unchanged_fingerprints: string[];
  summary: string;
}

export interface KeyActionResult {
  fingerprint: string;
  summary: string;
}

export interface X509CertificateSummary {
  fingerprint: string;
  key_id: string;
  subject: string;
  issuer: string;
  serial_number: string;
  validity: string;
  algorithm: string;
  bits: number;
  created_at: string | null;
  expires_at: string | null;
  has_secret: boolean;
  is_trusted_root: boolean;
}

export interface SmartcardStatus {
  available: boolean;
  summary: string;
  reader: string | null;
  serial_number: string | null;
  application_id: string | null;
  manufacturer: string | null;
  cardholder: string | null;
  signature_key: string | null;
  encryption_key: string | null;
  authentication_key: string | null;
}

export interface KeyserverSearchResult {
  fingerprint: string;
  algorithm: string;
  bits: number;
  created_at: number | null;
  user_ids: string[];
}
