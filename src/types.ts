export type VaultKind = "none" | "folder" | "archive";

export interface KeySummary {
  fingerprint: string;
  user_ids: string[];
  has_secret: boolean;
  is_selected_private: boolean;
  is_selected_recipient: boolean;
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
}
