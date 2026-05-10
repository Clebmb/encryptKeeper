use std::{fs, path::PathBuf};

use tauri::{AppHandle, Manager, State};

use crate::{
    app_state::AppState,
    errors::{AppError, AppResult},
    models::{
        ClipboardNoteContent, FileOperationResult, KeyDetails, KeySummary, NoteEncryptionStatus,
        NoteRecipientInfo, NoteSignatureStatus, OpenNoteResult, PinnedKeySettings, SessionStatus,
    },
};

fn app_config_dir(app: &AppHandle) -> AppResult<PathBuf> {
    app.path()
        .app_config_dir()
        .map_err(|cause| AppError::External(cause.to_string()))
}

fn require_session_passphrase(state: &State<'_, AppState>) -> AppResult<String> {
    let mut session = state
        .session
        .write()
        .map_err(|_| AppError::External("session lock poisoned".into()))?;
    Ok(session.ensure_unlocked()?.to_string())
}

fn selected_key_context(state: &State<'_, AppState>) -> AppResult<(String, Vec<String>)> {
    let key_manager = state
        .keys
        .read()
        .map_err(|_| AppError::External("key manager lock poisoned".into()))?;
    let signer = key_manager
        .selected_private_key()
        .ok_or(AppError::MissingPrivateKeySelection)?;
    Ok((signer, key_manager.selected_recipients()))
}

fn key_identities(state: &State<'_, AppState>) -> AppResult<Vec<crate::services::crypto_service::ParsedKeyIdentity>> {
    let public_listing = state.crypto.list_keys(false)?;
    let secret_listing = state.crypto.list_keys(true)?;
    Ok(state
        .crypto
        .parse_key_identities(&public_listing, &secret_listing))
}

fn file_name_string(path: &PathBuf) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| "file".to_string())
}

fn encrypted_output_path(output_dir: &str, input_path: &str) -> PathBuf {
    let source = PathBuf::from(input_path);
    let mut file_name = file_name_string(&source);
    if !file_name.ends_with(".gpg") {
        file_name.push_str(".gpg");
    }
    PathBuf::from(output_dir).join(file_name)
}

fn detached_signature_output_path(output_dir: &str, input_path: &str) -> PathBuf {
    let source = PathBuf::from(input_path);
    let file_name = format!("{}.sig", file_name_string(&source));
    PathBuf::from(output_dir).join(file_name)
}

fn decrypted_output_path(output_dir: &str, input_path: &str) -> PathBuf {
    let source = PathBuf::from(input_path);
    let file_name = file_name_string(&source);
    let final_name = if let Some(trimmed) = file_name.strip_suffix(".gpg") {
        trimmed.to_string()
    } else {
        format!("{file_name}.decrypted")
    };
    PathBuf::from(output_dir).join(final_name)
}

#[tauri::command]
pub fn get_status(state: State<'_, AppState>) -> AppResult<SessionStatus> {
    let mut session = state
        .session
        .write()
        .map_err(|_| AppError::External("session lock poisoned".into()))?;
    let keys = state
        .keys
        .read()
        .map_err(|_| AppError::External("key manager lock poisoned".into()))?;
    let vault = state
        .vault
        .read()
        .map_err(|_| AppError::External("vault lock poisoned".into()))?;

    Ok(SessionStatus {
        vault_kind: vault.vault_kind().to_string(),
        vault_path: vault.vault_path(),
        archive_unlocked: false,
        session_unlocked: session.is_unlocked(),
        selected_private_key: keys.selected_private_key(),
        selected_recipients: keys.selected_recipients(),
        inactivity_timeout_secs: session.timeout_secs(),
        remaining_auto_lock_secs: session.remaining_timeout_secs(),
        recursive_scan: session.recursive_scan(),
        auto_save: session.auto_save(),
    })
}

#[tauri::command]
pub fn open_folder_vault(
    path: String,
    recursive: bool,
    state: State<'_, AppState>,
) -> AppResult<Vec<crate::models::NoteSummary>> {
    let mut session = state
        .session
        .write()
        .map_err(|_| AppError::External("session lock poisoned".into()))?;
    session.set_recursive_scan(recursive);
    let mut vault = state
        .vault
        .write()
        .map_err(|_| AppError::External("vault lock poisoned".into()))?;
    vault.open_folder(PathBuf::from(path), recursive)
}

#[tauri::command]
pub fn list_notes(state: State<'_, AppState>) -> AppResult<Vec<crate::models::NoteSummary>> {
    let vault = state
        .vault
        .read()
        .map_err(|_| AppError::External("vault lock poisoned".into()))?;
    vault.list_notes()
}

#[tauri::command]
pub fn refresh_notes(state: State<'_, AppState>) -> AppResult<Vec<crate::models::NoteSummary>> {
    let mut vault = state
        .vault
        .write()
        .map_err(|_| AppError::External("vault lock poisoned".into()))?;
    vault.refresh_active_vault()
}

#[tauri::command]
pub fn open_note(note_id: String, state: State<'_, AppState>) -> AppResult<OpenNoteResult> {
    let passphrase = require_session_passphrase(&state)?;
    let vault = state
        .vault
        .read()
        .map_err(|_| AppError::External("vault lock poisoned".into()))?;
    let note = vault
        .list_notes()?
        .into_iter()
        .find(|note| note.id == note_id)
        .ok_or(AppError::NoteNotFound)?;
    let path = vault.note_path(&note_id)?;
    let decrypted = state.crypto.decrypt_file(&path, &passphrase)?;
    Ok(OpenNoteResult {
        note,
        content: decrypted.content,
    })
}

#[tauri::command]
pub fn open_note_with_password(
    note_id: String,
    password: String,
    state: State<'_, AppState>,
) -> AppResult<OpenNoteResult> {
    if password.is_empty() {
        return Err(AppError::Validation("Password is required.".into()));
    }
    let vault = state
        .vault
        .read()
        .map_err(|_| AppError::External("vault lock poisoned".into()))?;
    let note = vault
        .list_notes()?
        .into_iter()
        .find(|note| note.id == note_id)
        .ok_or(AppError::NoteNotFound)?;
    let path = vault.note_path(&note_id)?;
    let decrypted = state.crypto.decrypt_symmetric_file(&path, &password)?;
    Ok(OpenNoteResult {
        note,
        content: decrypted.content,
    })
}

#[tauri::command]
pub fn resolve_clipboard_note_content(
    raw_content: String,
    state: State<'_, AppState>,
) -> AppResult<ClipboardNoteContent> {
    let trimmed = raw_content.trim();
    if trimmed.contains("-----BEGIN PGP SIGNED MESSAGE-----")
        && trimmed.contains("-----BEGIN PGP SIGNATURE-----")
    {
        let identities = key_identities(&state)?;
        let verified = state.crypto.verify_clear_signed_text(&raw_content)?;
        return Ok(ClipboardNoteContent {
            content: verified.content,
            was_decrypted: true,
            signature: Some(
                state
                    .crypto
                    .enrich_signature_status(verified.signature, &identities),
            ),
        });
    }

    if !trimmed.contains("-----BEGIN PGP MESSAGE-----")
        || !trimmed.contains("-----END PGP MESSAGE-----")
    {
        return Ok(ClipboardNoteContent {
            content: raw_content,
            was_decrypted: false,
            signature: None,
        });
    }

    let passphrase = require_session_passphrase(&state)?;

    match state.crypto.decrypt_armored_text(&raw_content, &passphrase) {
        Ok(decrypted) => {
            let identities = key_identities(&state)?;
            Ok(ClipboardNoteContent {
                content: decrypted.content,
                was_decrypted: true,
                signature: Some(
                    state
                        .crypto
                        .enrich_signature_status(decrypted.signature, &identities),
                ),
            })
        }
        Err(AppError::MissingPrivateKey | AppError::InvalidGpgFile) => Ok(ClipboardNoteContent {
            content: raw_content,
            was_decrypted: false,
            signature: None,
        }),
        Err(cause) => Err(cause),
    }
}

#[tauri::command]
pub fn save_note(
    note_id: String,
    content: String,
    use_signature: bool,
    state: State<'_, AppState>,
) -> AppResult<()> {
    let passphrase = require_session_passphrase(&state)?;
    let (signer, recipients) = selected_key_context(&state)?;
    let vault = state
        .vault
        .read()
        .map_err(|_| AppError::External("vault lock poisoned".into()))?;
    vault.atomic_write_encrypted(&note_id, |temp_path| {
        if use_signature || recipients.is_empty() {
            state
                .crypto
                .sign_text_to_file(&signer, &passphrase, &content, temp_path)
        } else {
            state.crypto.encrypt_text_to_file(
                &recipients,
                &signer,
                &passphrase,
                &content,
                temp_path,
            )
        }
    })
}

#[tauri::command]
pub fn save_note_with_password(
    note_id: String,
    content: String,
    password: String,
    state: State<'_, AppState>,
) -> AppResult<()> {
    let vault = state
        .vault
        .read()
        .map_err(|_| AppError::External("vault lock poisoned".into()))?;
    vault.atomic_write_encrypted(&note_id, |temp_path| {
        state
            .crypto
            .encrypt_text_symmetric_to_file(&password, &content, temp_path)
    })
}

#[tauri::command]
pub fn preview_pgp_block(
    content: String,
    use_signature: bool,
    state: State<'_, AppState>,
) -> AppResult<String> {
    let passphrase = require_session_passphrase(&state)?;
    let (signer, recipients) = selected_key_context(&state)?;
    if use_signature || recipients.is_empty() {
        state
            .crypto
            .sign_text_to_armor(&signer, &passphrase, &content)
    } else {
        state
            .crypto
            .encrypt_text_to_armor(&recipients, &signer, &passphrase, &content)
    }
}

#[tauri::command]
pub fn verify_clipboard_signature(
    signature_text: String,
    content: String,
    state: State<'_, AppState>,
) -> AppResult<NoteSignatureStatus> {
    let identities = key_identities(&state)?;
    let temp_dir = state.secure_temp.create_scoped_dir("encryptkeeper-verify")?;
    let signature_path = temp_dir.file_path("clipboard.sig");
    let content_path = temp_dir.file_path("clipboard.txt");
    fs::write(&signature_path, signature_text)?;
    fs::write(&content_path, content)?;
    let signature = state
        .crypto
        .verify_detached_signature(&signature_path, &content_path)?;
    Ok(state.crypto.enrich_signature_status(signature, &identities))
}

#[tauri::command]
pub fn inspect_note_encryption(
    note_id: String,
    state: State<'_, AppState>,
) -> AppResult<NoteEncryptionStatus> {
    let path = state
        .vault
        .read()
        .map_err(|_| AppError::External("vault lock poisoned".into()))?
        .note_path(&note_id)?;
    let identities = key_identities(&state)?;
    let key_manager = state
        .keys
        .read()
        .map_err(|_| AppError::External("key manager lock poisoned".into()))?;
    let selected_private = key_manager.selected_private_key();
    let selected_recipients = key_manager.selected_recipients();
    let recipient_key_ids = state.crypto.inspect_file_recipients(&path)?;
    let signature = match require_session_passphrase(&state) {
        Ok(passphrase) => match state.crypto.decrypt_file(&path, &passphrase) {
            Ok(decrypted) => state
                .crypto
                .enrich_signature_status(decrypted.signature, &identities),
            Err(_) => NoteSignatureStatus {
                state: "unknown".into(),
                signer_key_id: None,
                signer_fingerprint: None,
                signer_label: None,
                summary:
                    "Signature status is unavailable because this note could not be decrypted with the active key."
                        .into(),
            },
        },
        Err(_) => NoteSignatureStatus {
            state: "unknown".into(),
            signer_key_id: None,
            signer_fingerprint: None,
            signer_label: None,
            summary: "Unlock the session to verify this note's signature.".into(),
        },
    };

    let mut recipients = Vec::new();
    let mut file_primary_fingerprints = std::collections::HashSet::new();
    let mut can_decrypt_with_selected_key = false;

    for key_id in recipient_key_ids {
        if let Some(identity) = identities
            .iter()
            .find(|identity| identity.key_ids.contains(&key_id))
        {
            let fingerprint = identity.primary_fingerprint.clone();
            if selected_private
                .as_ref()
                .is_some_and(|value| value == &fingerprint)
            {
                can_decrypt_with_selected_key = true;
            }
            file_primary_fingerprints.insert(fingerprint.clone());
            recipients.push(NoteRecipientInfo {
                key_id,
                fingerprint: Some(fingerprint.clone()),
                label: identity
                    .user_ids
                    .first()
                    .cloned()
                    .unwrap_or_else(|| fingerprint.clone()),
                has_secret: identity.has_secret,
                is_selected_private: selected_private
                    .as_ref()
                    .is_some_and(|value| value == &fingerprint),
                is_selected_recipient: selected_recipients.contains(&fingerprint),
            });
        } else {
            recipients.push(NoteRecipientInfo {
                key_id: key_id.clone(),
                fingerprint: None,
                label: format!("Unknown key {key_id}"),
                has_secret: false,
                is_selected_private: false,
                is_selected_recipient: false,
            });
        }
    }

    let selected_recipient_set = selected_recipients
        .into_iter()
        .collect::<std::collections::HashSet<_>>();

    Ok(NoteEncryptionStatus {
        recipients,
        can_decrypt_with_selected_key,
        matches_selected_recipients: file_primary_fingerprints == selected_recipient_set,
        signature,
    })
}

#[tauri::command]
pub fn create_note(
    name: String,
    content: String,
    use_signature: bool,
    state: State<'_, AppState>,
) -> AppResult<crate::models::NoteSummary> {
    let passphrase = require_session_passphrase(&state)?;
    let (signer, recipients) = selected_key_context(&state)?;
    let mut vault = state
        .vault
        .write()
        .map_err(|_| AppError::External("vault lock poisoned".into()))?;
    let note = vault.create_note_record(&name)?;
    vault.atomic_write_encrypted(&note.id, |temp_path| {
        if use_signature || recipients.is_empty() {
            state
                .crypto
                .sign_text_to_file(&signer, &passphrase, &content, temp_path)
        } else {
            state.crypto.encrypt_text_to_file(
                &recipients,
                &signer,
                &passphrase,
                &content,
                temp_path,
            )
        }
    })?;
    Ok(note)
}

#[tauri::command]
pub fn create_note_with_password(
    name: String,
    content: String,
    password: String,
    state: State<'_, AppState>,
) -> AppResult<crate::models::NoteSummary> {
    let mut vault = state
        .vault
        .write()
        .map_err(|_| AppError::External("vault lock poisoned".into()))?;
    let note = vault.create_note_record(&name)?;
    vault.atomic_write_encrypted(&note.id, |temp_path| {
        state
            .crypto
            .encrypt_text_symmetric_to_file(&password, &content, temp_path)
    })?;
    Ok(note)
}

#[tauri::command]
pub fn rename_note(
    note_id: String,
    new_name: String,
    state: State<'_, AppState>,
) -> AppResult<crate::models::NoteSummary> {
    let mut vault = state
        .vault
        .write()
        .map_err(|_| AppError::External("vault lock poisoned".into()))?;
    vault.rename_note_record(&note_id, &new_name)
}

#[tauri::command]
pub fn delete_note(note_id: String, state: State<'_, AppState>) -> AppResult<()> {
    let mut vault = state
        .vault
        .write()
        .map_err(|_| AppError::External("vault lock poisoned".into()))?;
    vault.delete_note(&note_id)
}

#[tauri::command]
pub fn encrypt_files(
    input_paths: Vec<String>,
    output_dir: String,
    state: State<'_, AppState>,
) -> AppResult<Vec<FileOperationResult>> {
    let passphrase = require_session_passphrase(&state)?;
    let (signer, recipients) = selected_key_context(&state)?;
    fs::create_dir_all(&output_dir)?;

    let mut results = Vec::new();
    for input_path in input_paths {
        let output_path = encrypted_output_path(&output_dir, &input_path);
        state.crypto.encrypt_file_to_file(
            &recipients,
            &signer,
            &passphrase,
            PathBuf::from(&input_path).as_path(),
            output_path.as_path(),
        )?;
        results.push(FileOperationResult {
            input_path: input_path.clone(),
            output_path: output_path.display().to_string(),
            operation: "encrypt".into(),
        });
    }
    Ok(results)
}

#[tauri::command]
pub fn decrypt_files(
    input_paths: Vec<String>,
    output_dir: String,
    state: State<'_, AppState>,
) -> AppResult<Vec<FileOperationResult>> {
    let passphrase = require_session_passphrase(&state)?;
    fs::create_dir_all(&output_dir)?;

    let mut results = Vec::new();
    for input_path in input_paths {
        let output_path = decrypted_output_path(&output_dir, &input_path);
        state.crypto.decrypt_file_to_path(
            PathBuf::from(&input_path).as_path(),
            output_path.as_path(),
            &passphrase,
        )?;
        results.push(FileOperationResult {
            input_path: input_path.clone(),
            output_path: output_path.display().to_string(),
            operation: "decrypt".into(),
        });
    }
    Ok(results)
}

#[tauri::command]
pub fn sign_files(
    input_paths: Vec<String>,
    output_dir: String,
    state: State<'_, AppState>,
) -> AppResult<Vec<FileOperationResult>> {
    let passphrase = require_session_passphrase(&state)?;
    let (signer, _) = selected_key_context(&state)?;
    fs::create_dir_all(&output_dir)?;

    let mut results = Vec::new();
    for input_path in input_paths {
        let output_path = detached_signature_output_path(&output_dir, &input_path);
        state.crypto.create_detached_signature(
            &signer,
            &passphrase,
            PathBuf::from(&input_path).as_path(),
            output_path.as_path(),
        )?;
        results.push(FileOperationResult {
            input_path: input_path.clone(),
            output_path: output_path.display().to_string(),
            operation: "sign".into(),
        });
    }
    Ok(results)
}

#[tauri::command]
pub fn verify_file_signature(
    input_path: String,
    signature_path: String,
    state: State<'_, AppState>,
) -> AppResult<NoteSignatureStatus> {
    let identities = key_identities(&state)?;
    let signature = state.crypto.verify_detached_signature(
        PathBuf::from(signature_path).as_path(),
        PathBuf::from(input_path).as_path(),
    )?;
    Ok(state.crypto.enrich_signature_status(signature, &identities))
}

#[tauri::command]
pub fn import_key_from_file(path: String, state: State<'_, AppState>) -> AppResult<()> {
    state.crypto.import_key(PathBuf::from(path).as_path())
}

#[tauri::command]
pub fn import_key_from_text(armored_text: String, state: State<'_, AppState>) -> AppResult<()> {
    state.crypto.import_key_text(&armored_text)
}

#[tauri::command]
pub fn create_key(
    name: String,
    email: String,
    passphrase: String,
    state: State<'_, AppState>,
) -> AppResult<()> {
    state.crypto.create_key(&name, &email, &passphrase)
}

#[tauri::command]
pub fn list_keys(state: State<'_, AppState>) -> AppResult<Vec<KeySummary>> {
    let public_listing = state.crypto.list_keys(false)?;
    let secret_listing = state.crypto.list_keys(true)?;
    let keys = state.crypto.parse_keys(&public_listing, &secret_listing);
    let key_manager = state
        .keys
        .read()
        .map_err(|_| AppError::External("key manager lock poisoned".into()))?;
    Ok(key_manager.map_keys(keys))
}

#[tauri::command]
pub fn get_key_details(
    fingerprint: String,
    state: State<'_, AppState>,
) -> AppResult<KeyDetails> {
    let public_listing = state.crypto.list_keys(false)?;
    let secret_listing = state.crypto.list_keys(true)?;
    let details = state
        .crypto
        .key_details(&public_listing, &secret_listing, &fingerprint)
        .ok_or_else(|| AppError::Validation("Key details could not be loaded.".into()))?;
    let key_manager = state
        .keys
        .read()
        .map_err(|_| AppError::External("key manager lock poisoned".into()))?;
    let mut summary = details.summary;
    summary.is_selected_private = key_manager
        .selected_private_key()
        .as_ref()
        .is_some_and(|value| value == &summary.fingerprint);
    summary.is_selected_recipient = key_manager
        .selected_recipients()
        .contains(&summary.fingerprint);
    Ok(KeyDetails {
        summary,
        subkeys: details.subkeys,
    })
}

#[tauri::command]
pub fn get_pinned_key_settings(
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<PinnedKeySettings> {
    let config_dir = app_config_dir(&app)?;
    state.pinned_settings.load(&config_dir)
}

#[tauri::command]
pub fn save_pinned_key_settings(
    private_key_fingerprint: Option<String>,
    recipient_fingerprints: Vec<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<PinnedKeySettings> {
    let config_dir = app_config_dir(&app)?;
    let settings = PinnedKeySettings {
        private_key_fingerprint,
        recipient_fingerprints,
    };
    state.pinned_settings.save(&config_dir, &settings)?;
    Ok(settings)
}

#[tauri::command]
pub fn select_private_key(fingerprint: String, state: State<'_, AppState>) -> AppResult<()> {
    let mut keys = state
        .keys
        .write()
        .map_err(|_| AppError::External("key manager lock poisoned".into()))?;
    keys.select_private_key(fingerprint);
    Ok(())
}

#[tauri::command]
pub fn export_public_key(
    fingerprint: String,
    output_path: String,
    state: State<'_, AppState>,
) -> AppResult<()> {
    state
        .crypto
        .export_public_key(&fingerprint, PathBuf::from(output_path).as_path())
}

#[tauri::command]
pub fn export_private_key(
    fingerprint: String,
    passphrase: String,
    output_path: String,
    state: State<'_, AppState>,
) -> AppResult<()> {
    state.crypto.export_secret_key(
        &fingerprint,
        &passphrase,
        PathBuf::from(output_path).as_path(),
    )
}

#[tauri::command]
pub fn remove_key(
    fingerprint: String,
    has_secret: bool,
    state: State<'_, AppState>,
) -> AppResult<()> {
    state.crypto.delete_key(&fingerprint, has_secret)?;
    let mut keys = state
        .keys
        .write()
        .map_err(|_| AppError::External("key manager lock poisoned".into()))?;
    keys.remove_key(&fingerprint);
    Ok(())
}

#[tauri::command]
pub fn set_recipients(fingerprints: Vec<String>, state: State<'_, AppState>) -> AppResult<()> {
    let mut keys = state
        .keys
        .write()
        .map_err(|_| AppError::External("key manager lock poisoned".into()))?;
    keys.set_recipients(fingerprints)
}

#[tauri::command]
pub fn unlock_session(passphrase: String, state: State<'_, AppState>) -> AppResult<()> {
    let private_key = state
        .keys
        .read()
        .map_err(|_| AppError::External("key manager lock poisoned".into()))?
        .selected_private_key()
        .ok_or(AppError::MissingPrivateKeySelection)?;
    state.crypto.verify_passphrase(&private_key, &passphrase)?;
    let mut session = state
        .session
        .write()
        .map_err(|_| AppError::External("session lock poisoned".into()))?;
    session.unlock(passphrase);
    Ok(())
}

#[tauri::command]
pub fn lock_session(state: State<'_, AppState>) -> AppResult<()> {
    let mut session = state
        .session
        .write()
        .map_err(|_| AppError::External("session lock poisoned".into()))?;
    session.lock();
    Ok(())
}

#[tauri::command]
pub fn update_preferences(
    recursive_scan: bool,
    inactivity_timeout_secs: u64,
    auto_save: bool,
    state: State<'_, AppState>,
) -> AppResult<SessionStatus> {
    {
        let mut session = state
            .session
            .write()
            .map_err(|_| AppError::External("session lock poisoned".into()))?;
        session.set_recursive_scan(recursive_scan);
        session.set_timeout_secs(inactivity_timeout_secs);
        session.set_auto_save(auto_save);
    }
    get_status(state)
}
