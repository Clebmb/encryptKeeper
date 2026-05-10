use std::{
    fs,
    path::{Path, PathBuf},
};

use tauri::{AppHandle, Manager, State};
use walkdir::WalkDir;

use crate::{
    app_state::AppState,
    errors::{AppError, AppResult},
    models::{
        ClipboardNoteContent, FileOperationResult, ImportKeyResult, KeyActionResult, KeyDetails,
        KeySummary, KeyserverSearchResult, NoteEncryptionStatus, NoteRecipientInfo,
        NoteSignatureStatus, OpenNoteResult, PinnedKeySettings, SessionStatus, SmartcardStatus,
        X509CertificateSummary,
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

struct BatchInput {
    input_path: PathBuf,
    relative_output: PathBuf,
}

fn relative_output_with_extension(relative_output: &Path, suffix: &str) -> PathBuf {
    let mut output = relative_output.to_path_buf();
    let file_name = output
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}{suffix}"))
        .unwrap_or_else(|| format!("file{suffix}"));
    output.set_file_name(file_name);
    output
}

fn relative_output_without_gpg(relative_output: &Path) -> PathBuf {
    let mut output = relative_output.to_path_buf();
    let file_name = output
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| {
            value
                .strip_suffix(".gpg")
                .or_else(|| value.strip_suffix(".GPG"))
                .unwrap_or(value)
                .to_string()
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "file.decrypted".to_string());
    output.set_file_name(file_name);
    output
}

fn relative_output_without_suffix(
    relative_output: &Path,
    suffixes: &[&str],
    fallback_suffix: &str,
) -> PathBuf {
    let mut output = relative_output.to_path_buf();
    let file_name = output
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| {
            suffixes
                .iter()
                .find_map(|suffix| value.strip_suffix(suffix))
                .unwrap_or(value)
                .to_string()
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("file{fallback_suffix}"));
    output.set_file_name(file_name);
    output
}

fn collect_batch_inputs(input_paths: &[String]) -> AppResult<Vec<BatchInput>> {
    let mut batch_inputs = Vec::new();

    for input_path in input_paths {
        let source = PathBuf::from(input_path);
        if source.is_file() {
            batch_inputs.push(BatchInput {
                relative_output: PathBuf::from(file_name_string(&source)),
                input_path: source,
            });
            continue;
        }

        if source.is_dir() {
            let root_name = source
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("folder"));
            for entry in WalkDir::new(&source).into_iter().filter_map(Result::ok) {
                if !entry.file_type().is_file() {
                    continue;
                }
                let relative = entry
                    .path()
                    .strip_prefix(&source)
                    .map_err(|cause| AppError::External(cause.to_string()))?;
                batch_inputs.push(BatchInput {
                    input_path: entry.path().to_path_buf(),
                    relative_output: root_name.join(relative),
                });
            }
            continue;
        }

        return Err(AppError::Validation(format!(
            "Path could not be processed: {}",
            source.display()
        )));
    }

    Ok(batch_inputs)
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
        archive_unlocked: vault.is_archive_open(),
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
pub fn open_archive_vault(
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
    vault.open_archive(PathBuf::from(path), recursive)
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
    for batch_input in collect_batch_inputs(&input_paths)? {
        let output_path = PathBuf::from(&output_dir)
            .join(relative_output_with_extension(&batch_input.relative_output, ".gpg"));
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        state.crypto.encrypt_file_to_file(
            &recipients,
            &signer,
            &passphrase,
            batch_input.input_path.as_path(),
            output_path.as_path(),
        )?;
        results.push(FileOperationResult {
            input_path: batch_input.input_path.display().to_string(),
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
    for batch_input in collect_batch_inputs(&input_paths)? {
        let output_path =
            PathBuf::from(&output_dir).join(relative_output_without_gpg(&batch_input.relative_output));
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        state.crypto.decrypt_file_to_path(
            batch_input.input_path.as_path(),
            output_path.as_path(),
            &passphrase,
        )?;
        results.push(FileOperationResult {
            input_path: batch_input.input_path.display().to_string(),
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
    for batch_input in collect_batch_inputs(&input_paths)? {
        let output_path = PathBuf::from(&output_dir)
            .join(relative_output_with_extension(&batch_input.relative_output, ".sig"));
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        state.crypto.create_detached_signature(
            &signer,
            &passphrase,
            batch_input.input_path.as_path(),
            output_path.as_path(),
        )?;
        results.push(FileOperationResult {
            input_path: batch_input.input_path.display().to_string(),
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
pub fn encrypt_cms_files(
    input_paths: Vec<String>,
    output_dir: String,
    recipients: Vec<String>,
    state: State<'_, AppState>,
) -> AppResult<Vec<FileOperationResult>> {
    fs::create_dir_all(&output_dir)?;

    let mut results = Vec::new();
    for batch_input in collect_batch_inputs(&input_paths)? {
        let output_path = PathBuf::from(&output_dir)
            .join(relative_output_with_extension(&batch_input.relative_output, ".p7m"));
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        state.crypto.encrypt_cms_file_to_file(
            &recipients,
            batch_input.input_path.as_path(),
            output_path.as_path(),
        )?;
        results.push(FileOperationResult {
            input_path: batch_input.input_path.display().to_string(),
            output_path: output_path.display().to_string(),
            operation: "encrypt-cms".into(),
        });
    }
    Ok(results)
}

#[tauri::command]
pub fn decrypt_cms_files(
    input_paths: Vec<String>,
    output_dir: String,
    state: State<'_, AppState>,
) -> AppResult<Vec<FileOperationResult>> {
    fs::create_dir_all(&output_dir)?;

    let mut results = Vec::new();
    for batch_input in collect_batch_inputs(&input_paths)? {
        let output_path = PathBuf::from(&output_dir).join(relative_output_without_suffix(
            &batch_input.relative_output,
            &[".p7m", ".P7M"],
            ".decrypted",
        ));
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        state
            .crypto
            .decrypt_cms_file_to_path(batch_input.input_path.as_path(), output_path.as_path())?;
        results.push(FileOperationResult {
            input_path: batch_input.input_path.display().to_string(),
            output_path: output_path.display().to_string(),
            operation: "decrypt-cms".into(),
        });
    }
    Ok(results)
}

#[tauri::command]
pub fn sign_cms_files(
    input_paths: Vec<String>,
    output_dir: String,
    signer: String,
    state: State<'_, AppState>,
) -> AppResult<Vec<FileOperationResult>> {
    fs::create_dir_all(&output_dir)?;

    let mut results = Vec::new();
    for batch_input in collect_batch_inputs(&input_paths)? {
        let output_path = PathBuf::from(&output_dir)
            .join(relative_output_with_extension(&batch_input.relative_output, ".p7s"));
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        state.crypto.create_cms_detached_signature(
            &signer,
            batch_input.input_path.as_path(),
            output_path.as_path(),
        )?;
        results.push(FileOperationResult {
            input_path: batch_input.input_path.display().to_string(),
            output_path: output_path.display().to_string(),
            operation: "sign-cms".into(),
        });
    }
    Ok(results)
}

#[tauri::command]
pub fn verify_cms_file_signature(
    input_path: String,
    signature_path: String,
    state: State<'_, AppState>,
) -> AppResult<NoteSignatureStatus> {
    state.crypto.verify_cms_detached_signature(
        PathBuf::from(signature_path).as_path(),
        PathBuf::from(input_path).as_path(),
    )
}

#[tauri::command]
pub fn import_key_from_file(
    path: String,
    state: State<'_, AppState>,
) -> AppResult<ImportKeyResult> {
    state.crypto.import_key(PathBuf::from(path).as_path())
}

#[tauri::command]
pub fn import_key_from_text(
    armored_text: String,
    state: State<'_, AppState>,
) -> AppResult<ImportKeyResult> {
    state.crypto.import_key_text(&armored_text)
}

#[tauri::command]
pub fn lookup_key(query: String, state: State<'_, AppState>) -> AppResult<ImportKeyResult> {
    state.crypto.locate_keys(&query)
}

#[tauri::command]
pub fn search_keyserver(
    query: String,
    state: State<'_, AppState>,
) -> AppResult<Vec<KeyserverSearchResult>> {
    state.crypto.search_keyserver(&query)
}

#[tauri::command]
pub fn import_key_from_keyserver(
    fingerprint: String,
    state: State<'_, AppState>,
) -> AppResult<ImportKeyResult> {
    state.crypto.receive_key_from_keyserver(&fingerprint)
}

#[tauri::command]
pub fn publish_key_to_keyserver(
    fingerprint: String,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state.crypto.send_key_to_keyserver(&fingerprint)
}

#[tauri::command]
pub fn refresh_key_from_keyserver(
    fingerprint: String,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state.crypto.refresh_key_from_keyserver(&fingerprint)
}

#[tauri::command]
pub fn refresh_all_keys_from_keyserver(state: State<'_, AppState>) -> AppResult<KeyActionResult> {
    state.crypto.refresh_all_keys_from_keyserver()
}

#[tauri::command]
pub fn add_subkey(
    fingerprint: String,
    algorithm: String,
    usage: String,
    expire: String,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    let passphrase = require_session_passphrase(&state)?;
    state
        .crypto
        .quick_add_subkey(&fingerprint, &passphrase, &algorithm, &usage, &expire)
}

#[tauri::command]
pub fn change_key_passphrase(
    fingerprint: String,
    new_passphrase: String,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    let current_passphrase = require_session_passphrase(&state)?;
    let selected_private_key = state
        .keys
        .read()
        .map_err(|_| AppError::External("key manager lock poisoned".into()))?
        .selected_private_key()
        .ok_or(AppError::MissingPrivateKeySelection)?;
    if !selected_private_key.eq_ignore_ascii_case(&fingerprint) {
        return Err(AppError::Validation(
            "Select and unlock this private key before changing its passphrase.".into(),
        ));
    }

    let result = state
        .crypto
        .change_key_passphrase(&fingerprint, &current_passphrase, &new_passphrase)?;
    let mut session = state
        .session
        .write()
        .map_err(|_| AppError::External("session lock poisoned".into()))?;
    session.unlock(new_passphrase);
    Ok(result)
}

#[tauri::command]
pub fn export_ownertrust(
    output_path: String,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state
        .crypto
        .export_ownertrust(PathBuf::from(output_path).as_path())
}

#[tauri::command]
pub fn import_ownertrust(
    input_path: String,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state
        .crypto
        .import_ownertrust(PathBuf::from(input_path).as_path())
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
    let signatures_listing = state.crypto.list_key_signatures(&fingerprint)?;
    let details = state
        .crypto
        .key_details(&public_listing, &secret_listing, &signatures_listing, &fingerprint)
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
        certifications: details.certifications,
    })
}

#[tauri::command]
pub fn get_smartcard_status(state: State<'_, AppState>) -> AppResult<SmartcardStatus> {
    state.crypto.smartcard_status()
}

#[tauri::command]
pub fn list_x509_certificates(state: State<'_, AppState>) -> AppResult<Vec<X509CertificateSummary>> {
    state.crypto.list_x509_certificates()
}

#[tauri::command]
pub fn learn_x509_card(state: State<'_, AppState>) -> AppResult<KeyActionResult> {
    state.crypto.learn_x509_card()
}

#[tauri::command]
pub fn create_x509_certificate(
    common_name: String,
    organization: String,
    email: String,
    expires_at: String,
    passphrase: String,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state.crypto.create_x509_certificate(
        &common_name,
        &organization,
        &email,
        &expires_at,
        &passphrase,
    )
}

#[tauri::command]
pub fn import_x509_certificate(path: String, state: State<'_, AppState>) -> AppResult<KeyActionResult> {
    state.crypto.import_x509_certificate(PathBuf::from(path).as_path())
}

#[tauri::command]
pub fn import_x509_certificate_text(
    certificate_text: String,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state.crypto.import_x509_certificate_text(&certificate_text)
}

#[tauri::command]
pub fn export_x509_certificate(
    fingerprint: String,
    output_path: String,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state
        .crypto
        .export_x509_certificate(&fingerprint, PathBuf::from(output_path).as_path())
}

#[tauri::command]
pub fn export_x509_secret_key_p12(
    fingerprint: String,
    output_path: String,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state
        .crypto
        .export_x509_secret_key_p12(&fingerprint, PathBuf::from(output_path).as_path())
}

#[tauri::command]
pub fn export_x509_secret_key_p8(
    fingerprint: String,
    output_path: String,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state
        .crypto
        .export_x509_secret_key_p8(&fingerprint, PathBuf::from(output_path).as_path())
}

#[tauri::command]
pub fn change_x509_passphrase(
    fingerprint: String,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state.crypto.change_x509_passphrase(&fingerprint)
}

#[tauri::command]
pub fn delete_x509_certificate(
    fingerprint: String,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state.crypto.delete_x509_certificate(&fingerprint)
}

#[tauri::command]
pub fn get_x509_certificate_chain(
    fingerprint: String,
    state: State<'_, AppState>,
) -> AppResult<String> {
    state.crypto.list_x509_certificate_chain(&fingerprint)
}

#[tauri::command]
pub fn import_x509_crl(path: String, state: State<'_, AppState>) -> AppResult<KeyActionResult> {
    state.crypto.import_x509_crl(PathBuf::from(path).as_path())
}

#[tauri::command]
pub fn set_x509_trust_root(
    fingerprint: String,
    trusted: bool,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state.crypto.set_x509_trust_root(&fingerprint, trusted)
}

#[tauri::command]
pub fn export_x509_trustlist(
    output_path: String,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state
        .crypto
        .export_x509_trustlist(PathBuf::from(output_path).as_path())
}

#[tauri::command]
pub fn import_x509_trustlist(
    input_path: String,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state
        .crypto
        .import_x509_trustlist(PathBuf::from(input_path).as_path())
}

#[tauri::command]
pub fn restart_smartcard_service(state: State<'_, AppState>) -> AppResult<KeyActionResult> {
    state.crypto.restart_smartcard_service()
}

#[tauri::command]
pub fn change_smartcard_pin(state: State<'_, AppState>) -> AppResult<KeyActionResult> {
    state.crypto.change_smartcard_pin()
}

#[tauri::command]
pub fn fetch_smartcard_public_key(state: State<'_, AppState>) -> AppResult<KeyActionResult> {
    state.crypto.fetch_smartcard_public_key()
}

#[tauri::command]
pub fn create_smartcard_key_stubs(state: State<'_, AppState>) -> AppResult<KeyActionResult> {
    state.crypto.create_smartcard_key_stubs()
}

#[tauri::command]
pub fn generate_smartcard_key(
    slot: String,
    algorithm: String,
    force: bool,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state.crypto.generate_smartcard_key(&slot, &algorithm, force)
}

#[tauri::command]
pub fn factory_reset_smartcard(state: State<'_, AppState>) -> AppResult<KeyActionResult> {
    state.crypto.factory_reset_smartcard()
}

#[tauri::command]
pub fn move_secret_key_to_smartcard(
    fingerprint: String,
    slot: String,
    force: bool,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state
        .crypto
        .move_secret_key_to_smartcard(&fingerprint, &slot, force)
}

#[tauri::command]
pub fn set_key_expiry(
    fingerprint: String,
    expire: String,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state.crypto.quick_set_expire(&fingerprint, &expire)
}

#[tauri::command]
pub fn set_key_ownertrust(
    fingerprint: String,
    trust: String,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state.crypto.quick_set_ownertrust(&fingerprint, &trust)
}

#[tauri::command]
pub fn certify_key(
    fingerprint: String,
    local_only: bool,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    let passphrase = require_session_passphrase(&state)?;
    let (signer, _) = selected_key_context(&state)?;
    state
        .crypto
        .quick_sign_key(&signer, &passphrase, &fingerprint, local_only)
}

#[tauri::command]
pub fn export_revocation_certificate(
    fingerprint: String,
    passphrase: String,
    output_path: String,
    state: State<'_, AppState>,
) -> AppResult<KeyActionResult> {
    state.crypto.export_revocation_certificate(
        &fingerprint,
        &passphrase,
        PathBuf::from(output_path).as_path(),
    )
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

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::{collect_batch_inputs, relative_output_with_extension, relative_output_without_gpg};

    #[test]
    fn expands_folder_inputs_and_preserves_relative_structure() {
        let temp = TempDir::new().expect("temp dir");
        let root = temp.path().join("batch");
        fs::create_dir_all(root.join("nested")).expect("create nested");
        fs::write(root.join("top.txt"), "top").expect("write top");
        fs::write(root.join("nested").join("inside.txt"), "inside").expect("write nested");

        let inputs = collect_batch_inputs(&[root.display().to_string()]).expect("collect batch inputs");

        assert_eq!(inputs.len(), 2);
        let mut relative_outputs = inputs
            .iter()
            .map(|item| item.relative_output.display().to_string())
            .collect::<Vec<_>>();
        relative_outputs.sort();
        assert_eq!(
            relative_outputs,
            vec![
                "batch\\nested\\inside.txt".to_string(),
                "batch\\top.txt".to_string()
            ]
        );
    }

    #[test]
    fn transforms_relative_output_names_for_batch_operations() {
        assert_eq!(
            relative_output_with_extension("reports\\daily.txt".as_ref(), ".gpg")
                .display()
                .to_string(),
            "reports\\daily.txt.gpg"
        );
        assert_eq!(
            relative_output_without_gpg("reports\\daily.txt.gpg".as_ref())
                .display()
                .to_string(),
            "reports\\daily.txt"
        );
    }
}
