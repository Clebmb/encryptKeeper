use std::path::PathBuf;

use tauri::State;

use crate::{
    app_state::AppState,
    errors::{AppError, AppResult},
    models::{KeySummary, OpenNoteResult, SessionStatus},
};

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
pub fn open_note(note_id: String, state: State<'_, AppState>) -> AppResult<OpenNoteResult> {
    let mut session = state
        .session
        .write()
        .map_err(|_| AppError::External("session lock poisoned".into()))?;
    let passphrase = session.ensure_unlocked()?.to_string();
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
    let content = state.crypto.decrypt_file(&path, &passphrase)?;
    Ok(OpenNoteResult { note, content })
}

#[tauri::command]
pub fn save_note(note_id: String, content: String, state: State<'_, AppState>) -> AppResult<()> {
    let mut session = state
        .session
        .write()
        .map_err(|_| AppError::External("session lock poisoned".into()))?;
    session.ensure_unlocked()?;
    let recipients = state
        .keys
        .read()
        .map_err(|_| AppError::External("key manager lock poisoned".into()))?
        .selected_recipients();
    let vault = state
        .vault
        .read()
        .map_err(|_| AppError::External("vault lock poisoned".into()))?;
    vault.atomic_write_encrypted(&note_id, |temp_path| {
        state.crypto.encrypt_text_to_file(&recipients, &content, temp_path)
    })
}

#[tauri::command]
pub fn create_note(
    name: String,
    content: String,
    state: State<'_, AppState>,
) -> AppResult<crate::models::NoteSummary> {
    let mut session = state
        .session
        .write()
        .map_err(|_| AppError::External("session lock poisoned".into()))?;
    session.ensure_unlocked()?;
    let recipients = state
        .keys
        .read()
        .map_err(|_| AppError::External("key manager lock poisoned".into()))?
        .selected_recipients();
    let mut vault = state
        .vault
        .write()
        .map_err(|_| AppError::External("vault lock poisoned".into()))?;
    let note = vault.create_note_record(&name)?;
    vault.atomic_write_encrypted(&note.id, |temp_path| {
        state.crypto.encrypt_text_to_file(&recipients, &content, temp_path)
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
pub fn import_key_from_file(path: String, state: State<'_, AppState>) -> AppResult<()> {
    state.crypto.import_key(PathBuf::from(path).as_path())
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
pub fn select_private_key(fingerprint: String, state: State<'_, AppState>) -> AppResult<()> {
    let mut keys = state
        .keys
        .write()
        .map_err(|_| AppError::External("key manager lock poisoned".into()))?;
    keys.select_private_key(fingerprint);
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
