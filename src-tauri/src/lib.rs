#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app_state;
mod commands;
mod errors;
mod models;
mod services;

use app_state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::open_folder_vault,
            commands::list_notes,
            commands::refresh_notes,
            commands::open_note,
            commands::open_note_with_password,
            commands::resolve_clipboard_note_content,
            commands::save_note,
            commands::save_note_with_password,
            commands::preview_pgp_block,
            commands::verify_clipboard_signature,
            commands::inspect_note_encryption,
            commands::create_note,
            commands::create_note_with_password,
            commands::rename_note,
            commands::delete_note,
            commands::import_key_from_file,
            commands::import_key_from_text,
            commands::create_key,
            commands::list_keys,
            commands::get_pinned_key_settings,
            commands::save_pinned_key_settings,
            commands::select_private_key,
            commands::export_public_key,
            commands::export_private_key,
            commands::remove_key,
            commands::set_recipients,
            commands::unlock_session,
            commands::lock_session,
            commands::update_preferences,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run encryptKeeper");
}
