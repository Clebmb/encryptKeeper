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
            commands::open_archive_vault,
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
            commands::encrypt_files,
            commands::decrypt_files,
            commands::sign_files,
            commands::verify_file_signature,
            commands::encrypt_cms_files,
            commands::decrypt_cms_files,
            commands::sign_cms_files,
            commands::verify_cms_file_signature,
            commands::import_key_from_file,
            commands::import_key_from_text,
            commands::lookup_key,
            commands::search_keyserver,
            commands::import_key_from_keyserver,
            commands::publish_key_to_keyserver,
            commands::refresh_key_from_keyserver,
            commands::refresh_all_keys_from_keyserver,
            commands::add_subkey,
            commands::change_key_passphrase,
            commands::export_ownertrust,
            commands::import_ownertrust,
            commands::create_key,
            commands::list_keys,
            commands::get_key_details,
            commands::get_smartcard_status,
            commands::list_x509_certificates,
            commands::learn_x509_card,
            commands::create_x509_certificate,
            commands::import_x509_certificate,
            commands::import_x509_certificate_text,
            commands::export_x509_certificate,
            commands::export_x509_secret_key_p12,
            commands::export_x509_secret_key_p8,
            commands::change_x509_passphrase,
            commands::delete_x509_certificate,
            commands::get_x509_certificate_chain,
            commands::import_x509_crl,
            commands::set_x509_trust_root,
            commands::export_x509_trustlist,
            commands::import_x509_trustlist,
            commands::restart_smartcard_service,
            commands::change_smartcard_pin,
            commands::fetch_smartcard_public_key,
            commands::create_smartcard_key_stubs,
            commands::generate_smartcard_key,
            commands::factory_reset_smartcard,
            commands::move_secret_key_to_smartcard,
            commands::set_key_expiry,
            commands::set_key_ownertrust,
            commands::certify_key,
            commands::export_revocation_certificate,
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
