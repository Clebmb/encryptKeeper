# Changelog

## 1.0.0 - encryptKeeper Professional

First release under the **encryptKeeper Professional** product name. No behavior changes; this is a packaging and branding release that locks in the 1.0 version line and ships dedicated NSIS and MSI Windows installers.

- Rebrand: app window title, product metadata, installer names, HTML title, and documentation reflect the **encryptKeeper Professional** name
- Version bumped to `1.0.0` across `package.json`, `src-tauri/Cargo.toml`, and `src-tauri/tauri.conf.json`
- Tauri bundler configured to emit both an **NSIS** installer and an **MSI** installer for Windows
- Cargo binary identifier `com.clebmbsoftware.encryptkeeper` retained for upgrade compatibility with previously installed copies

## 0.5.5

This release consolidates the full session work that moved encryptKeeper from a note-focused GPG utility into a broader OpenPGP and S/MIME desktop workspace.

### App Structure And UX

- Split the application into `Note Vault`, `Files`, and `Keyring` tabs
- Reworked the `Files` workspace layout and recipient handling to mirror the note workflow where it makes sense
- Added persistent `Recent Activity`, then made it collapsible, collapsed by default, and fully hideable through `Show Recent History`
- Made the `Keyring Tools` management dialog scroll safely within the viewport at smaller window sizes

### Vaults And Notes

- Added ZIP archive vault support alongside folder vaults
- Implemented archive extraction, editing, and sync-back flows so archive vaults behave like real editable vaults
- Added archive-aware saved-vault reopening and vault-type status badges
- Expanded note recipient inspection, clipboard import paths, signing, and verification behavior

### File Operations

- Added general-purpose file encrypt, decrypt, sign, and verify commands
- Added detached-signature verification
- Added folder batch processing with preserved relative output structure
- Added OpenPGP and S/MIME mode switching in the `Files` tab

### OpenPGP Keyring

- Added a separate `Keyring` workspace with richer key detail views
- Added import summaries, duplicate handling, key filtering, and quick-focus behavior for newly imported keys
- Added WKD and auto-discovery lookup plus public keyserver search
- Added keyserver publish, refresh, and full sync actions
- Added expiry updates, ownertrust changes, trust snapshot import/export, certification actions, revocation certificate export, passphrase rotation, and subkey creation
- Added certification visibility in key details

### X.509 And S/MIME

- Added X.509 certificate inventory and richer detail views
- Added self-signed X.509 certificate creation
- Added import from file and pasted certificate text
- Added certificate export, PKCS#12 export, PKCS#8 export, and X.509 passphrase change
- Added S/MIME encrypt, decrypt, sign, and verify flows in the `Files` workspace
- Added validated chain viewing, compact validation summaries, CRL import, trust-root mark/unmark, and trust snapshot flows
- Fixed X.509 secret-material detection and improved certificate deletion handling

### Hardware Tokens

- Added smartcard status visibility in `Keyring`
- Added service restart, PIN change, key fetch, shadow-stub sync, and on-card key generation
- Added local-key-to-card storage workflows and overwrite controls where needed
- Added factory reset with explicit confirmation

### Security And Backend Hardening

- Removed plaintext temp-file writes from the main encrypt and sign flows by streaming plaintext to GnuPG through stdin
- Added secure temp cleanup for detached-signature verification
- Expanded automated Rust coverage across archive, key-management, X.509, smartcard, and passphrase workflows
