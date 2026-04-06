<img width="128" height="128" alt="icon" src="https://github.com/user-attachments/assets/60a23219-fba7-4fca-9ad7-43f1245b8a2b" />

# encryptKeeper
Desktop app for managing encrypted `.gpg` text notes in a folder vault.

<img width="812" height="424" alt="encryptkeeper_xEkANPyxde" src="https://github.com/user-attachments/assets/ce6cf4e1-01bd-45e4-b062-e96339c41489" />

<img width="812" height="424" alt="encryptkeeper_K9GNQNV9N5" src="https://github.com/user-attachments/assets/1cc818b5-e16b-4782-aed1-f8b035ecb273" />

## Overview

encryptKeeper is a Tauri desktop app for writing, opening, and managing OpenPGP-encrypted note files on Windows. It uses your local GnuPG installation for key import, encryption, decryption, key creation, passphrase verification, and recipient inspection.

The app is built around folder-based vaults containing encrypted note files, with quick access to saved vault paths, session-based unlocking, clipboard-aware workflows, and compact key management.

## Current Features

### Vaults and note management

- Open a folder vault and scan it for `.gpg` note files
- Save vault paths for quick reopening from the header
- Pin a vault so it opens automatically when the app starts
- Edit or delete saved vault entries directly from the vault menu
- View the current vault path directly in the main header
- Create, open, edit, rename, save, and delete encrypted notes
- Refresh notes from disk when the vault contents change externally
- Search notes by path/name inside the current vault

### Encryption and decryption

- Encrypt notes to one or more selected recipient keys
- Decrypt notes with the currently selected private key after unlock
- Inspect note recipients and compare them with the current selected recipient set
- Re-encrypt the currently open note when recipient selections change
- Preview the generated armored PGP message block for the current note
- Copy the generated PGP block directly from the preview panel

### Clipboard workflows

- Create a new note from the current clipboard contents
- Automatically decrypt a clipboard PGP message into a new note when it matches the active unlocked key
- Paste plain text from the clipboard directly into a newly created note
- Enable `Use Clipboard` so `Ctrl+V` outside active text editing can:
  - detect decryptable PGP message blocks and create a note from them
  - detect OpenPGP key blocks and offer to import them
- Import OpenPGP keys from the clipboard

### Key management

- Import public or private OpenPGP keys from files
- Import OpenPGP keys from clipboard text
- Create new OpenPGP keypairs in the local GnuPG keyring
- Export public keys
- Export private keys
- Export public and private keys together
- Remove keys from the local keyring
- Reorder keys in the UI
- Choose a private key to use for decryption
- Choose recipient keys used for note encryption
- Pin per-key decrypt and recipient settings so they persist across app restarts
- Hover long key identities to reveal the full name/email and scroll truncated text

### Session and app behavior

- Unlock and lock the app without leaving plaintext in the editor after lock
- Press `Enter` in the passphrase field to unlock
- Optional auto-save while unlocked
- Configurable auto-lock timer, including fully disabled auto-lock
- Remember the last resized window size between launches
- Open with a compact default window height

## Preferences

The app currently includes the following user-facing preferences:

- `Recursive scan`
- `Use Clipboard`
- `Auto-save`
- `Hide Note Names`
- `Auto-Show Recipients`
- `Auto-Show PGP Block`
- Auto-lock timeout on/off with configurable minutes

## Windows Releases

If you just want to use the app, download a built Windows release from the repository Releases page.

## Installation

If you want to run from source, install:

- Node.js
- Rust
- GnuPG
- Tauri prerequisites for Windows

Then install dependencies:

```powershell
npm install
```

## Environment Check

Verify the required tools are available:

```powershell
npm run check:env
```

## Development

Run the desktop app in development mode:

```powershell
npm run tauri:dev
```

## Build

Create a production build:

```powershell
npm run tauri:build
```

## Other Scripts

```powershell
npm run build
npm run test
```

## Notes

- This is a desktop project for PC use.
- Imported keys are handled through your local GnuPG keyring, not stored in the repository.
- Browser mock mode exists for UI development, but the real app flow is the desktop Tauri build.
