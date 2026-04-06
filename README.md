<img width="128" height="128" alt="icon" src="https://github.com/user-attachments/assets/60a23219-fba7-4fca-9ad7-43f1245b8a2b" />

# encryptKeeper
Desktop app for managing encrypted `.gpg` text notes in a folder vault.

<img width="812" height="424" alt="encryptkeeper_xEkANPyxde" src="https://github.com/user-attachments/assets/ce6cf4e1-01bd-45e4-b062-e96339c41489" />

<img width="812" height="424" alt="encryptkeeper_K9GNQNV9N5" src="https://github.com/user-attachments/assets/1cc818b5-e16b-4782-aed1-f8b035ecb273" />

## What it does

encryptKeeper is a Tauri desktop app for writing, opening, and managing OpenPGP-encrypted note files on your PC. It uses your local GnuPG installation for key import, encryption, decryption, and passphrase verification.

## Features

- Open a folder vault and scan it for `.gpg` note files
- Create, open, edit, rename, and delete encrypted notes
- Encrypt notes to one or more selected recipient keys
- Import public and private OpenPGP key files
- Choose a private key for decryption and session unlock
- Unlock and lock the app without exposing plaintext after lock
- Auto-lock after a configurable inactivity timeout, or disable auto-lock entirely
- Optional auto-save while unlocked
- Compact desktop UI built for note editing and key management

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
