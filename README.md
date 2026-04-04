# encryptKeeper

Tauri-first desktop secure notepad for `.gpg` text notes.

## Current state

- Browser mock mode is available now for testing the UI without Rust, Tauri, or GPG.
- Real desktop mode exists as a Tauri/Rust scaffold with folder-vault flows and GPG integration points.
- Archive support is planned but not implemented yet.

## Run the UI right now

```powershell
npm install
npm run dev
```

Open the Vite URL shown in the terminal.

This launches browser mock mode:
- no real encryption
- no real filesystem access
- demo notes and keys stored in browser local storage

## Run the desktop app

First install prerequisites:
- Rust toolchain with `cargo` and `rustc`
- GnuPG with `gpg` on `PATH`
- Tauri platform prerequisites for Windows

Check your environment:

```powershell
npm run check:env
```

Then run:

```powershell
npm run tauri:dev
```

## Useful scripts

```powershell
npm run dev
npm run test
npm run build
npm run check:env
npm run tauri:dev
npm run tauri:build
```

## Important note

Mock mode exists only to test the UI and workflow shape. The real security properties depend on the Rust backend and system GPG tooling, not the browser fallback.
