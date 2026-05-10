# encryptKeeper

Desktop OpenPGP and S/MIME workspace built with Tauri, React, and GnuPG.

encryptKeeper is no longer just an encrypted note editor. The current app is organized around three working areas:

- `Note Vault` for encrypted notes in folder or archive vaults
- `Files` for OpenPGP and S/MIME file operations
- `Keyring` for OpenPGP keys, X.509 certificates, trust, and hardware token workflows

## Highlights

- OpenPGP note vaults with create, open, save, rename, delete, search, recipient inspection, signature verification, and clipboard-driven note import
- Folder vaults and ZIP archive vaults with saved paths, pinned reopen behavior, and archive round-trip editing
- Arbitrary file and folder encrypt, decrypt, sign, and verify workflows with detached signatures and preserved relative output structure for batch folder jobs
- OpenPGP key management with import, export, lookup, keyserver search, publish, refresh, trust changes, expiry updates, passphrase rotation, certification, revocation export, and subkey creation
- X.509 / S-MIME certificate inventory with create, import, export, PKCS#12, PKCS#8, passphrase change, validation, trust-root management, CRL import, and S/MIME file operations
- Hardware token support for status, PIN change, service restart, fetch key, sync stubs, on-card key generation, moving local key material to card, and factory reset
- Persistent recent activity feed with collapsible display and a settings toggle

## Main Areas

### Note Vault

- Open folder vaults and ZIP archive vaults
- Save, pin, reopen, and manage vault entries
- Create, open, edit, rename, save, refresh, and delete encrypted notes
- Encrypt notes to selected recipients or save signed / symmetric notes
- Inspect note recipients and verify note signatures on open
- Import notes from clipboard text, PGP blocks, and detached signature flows

### Files

- Encrypt, decrypt, sign, clear, and verify arbitrary files
- Verify detached signatures
- Queue files and folders together
- Preserve folder structure when processing batch folder jobs
- Choose output targets explicitly
- Switch between `OpenPGP` and `S-MIME` file workflows
- Reuse the selected key and recipient state from the integrated sidebar

### Keyring

- Browse OpenPGP keys and X.509 certificates in one workspace
- Inspect identity, fingerprints, usage, trust, subkeys, certifications, and validation state
- Import from files, pasted text, clipboard, WKD lookup, and public keyserver search
- Export public, secret, combined, PKCS#12, and PKCS#8 material where supported
- Update OpenPGP expiry, ownertrust, passphrases, certifications, revocation outputs, and subkeys
- Manage X.509 trust roots, validation chains, trust snapshots, and CRL imports
- Review recent import summaries and duplicate handling

## OpenPGP Features

- Local key generation
- Recipient selection for note and file encryption
- Detached and inline signature workflows
- Public keyserver publish, refresh, and full sync
- WKD and auto-discovery lookup
- Revocation certificate export
- Ownertrust import and export
- Passphrase rotation for existing secret keys
- Certification visibility for signed user IDs

## X.509 / S-MIME Features

- Self-signed X.509 certificate creation
- Certificate import from file and pasted certificate text
- Certificate export plus private material export through PKCS#12 and PKCS#8
- S/MIME encrypt, decrypt, sign, and detached-verify in the `Files` tab
- Validated chain view with compact validation summary
- CRL import
- Trust-root mark and unmark support through the local trust list
- X.509 passphrase changes for certificates with private material

## Hardware Token Features

- Smartcard and token status panel in `Keyring`
- Restart smartcard service
- Change token PIN
- Fetch linked public key from card metadata
- Sync local shadow stubs
- Generate on-card key material by slot and algorithm
- Store local OpenPGP key material onto the card
- Factory reset with explicit confirmation

## Preferences And Activity

- Collapsible `Recent Activity` feed
- `Show Recent History` setting to hide the panel entirely
- Auto-lock timeout control
- Auto-save
- Clipboard integration
- Recursive scan
- Note-name hiding
- Auto-show recipient and PGP block preferences

## Requirements

To run from source, install:

- Node.js
- Rust
- GnuPG with `gpg`, `gpgsm`, and smartcard support where needed
- Tauri prerequisites for Windows

Install dependencies:

```powershell
npm install
```

Verify the environment:

```powershell
npm run check:env
```

## Development

Run the desktop app:

```powershell
npm run tauri:dev
```

Run the frontend tests:

```powershell
npm test
```

Run the Rust tests:

```powershell
cargo test --manifest-path src-tauri/Cargo.toml
```

Build the frontend bundle:

```powershell
npm run build
```

Create a production desktop build:

```powershell
npm run tauri:build
```

## Release Notes

See [CHANGELOG.md](CHANGELOG.md) for the `0.5.5` release summary.
