use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::{
    errors::{AppError, AppResult},
    models::{KeyDetails, KeySubkey, KeySummary, NoteSignatureStatus},
};

#[derive(Default)]
pub struct CryptoService;

#[derive(Clone, Default)]
pub struct ParsedSubkey {
    pub fingerprint: String,
    pub key_id: String,
    pub algorithm: String,
    pub bits: u32,
    pub created_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub capabilities: Vec<String>,
    pub has_secret: bool,
}

#[derive(Clone, Default)]
pub struct ParsedKeyIdentity {
    pub primary_fingerprint: String,
    pub key_id: String,
    pub user_ids: Vec<String>,
    pub has_secret: bool,
    pub key_ids: Vec<String>,
    pub algorithm: String,
    pub bits: u32,
    pub created_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub trust: String,
    pub capabilities: Vec<String>,
    pub subkeys: Vec<ParsedSubkey>,
}

pub struct DecryptedContent {
    pub content: String,
    pub signature: NoteSignatureStatus,
}

impl CryptoService {
    pub fn create_key(&self, name: &str, email: &str, passphrase: &str) -> AppResult<()> {
        let trimmed_name = name.trim();
        let trimmed_email = email.trim();
        if trimmed_name.is_empty() {
            return Err(AppError::Validation("Key name is required.".into()));
        }
        if trimmed_email.is_empty() {
            return Err(AppError::Validation("Key email is required.".into()));
        }
        if passphrase.is_empty() {
            return Err(AppError::Validation("Key passphrase is required.".into()));
        }

        let user_id = format!("{trimmed_name} <{trimmed_email}>");
        let mut child = self
            .gpg_command()?
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--quick-generate-key",
                &user_id,
                "default",
                "default",
                "never",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| AppError::GpgUnavailable)?;

        if let Some(stdin) = &mut child.stdin {
            use std::io::Write;
            stdin.write_all(passphrase.as_bytes())?;
            stdin.write_all(b"\n")?;
        }

        let output = child.wait_with_output()?;
        if output.status.success() {
            return Ok(());
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn import_key(&self, path: &Path) -> AppResult<()> {
        let output = self
            .gpg_command()?
            .args(["--batch", "--import"])
            .arg(path.as_os_str())
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(());
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn import_key_text(&self, armored_text: &str) -> AppResult<()> {
        let mut child = self
            .gpg_command()?
            .args(["--batch", "--import"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| AppError::GpgUnavailable)?;

        if let Some(stdin) = &mut child.stdin {
            use std::io::Write;
            stdin.write_all(armored_text.as_bytes())?;
        }

        let output = child.wait_with_output()?;
        if output.status.success() {
            return Ok(());
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn list_keys(&self, secret_only: bool) -> AppResult<String> {
        let selector = if secret_only {
            "--list-secret-keys"
        } else {
            "--list-keys"
        };
        let output = self
            .gpg_command()?
            .args(["--batch", "--with-colons", selector])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return String::from_utf8(output.stdout).map_err(Into::into);
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn verify_passphrase(&self, fingerprint: &str, passphrase: &str) -> AppResult<()> {
        let mut child = self
            .gpg_command()?
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--local-user",
                fingerprint,
                "--armor",
                "--sign",
                "--output",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| AppError::GpgUnavailable)?;

        if let Some(stdin) = &mut child.stdin {
            use std::io::Write;
            stdin.write_all(passphrase.as_bytes())?;
            stdin.write_all(b"\n")?;
            stdin.write_all(b"unlock-check")?;
        }

        let output = child.wait_with_output()?;
        if output.status.success() {
            return Ok(());
        }
        Err(Self::passphrase_error(&String::from_utf8_lossy(&output.stderr)))
    }

    pub fn decrypt_file(&self, path: &Path, passphrase: &str) -> AppResult<DecryptedContent> {
        let mut child = self
            .gpg_command()?
            .args([
                "--batch",
                "--yes",
                "--status-fd",
                "2",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--decrypt",
            ])
            .arg(path.as_os_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| AppError::GpgUnavailable)?;

        if let Some(stdin) = &mut child.stdin {
            use std::io::Write;
            stdin.write_all(passphrase.as_bytes())?;
            stdin.write_all(b"\n")?;
        }

        let output = child.wait_with_output()?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.success() {
            return Ok(DecryptedContent {
                content: String::from_utf8(output.stdout)?,
                signature: Self::parse_signature_status(&stderr),
            });
        }

        Err(Self::passphrase_error(&stderr))
    }

    pub fn decrypt_armored_text(
        &self,
        armored_text: &str,
        passphrase: &str,
    ) -> AppResult<DecryptedContent> {
        let mut child = self
            .gpg_command()?
            .args([
                "--batch",
                "--yes",
                "--status-fd",
                "2",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--decrypt",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| AppError::GpgUnavailable)?;

        if let Some(stdin) = &mut child.stdin {
            use std::io::Write;
            stdin.write_all(passphrase.as_bytes())?;
            stdin.write_all(b"\n")?;
            stdin.write_all(armored_text.as_bytes())?;
        }

        let output = child.wait_with_output()?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.success() {
            return Ok(DecryptedContent {
                content: String::from_utf8(output.stdout)?,
                signature: Self::parse_signature_status(&stderr),
            });
        }

        Err(Self::passphrase_error(&stderr))
    }

    pub fn decrypt_symmetric_file(
        &self,
        path: &Path,
        password: &str,
    ) -> AppResult<DecryptedContent> {
        self.decrypt_file(path, password)
    }

    pub fn decrypt_file_to_path(
        &self,
        input_path: &Path,
        output_path: &Path,
        passphrase: &str,
    ) -> AppResult<()> {
        if passphrase.is_empty() {
            return Err(AppError::Validation("Key passphrase is required.".into()));
        }

        let mut child = self
            .gpg_command()?
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--output",
            ])
            .arg(output_path.as_os_str())
            .args(["--decrypt"])
            .arg(input_path.as_os_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| AppError::GpgUnavailable)?;

        if let Some(stdin) = &mut child.stdin {
            use std::io::Write;
            stdin.write_all(passphrase.as_bytes())?;
            stdin.write_all(b"\n")?;
        }

        let output = child.wait_with_output()?;
        if output.status.success() {
            return Ok(());
        }
        Err(Self::passphrase_error(&String::from_utf8_lossy(&output.stderr)))
    }

    pub fn verify_clear_signed_text(&self, signed_text: &str) -> AppResult<DecryptedContent> {
        let mut child = self
            .gpg_command()?
            .args(["--batch", "--yes", "--status-fd", "2", "--decrypt"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| AppError::GpgUnavailable)?;

        if let Some(stdin) = &mut child.stdin {
            use std::io::Write;
            stdin.write_all(signed_text.as_bytes())?;
        }

        let output = child.wait_with_output()?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.success() {
            return Ok(DecryptedContent {
                content: String::from_utf8(output.stdout)?,
                signature: Self::parse_signature_status(&stderr),
            });
        }

        Err(AppError::External(stderr.trim().to_string()))
    }

    pub fn verify_detached_signature(
        &self,
        signature_path: &Path,
        plaintext_path: &Path,
    ) -> AppResult<NoteSignatureStatus> {
        let output = self
            .gpg_command()?
            .args(["--batch", "--yes", "--status-fd", "2", "--verify"])
            .arg(signature_path.as_os_str())
            .arg(plaintext_path.as_os_str())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;

        let stderr = String::from_utf8_lossy(&output.stderr);
        let signature = Self::parse_signature_status(&stderr);
        if output.status.success() || signature.state != "none" {
            return Ok(signature);
        }

        Err(AppError::External(stderr.trim().to_string()))
    }

    pub fn encrypt_text_to_file(
        &self,
        recipients: &[String],
        signer: &str,
        passphrase: &str,
        plaintext: &str,
        output_path: &Path,
    ) -> AppResult<()> {
        if recipients.is_empty() {
            return Err(AppError::MissingRecipients);
        }
        if signer.trim().is_empty() {
            return Err(AppError::MissingPrivateKeySelection);
        }
        if passphrase.is_empty() {
            return Err(AppError::Validation("Key passphrase is required.".into()));
        }

        let mut command = self.gpg_command()?;
        command
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--armor",
                "--local-user",
                signer,
                "--sign",
                "--encrypt",
                "--output",
            ])
            .arg(output_path.as_os_str())
            .args(["--trust-model", "always"]);

        for recipient in recipients {
            command.arg("--recipient").arg(recipient);
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let output = Self::run_with_passphrase_and_input(command, passphrase, plaintext.as_bytes())?;
        if output.status.success() {
            return Ok(());
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn encrypt_file_to_file(
        &self,
        recipients: &[String],
        signer: &str,
        passphrase: &str,
        input_path: &Path,
        output_path: &Path,
    ) -> AppResult<()> {
        if recipients.is_empty() {
            return Err(AppError::MissingRecipients);
        }
        if signer.trim().is_empty() {
            return Err(AppError::MissingPrivateKeySelection);
        }
        if passphrase.is_empty() {
            return Err(AppError::Validation("Key passphrase is required.".into()));
        }

        let mut command = self.gpg_command()?;
        command
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--local-user",
                signer,
                "--sign",
                "--encrypt",
                "--output",
            ])
            .arg(output_path.as_os_str())
            .args(["--trust-model", "always"]);

        for recipient in recipients {
            command.arg("--recipient").arg(recipient);
        }

        command
            .arg(input_path.as_os_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let output = Self::run_with_passphrase_only(command, passphrase)?;
        if output.status.success() {
            return Ok(());
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn sign_text_to_file(
        &self,
        signer: &str,
        passphrase: &str,
        plaintext: &str,
        output_path: &Path,
    ) -> AppResult<()> {
        if signer.trim().is_empty() {
            return Err(AppError::MissingPrivateKeySelection);
        }
        if passphrase.is_empty() {
            return Err(AppError::Validation("Key passphrase is required.".into()));
        }

        let mut command = self.gpg_command()?;
        command
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--local-user",
                signer,
                "--clear-sign",
                "--output",
            ])
            .arg(output_path.as_os_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let output = Self::run_with_passphrase_and_input(command, passphrase, plaintext.as_bytes())?;
        if output.status.success() {
            return Ok(());
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn sign_text_to_armor(
        &self,
        signer: &str,
        passphrase: &str,
        plaintext: &str,
    ) -> AppResult<String> {
        if signer.trim().is_empty() {
            return Err(AppError::MissingPrivateKeySelection);
        }
        if passphrase.is_empty() {
            return Err(AppError::Validation("Key passphrase is required.".into()));
        }

        let mut command = self.gpg_command()?;
        command
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--local-user",
                signer,
                "--clear-sign",
                "--output",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = Self::run_with_passphrase_and_input(command, passphrase, plaintext.as_bytes())?;
        if output.status.success() {
            return String::from_utf8(output.stdout).map_err(Into::into);
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn create_detached_signature(
        &self,
        signer: &str,
        passphrase: &str,
        input_path: &Path,
        output_path: &Path,
    ) -> AppResult<()> {
        if signer.trim().is_empty() {
            return Err(AppError::MissingPrivateKeySelection);
        }
        if passphrase.is_empty() {
            return Err(AppError::Validation("Key passphrase is required.".into()));
        }

        let mut command = self.gpg_command()?;
        command
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--armor",
                "--detach-sign",
                "--local-user",
                signer,
                "--output",
            ])
            .arg(output_path.as_os_str())
            .arg(input_path.as_os_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let output = Self::run_with_passphrase_only(command, passphrase)?;
        if output.status.success() {
            return Ok(());
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn encrypt_text_symmetric_to_file(
        &self,
        password: &str,
        plaintext: &str,
        output_path: &Path,
    ) -> AppResult<()> {
        if password.is_empty() {
            return Err(AppError::Validation("Password is required.".into()));
        }

        let mut command = self.gpg_command()?;
        command
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--armor",
                "--symmetric",
                "--cipher-algo",
                "AES256",
                "--output",
            ])
            .arg(output_path.as_os_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let output = Self::run_with_passphrase_and_input(command, password, plaintext.as_bytes())?;
        if output.status.success() {
            return Ok(());
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn encrypt_text_to_armor(
        &self,
        recipients: &[String],
        signer: &str,
        passphrase: &str,
        plaintext: &str,
    ) -> AppResult<String> {
        if recipients.is_empty() {
            return Err(AppError::MissingRecipients);
        }
        if signer.trim().is_empty() {
            return Err(AppError::MissingPrivateKeySelection);
        }
        if passphrase.is_empty() {
            return Err(AppError::Validation("Key passphrase is required.".into()));
        }

        let mut command = self.gpg_command()?;
        command
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--armor",
                "--local-user",
                signer,
                "--sign",
                "--encrypt",
                "--output",
                "-",
            ])
            .args(["--trust-model", "always"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        for recipient in recipients {
            command.arg("--recipient").arg(recipient);
        }

        let output = Self::run_with_passphrase_and_input(command, passphrase, plaintext.as_bytes())?;
        if output.status.success() {
            return String::from_utf8(output.stdout).map_err(Into::into);
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn export_public_key(&self, fingerprint: &str, output_path: &Path) -> AppResult<()> {
        let output = self
            .gpg_command()?
            .args(["--batch", "--yes", "--armor", "--output"])
            .arg(output_path.as_os_str())
            .args(["--export", fingerprint])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(());
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn export_secret_key(
        &self,
        fingerprint: &str,
        passphrase: &str,
        output_path: &Path,
    ) -> AppResult<()> {
        if passphrase.is_empty() {
            return Err(AppError::Validation("Key passphrase is required.".into()));
        }

        let mut child = self
            .gpg_command()?
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--armor",
                "--output",
            ])
            .arg(output_path.as_os_str())
            .args(["--export-secret-keys", fingerprint])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| AppError::GpgUnavailable)?;

        if let Some(stdin) = &mut child.stdin {
            use std::io::Write;
            stdin.write_all(passphrase.as_bytes())?;
            stdin.write_all(b"\n")?;
        }

        let output = child.wait_with_output()?;
        if output.status.success() {
            return Ok(());
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn delete_key(&self, fingerprint: &str, has_secret: bool) -> AppResult<()> {
        let delete_flag = if has_secret {
            "--delete-secret-and-public-key"
        } else {
            "--delete-key"
        };

        let output = self
            .gpg_command()?
            .args(["--batch", "--yes", delete_flag, fingerprint])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(());
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn inspect_file_recipients(&self, path: &Path) -> AppResult<Vec<String>> {
        let output = self
            .gpg_command()?
            .args(["--batch", "--list-packets"])
            .arg(path.as_os_str())
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if !output.status.success() {
            return Err(AppError::External(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }

        let stdout = String::from_utf8(output.stdout)?;
        let mut recipients = Vec::new();
        for line in stdout.lines() {
            if line.contains(":pubkey enc packet") {
                if let Some((_, key_id)) = line.split_once("keyid ") {
                    let normalized = key_id.trim().to_uppercase();
                    if !recipients.contains(&normalized) {
                        recipients.push(normalized);
                    }
                }
            }
        }
        Ok(recipients)
    }

    fn gpg_command(&self) -> AppResult<Command> {
        let gpg = self.resolve_gpg_binary()?;
        let mut command = Command::new(gpg);
        #[cfg(windows)]
        if let Some(extra_path) = Self::windows_gpg_path_prefix() {
            let combined = match std::env::var_os("PATH") {
                Some(existing) => {
                    let mut paths = vec![extra_path];
                    paths.extend(std::env::split_paths(&existing));
                    std::env::join_paths(paths).ok()
                }
                None => std::env::join_paths([extra_path]).ok(),
            };
            if let Some(path_value) = combined {
                command.env("PATH", path_value);
            }
        }
        Ok(command)
    }

    fn resolve_gpg_binary(&self) -> AppResult<PathBuf> {
        if Self::is_gpg_callable(OsStr::new("gpg")) {
            return Ok(PathBuf::from("gpg"));
        }

        #[cfg(windows)]
        for candidate in Self::windows_gpg_candidates() {
            if Self::is_gpg_callable(candidate.as_os_str()) {
                return Ok(candidate);
            }
        }

        Err(AppError::GpgUnavailable)
    }

    fn is_gpg_callable(binary: &OsStr) -> bool {
        Command::new(binary)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    pub fn parse_keys(&self, public_listing: &str, secret_listing: &str) -> Vec<KeySummary> {
        self.parse_key_identities(public_listing, secret_listing)
            .into_iter()
            .map(Self::identity_to_key_summary)
            .collect()
    }

    pub fn key_details(
        &self,
        public_listing: &str,
        secret_listing: &str,
        fingerprint: &str,
    ) -> Option<KeyDetails> {
        self.parse_key_identities(public_listing, secret_listing)
            .into_iter()
            .find(|identity| identity.primary_fingerprint == fingerprint)
            .map(|identity| KeyDetails {
                summary: Self::identity_to_key_summary(identity.clone()),
                subkeys: identity
                    .subkeys
                    .into_iter()
                    .map(|subkey| KeySubkey {
                        fingerprint: subkey.fingerprint,
                        key_id: subkey.key_id,
                        algorithm: subkey.algorithm,
                        bits: subkey.bits,
                        created_at: subkey.created_at,
                        expires_at: subkey.expires_at,
                        capabilities: subkey.capabilities,
                        has_secret: subkey.has_secret,
                    })
                    .collect(),
            })
    }

    pub fn parse_key_identities(
        &self,
        public_listing: &str,
        secret_listing: &str,
    ) -> Vec<ParsedKeyIdentity> {
        let secret_fingerprints = Self::collect_primary_fingerprints(secret_listing, "sec");
        let secret_subkey_fingerprints = Self::collect_primary_fingerprints(secret_listing, "ssb");

        let mut summaries = Vec::new();
        let mut current: Option<ParsedKeyIdentity> = None;
        let mut pending_public_fingerprint = false;
        let mut pending_subkey: Option<ParsedSubkey> = None;
        let mut pending_subkey_fingerprint = false;

        for line in public_listing.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            let record_type = parts.first().copied().unwrap_or_default();
            match record_type {
                "pub" => {
                    if let Some(subkey) = pending_subkey.take() {
                        if let Some(identity) = &mut current {
                            identity.subkeys.push(subkey);
                        }
                    }
                    if let Some(identity) = current.take() {
                        summaries.push(identity);
                    }
                    current = Some(ParsedKeyIdentity {
                        has_secret: false,
                        trust: Self::parse_trust(parts.get(1).copied().unwrap_or_default()),
                        bits: parts.get(2).and_then(|value| value.parse::<u32>().ok()).unwrap_or(0),
                        algorithm: Self::parse_algorithm(parts.get(3).copied().unwrap_or_default()),
                        key_id: parts.get(4).copied().unwrap_or_default().to_uppercase(),
                        created_at: Self::parse_epoch(parts.get(5).copied()),
                        expires_at: Self::parse_epoch(parts.get(6).copied()),
                        capabilities: Self::parse_capabilities(parts.get(11).copied().unwrap_or_default()),
                        ..ParsedKeyIdentity::default()
                    });
                    pending_public_fingerprint = true;
                    pending_subkey_fingerprint = false;
                }
                "sub" => {
                    if let Some(subkey) = pending_subkey.take() {
                        if let Some(identity) = &mut current {
                            identity.subkeys.push(subkey);
                        }
                    }
                    pending_subkey = Some(ParsedSubkey {
                        key_id: parts.get(4).copied().unwrap_or_default().to_uppercase(),
                        algorithm: Self::parse_algorithm(parts.get(3).copied().unwrap_or_default()),
                        bits: parts.get(2).and_then(|value| value.parse::<u32>().ok()).unwrap_or(0),
                        created_at: Self::parse_epoch(parts.get(5).copied()),
                        expires_at: Self::parse_epoch(parts.get(6).copied()),
                        capabilities: Self::parse_capabilities(parts.get(11).copied().unwrap_or_default()),
                        ..ParsedSubkey::default()
                    });
                    pending_subkey_fingerprint = true;
                    pending_public_fingerprint = false;
                }
                "fpr" => {
                    if pending_public_fingerprint {
                        if let Some(identity) = &mut current {
                            identity.primary_fingerprint =
                                parts.get(9).copied().unwrap_or_default().to_uppercase();
                            identity.has_secret =
                                secret_fingerprints.contains(&identity.primary_fingerprint);
                            if !identity.primary_fingerprint.is_empty() {
                                identity
                                    .key_ids
                                    .push(Self::short_key_id(&identity.primary_fingerprint));
                            }
                        }
                        pending_public_fingerprint = false;
                    } else if pending_subkey_fingerprint {
                        if let Some(subkey) = &mut pending_subkey {
                            subkey.fingerprint =
                                parts.get(9).copied().unwrap_or_default().to_uppercase();
                            subkey.has_secret = secret_subkey_fingerprints.contains(&subkey.fingerprint);
                            if subkey.key_id.is_empty() && !subkey.fingerprint.is_empty() {
                                subkey.key_id = Self::short_key_id(&subkey.fingerprint);
                            }
                            if let Some(identity) = &mut current {
                                if !subkey.key_id.is_empty() {
                                    identity.key_ids.push(subkey.key_id.clone());
                                }
                            }
                        }
                        pending_subkey_fingerprint = false;
                    }
                }
                "uid" => {
                    if let Some(identity) = &mut current {
                        if let Some(uid) = parts.get(9) {
                            identity.user_ids.push((*uid).to_string());
                        }
                    }
                }
                _ => {}
            }
        }

        if let Some(subkey) = pending_subkey.take() {
            if let Some(identity) = &mut current {
                identity.subkeys.push(subkey);
            }
        }
        if let Some(identity) = current.take() {
            summaries.push(identity);
        }

        let mut dedup = HashMap::new();
        for summary in summaries {
            dedup.insert(summary.primary_fingerprint.clone(), summary);
        }
        let mut ordered = dedup.into_values().collect::<Vec<_>>();
        ordered.sort_by(|left, right| {
            let left_name = left.user_ids.first().map(String::as_str).unwrap_or("");
            let right_name = right.user_ids.first().map(String::as_str).unwrap_or("");
            left_name
                .cmp(right_name)
                .then_with(|| left.primary_fingerprint.cmp(&right.primary_fingerprint))
        });
        ordered
    }

    fn identity_to_key_summary(identity: ParsedKeyIdentity) -> KeySummary {
        KeySummary {
            key_id: identity.key_id,
            fingerprint: identity.primary_fingerprint,
            user_ids: identity.user_ids,
            has_secret: identity.has_secret,
            algorithm: identity.algorithm,
            bits: identity.bits,
            created_at: identity.created_at,
            expires_at: identity.expires_at,
            trust: identity.trust,
            capabilities: identity.capabilities,
            is_selected_private: false,
            is_selected_recipient: false,
        }
    }

    fn short_key_id(fingerprint: &str) -> String {
        fingerprint
            .chars()
            .rev()
            .take(16)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<String>()
            .to_uppercase()
    }

    fn collect_primary_fingerprints(listing: &str, record_type: &str) -> HashSet<String> {
        let mut fingerprints = HashSet::new();
        let mut waiting_for_primary_fpr = false;

        for line in listing.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            match parts.first().copied().unwrap_or_default() {
                value if value == record_type => waiting_for_primary_fpr = true,
                "fpr" if waiting_for_primary_fpr => {
                    if let Some(fingerprint) = parts.get(9) {
                        fingerprints.insert((*fingerprint).to_uppercase());
                    }
                    waiting_for_primary_fpr = false;
                }
                _ => {}
            }
        }

        fingerprints
    }

    fn parse_epoch(value: Option<&str>) -> Option<u64> {
        value
            .filter(|candidate| !candidate.is_empty())
            .and_then(|candidate| candidate.parse::<u64>().ok())
    }

    fn parse_algorithm(code: &str) -> String {
        match code {
            "1" => "RSA".into(),
            "16" => "ElGamal".into(),
            "17" => "DSA".into(),
            "18" => "ECDH".into(),
            "19" => "ECDSA".into(),
            "22" => "EdDSA".into(),
            "" => "Unknown".into(),
            value => format!("Algo {value}"),
        }
    }

    fn parse_capabilities(value: &str) -> Vec<String> {
        value
            .chars()
            .map(|capability| match capability {
                'e' | 'E' => "Encrypt",
                's' | 'S' => "Sign",
                'c' | 'C' => "Certify",
                'a' | 'A' => "Authenticate",
                'd' | 'D' => "Disabled",
                '?' => "Unknown",
                _ => "",
            })
            .filter(|label| !label.is_empty())
            .map(str::to_string)
            .collect()
    }

    fn parse_trust(value: &str) -> String {
        match value {
            "o" => "Unknown",
            "i" => "Invalid",
            "d" => "Disabled",
            "r" => "Revoked",
            "e" => "Expired",
            "-" => "Unchecked",
            "q" => "Undefined",
            "n" => "Never",
            "m" => "Marginal",
            "f" => "Full",
            "u" => "Ultimate",
            _ => "Unknown",
        }
        .to_string()
    }

    fn run_with_passphrase_only(
        mut command: Command,
        passphrase: &str,
    ) -> AppResult<std::process::Output> {
        let mut child = command.spawn().map_err(|_| AppError::GpgUnavailable)?;
        if let Some(stdin) = &mut child.stdin {
            use std::io::Write;
            stdin.write_all(passphrase.as_bytes())?;
            stdin.write_all(b"\n")?;
        }
        child.wait_with_output().map_err(Into::into)
    }

    fn run_with_passphrase_and_input(
        mut command: Command,
        passphrase: &str,
        input: &[u8],
    ) -> AppResult<std::process::Output> {
        let mut child = command.spawn().map_err(|_| AppError::GpgUnavailable)?;
        if let Some(stdin) = &mut child.stdin {
            use std::io::Write;
            stdin.write_all(passphrase.as_bytes())?;
            stdin.write_all(b"\n")?;
            stdin.write_all(input)?;
        }
        child.wait_with_output().map_err(Into::into)
    }

    fn passphrase_error(stderr: &str) -> AppError {
        if stderr.contains("Bad passphrase") {
            return AppError::WrongPrivateKeyPassphrase;
        }
        if stderr.contains("No secret key") {
            return AppError::MissingPrivateKey;
        }
        if stderr.contains("decryption failed") {
            return AppError::InvalidGpgFile;
        }
        AppError::External(stderr.trim().to_string())
    }

    pub fn enrich_signature_status(
        &self,
        mut signature: NoteSignatureStatus,
        identities: &[ParsedKeyIdentity],
    ) -> NoteSignatureStatus {
        let signer = signature
            .signer_fingerprint
            .as_ref()
            .and_then(|fingerprint| {
                self.find_identity_for_fingerprint_or_key_id(identities, fingerprint)
            })
            .or_else(|| {
                signature.signer_key_id.as_ref().and_then(|key_id| {
                    self.find_identity_for_fingerprint_or_key_id(identities, key_id)
                })
            });

        if let Some(identity) = signer {
            signature.signer_fingerprint = Some(identity.primary_fingerprint.clone());
            signature.signer_label = identity
                .user_ids
                .first()
                .cloned()
                .or_else(|| Some(identity.primary_fingerprint.clone()));
            signature.summary = match signature.state.as_str() {
                "good" => format!(
                    "Good signature from {}.",
                    signature.signer_label.as_deref().unwrap_or("known key")
                ),
                "bad" => format!(
                    "Bad signature claiming to be from {}.",
                    signature.signer_label.as_deref().unwrap_or("known key")
                ),
                "unknown" => format!(
                    "Signature could not be verified for {}.",
                    signature.signer_label.as_deref().unwrap_or("known key")
                ),
                _ => signature.summary,
            };
        }

        signature
    }

    fn find_identity_for_fingerprint_or_key_id<'a>(
        &self,
        identities: &'a [ParsedKeyIdentity],
        value: &str,
    ) -> Option<&'a ParsedKeyIdentity> {
        let normalized = value.to_uppercase();
        let short_key_id = Self::short_key_id(&normalized);
        identities.iter().find(|identity| {
            identity
                .primary_fingerprint
                .eq_ignore_ascii_case(&normalized)
                || identity
                    .key_ids
                    .iter()
                    .any(|key_id| key_id == &normalized || key_id == &short_key_id)
        })
    }

    fn parse_signature_status(status_output: &str) -> NoteSignatureStatus {
        let mut signer_key_id = None;
        let mut signer_fingerprint = None;
        let mut signer_label = None;
        let mut state = "none".to_string();
        let mut missing_public_key = false;

        for line in status_output.lines() {
            let Some(rest) = line.strip_prefix("[GNUPG:] ") else {
                continue;
            };
            let mut parts = rest.split_whitespace();
            match parts.next().unwrap_or_default() {
                "GOODSIG" => {
                    state = "good".to_string();
                    signer_key_id = parts.next().map(|value| value.to_uppercase());
                    let label = parts.collect::<Vec<_>>().join(" ");
                    if !label.is_empty() {
                        signer_label = Some(label);
                    }
                }
                "VALIDSIG" => {
                    signer_fingerprint = parts.next().map(|value| value.to_uppercase());
                }
                "BADSIG" => {
                    state = "bad".to_string();
                    signer_key_id = parts.next().map(|value| value.to_uppercase());
                    let label = parts.collect::<Vec<_>>().join(" ");
                    if !label.is_empty() {
                        signer_label = Some(label);
                    }
                }
                "EXPSIG" | "EXPKEYSIG" | "REVKEYSIG" => {
                    if state != "bad" {
                        state = "unknown".to_string();
                    }
                    signer_key_id = parts.next().map(|value| value.to_uppercase());
                    let label = parts.collect::<Vec<_>>().join(" ");
                    if !label.is_empty() {
                        signer_label = Some(label);
                    }
                }
                "ERRSIG" => {
                    if state != "bad" {
                        state = "unknown".to_string();
                    }
                    signer_key_id = parts.next().map(|value| value.to_uppercase());
                }
                "NO_PUBKEY" => {
                    missing_public_key = true;
                }
                _ => {}
            }
        }

        let summary = match state.as_str() {
            "good" => signer_label
                .as_ref()
                .map(|label| format!("Good signature from {label}."))
                .unwrap_or_else(|| "Good signature.".to_string()),
            "bad" => signer_label
                .as_ref()
                .map(|label| format!("Bad signature claiming to be from {label}."))
                .unwrap_or_else(|| "Bad signature.".to_string()),
            "unknown" if missing_public_key => {
                "Signature could not be verified because the signer public key is not imported."
                    .to_string()
            }
            "unknown" => "Signature could not be verified.".to_string(),
            _ => "No signature found.".to_string(),
        };

        NoteSignatureStatus {
            state,
            signer_key_id,
            signer_fingerprint,
            signer_label,
            summary,
        }
    }
}

#[cfg(windows)]
impl CryptoService {
    fn windows_gpg_candidates() -> Vec<PathBuf> {
        let mut candidates = Vec::new();
        for base in [
            std::env::var_os("ProgramFiles"),
            std::env::var_os("ProgramFiles(x86)"),
            std::env::var_os("LOCALAPPDATA"),
        ]
        .into_iter()
        .flatten()
        {
            let root = PathBuf::from(base);
            candidates.push(root.join("GnuPG").join("bin").join("gpg.exe"));
            candidates.push(root.join("Gpg4win").join("bin").join("gpg.exe"));
            candidates.push(root.join("Git").join("usr").join("bin").join("gpg.exe"));
        }
        candidates
    }

    fn windows_gpg_path_prefix() -> Option<PathBuf> {
        Self::windows_gpg_candidates()
            .into_iter()
            .find(|candidate| candidate.exists())
            .and_then(|candidate| candidate.parent().map(Path::to_path_buf))
    }
}

#[cfg(test)]
mod tests {
    use super::CryptoService;

    #[test]
    fn parses_key_listings() {
        let service = CryptoService;
        let public_listing =
            "pub:u:3072:1:ABC123:1712707200:0:::::scESC:\nfpr:::::::::ABC123\nuid:::::::::Alice Example\n";
        let secret_listing = "sec:::::::::\nfpr:::::::::ABC123\n";
        let keys = service.parse_keys(public_listing, secret_listing);
        assert_eq!(keys.len(), 1);
        assert!(keys[0].has_secret);
        assert_eq!(keys[0].algorithm, "RSA");
        assert!(keys[0].capabilities.iter().any(|value| value == "Sign"));
    }

    #[test]
    fn prefers_primary_fingerprint_over_subkey_fingerprint() {
        let service = CryptoService;
        let public_listing = concat!(
            "pub:u:3072:1:PRIMARY123:1712707200:0:::::scESC:\n",
            "fpr:::::::::PRIMARY123\n",
            "uid:::::::::Alice Example\n",
            "sub:u:255:22:SUBKEY456:1712707200:0:::::sa:\n",
            "fpr:::::::::SUBKEY456\n"
        );
        let secret_listing =
            "sec:::::::::\nfpr:::::::::PRIMARY123\nssb:::::::::\nfpr:::::::::SUBKEY456\n";

        let keys = service.parse_keys(public_listing, secret_listing);

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].fingerprint, "PRIMARY123");
        assert!(keys[0].has_secret);
    }

    #[test]
    fn parses_key_details_subkeys() {
        let service = CryptoService;
        let public_listing = concat!(
            "pub:u:3072:1:PRIMARY123:1712707200:0:::::scESC:\n",
            "fpr:::::::::PRIMARY123\n",
            "uid:::::::::Alice Example <alice@example.test>\n",
            "sub:u:255:22:SUBKEY456:1712707200:0:::::e:\n",
            "fpr:::::::::SUBKEY456\n"
        );
        let secret_listing = "sec:::::::::\nfpr:::::::::PRIMARY123\n";

        let details = service
            .key_details(public_listing, secret_listing, "PRIMARY123")
            .expect("details");

        assert_eq!(details.summary.key_id, "PRIMARY123");
        assert_eq!(details.subkeys.len(), 1);
        assert_eq!(details.subkeys[0].algorithm, "EdDSA");
    }

    #[test]
    fn parses_good_signature_status() {
        let signature = CryptoService::parse_signature_status(
            "[GNUPG:] GOODSIG ABCDEF1234567890 Alice Example <alice@example.test>\n\
             [GNUPG:] VALIDSIG 0123456789ABCDEF0123456789ABCDEF01234567 2026-04-14 0 4 0 1 10 00 0123456789ABCDEF0123456789ABCDEF01234567\n",
        );

        assert_eq!(signature.state, "good");
        assert_eq!(signature.signer_key_id.as_deref(), Some("ABCDEF1234567890"));
        assert_eq!(
            signature.signer_fingerprint.as_deref(),
            Some("0123456789ABCDEF0123456789ABCDEF01234567")
        );
        assert!(signature.summary.contains("Good signature"));
    }

    #[test]
    fn parses_missing_signature_status() {
        let signature = CryptoService::parse_signature_status("[GNUPG:] DECRYPTION_OKAY\n");

        assert_eq!(signature.state, "none");
        assert_eq!(signature.summary, "No signature found.");
    }
}
