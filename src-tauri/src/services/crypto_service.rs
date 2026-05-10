use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::{
    errors::{AppError, AppResult},
    models::{KeySummary, NoteSignatureStatus},
};

#[derive(Default)]
pub struct CryptoService;

#[derive(Clone)]
pub struct ParsedKeyIdentity {
    pub primary_fingerprint: String,
    pub user_ids: Vec<String>,
    pub has_secret: bool,
    pub key_ids: Vec<String>,
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
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("Bad passphrase") {
            return Err(AppError::WrongPrivateKeyPassphrase);
        }
        if stderr.contains("No secret key") {
            return Err(AppError::MissingPrivateKey);
        }
        Err(AppError::External(stderr.trim().to_string()))
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

        if stderr.contains("Bad passphrase") {
            return Err(AppError::WrongPrivateKeyPassphrase);
        }
        if stderr.contains("No secret key") {
            return Err(AppError::MissingPrivateKey);
        }
        if stderr.contains("decryption failed") {
            return Err(AppError::InvalidGpgFile);
        }
        Err(AppError::External(stderr.trim().to_string()))
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

        if stderr.contains("Bad passphrase") {
            return Err(AppError::WrongPrivateKeyPassphrase);
        }
        if stderr.contains("No secret key") {
            return Err(AppError::MissingPrivateKey);
        }
        if stderr.contains("decryption failed") {
            return Err(AppError::InvalidGpgFile);
        }
        Err(AppError::External(stderr.trim().to_string()))
    }

    pub fn decrypt_symmetric_file(
        &self,
        path: &Path,
        password: &str,
    ) -> AppResult<DecryptedContent> {
        self.decrypt_file(path, password)
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

    pub fn verify_detached_signature_text(
        &self,
        signature_text: &str,
        plaintext: &str,
    ) -> AppResult<NoteSignatureStatus> {
        let signature_path = Self::write_temp_with_extension(signature_text, "asc")?;
        let plaintext_path = Self::write_temp_with_extension(plaintext, "txt")?;
        let output = self
            .gpg_command()?
            .args(["--batch", "--yes", "--status-fd", "2", "--verify"])
            .arg(signature_path.as_os_str())
            .arg(plaintext_path.as_os_str())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|_| AppError::GpgUnavailable);
        let _ = fs::remove_file(&signature_path);
        let _ = fs::remove_file(&plaintext_path);

        let output = output?;
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
        let plaintext_path = Self::write_plaintext_temp(plaintext)?;

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
            .arg(plaintext_path.as_os_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let output = Self::run_with_passphrase_stdin(command, passphrase, &plaintext_path)?;
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
        let plaintext_path = Self::write_plaintext_temp(plaintext)?;

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
            .arg(plaintext_path.as_os_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let output = Self::run_with_passphrase_stdin(command, passphrase, &plaintext_path)?;
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
        let plaintext_path = Self::write_plaintext_temp(plaintext)?;

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
            .arg(plaintext_path.as_os_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = Self::run_with_passphrase_stdin(command, passphrase, &plaintext_path)?;
        if output.status.success() {
            return String::from_utf8(output.stdout).map_err(Into::into);
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

        let plaintext_path = Self::write_plaintext_temp(plaintext)?;
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
            .arg(plaintext_path.as_os_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let output = Self::run_with_passphrase_stdin(command, password, &plaintext_path)?;
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
        let plaintext_path = Self::write_plaintext_temp(plaintext)?;

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
        command.arg(plaintext_path.as_os_str());

        let output = Self::run_with_passphrase_stdin(command, passphrase, &plaintext_path)?;
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
            .map(|identity| KeySummary {
                has_secret: identity.has_secret,
                fingerprint: identity.primary_fingerprint,
                user_ids: identity.user_ids,
                is_selected_private: false,
                is_selected_recipient: false,
            })
            .collect()
    }

    pub fn parse_key_identities(
        &self,
        public_listing: &str,
        secret_listing: &str,
    ) -> Vec<ParsedKeyIdentity> {
        let secret_fingerprints = Self::collect_primary_fingerprints(secret_listing, "sec");

        let mut summaries = Vec::new();
        let mut current_fingerprint: Option<String> = None;
        let mut current_user_ids = Vec::new();
        let mut waiting_for_primary_fpr = false;
        let mut waiting_for_subkey_fpr = false;
        let mut current_key_ids = Vec::new();

        for line in public_listing.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            match parts.first().copied().unwrap_or_default() {
                "pub" => {
                    if let Some(fingerprint) = current_fingerprint.take() {
                        summaries.push(ParsedKeyIdentity {
                            has_secret: secret_fingerprints.contains(&fingerprint),
                            primary_fingerprint: fingerprint,
                            user_ids: current_user_ids.clone(),
                            key_ids: current_key_ids.clone(),
                        });
                        current_user_ids.clear();
                        current_key_ids.clear();
                    }
                    waiting_for_primary_fpr = true;
                    waiting_for_subkey_fpr = false;
                }
                "sub" => {
                    waiting_for_subkey_fpr = true;
                }
                "fpr" => {
                    if waiting_for_primary_fpr {
                        current_fingerprint = parts.get(9).map(|value| (*value).to_string());
                        if let Some(fingerprint) = &current_fingerprint {
                            current_key_ids.push(Self::short_key_id(fingerprint));
                        }
                        waiting_for_primary_fpr = false;
                    } else if waiting_for_subkey_fpr {
                        if let Some(fingerprint) = parts.get(9) {
                            current_key_ids.push(Self::short_key_id(fingerprint));
                        }
                        waiting_for_subkey_fpr = false;
                    }
                }
                "uid" => {
                    if let Some(uid) = parts.get(9) {
                        current_user_ids.push((*uid).to_string());
                    }
                }
                _ => {}
            }
        }

        if let Some(fingerprint) = current_fingerprint.take() {
            summaries.push(ParsedKeyIdentity {
                has_secret: secret_fingerprints.contains(&fingerprint),
                primary_fingerprint: fingerprint,
                user_ids: current_user_ids,
                key_ids: current_key_ids,
            });
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
                        fingerprints.insert((*fingerprint).to_string());
                    }
                    waiting_for_primary_fpr = false;
                }
                _ => {}
            }
        }

        fingerprints
    }

    fn write_plaintext_temp(plaintext: &str) -> AppResult<PathBuf> {
        Self::write_temp_with_extension(plaintext, "tmp")
    }

    fn write_temp_with_extension(content: &str, extension: &str) -> AppResult<PathBuf> {
        let path = std::env::temp_dir().join(format!(
            "encryptkeeper-{}.{}",
            uuid::Uuid::new_v4(),
            extension
        ));
        fs::write(&path, content)?;
        Ok(path)
    }

    fn run_with_passphrase_stdin(
        mut command: Command,
        passphrase: &str,
        plaintext_path: &Path,
    ) -> AppResult<std::process::Output> {
        let result = (|| {
            let mut child = command.spawn().map_err(|_| AppError::GpgUnavailable)?;
            if let Some(stdin) = &mut child.stdin {
                use std::io::Write;
                stdin.write_all(passphrase.as_bytes())?;
                stdin.write_all(b"\n")?;
            }
            child.wait_with_output().map_err(Into::into)
        })();
        let _ = fs::remove_file(plaintext_path);
        result
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
        let public_listing = "pub:::::::::\nfpr:::::::::ABC123\nuid:::::::::Alice Example\n";
        let secret_listing = "sec:::::::::\nfpr:::::::::ABC123\n";
        let keys = service.parse_keys(public_listing, secret_listing);
        assert_eq!(keys.len(), 1);
        assert!(keys[0].has_secret);
    }

    #[test]
    fn prefers_primary_fingerprint_over_subkey_fingerprint() {
        let service = CryptoService;
        let public_listing = concat!(
            "pub:::::::::\n",
            "fpr:::::::::PRIMARY123\n",
            "uid:::::::::Alice Example\n",
            "sub:::::::::\n",
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
