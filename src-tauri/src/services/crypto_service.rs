use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::{
    errors::{AppError, AppResult},
    models::KeySummary,
};

#[derive(Default)]
pub struct CryptoService;

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
        Err(AppError::External(String::from_utf8_lossy(&output.stderr).trim().to_string()))
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
        Err(AppError::External(String::from_utf8_lossy(&output.stderr).trim().to_string()))
    }

    pub fn list_keys(&self, secret_only: bool) -> AppResult<String> {
        let selector = if secret_only { "--list-secret-keys" } else { "--list-keys" };
        let output = self
            .gpg_command()?
            .args(["--batch", "--with-colons", selector])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return String::from_utf8(output.stdout).map_err(Into::into);
        }
        Err(AppError::External(String::from_utf8_lossy(&output.stderr).trim().to_string()))
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

    pub fn decrypt_file(&self, path: &Path, passphrase: &str) -> AppResult<String> {
        let mut child = self
            .gpg_command()?
            .args([
                "--batch",
                "--yes",
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
        if output.status.success() {
            return String::from_utf8(output.stdout).map_err(Into::into);
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
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

    pub fn encrypt_text_to_file(
        &self,
        recipients: &[String],
        plaintext: &str,
        output_path: &Path,
    ) -> AppResult<()> {
        if recipients.is_empty() {
            return Err(AppError::MissingRecipients);
        }

        let mut command = self.gpg_command()?;
        command
            .args(["--batch", "--yes", "--armor", "--encrypt", "--output"])
            .arg(output_path.as_os_str())
            .args(["--trust-model", "always"]);

        for recipient in recipients {
            command.arg("--recipient").arg(recipient);
        }

        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| AppError::GpgUnavailable)?;

        if let Some(stdin) = &mut child.stdin {
            use std::io::Write;
            stdin.write_all(plaintext.as_bytes())?;
        }

        let output = child.wait_with_output()?;
        if output.status.success() {
            return Ok(());
        }
        Err(AppError::External(String::from_utf8_lossy(&output.stderr).trim().to_string()))
    }

    pub fn encrypt_text_to_armor(&self, recipients: &[String], plaintext: &str) -> AppResult<String> {
        if recipients.is_empty() {
            return Err(AppError::MissingRecipients);
        }

        let mut command = self.gpg_command()?;
        command
            .args(["--batch", "--yes", "--armor", "--encrypt", "--output", "-"])
            .args(["--trust-model", "always"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        for recipient in recipients {
            command.arg("--recipient").arg(recipient);
        }

        let mut child = command.spawn().map_err(|_| AppError::GpgUnavailable)?;

        if let Some(stdin) = &mut child.stdin {
            use std::io::Write;
            stdin.write_all(plaintext.as_bytes())?;
        }

        let output = child.wait_with_output()?;
        if output.status.success() {
            return String::from_utf8(output.stdout).map_err(Into::into);
        }
        Err(AppError::External(String::from_utf8_lossy(&output.stderr).trim().to_string()))
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
        Err(AppError::External(String::from_utf8_lossy(&output.stderr).trim().to_string()))
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
        Err(AppError::External(String::from_utf8_lossy(&output.stderr).trim().to_string()))
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
        Err(AppError::External(String::from_utf8_lossy(&output.stderr).trim().to_string()))
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
        let secret_fingerprints = Self::collect_primary_fingerprints(secret_listing, "sec");

        let mut summaries = Vec::new();
        let mut current_fingerprint: Option<String> = None;
        let mut current_user_ids = Vec::new();
        let mut waiting_for_primary_fpr = false;

        for line in public_listing.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            match parts.first().copied().unwrap_or_default() {
                "pub" => {
                    if let Some(fingerprint) = current_fingerprint.take() {
                        summaries.push(KeySummary {
                            has_secret: secret_fingerprints.contains(&fingerprint),
                            fingerprint,
                            user_ids: current_user_ids.clone(),
                            is_selected_private: false,
                            is_selected_recipient: false,
                        });
                        current_user_ids.clear();
                    }
                    waiting_for_primary_fpr = true;
                }
                "fpr" => {
                    if waiting_for_primary_fpr {
                        current_fingerprint = parts.get(9).map(|value| (*value).to_string());
                        waiting_for_primary_fpr = false;
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
            summaries.push(KeySummary {
                has_secret: secret_fingerprints.contains(&fingerprint),
                fingerprint,
                user_ids: current_user_ids,
                is_selected_private: false,
                is_selected_recipient: false,
            });
        }

        let mut dedup = HashMap::new();
        for summary in summaries {
            dedup.insert(summary.fingerprint.clone(), summary);
        }
        let mut ordered = dedup.into_values().collect::<Vec<_>>();
        ordered.sort_by(|left, right| {
            let left_name = left.user_ids.first().map(String::as_str).unwrap_or("");
            let right_name = right.user_ids.first().map(String::as_str).unwrap_or("");
            left_name
                .cmp(right_name)
                .then_with(|| left.fingerprint.cmp(&right.fingerprint))
        });
        ordered
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
        let secret_listing = "sec:::::::::\nfpr:::::::::PRIMARY123\nssb:::::::::\nfpr:::::::::SUBKEY456\n";

        let keys = service.parse_keys(public_listing, secret_listing);

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].fingerprint, "PRIMARY123");
        assert!(keys[0].has_secret);
    }
}
