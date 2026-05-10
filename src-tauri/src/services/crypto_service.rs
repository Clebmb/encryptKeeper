use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::{
    errors::{AppError, AppResult},
    models::{
        ImportKeyResult, KeyActionResult, KeyCertification, KeyDetails, KeySubkey, KeySummary,
        KeyserverSearchResult, NoteSignatureStatus, SmartcardStatus, X509CertificateSummary,
    },
};
use tempfile::TempDir;

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
    fn gpgsm_command(&self) -> AppResult<Command> {
        let mut command = Command::new("gpgsm");
        command.env("LANG", "C");
        command.env("LC_ALL", "C");
        Ok(command)
    }

    fn gpgconf_command(&self) -> AppResult<Command> {
        #[cfg(windows)]
        {
            if let Some(prefix) = Self::windows_gpg_path_prefix() {
                let candidate = prefix.join("gpgconf.exe");
                if candidate.exists() {
                    let mut command = Command::new(candidate);
                    command.env("LANG", "C");
                    command.env("LC_ALL", "C");
                    return Ok(command);
                }
            }
        }

        let mut command = Command::new("gpgconf");
        command.env("LANG", "C");
        command.env("LC_ALL", "C");
        Ok(command)
    }

    fn gpg_card_command(&self) -> AppResult<Command> {
        let mut command = Command::new("gpg-card");
        command.env("LANG", "C");
        command.env("LC_ALL", "C");
        Ok(command)
    }

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

    pub fn import_key(&self, path: &Path) -> AppResult<ImportKeyResult> {
        let before = self.current_key_fingerprints()?;
        let output = self
            .gpg_command()?
            .args(["--batch", "--status-fd", "2", "--import"])
            .arg(path.as_os_str())
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            let parsed = Self::parse_import_result(&String::from_utf8_lossy(&output.stderr));
            return self.classify_import_result(parsed, &before);
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn import_key_text(&self, armored_text: &str) -> AppResult<ImportKeyResult> {
        let before = self.current_key_fingerprints()?;
        let mut child = self
            .gpg_command()?
            .args(["--batch", "--status-fd", "2", "--import"])
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
            let parsed = Self::parse_import_result(&String::from_utf8_lossy(&output.stderr));
            return self.classify_import_result(parsed, &before);
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn locate_keys(&self, query: &str) -> AppResult<ImportKeyResult> {
        let trimmed_query = query.trim();
        if trimmed_query.is_empty() {
            return Err(AppError::Validation("Lookup query is required.".into()));
        }
        let before = self.current_key_fingerprints()?;

        let output = self
            .gpg_command()?
            .args([
                "--batch",
                "--yes",
                "--status-fd",
                "2",
                "--keyserver",
                "hkps://keys.openpgp.org",
                "--auto-key-locate",
                "clear,wkd,keyserver",
                "--locate-keys",
                trimmed_query,
            ])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            let parsed = Self::parse_import_result(&String::from_utf8_lossy(&output.stderr));
            let mut result = self.classify_import_result(parsed, &before)?;
            if result.imported == 0 && result.unchanged == 0 && result.secret_imported == 0 {
                result.summary =
                    format!("Lookup completed for {trimmed_query}. Review the keyring for matches.");
            } else if result.summary == "Key import completed." {
                result.summary = format!("Lookup completed for {trimmed_query}. {}", result.summary);
            }
            return Ok(result);
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn smartcard_status(&self) -> AppResult<SmartcardStatus> {
        let output = self
            .gpg_command()?
            .args(["--batch", "--card-status"])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = if stdout.trim().is_empty() {
            stderr.to_string()
        } else if stderr.trim().is_empty() {
            stdout.to_string()
        } else {
            format!("{stdout}\n{stderr}")
        };

        if output.status.success() {
            return Ok(Self::parse_smartcard_status(&combined));
        }

        let normalized = combined.to_lowercase();
        if normalized.contains("no such device")
            || normalized.contains("no smartcard daemon")
            || normalized.contains("openpgp card not available")
            || normalized.contains("error getting version")
        {
            return Ok(SmartcardStatus {
                available: false,
                summary: "No smartcard or hardware token detected.".into(),
                reader: None,
                serial_number: None,
                application_id: None,
                manufacturer: None,
                cardholder: None,
                signature_key: None,
                encryption_key: None,
                authentication_key: None,
            });
        }

        Err(AppError::External(combined.trim().to_string()))
    }

    pub fn restart_smartcard_service(&self) -> AppResult<KeyActionResult> {
        let kill = self
            .gpgconf_command()?
            .args(["--kill", "scdaemon"])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if !kill.status.success() {
            return Err(AppError::External(
                String::from_utf8_lossy(&kill.stderr).trim().to_string(),
            ));
        }

        let launch = self
            .gpgconf_command()?
            .args(["--launch", "scdaemon"])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if launch.status.success() {
            return Ok(KeyActionResult {
                fingerprint: "smartcard".into(),
                summary: "Restarted the smartcard service.".into(),
            });
        }
        Err(AppError::External(
            String::from_utf8_lossy(&launch.stderr).trim().to_string(),
        ))
    }

    pub fn change_smartcard_pin(&self) -> AppResult<KeyActionResult> {
        let output = self
            .gpg_command()?
            .arg("--change-pin")
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: "smartcard".into(),
                summary: "Completed the smartcard PIN workflow.".into(),
            });
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        if Self::is_smartcard_unavailable_message(&stderr) {
            return Err(AppError::Validation(
                "No smartcard or hardware token detected.".into(),
            ));
        }
        Err(AppError::External(stderr.trim().to_string()))
    }

    pub fn fetch_smartcard_public_key(&self) -> AppResult<KeyActionResult> {
        let output = self
            .gpg_card_command()?
            .arg("FETCH")
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: "smartcard".into(),
                summary: "Fetched linked public key material from the hardware token.".into(),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = if stdout.trim().is_empty() {
            stderr.to_string()
        } else if stderr.trim().is_empty() {
            stdout.to_string()
        } else {
            format!("{stdout}\n{stderr}")
        };

        if Self::is_smartcard_unavailable_message(&combined) {
            return Err(AppError::Validation(
                "No smartcard or hardware token detected.".into(),
            ));
        }
        if combined.to_lowercase().contains("no key") || combined.to_lowercase().contains("no url")
        {
            return Err(AppError::Validation(
                "The hardware token does not expose a fetchable public key reference.".into(),
            ));
        }
        Err(AppError::External(combined.trim().to_string()))
    }

    pub fn create_smartcard_key_stubs(&self) -> AppResult<KeyActionResult> {
        let output = self
            .gpg_card_command()?
            .args(["LIST", "--shadow"])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: "smartcard".into(),
                summary: "Created local shadow keys for the hardware token.".into(),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = if stdout.trim().is_empty() {
            stderr.to_string()
        } else if stderr.trim().is_empty() {
            stdout.to_string()
        } else {
            format!("{stdout}\n{stderr}")
        };

        if Self::is_smartcard_unavailable_message(&combined) {
            return Err(AppError::Validation(
                "No smartcard or hardware token detected.".into(),
            ));
        }
        Err(AppError::External(combined.trim().to_string()))
    }

    pub fn generate_smartcard_key(
        &self,
        slot: &str,
        algorithm: &str,
        force: bool,
    ) -> AppResult<KeyActionResult> {
        let trimmed_slot = slot.trim();
        let trimmed_algorithm = algorithm.trim();
        if trimmed_slot.is_empty() {
            return Err(AppError::Validation("Card key slot is required.".into()));
        }
        if trimmed_algorithm.is_empty() {
            return Err(AppError::Validation("Card key algorithm is required.".into()));
        }

        let mut command = self.gpg_card_command()?;
        command.arg("GENERATE");
        if force {
            command.arg("--force");
        }
        let output = command
            .arg(format!("--algo={trimmed_algorithm}"))
            .arg(trimmed_slot)
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: "smartcard".into(),
                summary: format!(
                    "{} {trimmed_algorithm} key material on hardware token slot {trimmed_slot}.",
                    if force { "Replaced" } else { "Generated" }
                ),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = if stdout.trim().is_empty() {
            stderr.to_string()
        } else if stderr.trim().is_empty() {
            stdout.to_string()
        } else {
            format!("{stdout}\n{stderr}")
        };

        if Self::is_smartcard_unavailable_message(&combined) {
            return Err(AppError::Validation(
                "No smartcard or hardware token detected.".into(),
            ));
        }
        Err(AppError::External(combined.trim().to_string()))
    }

    pub fn factory_reset_smartcard(&self) -> AppResult<KeyActionResult> {
        let output = self
            .gpg_card_command()?
            .arg("FACTORY-RESET")
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: "smartcard".into(),
                summary: "Factory reset completed for the hardware token.".into(),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = if stdout.trim().is_empty() {
            stderr.to_string()
        } else if stderr.trim().is_empty() {
            stdout.to_string()
        } else {
            format!("{stdout}\n{stderr}")
        };

        if Self::is_smartcard_unavailable_message(&combined) {
            return Err(AppError::Validation(
                "No smartcard or hardware token detected.".into(),
            ));
        }
        Err(AppError::External(combined.trim().to_string()))
    }

    pub fn move_secret_key_to_smartcard(
        &self,
        fingerprint: &str,
        slot: &str,
        force: bool,
    ) -> AppResult<KeyActionResult> {
        let normalized_fingerprint = Self::normalize_fingerprint(fingerprint);
        let trimmed_slot = slot.trim();
        if normalized_fingerprint.is_empty() {
            return Err(AppError::Validation("Secret key fingerprint is required.".into()));
        }
        if trimmed_slot.is_empty() {
            return Err(AppError::Validation("Card key slot is required.".into()));
        }

        let keygrip = self.secret_keygrip_for_fingerprint(&normalized_fingerprint)?;

        let mut command = self.gpg_card_command()?;
        command.arg("WRITEKEY");
        if force {
            command.arg("--force");
        }
        let output = command
            .arg(trimmed_slot)
            .arg(&keygrip)
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: normalized_fingerprint.clone(),
                summary: format!(
                    "{} local secret key {} into hardware token slot {}.",
                    if force { "Moved" } else { "Stored" },
                    normalized_fingerprint,
                    trimmed_slot
                ),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = if stdout.trim().is_empty() {
            stderr.to_string()
        } else if stderr.trim().is_empty() {
            stdout.to_string()
        } else {
            format!("{stdout}\n{stderr}")
        };

        if Self::is_smartcard_unavailable_message(&combined) {
            return Err(AppError::Validation(
                "No smartcard or hardware token detected.".into(),
            ));
        }
        Err(AppError::External(combined.trim().to_string()))
    }

    pub fn search_keyserver(&self, query: &str) -> AppResult<Vec<KeyserverSearchResult>> {
        let trimmed_query = query.trim();
        if trimmed_query.is_empty() {
            return Err(AppError::Validation("Search query is required.".into()));
        }

        let output = self
            .gpg_command()?
            .args([
                "--batch",
                "--with-colons",
                "--keyserver",
                "hkps://keys.openpgp.org",
                "--search-keys",
                trimmed_query,
            ])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;

        if output.status.success() {
            return Ok(Self::parse_keyserver_search_results(
                &String::from_utf8_lossy(&output.stdout),
            ));
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("not found on keyserver") {
            return Ok(Vec::new());
        }
        Err(AppError::External(stderr.trim().to_string()))
    }

    pub fn receive_key_from_keyserver(&self, fingerprint: &str) -> AppResult<ImportKeyResult> {
        let trimmed = fingerprint.trim();
        if trimmed.is_empty() {
            return Err(AppError::Validation("Fingerprint is required.".into()));
        }
        let before = self.current_key_fingerprints()?;

        let output = self
            .gpg_command()?
            .args([
                "--batch",
                "--status-fd",
                "2",
                "--keyserver",
                "hkps://keys.openpgp.org",
                "--receive-keys",
                trimmed,
            ])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            let parsed = Self::parse_import_result(&String::from_utf8_lossy(&output.stderr));
            return self.classify_import_result(parsed, &before);
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn send_key_to_keyserver(&self, fingerprint: &str) -> AppResult<KeyActionResult> {
        let trimmed = fingerprint.trim();
        if trimmed.is_empty() {
            return Err(AppError::Validation("Fingerprint is required.".into()));
        }

        let output = self
            .gpg_command()?
            .args([
                "--batch",
                "--yes",
                "--keyserver",
                "hkps://keys.openpgp.org",
                "--send-keys",
                trimmed,
            ])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: trimmed.to_string(),
                summary: format!("Published {trimmed} to the public keyserver."),
            });
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn refresh_key_from_keyserver(&self, fingerprint: &str) -> AppResult<KeyActionResult> {
        let result = self.receive_key_from_keyserver(fingerprint)?;
        Ok(KeyActionResult {
            fingerprint: fingerprint.trim().to_string(),
            summary: format!("Refreshed from keyserver. {}", result.summary),
        })
    }

    pub fn refresh_all_keys_from_keyserver(&self) -> AppResult<KeyActionResult> {
        let output = self
            .gpg_command()?
            .args([
                "--batch",
                "--status-fd",
                "2",
                "--keyserver",
                "hkps://keys.openpgp.org",
                "--refresh-keys",
            ])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            let parsed = Self::parse_import_result(&String::from_utf8_lossy(&output.stderr));
            let summary = if parsed.summary == "Key import completed." {
                "Refreshed keyring from keyserver.".to_string()
            } else {
                format!("Refreshed keyring from keyserver. {}", parsed.summary)
            };
            return Ok(KeyActionResult {
                fingerprint: "all".into(),
                summary,
            });
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn quick_add_subkey(
        &self,
        fingerprint: &str,
        passphrase: &str,
        algorithm: &str,
        usage: &str,
        expire: &str,
    ) -> AppResult<KeyActionResult> {
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
                "--quick-add-key",
                fingerprint,
                algorithm,
                usage,
                expire,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let output = Self::run_with_passphrase_only(command, passphrase)?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: fingerprint.to_string(),
                summary: format!("Added a {usage} subkey to {fingerprint}."),
            });
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn quick_set_expire(&self, fingerprint: &str, expire: &str) -> AppResult<KeyActionResult> {
        let output = self
            .gpg_command()?
            .args(["--batch", "--yes", "--quick-set-expire", fingerprint, expire])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: fingerprint.to_string(),
                summary: format!("Updated expiration for {fingerprint}."),
            });
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn quick_set_ownertrust(
        &self,
        fingerprint: &str,
        trust_value: &str,
    ) -> AppResult<KeyActionResult> {
        let output = self
            .gpg_command()?
            .args([
                "--batch",
                "--yes",
                "--quick-set-ownertrust",
                fingerprint,
                trust_value,
            ])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: fingerprint.to_string(),
                summary: format!("Updated ownertrust for {fingerprint} to {trust_value}."),
            });
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn export_ownertrust(&self, output_path: &Path) -> AppResult<KeyActionResult> {
        let contents = self.export_ownertrust_text()?;
        fs::write(output_path, contents)?;
        Ok(KeyActionResult {
            fingerprint: "ownertrust".into(),
            summary: format!("Exported ownertrust to {}.", output_path.display()),
        })
    }

    fn export_ownertrust_text(&self) -> AppResult<String> {
        let output = self
            .gpg_command()?
            .args(["--batch", "--yes", "--export-ownertrust"])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return String::from_utf8(output.stdout).map_err(Into::into);
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn import_ownertrust(&self, input_path: &Path) -> AppResult<KeyActionResult> {
        let output = self
            .gpg_command()?
            .args(["--batch", "--yes", "--import-ownertrust"])
            .arg(input_path.as_os_str())
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: "ownertrust".into(),
                summary: format!("Imported ownertrust from {}.", input_path.display()),
            });
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn quick_sign_key(
        &self,
        signer: &str,
        passphrase: &str,
        fingerprint: &str,
        local_only: bool,
    ) -> AppResult<KeyActionResult> {
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
            ])
            .arg(if local_only {
                "--quick-lsign-key"
            } else {
                "--quick-sign-key"
            })
            .arg(fingerprint)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let output = Self::run_with_passphrase_only(command, passphrase)?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: fingerprint.to_string(),
                summary: if local_only {
                    format!("Locally certified {fingerprint}.")
                } else {
                    format!("Certified {fingerprint}.")
                },
            });
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn change_key_passphrase(
        &self,
        fingerprint: &str,
        current_passphrase: &str,
        new_passphrase: &str,
    ) -> AppResult<KeyActionResult> {
        if current_passphrase.is_empty() {
            return Err(AppError::Validation("Current key passphrase is required.".into()));
        }
        if new_passphrase.is_empty() {
            return Err(AppError::Validation("New key passphrase is required.".into()));
        }

        let mut command = self.gpg_command()?;
        command
            .args([
                "--batch",
                "--yes",
                "--command-fd",
                "0",
                "--pinentry-mode",
                "loopback",
                "--passwd",
                fingerprint,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let output = Self::run_with_input_lines(
            command,
            &[current_passphrase, new_passphrase, new_passphrase, "y"],
        )?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: fingerprint.to_string(),
                summary: format!("Updated passphrase for {fingerprint}."),
            });
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(Self::passphrase_error(&stderr))
    }

    pub fn export_revocation_certificate(
        &self,
        fingerprint: &str,
        passphrase: &str,
        output_path: &Path,
    ) -> AppResult<KeyActionResult> {
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
            .args(["--gen-revoke", fingerprint])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| AppError::GpgUnavailable)?;

        if let Some(stdin) = &mut child.stdin {
            use std::io::Write;
            stdin.write_all(passphrase.as_bytes())?;
            stdin.write_all(b"\n")?;
            stdin.write_all(b"0\n")?;
            stdin.write_all(b"\n")?;
            stdin.write_all(b"y\n")?;
        }

        let output = child.wait_with_output()?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: fingerprint.to_string(),
                summary: format!(
                    "Saved revocation certificate to {}.",
                    output_path.display()
                ),
            });
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

    pub fn list_key_signatures(&self, fingerprint: &str) -> AppResult<String> {
        let output = self
            .gpg_command()?
            .args(["--batch", "--with-colons", "--list-sigs", fingerprint])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return String::from_utf8(output.stdout).map_err(Into::into);
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn list_x509_certificates(&self) -> AppResult<Vec<X509CertificateSummary>> {
        let trusted_roots = self.trusted_x509_roots().unwrap_or_default();
        let output = Command::new("gpgsm")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .args(["--with-colons", "--list-keys"])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if !output.status.success() {
            return Err(AppError::External(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }

        let secret_output = Command::new("gpgsm")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .args(["--with-colons", "--list-secret-keys"])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if !secret_output.status.success() {
            return Err(AppError::External(
                String::from_utf8_lossy(&secret_output.stderr)
                    .trim()
                    .to_string(),
            ));
        }

        Ok(Self::apply_x509_trust_roots(
            Self::merge_x509_certificates(
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&secret_output.stdout),
            ),
            &trusted_roots,
        ))
    }

    pub fn learn_x509_card(&self) -> AppResult<KeyActionResult> {
        let output = self
            .gpgsm_command()?
            .arg("--learn-card")
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: "x509-card".into(),
                summary: "Learned X.509 certificate material from the smartcard.".into(),
            });
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        if Self::is_smartcard_unavailable_message(&stderr) {
            return Err(AppError::Validation(
                "No smartcard or hardware token detected.".into(),
            ));
        }
        Err(AppError::External(stderr.trim().to_string()))
    }

    pub fn import_x509_certificate(&self, path: &Path) -> AppResult<KeyActionResult> {
        let output = Command::new("gpgsm")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .args(["--batch", "--yes", "--import"])
            .arg(path.as_os_str())
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: "x509".into(),
                summary: format!("Imported X.509 certificate from {}.", path.display()),
            });
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn import_x509_certificate_text(&self, certificate_text: &str) -> AppResult<KeyActionResult> {
        let trimmed = certificate_text.trim();
        if trimmed.is_empty() {
            return Err(AppError::Validation("Certificate text is required.".into()));
        }

        let temp_dir = TempDir::new().map_err(|error| AppError::External(error.to_string()))?;
        let import_path = temp_dir.path().join("import-cert.pem");
        fs::write(&import_path, trimmed.as_bytes())?;
        self.import_x509_certificate(import_path.as_path())
    }

    pub fn create_x509_certificate(
        &self,
        common_name: &str,
        organization: &str,
        email: &str,
        expires_at: &str,
        passphrase: &str,
    ) -> AppResult<KeyActionResult> {
        let trimmed_common_name = common_name.trim();
        let trimmed_organization = organization.trim();
        let trimmed_email = email.trim();
        let trimmed_expires_at = expires_at.trim();

        if trimmed_common_name.is_empty() {
            return Err(AppError::Validation("Certificate name is required.".into()));
        }
        if trimmed_expires_at.is_empty() {
            return Err(AppError::Validation("Certificate expiry date is required.".into()));
        }
        if passphrase.is_empty() {
            return Err(AppError::Validation("Certificate passphrase is required.".into()));
        }

        let before = self.current_x509_fingerprints()?;
        let subject_dn = Self::build_x509_subject_dn(trimmed_common_name, trimmed_organization);
        let mut parameters = vec![
            "Key-Type: RSA".to_string(),
            "Key-Length: 3072".to_string(),
            format!("Name-DN: {subject_dn}"),
            "Serial: random".to_string(),
            format!("Expire-Date: {trimmed_expires_at}"),
        ];
        if !trimmed_email.is_empty() {
            parameters.push(format!("Name-Email: {trimmed_email}"));
        }
        let parameter_text = format!("{}\n", parameters.join("\n"));

        let temp_dir = TempDir::new().map_err(|error| AppError::External(error.to_string()))?;
        let parameter_path = temp_dir.path().join("x509-create.params");
        fs::write(&parameter_path, parameter_text)?;

        let output = self
            .gpgsm_command()?
            .args([
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                passphrase,
                "--generate-key",
            ])
            .arg(parameter_path.as_os_str())
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if !output.status.success() {
            return Err(AppError::External(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }
        if !output.stdout.is_empty() {
            let generated_path = temp_dir.path().join("generated.cer");
            fs::write(&generated_path, &output.stdout)?;
            let import_output = self
                .gpgsm_command()?
                .args(["--batch", "--yes", "--import"])
                .arg(generated_path.as_os_str())
                .output()
                .map_err(|_| AppError::GpgUnavailable)?;
            if !import_output.status.success() {
                return Err(AppError::External(
                    String::from_utf8_lossy(&import_output.stderr)
                        .trim()
                        .to_string(),
                ));
            }
        }

        let certificates = self.list_x509_certificates()?;
        let created = certificates
            .iter()
            .find(|certificate| !before.contains(&certificate.fingerprint))
            .or_else(|| certificates.iter().find(|certificate| certificate.subject == subject_dn));

        Ok(KeyActionResult {
            fingerprint: created
                .map(|certificate| certificate.fingerprint.clone())
                .unwrap_or_else(|| "x509".to_string()),
            summary: format!("Created X.509 certificate for {subject_dn}."),
        })
    }

    pub fn export_x509_certificate(
        &self,
        fingerprint: &str,
        output_path: &Path,
    ) -> AppResult<KeyActionResult> {
        let output = Command::new("gpgsm")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .args(["--batch", "--yes", "--armor", "--output"])
            .arg(output_path.as_os_str())
            .args(["--export", fingerprint])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: fingerprint.to_string(),
                summary: format!("Exported X.509 certificate to {}.", output_path.display()),
            });
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn export_x509_secret_key_p12(
        &self,
        fingerprint: &str,
        output_path: &Path,
    ) -> AppResult<KeyActionResult> {
        let output = self
            .gpgsm_command()?
            .args(["--export-secret-key-p12", fingerprint])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            fs::write(output_path, output.stdout)?;
            return Ok(KeyActionResult {
                fingerprint: fingerprint.to_string(),
                summary: format!("Exported PKCS#12 bundle to {}.", output_path.display()),
            });
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn export_x509_secret_key_p8(
        &self,
        fingerprint: &str,
        output_path: &Path,
    ) -> AppResult<KeyActionResult> {
        let output = self
            .gpgsm_command()?
            .args(["--armor", "--export-secret-key-p8", fingerprint])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            fs::write(output_path, output.stdout)?;
            return Ok(KeyActionResult {
                fingerprint: fingerprint.to_string(),
                summary: format!("Exported PKCS#8 key to {}.", output_path.display()),
            });
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn change_x509_passphrase(&self, fingerprint: &str) -> AppResult<KeyActionResult> {
        let output = self
            .gpgsm_command()?
            .args(["--change-passphrase", fingerprint])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: fingerprint.to_string(),
                summary: format!("Completed the X.509 passphrase workflow for {fingerprint}."),
            });
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn delete_x509_certificate(&self, fingerprint: &str) -> AppResult<KeyActionResult> {
        let secret_keygrip = self.x509_secret_keygrip_for_fingerprint(fingerprint).ok();
        let output = self
            .gpgsm_command()?
            .args(["--batch", "--yes", "--delete-keys", fingerprint])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            if let Some(keygrip) = secret_keygrip {
                let secret_key_path = self.gnupg_home_dir()?.join("private-keys-v1.d").join(format!("{keygrip}.key"));
                if secret_key_path.exists() {
                    fs::remove_file(secret_key_path)?;
                }
            }
            return Ok(KeyActionResult {
                fingerprint: fingerprint.to_string(),
                summary: format!("Removed X.509 certificate {fingerprint}."),
            });
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn list_x509_certificate_chain(&self, fingerprint: &str) -> AppResult<String> {
        let output = self
            .gpgsm_command()?
            .args(["--with-validation", "--list-chain", fingerprint])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            let stdout = String::from_utf8(output.stdout)?;
            let stderr = String::from_utf8_lossy(&output.stderr);
            let combined = if stderr.trim().is_empty() {
                stdout
            } else if stdout.trim().is_empty() {
                stderr.to_string()
            } else {
                format!("{stdout}\n{stderr}")
            };
            return Ok(combined.trim().to_string());
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn import_x509_crl(&self, path: &Path) -> AppResult<KeyActionResult> {
        let output = self
            .gpgsm_command()?
            .args(["--call-dirmngr", "loadcrl"])
            .arg(path.as_os_str())
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(KeyActionResult {
                fingerprint: "x509-crl".into(),
                summary: format!("Loaded certificate revocation data from {}.", path.display()),
            });
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn set_x509_trust_root(
        &self,
        fingerprint: &str,
        trusted: bool,
    ) -> AppResult<KeyActionResult> {
        let normalized = Self::normalize_fingerprint(fingerprint);
        if normalized.is_empty() {
            return Err(AppError::Validation("Certificate fingerprint is required.".into()));
        }

        let trustlist_path = self.trustlist_path()?;
        let mut entries = self.read_trustlist_entries(&trustlist_path)?;
        if trusted {
            if !entries.iter().any(|entry| entry.eq_ignore_ascii_case(&normalized)) {
                entries.push(normalized.clone());
            }
        } else {
            entries.retain(|entry| !entry.eq_ignore_ascii_case(&normalized));
        }
        self.write_trustlist_entries(&trustlist_path, &entries)?;

        let reload = self
            .gpgconf_command()?
            .args(["--reload", "gpg-agent"])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if !reload.status.success() {
            return Err(AppError::External(
                String::from_utf8_lossy(&reload.stderr).trim().to_string(),
            ));
        }

        Ok(KeyActionResult {
            fingerprint: normalized.clone(),
            summary: if trusted {
                format!("Marked {normalized} as a trusted root certificate.")
            } else {
                format!("Removed {normalized} from trusted root certificates.")
            },
        })
    }

    pub fn export_x509_trustlist(&self, output_path: &Path) -> AppResult<KeyActionResult> {
        let entries = self.read_trustlist_entries(&self.trustlist_path()?)?;
        fs::write(output_path, Self::render_trustlist_entries(&entries))?;
        Ok(KeyActionResult {
            fingerprint: "x509-trustlist".into(),
            summary: format!(
                "Exported {} trusted root certificate{} to {}.",
                entries.len(),
                if entries.len() == 1 { "" } else { "s" },
                output_path.display()
            ),
        })
    }

    pub fn import_x509_trustlist(&self, input_path: &Path) -> AppResult<KeyActionResult> {
        let contents = fs::read_to_string(input_path)?;
        let entries = Self::parse_trustlist_entries(&contents);
        self.write_trustlist_entries(&self.trustlist_path()?, &entries)?;

        let reload = self
            .gpgconf_command()?
            .args(["--reload", "gpg-agent"])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if !reload.status.success() {
            return Err(AppError::External(
                String::from_utf8_lossy(&reload.stderr).trim().to_string(),
            ));
        }

        Ok(KeyActionResult {
            fingerprint: "x509-trustlist".into(),
            summary: format!(
                "Imported {} trusted root certificate{} from {}.",
                entries.len(),
                if entries.len() == 1 { "" } else { "s" },
                input_path.display()
            ),
        })
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

    pub fn encrypt_cms_file_to_file(
        &self,
        recipients: &[String],
        input_path: &Path,
        output_path: &Path,
    ) -> AppResult<()> {
        if recipients.is_empty() {
            return Err(AppError::Validation(
                "Choose one or more X.509 recipient certificates.".into(),
            ));
        }

        let mut command = self.gpgsm_command()?;
        command.args(["--batch", "--yes", "--encrypt", "--output"]);
        command.arg(output_path.as_os_str());
        for recipient in recipients {
            command.arg("--recipient").arg(recipient);
        }
        command.arg(input_path.as_os_str());

        let output = command.output().map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(());
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn decrypt_cms_file_to_path(&self, input_path: &Path, output_path: &Path) -> AppResult<()> {
        let output = self
            .gpgsm_command()?
            .args(["--batch", "--yes", "--decrypt", "--output"])
            .arg(output_path.as_os_str())
            .arg(input_path.as_os_str())
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(());
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn create_cms_detached_signature(
        &self,
        signer: &str,
        input_path: &Path,
        output_path: &Path,
    ) -> AppResult<()> {
        let output = self
            .gpgsm_command()?
            .args([
                "--batch",
                "--yes",
                "--local-user",
                signer,
                "--output",
            ])
            .arg(output_path.as_os_str())
            .arg("--detach-sign")
            .arg(input_path.as_os_str())
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if output.status.success() {
            return Ok(());
        }
        Err(AppError::External(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    pub fn verify_cms_detached_signature(
        &self,
        signature_path: &Path,
        input_path: &Path,
    ) -> AppResult<NoteSignatureStatus> {
        let output = self
            .gpgsm_command()?
            .args(["--batch", "--status-fd", "2", "--verify"])
            .arg(signature_path.as_os_str())
            .arg(input_path.as_os_str())
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.success() {
            return Ok(NoteSignatureStatus {
                state: "good".into(),
                signer_key_id: None,
                signer_fingerprint: None,
                signer_label: None,
                summary: "CMS signature verified.".into(),
            });
        }

        let normalized = stderr.to_lowercase();
        let summary = if normalized.contains("no data")
            || normalized.contains("invalid")
            || normalized.contains("bad")
        {
            "CMS signature verification failed.".to_string()
        } else {
            stderr.trim().to_string()
        };
        Ok(NoteSignatureStatus {
            state: "bad".into(),
            signer_key_id: None,
            signer_fingerprint: None,
            signer_label: None,
            summary,
        })
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
        signatures_listing: &str,
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
                certifications: Self::parse_key_certifications(
                    signatures_listing,
                    &identity.primary_fingerprint,
                    &identity.key_id,
                ),
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

    fn current_x509_fingerprints(&self) -> AppResult<HashSet<String>> {
        Ok(self
            .list_x509_certificates()?
            .into_iter()
            .map(|certificate| certificate.fingerprint)
            .collect())
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

    fn build_x509_subject_dn(common_name: &str, organization: &str) -> String {
        let mut parts = Vec::new();
        parts.push(format!("CN={}", Self::escape_x509_dn_value(common_name)));
        if !organization.is_empty() {
            parts.push(format!("O={}", Self::escape_x509_dn_value(organization)));
        }
        parts.join(",")
    }

    fn escape_x509_dn_value(value: &str) -> String {
        let mut escaped = value
            .replace('\\', "\\\\")
            .replace(',', "\\,")
            .replace('+', "\\+")
            .replace('"', "\\\"")
            .replace('<', "\\<")
            .replace('>', "\\>")
            .replace(';', "\\;");

        if escaped.starts_with(' ') || escaped.starts_with('#') {
            escaped.insert(0, '\\');
        }
        if escaped.ends_with(' ') {
            escaped.pop();
            escaped.push_str("\\ ");
        }

        escaped
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

    fn run_with_input_lines(
        mut command: Command,
        lines: &[&str],
    ) -> AppResult<std::process::Output> {
        let mut child = command.spawn().map_err(|_| AppError::GpgUnavailable)?;
        if let Some(stdin) = &mut child.stdin {
            use std::io::Write;
            for line in lines {
                stdin.write_all(line.as_bytes())?;
                stdin.write_all(b"\n")?;
            }
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

    fn parse_import_result(status_output: &str) -> ImportKeyResult {
        let mut imported = 0_u32;
        let mut unchanged = 0_u32;
        let mut secret_imported = 0_u32;
        let mut fingerprints = Vec::new();

        for line in status_output.lines() {
            let Some(rest) = line.strip_prefix("[GNUPG:] ") else {
                continue;
            };
            let mut parts = rest.split_whitespace();
            match parts.next().unwrap_or_default() {
                "IMPORT_OK" => {
                    let _reason = parts.next();
                    if let Some(fingerprint) = parts.next() {
                        fingerprints.push(fingerprint.to_uppercase());
                    }
                }
                "IMPORT_RES" => {
                    let values = parts.collect::<Vec<_>>();
                    imported = values
                        .get(2)
                        .and_then(|value| value.parse::<u32>().ok())
                        .unwrap_or(0);
                    unchanged = values
                        .get(3)
                        .and_then(|value| value.parse::<u32>().ok())
                        .unwrap_or(0);
                    secret_imported = values
                        .get(12)
                        .and_then(|value| value.parse::<u32>().ok())
                        .unwrap_or(0);
                }
                _ => {}
            }
        }

        if fingerprints.is_empty() && imported == 0 && unchanged == 0 && secret_imported == 0 {
            imported = 1;
        }

        let mut summary_parts = Vec::new();
        if imported > 0 {
            summary_parts.push(format!("Imported {imported} key(s)"));
        }
        if unchanged > 0 {
            summary_parts.push(format!("{unchanged} unchanged"));
        }
        if secret_imported > 0 {
            summary_parts.push(format!("{secret_imported} secret key(s)"));
        }
        let summary = if summary_parts.is_empty() {
            "Key import completed.".to_string()
        } else {
            format!("{}.", summary_parts.join(", "))
        };

        ImportKeyResult {
            imported,
            unchanged,
            secret_imported,
            fingerprints,
            imported_fingerprints: Vec::new(),
            unchanged_fingerprints: Vec::new(),
            summary,
        }
    }

    fn current_key_fingerprints(&self) -> AppResult<HashSet<String>> {
        let public_listing = self.list_keys(false)?;
        let secret_listing = self.list_keys(true)?;
        Ok(self
            .parse_key_identities(&public_listing, &secret_listing)
            .into_iter()
            .map(|identity| identity.primary_fingerprint)
            .collect())
    }

    fn classify_import_result(
        &self,
        mut result: ImportKeyResult,
        before: &HashSet<String>,
    ) -> AppResult<ImportKeyResult> {
        let after = self.current_key_fingerprints()?;
        let reported = result
            .fingerprints
            .iter()
            .cloned()
            .collect::<HashSet<_>>();

        let mut imported_fingerprints = result
            .fingerprints
            .iter()
            .filter(|fingerprint| !before.contains(*fingerprint))
            .cloned()
            .collect::<Vec<_>>();
        let mut unchanged_fingerprints = result
            .fingerprints
            .iter()
            .filter(|fingerprint| before.contains(*fingerprint))
            .cloned()
            .collect::<Vec<_>>();

        if imported_fingerprints.is_empty() && result.imported > 0 {
            imported_fingerprints = after.difference(before).cloned().collect::<Vec<_>>();
        }

        if unchanged_fingerprints.is_empty() && result.unchanged > 0 {
            unchanged_fingerprints = reported.intersection(before).cloned().collect::<Vec<_>>();
        }

        imported_fingerprints.sort();
        imported_fingerprints.dedup();
        unchanged_fingerprints.sort();
        unchanged_fingerprints.dedup();

        if result.fingerprints.is_empty() {
            let mut combined = imported_fingerprints.clone();
            combined.extend(unchanged_fingerprints.iter().cloned());
            combined.sort();
            combined.dedup();
            result.fingerprints = combined;
        }

        result.imported_fingerprints = imported_fingerprints;
        result.unchanged_fingerprints = unchanged_fingerprints;
        Ok(result)
    }

    fn parse_smartcard_status(output: &str) -> SmartcardStatus {
        let mut reader = None;
        let mut serial_number = None;
        let mut application_id = None;
        let mut manufacturer = None;
        let mut cardholder = None;
        let mut signature_key = None;
        let mut encryption_key = None;
        let mut authentication_key = None;

        for line in output.lines() {
            let trimmed = line.trim();
            let Some((label, value)) = trimmed.split_once(':') else {
                continue;
            };
            let key = label.replace('.', "").trim().to_lowercase();
            let parsed = value.trim();
            if parsed.is_empty() || parsed == "[none]" {
                continue;
            }

            match key.as_str() {
                "reader" => reader = Some(parsed.to_string()),
                "serial number" => serial_number = Some(parsed.to_string()),
                "application id" => application_id = Some(parsed.to_string()),
                "manufacturer" => manufacturer = Some(parsed.to_string()),
                "name of cardholder" => cardholder = Some(parsed.to_string()),
                "signature key" => signature_key = Some(parsed.to_string()),
                "encryption key" => encryption_key = Some(parsed.to_string()),
                "authentication key" => authentication_key = Some(parsed.to_string()),
                _ => {}
            }
        }

        let available = reader.is_some() || serial_number.is_some() || application_id.is_some();
        let summary = if available {
            format!(
                "Hardware token detected{}.",
                reader
                    .as_ref()
                    .map(|value| format!(" on {value}"))
                    .unwrap_or_default()
            )
        } else {
            "No smartcard or hardware token detected.".to_string()
        };

        SmartcardStatus {
            available,
            summary,
            reader,
            serial_number,
            application_id,
            manufacturer,
            cardholder,
            signature_key,
            encryption_key,
            authentication_key,
        }
    }

    fn parse_keyserver_search_results(output: &str) -> Vec<KeyserverSearchResult> {
        let mut results = Vec::new();
        let mut current: Option<KeyserverSearchResult> = None;

        for line in output.lines() {
            let parts = line.split(':').collect::<Vec<_>>();
            match parts.first().copied().unwrap_or_default() {
                "pub" => {
                    if let Some(existing) = current.take() {
                        results.push(existing);
                    }
                    current = Some(KeyserverSearchResult {
                        fingerprint: parts.get(1).copied().unwrap_or_default().to_uppercase(),
                        algorithm: Self::parse_algorithm(parts.get(2).copied().unwrap_or_default()),
                        bits: parts
                            .get(3)
                            .and_then(|value| value.parse::<u32>().ok())
                            .unwrap_or(0),
                        created_at: Self::parse_epoch(parts.get(4).copied()),
                        user_ids: Vec::new(),
                    });
                }
                "uid" => {
                    if let Some(current) = &mut current {
                        let user_id = parts
                            .get(1)
                            .copied()
                            .unwrap_or_default()
                            .replace("%3C", "<")
                            .replace("%3E", ">")
                            .replace("%40", "@");
                        current.user_ids.push(user_id);
                    }
                }
                _ => {}
            }
        }

        if let Some(existing) = current.take() {
            results.push(existing);
        }

        results
    }

    fn parse_key_certifications(
        output: &str,
        primary_fingerprint: &str,
        primary_key_id: &str,
    ) -> Vec<KeyCertification> {
        let mut certifications: Vec<KeyCertification> = Vec::new();
        let mut current_pub_fingerprint = String::new();
        let mut current_uid: Option<String> = None;
        let mut pending_sig_fingerprint: Option<String> = None;

        for line in output.lines() {
            let parts = line.split(':').collect::<Vec<_>>();
            match parts.first().copied().unwrap_or_default() {
                "pub" => {
                    current_pub_fingerprint.clear();
                    current_uid = None;
                    pending_sig_fingerprint = None;
                }
                "fpr" => {
                    let value = parts.get(9).copied().unwrap_or_default().to_uppercase();
                    if pending_sig_fingerprint.is_some() {
                        if let Some(last) = certifications.last_mut() {
                            last.signer_fingerprint = Some(value);
                        }
                        pending_sig_fingerprint = None;
                    } else if current_pub_fingerprint.is_empty() {
                        current_pub_fingerprint = value;
                    }
                }
                "uid" => {
                    current_uid = parts.get(9).map(|value| (*value).to_string());
                }
                "sig" if current_pub_fingerprint.eq_ignore_ascii_case(primary_fingerprint) => {
                    let signer_key_id = parts.get(4).copied().unwrap_or_default().to_uppercase();
                    let signer_label = parts
                        .get(9)
                        .copied()
                        .filter(|value| !value.is_empty())
                        .unwrap_or("Unknown signer")
                        .to_string();
                    let signature_class = parts.get(10).copied().unwrap_or_default();
                    let is_self_signature = signer_key_id == primary_key_id
                        || parts
                            .get(12)
                            .copied()
                            .is_some_and(|value| value.eq_ignore_ascii_case(primary_fingerprint));
                    certifications.push(KeyCertification {
                        signer_key_id,
                        signer_fingerprint: None,
                        signer_label,
                        subject_user_id: current_uid.clone(),
                        created_at: Self::parse_epoch(parts.get(5).copied()),
                        kind: Self::parse_certification_kind(signature_class, is_self_signature),
                        is_self_signature,
                    });
                    pending_sig_fingerprint = Some(String::new());
                }
                _ => {}
            }
        }

        certifications.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| left.signer_label.cmp(&right.signer_label))
        });
        certifications
    }

    fn parse_certification_kind(signature_class: &str, is_self_signature: bool) -> String {
        if is_self_signature {
            return "Self-signature".to_string();
        }
        match signature_class {
            value if value.starts_with("10") => "Generic certification".to_string(),
            value if value.starts_with("11") => "Persona certification".to_string(),
            value if value.starts_with("12") => "Casual certification".to_string(),
            value if value.starts_with("13") => "Positive certification".to_string(),
            _ => "Certification".to_string(),
        }
    }

    fn is_smartcard_unavailable_message(message: &str) -> bool {
        let normalized = message.to_lowercase();
        normalized.contains("no such device")
            || normalized.contains("no smartcard daemon")
            || normalized.contains("openpgp card not available")
            || normalized.contains("service is not running")
            || normalized.contains("error getting version")
    }

    fn merge_x509_certificates(
        public_listing: &str,
        secret_listing: &str,
    ) -> Vec<X509CertificateSummary> {
        let mut certificates = Self::parse_x509_certificates(public_listing, false);
        let secret_certificates = Self::parse_x509_certificates(secret_listing, true);
        let secret_fingerprints = secret_certificates
            .iter()
            .map(|certificate| certificate.fingerprint.clone())
            .collect::<HashSet<_>>();

        for certificate in &mut certificates {
            certificate.has_secret = secret_fingerprints.contains(&certificate.fingerprint);
        }

        let mut known_fingerprints = certificates
            .iter()
            .map(|certificate| certificate.fingerprint.clone())
            .collect::<HashSet<_>>();
        for certificate in secret_certificates {
            if known_fingerprints.insert(certificate.fingerprint.clone()) {
                certificates.push(certificate);
            }
        }

        certificates.sort_by(|left, right| {
            left.subject
                .cmp(&right.subject)
                .then_with(|| left.fingerprint.cmp(&right.fingerprint))
        });
        certificates
    }

    fn apply_x509_trust_roots(
        mut certificates: Vec<X509CertificateSummary>,
        trusted_roots: &HashSet<String>,
    ) -> Vec<X509CertificateSummary> {
        for certificate in &mut certificates {
            certificate.is_trusted_root = trusted_roots.contains(&certificate.fingerprint);
        }
        certificates
    }

    fn parse_x509_certificates(output: &str, has_secret: bool) -> Vec<X509CertificateSummary> {
        let mut certificates = Vec::new();
        let mut current: Option<X509CertificateSummary> = None;

        for line in output.lines() {
            let parts = line.split(':').collect::<Vec<_>>();
            match parts.first().copied().unwrap_or_default() {
                "crt" | "crs" => {
                    if let Some(existing) = current.take() {
                        certificates.push(existing);
                    }
                    current = Some(X509CertificateSummary {
                        fingerprint: String::new(),
                        key_id: parts.get(4).copied().unwrap_or_default().to_uppercase(),
                        subject: String::new(),
                        issuer: parts.get(9).copied().unwrap_or_default().to_string(),
                        serial_number: parts.get(7).copied().unwrap_or_default().to_string(),
                        validity: Self::parse_trust(parts.get(1).copied().unwrap_or_default()),
                        algorithm: Self::parse_algorithm(parts.get(3).copied().unwrap_or_default()),
                        bits: parts
                            .get(2)
                            .and_then(|value| value.parse::<u32>().ok())
                            .unwrap_or(0),
                        created_at: parts
                            .get(5)
                            .copied()
                            .filter(|value| !value.is_empty())
                            .map(str::to_string),
                        expires_at: parts
                            .get(6)
                            .copied()
                            .filter(|value| !value.is_empty())
                            .map(str::to_string),
                        has_secret,
                        is_trusted_root: false,
                    });
                }
                "fpr" => {
                    if let Some(current) = &mut current {
                        current.fingerprint = parts.get(9).copied().unwrap_or_default().to_uppercase();
                    }
                }
                "uid" => {
                    if let Some(current) = &mut current {
                        if current.subject.is_empty() {
                            current.subject = parts.get(9).copied().unwrap_or_default().to_string();
                        }
                    }
                }
                _ => {}
            }
        }

        if let Some(existing) = current.take() {
            certificates.push(existing);
        }

        certificates
    }

    fn trusted_x509_roots(&self) -> AppResult<HashSet<String>> {
        Ok(self
            .read_trustlist_entries(&self.trustlist_path()?)?
            .into_iter()
            .collect())
    }

    fn trustlist_path(&self) -> AppResult<PathBuf> {
        Ok(self.gnupg_home_dir()?.join("trustlist.txt"))
    }

    fn read_trustlist_entries(&self, path: &Path) -> AppResult<Vec<String>> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let contents = fs::read_to_string(path)?;
        Ok(Self::parse_trustlist_entries(&contents))
    }

    fn write_trustlist_entries(&self, path: &Path, entries: &[String]) -> AppResult<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, Self::render_trustlist_entries(entries))?;
        Ok(())
    }

    fn parse_trustlist_entries(contents: &str) -> Vec<String> {
        contents
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "include-default" {
                    return None;
                }
                let mut parts = trimmed.split_whitespace();
                let fingerprint = parts.next().unwrap_or_default();
                let flags = parts.collect::<Vec<_>>().join(" ").to_uppercase();
                if !flags.contains('S') {
                    return None;
                }
                let normalized = Self::normalize_fingerprint(fingerprint);
                (!normalized.is_empty()).then_some(normalized)
            })
            .collect()
    }

    fn render_trustlist_entries(entries: &[String]) -> String {
        let mut sorted = entries
            .iter()
            .map(|entry| Self::normalize_fingerprint(entry))
            .filter(|entry| !entry.is_empty())
            .collect::<Vec<_>>();
        sorted.sort();
        sorted.dedup();

        let mut lines = vec![
            "# Local EncryptKeeper trust list".to_string(),
            "include-default".to_string(),
            String::new(),
        ];
        for entry in sorted {
            lines.push(format!("{entry} S"));
        }
        lines.push(String::new());
        lines.join("\n")
    }

    fn normalize_fingerprint(value: &str) -> String {
        value
            .chars()
            .filter(|character| character.is_ascii_hexdigit())
            .collect::<String>()
            .to_uppercase()
    }

    fn gnupg_home_dir(&self) -> AppResult<PathBuf> {
        std::env::var_os("GNUPGHOME")
            .map(PathBuf::from)
            .or_else(|| {
                #[cfg(windows)]
                {
                    std::env::var_os("APPDATA")
                        .map(PathBuf::from)
                        .map(|path| path.join("gnupg"))
                }
                #[cfg(not(windows))]
                {
                    std::env::var_os("HOME")
                        .map(PathBuf::from)
                        .map(|path| path.join(".gnupg"))
                }
            })
            .ok_or_else(|| AppError::External("Unable to resolve the GnuPG home directory.".into()))
    }

    fn x509_secret_keygrip_for_fingerprint(&self, fingerprint: &str) -> AppResult<String> {
        let normalized_target = Self::normalize_fingerprint(fingerprint);
        if normalized_target.is_empty() {
            return Err(AppError::Validation("Certificate fingerprint is required.".into()));
        }

        let output = self
            .gpgsm_command()?
            .args([
                "--with-colons",
                "--with-keygrip",
                "--list-secret-keys",
                &normalized_target,
            ])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if !output.status.success() {
            return Err(AppError::External(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }

        let mut pending_fpr: Option<String> = None;
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let parts = line.split(':').collect::<Vec<_>>();
            match parts.first().copied().unwrap_or_default() {
                "fpr" => {
                    pending_fpr = parts.get(9).map(|value| Self::normalize_fingerprint(value));
                }
                "grp" => {
                    if pending_fpr
                        .as_deref()
                        .map(|value| value == normalized_target)
                        .unwrap_or(false)
                    {
                        let keygrip = parts
                            .get(9)
                            .map(|value| Self::normalize_fingerprint(value))
                            .unwrap_or_default();
                        if !keygrip.is_empty() {
                            return Ok(keygrip);
                        }
                    }
                    pending_fpr = None;
                }
                _ => {}
            }
        }

        Err(AppError::Validation(
            "No local X.509 secret keygrip was found for the selected certificate.".into(),
        ))
    }

    fn secret_keygrip_for_fingerprint(&self, fingerprint: &str) -> AppResult<String> {
        let output = self
            .gpg_command()?
            .args(["--batch", "--with-colons", "--with-keygrip", "--list-secret-keys", fingerprint])
            .output()
            .map_err(|_| AppError::GpgUnavailable)?;
        if !output.status.success() {
            return Err(AppError::External(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }

        let normalized_target = Self::normalize_fingerprint(fingerprint);
        let mut pending_fpr: Option<String> = None;
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let parts = line.split(':').collect::<Vec<_>>();
            match parts.first().copied().unwrap_or_default() {
                "fpr" => {
                    pending_fpr = parts.get(9).map(|value| Self::normalize_fingerprint(value));
                }
                "grp" => {
                    if pending_fpr
                        .as_deref()
                        .map(|value| value == normalized_target)
                        .unwrap_or(false)
                    {
                        let keygrip = parts
                            .get(9)
                            .map(|value| Self::normalize_fingerprint(value))
                            .unwrap_or_default();
                        if !keygrip.is_empty() {
                            return Ok(keygrip);
                        }
                    }
                    pending_fpr = None;
                }
                _ => {}
            }
        }

        Err(AppError::Validation(
            "The selected secret key does not expose a movable local keygrip.".into(),
        ))
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
    use std::{path::Path, process::Command, sync::Mutex};

    use tempfile::TempDir;

    use super::CryptoService;

    static GNUPG_ENV_LOCK: Mutex<()> = Mutex::new(());

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
            .key_details(public_listing, secret_listing, "", "PRIMARY123")
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

    #[test]
    fn parses_import_result_status() {
        let result = CryptoService::parse_import_result(
            "[GNUPG:] IMPORT_OK 1 ABCDEF1234567890ABCDEF1234567890ABCDEF12\n\
             [GNUPG:] IMPORT_RES 1 0 1 0 0 0 0 0 1 0 0 0 1 0 0\n",
        );

        assert_eq!(result.imported, 1);
        assert_eq!(result.unchanged, 0);
        assert_eq!(result.secret_imported, 1);
        assert_eq!(
            result.fingerprints,
            vec!["ABCDEF1234567890ABCDEF1234567890ABCDEF12".to_string()]
        );
    }

    #[test]
    fn parses_smartcard_status_output() {
        let status = CryptoService::parse_smartcard_status(
            "Reader ...........: Yubico YubiKey OTP+FIDO+CCID 00 00\n\
             Application ID ...: D2760001240102010000000000010000\n\
             Serial number ....: 12345678\n\
             Manufacturer .....: Yubico\n\
             Name of cardholder: Alice Example\n\
             Signature key ....: ABCDEF1234567890\n\
             Encryption key....: 0123456789ABCDEF\n\
             Authentication key: FEDCBA9876543210\n",
        );

        assert!(status.available);
        assert_eq!(status.reader.as_deref(), Some("Yubico YubiKey OTP+FIDO+CCID 00 00"));
        assert_eq!(status.serial_number.as_deref(), Some("12345678"));
        assert_eq!(status.cardholder.as_deref(), Some("Alice Example"));
    }

    #[test]
    fn detects_smartcard_unavailable_messages() {
        assert!(CryptoService::is_smartcard_unavailable_message(
            "gpg: OpenPGP card not available: Service is not running"
        ));
        assert!(CryptoService::is_smartcard_unavailable_message(
            "gpg: selecting card failed: No such device"
        ));
        assert!(!CryptoService::is_smartcard_unavailable_message(
            "gpg: general failure while changing pin"
        ));
    }

    #[test]
    fn parses_x509_certificate_listings() {
        let certificates = CryptoService::merge_x509_certificates(
            concat!(
                "crt:f:2048:1:AABBCCDDEEFF0011:2025-01-01:2027-01-01:01A2B3C4::CN=Demo Root CA,O=EncryptKeeper,C=US:\n",
                "fpr:::::::::11223344556677889900AABBCCDDEEFF00112233:99887766554433221100FFEEDDCCBBAA00998877:\n",
                "uid:f::::2025-01-01::HASH::CN=Demo User,O=EncryptKeeper,C=US:\n",
                "crt:u:256:18:0011223344556677:2024-03-01:2026-03-01:ABCDEF01::CN=Demo ECC CA,O=EncryptKeeper,C=US:\n",
                "fpr:::::::::FFEEDDCCBBAA0099887766554433221100AABBCC:\n",
                "uid:u::::2024-03-01::HASH::CN=ECC User,O=EncryptKeeper,C=US:\n",
            ),
            concat!(
                "crs:u:256:18:0011223344556677:2024-03-01:2026-03-01:ABCDEF01::CN=Demo ECC CA,O=EncryptKeeper,C=US:\n",
                "fpr:::::::::FFEEDDCCBBAA0099887766554433221100AABBCC:\n",
                "uid:u::::2024-03-01::HASH::CN=ECC User,O=EncryptKeeper,C=US:\n",
                "crs:u:2048:1:DEADBEEF00112233:2025-01-01:2028-01-01:FFEEAABB::CN=Secret Only,O=EncryptKeeper,C=US:\n",
                "fpr:::::::::AABBCCDD11223344556677889900FFEEDDCCBBAA:\n",
                "uid:u::::2025-01-01::HASH::CN=Secret Only,O=EncryptKeeper,C=US:\n",
            ),
        );

        assert_eq!(certificates.len(), 3);
        assert_eq!(certificates[0].subject, "CN=Demo User,O=EncryptKeeper,C=US");
        assert_eq!(certificates[0].issuer, "CN=Demo Root CA,O=EncryptKeeper,C=US");
        assert!(!certificates[0].has_secret);
        assert_eq!(certificates[1].fingerprint, "FFEEDDCCBBAA0099887766554433221100AABBCC");
        assert!(certificates[1].has_secret);
        assert_eq!(certificates[2].subject, "CN=Secret Only,O=EncryptKeeper,C=US");
        assert!(certificates[2].has_secret);
    }

    #[test]
    fn parses_trustlist_entries() {
        let entries = CryptoService::parse_trustlist_entries(
            "# comment\ninclude-default\n\n1122:3344:5566:7788:9900:AABB:CCDD:EEFF:0011:2233 S relax\nAABBCCDDEEFF0011223344556677889900AABBCC P\n",
        );

        assert_eq!(entries, vec!["11223344556677889900AABBCCDDEEFF00112233"]);
    }

    #[test]
    fn renders_trustlist_entries_with_include_default() {
        let rendered = CryptoService::render_trustlist_entries(&[
            "ffeeddccbbaa0099887766554433221100aabbcc".into(),
            "11223344556677889900AABBCCDDEEFF00112233".into(),
        ]);

        assert!(rendered.contains("include-default"));
        assert!(rendered.contains("11223344556677889900AABBCCDDEEFF00112233 S"));
        assert!(rendered.contains("FFEEDDCCBBAA0099887766554433221100AABBCC S"));
    }

    #[test]
    fn creates_x509_certificate_in_batch_mode() {
        let _guard = GNUPG_ENV_LOCK.lock().expect("lock gnupg env");
        let temp_home = TempDir::new().expect("temporary gnupg home");
        let previous_home = std::env::var_os("GNUPGHOME");
        std::env::set_var("GNUPGHOME", temp_home.path());

        let service = CryptoService;
        let result = service
            .create_x509_certificate(
                "Batch Demo",
                "EncryptKeeper",
                "batch-demo@example.test",
                "2030-01-01",
                "x509-passphrase",
            )
            .expect("create certificate");

        let certificates = service
            .list_x509_certificates()
            .expect("list x509 certificates");

        if let Some(previous_home) = previous_home {
            std::env::set_var("GNUPGHOME", previous_home);
        } else {
            std::env::remove_var("GNUPGHOME");
        }

        assert!(result.summary.contains("Created X.509 certificate"));
        assert!(certificates.iter().any(|certificate| {
            certificate.fingerprint == result.fingerprint
                && certificate.subject == "CN=Batch Demo,O=EncryptKeeper"
                && certificate.has_secret
        }));
    }

    #[test]
    fn deletes_x509_secret_key_material_with_certificate() {
        let _guard = GNUPG_ENV_LOCK.lock().expect("lock gnupg env");
        let temp_home = TempDir::new().expect("temporary gnupg home");
        let previous_home = std::env::var_os("GNUPGHOME");
        std::env::set_var("GNUPGHOME", temp_home.path());

        let service = CryptoService;
        let created = service
            .create_x509_certificate(
                "Delete Demo",
                "EncryptKeeper",
                "delete-demo@example.test",
                "2030-01-01",
                "x509-passphrase",
            )
            .expect("create certificate");

        let keygrip = service
            .x509_secret_keygrip_for_fingerprint(&created.fingerprint)
            .expect("x509 secret keygrip");
        let secret_key_path = temp_home
            .path()
            .join("private-keys-v1.d")
            .join(format!("{keygrip}.key"));
        assert!(secret_key_path.exists(), "secret key file should exist before deletion");

        service
            .delete_x509_certificate(&created.fingerprint)
            .expect("delete certificate");
        let certificates = service
            .list_x509_certificates()
            .expect("list x509 certificates after delete");

        match previous_home {
            Some(value) => std::env::set_var("GNUPGHOME", value),
            None => std::env::remove_var("GNUPGHOME"),
        }

        assert!(!secret_key_path.exists(), "secret key file should be removed");
        assert!(
            !certificates
                .iter()
                .any(|certificate| certificate.fingerprint == created.fingerprint),
            "certificate should be removed from listing"
        );
    }

    #[test]
    fn parses_keyserver_search_results_output() {
        let results = CryptoService::parse_keyserver_search_results(
            "info:1:1\n\
             pub:D477040C70C2156A5C298549BB7E9101495E6BF7:22:256:1701906891::\n\
             uid:%3Cdkg@debian.org%3E:1705467792::\n\
             uid:%3Cdkg@fifthhorseman.net%3E:1705467792::\n",
        );

        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].fingerprint,
            "D477040C70C2156A5C298549BB7E9101495E6BF7"
        );
        assert_eq!(results[0].algorithm, "EdDSA");
        assert_eq!(results[0].user_ids.len(), 2);
    }

    #[test]
    fn parses_key_certifications_output() {
        let certifications = CryptoService::parse_key_certifications(
            concat!(
                "pub:u:255:22:FA658DDD00BF50E2:1778432491:1778518891::u:::scSC:::::ed25519:::0:\n",
                "fpr:::::::::920906611DB8C8BB3805D181FA658DDD00BF50E2:\n",
                "uid:u::::1778432491::A2779A6F33BC15EE8A37867D06BBEB88CBA1A073::Bob Example <bob@example.com>::::::::::0:\n",
                "sig:::22:FA658DDD00BF50E2:1778432491::::Bob Example <bob@example.com>:13x::920906611DB8C8BB3805D181FA658DDD00BF50E2:::10:\n",
                "sig:::22:F31AC93414E17306:1778432491::::Alice Example <alice@example.com>:10x::58941603C1416BE6D49D713BF31AC93414E17306:::10:\n",
            ),
            "920906611DB8C8BB3805D181FA658DDD00BF50E2",
            "FA658DDD00BF50E2",
        );

        assert_eq!(certifications.len(), 2);
        assert!(certifications[0].is_self_signature || certifications[1].is_self_signature);
        assert!(certifications.iter().any(|item| item.kind == "Generic certification"));
        assert!(certifications
            .iter()
            .any(|item| item.signer_label.contains("Alice Example")));
    }

    #[test]
    fn changes_key_passphrase_with_passwd_flow() {
        fn run_gpg(home: &Path, args: &[&str], input: Option<&str>) -> std::process::Output {
            let mut command = Command::new("gpg");
            command.env("GNUPGHOME", home);
            command.args(args);
            if input.is_some() {
                command.stdin(std::process::Stdio::piped());
            }
            command.stdout(std::process::Stdio::piped());
            command.stderr(std::process::Stdio::piped());

            let mut child = command.spawn().expect("spawn gpg");
            if let Some(input) = input {
                use std::io::Write;
                if let Some(stdin) = &mut child.stdin {
                    stdin.write_all(input.as_bytes()).expect("write gpg stdin");
                }
            }
            child.wait_with_output().expect("wait for gpg")
        }

        fn sign_with_passphrase(home: &Path, fingerprint: &str, passphrase: &str) -> i32 {
            let kill = Command::new("gpgconf")
                .env("GNUPGHOME", home)
                .args(["--kill", "gpg-agent"])
                .output()
                .expect("kill gpg-agent");
            assert!(kill.status.success(), "{}", String::from_utf8_lossy(&kill.stderr));

            let output = run_gpg(
                home,
                &[
                    "--batch",
                    "--yes",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    passphrase,
                    "--local-user",
                    fingerprint,
                    "--armor",
                    "--output",
                    "-",
                    "--clearsign",
                ],
                Some("hello"),
            );
            output.status.code().unwrap_or(-1)
        }

        let temp_home = TempDir::new().expect("temporary gnupg home");
        let home_path = temp_home.path();

        let generated = run_gpg(
            home_path,
            &[
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "oldpass",
                "--quick-generate-key",
                "EK Test <ek@example.com>",
                "ed25519",
                "cert,sign",
                "1d",
            ],
            None,
        );
        assert!(
            generated.status.success(),
            "{}",
            String::from_utf8_lossy(&generated.stderr)
        );

        let listed = run_gpg(home_path, &["--batch", "--with-colons", "--list-secret-keys"], None);
        assert!(
            listed.status.success(),
            "{}",
            String::from_utf8_lossy(&listed.stderr)
        );
        let listing = String::from_utf8_lossy(&listed.stdout);
        let fingerprint = listing
            .lines()
            .find_map(|line| {
                let parts = line.split(':').collect::<Vec<_>>();
                (parts.first().copied() == Some("fpr"))
                    .then(|| parts.get(9).copied().unwrap_or_default().to_string())
            })
            .expect("generated key fingerprint");

        assert_eq!(sign_with_passphrase(home_path, &fingerprint, "oldpass"), 0);
        assert_ne!(sign_with_passphrase(home_path, &fingerprint, "badpass"), 0);

        let mut passwd = Command::new("gpg");
        passwd
            .env("GNUPGHOME", home_path)
            .args([
                "--batch",
                "--yes",
                "--command-fd",
                "0",
                "--pinentry-mode",
                "loopback",
                "--passwd",
                &fingerprint,
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        let output = CryptoService::run_with_input_lines(
            passwd,
            &["oldpass", "newpass", "newpass", "y"],
        )
        .expect("change passphrase");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        assert_ne!(sign_with_passphrase(home_path, &fingerprint, "oldpass"), 0);
        assert_eq!(sign_with_passphrase(home_path, &fingerprint, "newpass"), 0);
    }

    #[test]
    fn exports_ownertrust_snapshot() {
        let _guard = GNUPG_ENV_LOCK.lock().expect("lock gnupg env");
        let temp_home = TempDir::new().expect("temporary gnupg home");
        let home_path = temp_home.path();
        let export_path = home_path.join("ownertrust.txt");

        let generated = Command::new("gpg")
            .env("GNUPGHOME", home_path)
            .args([
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "ownertrustpass",
                "--quick-generate-key",
                "Trust Export <trust@example.com>",
                "ed25519",
                "default",
                "1d",
            ])
            .output()
            .expect("generate key");
        assert!(
            generated.status.success(),
            "{}",
            String::from_utf8_lossy(&generated.stderr)
        );

        let listed = Command::new("gpg")
            .env("GNUPGHOME", home_path)
            .args(["--batch", "--with-colons", "--list-keys"])
            .output()
            .expect("list keys");
        assert!(
            listed.status.success(),
            "{}",
            String::from_utf8_lossy(&listed.stderr)
        );
        let listing = String::from_utf8_lossy(&listed.stdout);
        let fingerprint = listing
            .lines()
            .find_map(|line| {
                let parts = line.split(':').collect::<Vec<_>>();
                (parts.first().copied() == Some("fpr"))
                    .then(|| parts.get(9).copied().unwrap_or_default().to_string())
            })
            .expect("generated key fingerprint");

        let trusted = Command::new("gpg")
            .env("GNUPGHOME", home_path)
            .args([
                "--batch",
                "--yes",
                "--quick-set-ownertrust",
                &fingerprint,
                "ultimate",
            ])
            .output()
            .expect("set ownertrust");
        assert!(
            trusted.status.success(),
            "{}",
            String::from_utf8_lossy(&trusted.stderr)
        );

        let previous_home = std::env::var_os("GNUPGHOME");
        std::env::set_var("GNUPGHOME", home_path);
        let service = CryptoService;
        let result = service
            .export_ownertrust(&export_path)
            .expect("export ownertrust through service");
        assert!(result.summary.contains("Exported ownertrust"));
        match previous_home {
            Some(value) => std::env::set_var("GNUPGHOME", value),
            None => std::env::remove_var("GNUPGHOME"),
        }

        let contents = std::fs::read_to_string(&export_path).expect("read ownertrust file");
        assert!(!contents.trim().is_empty());
    }
}
