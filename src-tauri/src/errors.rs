use std::{io, string::FromUtf8Error};

use thiserror::Error;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("GPG is not installed or not available on PATH.")]
    GpgUnavailable,
    #[error("Vault is not open.")]
    VaultNotOpen,
    #[error("Archive support is not implemented in this MVP build.")]
    ArchiveNotImplemented,
    #[error("Session is locked.")]
    SessionLocked,
    #[error("No private key has been selected.")]
    MissingPrivateKeySelection,
    #[error("No recipient public key has been selected.")]
    MissingRecipients,
    #[error("The note was not found.")]
    NoteNotFound,
    #[error("Invalid note name.")]
    InvalidNoteName,
    #[error("Wrong private key passphrase.")]
    WrongPrivateKeyPassphrase,
    #[error("A required private key is missing.")]
    MissingPrivateKey,
    #[error("Invalid or corrupt .gpg file.")]
    InvalidGpgFile,
    #[error("{0}")]
    Validation(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Utf8(#[from] FromUtf8Error),
    #[error("{0}")]
    External(String),
}

impl serde::Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
