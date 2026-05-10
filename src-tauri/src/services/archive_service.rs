use crate::errors::{AppError, AppResult};

#[derive(Default)]
pub struct ArchiveService;

impl ArchiveService {
    pub fn open_archive(&self, _path: &str, _password: Option<String>) -> AppResult<()> {
        Err(AppError::ArchiveNotImplemented)
    }
}
