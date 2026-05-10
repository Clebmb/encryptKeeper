use std::{
    fs,
    path::PathBuf,
};

use uuid::Uuid;

use crate::errors::AppResult;

#[derive(Default)]
pub struct SecureTempManager;

pub struct ScopedTempDir {
    path: PathBuf,
}

impl SecureTempManager {
    pub fn create_scoped_dir(&self, prefix: &str) -> AppResult<ScopedTempDir> {
        let path = std::env::temp_dir().join(format!("{prefix}-{}", Uuid::new_v4()));
        fs::create_dir_all(&path)?;
        Ok(ScopedTempDir { path })
    }
}

impl ScopedTempDir {
    pub fn file_path(&self, file_name: &str) -> PathBuf {
        self.path.join(file_name)
    }
}

impl Drop for ScopedTempDir {
    fn drop(&mut self) {
        if self.path.exists() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::SecureTempManager;

    #[test]
    fn scoped_dir_cleans_up_on_drop() {
        let manager = SecureTempManager;
        let path = {
            let dir = manager.create_scoped_dir("encryptkeeper-secure-temp").unwrap();
            let file_path = dir.file_path("sample.txt");
            fs::write(&file_path, b"secret").unwrap();
            assert!(file_path.exists());
            file_path.parent().unwrap().to_path_buf()
        };

        assert!(!path.exists());
    }
}
