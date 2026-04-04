use std::{fs, path::PathBuf};

#[derive(Default)]
pub struct SecureTempManager;

impl SecureTempManager {
    pub fn cleanup_path(&self, path: &PathBuf) {
        if path.exists() {
            let _ = fs::remove_dir_all(path);
            let _ = fs::remove_file(path);
        }
    }
}
