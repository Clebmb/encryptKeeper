use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use walkdir::WalkDir;

use crate::{
    errors::{AppError, AppResult},
    models::NoteSummary,
};

#[derive(Default)]
pub struct VaultService {
    active_vault: Option<ActiveVault>,
}

#[derive(Clone)]
enum ActiveVault {
    Folder {
        root: PathBuf,
        recursive: bool,
        notes: Vec<NoteRecord>,
    },
    Archive {
        archive_path: PathBuf,
    },
}

#[derive(Clone)]
struct NoteRecord {
    id: String,
    relative_path: PathBuf,
    absolute_path: PathBuf,
}

impl VaultService {
    pub fn open_folder(&mut self, path: PathBuf, recursive: bool) -> AppResult<Vec<NoteSummary>> {
        let notes = Self::scan_folder(&path, recursive)?;
        self.active_vault = Some(ActiveVault::Folder {
            root: path,
            recursive,
            notes: notes.clone(),
        });
        Ok(notes.into_iter().map(Self::record_to_summary).collect())
    }

    pub fn list_notes(&self) -> AppResult<Vec<NoteSummary>> {
        match &self.active_vault {
            Some(ActiveVault::Folder { notes, .. }) => Ok(notes
                .iter()
                .cloned()
                .map(Self::record_to_summary)
                .collect::<Vec<_>>()),
            Some(ActiveVault::Archive { .. }) => Err(AppError::ArchiveNotImplemented),
            None => Ok(Vec::new()),
        }
    }

    pub fn vault_kind(&self) -> &'static str {
        match self.active_vault {
            Some(ActiveVault::Folder { .. }) => "folder",
            Some(ActiveVault::Archive { .. }) => "archive",
            None => "none",
        }
    }

    pub fn vault_path(&self) -> Option<String> {
        match &self.active_vault {
            Some(ActiveVault::Folder { root, .. }) => Some(root.display().to_string()),
            Some(ActiveVault::Archive { archive_path }) => Some(archive_path.display().to_string()),
            None => None,
        }
    }

    pub fn note_path(&self, note_id: &str) -> AppResult<PathBuf> {
        self.find_note(note_id).map(|note| note.absolute_path)
    }

    pub fn create_note_record(&mut self, name: &str) -> AppResult<NoteSummary> {
        let relative = sanitize_note_path(name)?;
        let root = match &self.active_vault {
            Some(ActiveVault::Folder { root, .. }) => root.clone(),
            Some(ActiveVault::Archive { .. }) => return Err(AppError::ArchiveNotImplemented),
            None => return Err(AppError::VaultNotOpen),
        };

        let absolute_path = root.join(&relative);
        if let Some(parent) = absolute_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let record = NoteRecord {
            id: note_id_for_path(&relative),
            relative_path: relative,
            absolute_path,
        };
        self.insert_or_replace(record.clone());
        Ok(Self::record_to_summary(record))
    }

    pub fn rename_note_record(&mut self, note_id: &str, new_name: &str) -> AppResult<NoteSummary> {
        let relative = sanitize_note_path(new_name)?;
        match &mut self.active_vault {
            Some(ActiveVault::Folder { root, notes, .. }) => {
                let existing_index = notes
                    .iter()
                    .position(|note| note.id == note_id)
                    .ok_or(AppError::NoteNotFound)?;
                let existing = notes[existing_index].clone();
                let next_absolute = root.join(&relative);
                if let Some(parent) = next_absolute.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::rename(&existing.absolute_path, &next_absolute)?;
                let updated = NoteRecord {
                    id: existing.id,
                    relative_path: relative,
                    absolute_path: next_absolute,
                };
                notes[existing_index] = updated.clone();
                Ok(Self::record_to_summary(updated))
            }
            Some(ActiveVault::Archive { .. }) => Err(AppError::ArchiveNotImplemented),
            None => Err(AppError::VaultNotOpen),
        }
    }

    pub fn delete_note(&mut self, note_id: &str) -> AppResult<()> {
        match &mut self.active_vault {
            Some(ActiveVault::Folder { notes, .. }) => {
                let existing_index = notes
                    .iter()
                    .position(|note| note.id == note_id)
                    .ok_or(AppError::NoteNotFound)?;
                let note = notes.remove(existing_index);
                if note.absolute_path.exists() {
                    fs::remove_file(note.absolute_path)?;
                }
                Ok(())
            }
            Some(ActiveVault::Archive { .. }) => Err(AppError::ArchiveNotImplemented),
            None => Err(AppError::VaultNotOpen),
        }
    }

    pub fn atomic_write_encrypted(
        &self,
        note_id: &str,
        write: impl FnOnce(&Path) -> AppResult<()>,
    ) -> AppResult<()> {
        let target = self.note_path(note_id)?;
        let temp_path = target.with_extension("gpg.tmp");
        write(&temp_path)?;
        fs::rename(temp_path, target)?;
        Ok(())
    }

    fn insert_or_replace(&mut self, record: NoteRecord) {
        if let Some(ActiveVault::Folder { notes, .. }) = &mut self.active_vault {
            if let Some(index) = notes
                .iter()
                .position(|existing| existing.relative_path == record.relative_path)
            {
                notes[index] = record;
            } else {
                notes.push(record);
                notes.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
            }
        }
    }

    fn find_note(&self, note_id: &str) -> AppResult<NoteRecord> {
        match &self.active_vault {
            Some(ActiveVault::Folder { notes, .. }) => notes
                .iter()
                .find(|note| note.id == note_id)
                .cloned()
                .ok_or(AppError::NoteNotFound),
            Some(ActiveVault::Archive { .. }) => Err(AppError::ArchiveNotImplemented),
            None => Err(AppError::VaultNotOpen),
        }
    }

    fn scan_folder(root: &Path, recursive: bool) -> AppResult<Vec<NoteRecord>> {
        if !root.is_dir() {
            return Err(AppError::Validation("Folder vault path is not a directory.".into()));
        }
        let mut notes = Vec::new();
        let mut walker = WalkDir::new(root);
        if !recursive {
            walker = walker.max_depth(1);
        }
        for entry in walker
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_file())
        {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("gpg") {
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|error| AppError::External(error.to_string()))?
                .to_path_buf();
            notes.push(NoteRecord {
                id: note_id_for_path(&relative),
                relative_path: relative,
                absolute_path: path.to_path_buf(),
            });
        }
        notes.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        Ok(notes)
    }

    fn record_to_summary(record: NoteRecord) -> NoteSummary {
        let name = record
            .relative_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_string();
        NoteSummary {
            id: record.id,
            name,
            relative_path: record.relative_path.display().to_string(),
        }
    }
}

fn note_id_for_path(relative_path: &Path) -> String {
    relative_path.to_string_lossy().replace('\\', "/")
}

fn sanitize_note_path(name: &str) -> AppResult<PathBuf> {
    let normalized = name.trim().replace('\\', "/");
    if normalized.is_empty() {
        return Err(AppError::InvalidNoteName);
    }
    let path = PathBuf::from(if normalized.ends_with(".gpg") {
        normalized
    } else {
        format!("{normalized}.gpg")
    });
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(AppError::InvalidNoteName);
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{sanitize_note_path, VaultService};

    #[test]
    fn sanitizes_note_paths() {
        let path = sanitize_note_path("nested/secret").unwrap();
        assert_eq!(path.to_string_lossy(), "nested/secret.gpg");
        assert!(sanitize_note_path("../secret").is_err());
    }

    #[test]
    fn scans_gpg_files() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("a.gpg"), b"abc").unwrap();
        fs::create_dir_all(temp.path().join("nested")).unwrap();
        fs::write(temp.path().join("nested").join("b.gpg"), b"def").unwrap();

        let mut vault = VaultService::default();
        let notes = vault.open_folder(temp.path().to_path_buf(), true).unwrap();
        assert_eq!(notes.len(), 2);
    }
}
