use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use walkdir::WalkDir;

use crate::{
    errors::{AppError, AppResult},
    services::archive_service::ArchiveService,
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
        temp_root: PathBuf,
        recursive: bool,
        notes: Vec<NoteRecord>,
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
        self.cleanup_active_vault();
        let notes = Self::scan_folder(&path, recursive)?;
        self.active_vault = Some(ActiveVault::Folder {
            root: path,
            recursive,
            notes: notes.clone(),
        });
        Ok(notes.into_iter().map(Self::record_to_summary).collect())
    }

    pub fn open_archive(&mut self, path: PathBuf, recursive: bool) -> AppResult<Vec<NoteSummary>> {
        self.cleanup_active_vault();
        let workspace = ArchiveService::prepare_workspace(&path)?;
        let notes = Self::scan_folder(&workspace.root, recursive)?;
        self.active_vault = Some(ActiveVault::Archive {
            archive_path: workspace.archive_path,
            temp_root: workspace.root,
            recursive,
            notes: notes.clone(),
        });
        Ok(notes.into_iter().map(Self::record_to_summary).collect())
    }

    pub fn list_notes(&self) -> AppResult<Vec<NoteSummary>> {
        match &self.active_vault {
            Some(ActiveVault::Folder { notes, .. }) | Some(ActiveVault::Archive { notes, .. }) => {
                Ok(notes
                    .iter()
                    .cloned()
                    .map(Self::record_to_summary)
                    .collect::<Vec<_>>())
            }
            None => Ok(Vec::new()),
        }
    }

    pub fn refresh_active_vault(&mut self) -> AppResult<Vec<NoteSummary>> {
        match &self.active_vault {
            Some(ActiveVault::Folder { root, recursive, .. }) => {
                let root = root.clone();
                let recursive = *recursive;
                self.open_folder(root, recursive)
            }
            Some(ActiveVault::Archive {
                archive_path,
                recursive,
                ..
            }) => {
                let archive_path = archive_path.clone();
                let recursive = *recursive;
                self.open_archive(archive_path, recursive)
            }
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
            Some(ActiveVault::Archive { archive_path, .. }) => Some(archive_path.display().to_string()),
            None => None,
        }
    }

    pub fn note_path(&self, note_id: &str) -> AppResult<PathBuf> {
        self.find_note(note_id).map(|note| note.absolute_path)
    }

    pub fn create_note_record(&mut self, name: &str) -> AppResult<NoteSummary> {
        let relative = sanitize_note_path(name)?;
        let root = self.active_root()?.to_path_buf();

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
        self.sync_archive_if_needed()?;
        Ok(Self::record_to_summary(record))
    }

    pub fn rename_note_record(&mut self, note_id: &str, new_name: &str) -> AppResult<NoteSummary> {
        let relative = sanitize_note_path(new_name)?;
        match &mut self.active_vault {
            Some(ActiveVault::Folder { root, notes, .. })
            | Some(ActiveVault::Archive {
                temp_root: root,
                notes,
                ..
            }) => {
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
                self.sync_archive_if_needed()?;
                Ok(Self::record_to_summary(updated))
            }
            None => Err(AppError::VaultNotOpen),
        }
    }

    pub fn delete_note(&mut self, note_id: &str) -> AppResult<()> {
        match &mut self.active_vault {
            Some(ActiveVault::Folder { notes, .. }) | Some(ActiveVault::Archive { notes, .. }) => {
                let existing_index = notes
                    .iter()
                    .position(|note| note.id == note_id)
                    .ok_or(AppError::NoteNotFound)?;
                let note = notes.remove(existing_index);
                if note.absolute_path.exists() {
                    fs::remove_file(note.absolute_path)?;
                }
                self.sync_archive_if_needed()?;
                Ok(())
            }
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
        self.sync_archive_if_needed()?;
        Ok(())
    }

    fn insert_or_replace(&mut self, record: NoteRecord) {
        if let Some(ActiveVault::Folder { notes, .. } | ActiveVault::Archive { notes, .. }) =
            &mut self.active_vault
        {
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
            Some(ActiveVault::Folder { notes, .. }) | Some(ActiveVault::Archive { notes, .. }) => {
                notes
                    .iter()
                    .find(|note| note.id == note_id)
                    .cloned()
                    .ok_or(AppError::NoteNotFound)
            }
            None => Err(AppError::VaultNotOpen),
        }
    }

    pub fn is_archive_open(&self) -> bool {
        matches!(self.active_vault, Some(ActiveVault::Archive { .. }))
    }

    fn active_root(&self) -> AppResult<&Path> {
        match &self.active_vault {
            Some(ActiveVault::Folder { root, .. }) => Ok(root.as_path()),
            Some(ActiveVault::Archive { temp_root, .. }) => Ok(temp_root.as_path()),
            None => Err(AppError::VaultNotOpen),
        }
    }

    fn sync_archive_if_needed(&self) -> AppResult<()> {
        if let Some(ActiveVault::Archive {
            archive_path,
            temp_root,
            ..
        }) = &self.active_vault
        {
            ArchiveService::write_archive(archive_path.as_path(), temp_root.as_path())?;
        }
        Ok(())
    }

    fn cleanup_active_vault(&mut self) {
        if let Some(ActiveVault::Archive { temp_root, .. }) = &self.active_vault {
            let _ = ArchiveService::cleanup_workspace(temp_root.as_path());
        }
        self.active_vault = None;
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

impl Drop for VaultService {
    fn drop(&mut self) {
        self.cleanup_active_vault();
    }
}

fn note_id_for_path(relative_path: &Path) -> String {
    relative_path.to_string_lossy().replace('\\', "/")
}

pub fn sanitize_note_path(name: &str) -> AppResult<PathBuf> {
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
    use std::{fs, io::Write};

    use tempfile::tempdir;

    use crate::services::archive_service::ArchiveService;

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

    #[test]
    fn round_trips_archive_vault_note_changes() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("alpha.gpg"), b"alpha").unwrap();

        let archive_path = temp.path().join("vault.zip");
        ArchiveService::write_archive(&archive_path, &source).unwrap();

        let mut vault = VaultService::default();
        let notes = vault.open_archive(archive_path.clone(), true).unwrap();
        assert_eq!(notes.len(), 1);

        let created = vault.create_note_record("beta").unwrap();
        vault
            .atomic_write_encrypted(&created.id, |temp_path| {
                let mut file = fs::File::create(temp_path)?;
                file.write_all(b"beta")?;
                Ok(())
            })
            .unwrap();
        vault.rename_note_record("alpha.gpg", "renamed").unwrap();
        vault.delete_note(&created.id).unwrap();

        let reopened = vault.open_archive(archive_path, true).unwrap();
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened[0].relative_path, "renamed.gpg");
    }
}
