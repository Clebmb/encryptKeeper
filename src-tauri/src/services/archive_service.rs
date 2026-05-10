use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use tempfile::Builder;
use walkdir::WalkDir;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

use crate::{
    errors::{AppError, AppResult},
    services::vault_service::sanitize_note_path,
};

pub struct ArchiveWorkspace {
    pub archive_path: PathBuf,
    pub root: PathBuf,
}

#[derive(Default)]
pub struct ArchiveService;

impl ArchiveService {
    pub fn prepare_workspace(path: &Path) -> AppResult<ArchiveWorkspace> {
        if !path.is_file() {
            return Err(AppError::Validation("Archive vault path is not a file.".into()));
        }

        let workspace = Builder::new()
            .prefix("encryptkeeper-archive-")
            .tempdir()
            .map_err(|error| AppError::External(error.to_string()))?;
        let root = workspace.keep();

        if path.metadata()?.len() > 0 {
            Self::extract_zip_archive(path, &root)?;
        }

        Ok(ArchiveWorkspace {
            archive_path: path.to_path_buf(),
            root,
        })
    }

    pub fn write_archive(archive_path: &Path, source_dir: &Path) -> AppResult<()> {
        if let Some(parent) = archive_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let temp_path = archive_path.with_extension("zip.tmp");
        let file = File::create(&temp_path)?;
        let mut writer = ZipWriter::new(file);
        let options =
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

        for entry in WalkDir::new(source_dir)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_file())
        {
            let path = entry.path();
            let relative = path
                .strip_prefix(source_dir)
                .map_err(|error| AppError::External(error.to_string()))?;
            let relative_note_path = sanitize_note_path(&relative.to_string_lossy())?;
            let archive_name = relative_note_path.to_string_lossy().replace('\\', "/");
            writer
                .start_file(archive_name, options)
                .map_err(|error| AppError::External(error.to_string()))?;
            let mut input = File::open(path)?;
            io::copy(&mut input, &mut writer)?;
        }

        writer
            .finish()
            .map_err(|error| AppError::External(error.to_string()))?;
        fs::rename(temp_path, archive_path)?;
        Ok(())
    }

    pub fn cleanup_workspace(path: &Path) -> AppResult<()> {
        if path.exists() {
            fs::remove_dir_all(path)?;
        }
        Ok(())
    }

    fn extract_zip_archive(archive_path: &Path, destination: &Path) -> AppResult<()> {
        let file = File::open(archive_path)?;
        let mut archive =
            ZipArchive::new(file).map_err(|error| AppError::External(error.to_string()))?;

        for index in 0..archive.len() {
            let mut entry = archive
                .by_index(index)
                .map_err(|error| AppError::External(error.to_string()))?;
            if entry.is_dir() {
                continue;
            }

            let safe_name = entry
                .enclosed_name()
                .map(|path| path.to_path_buf())
                .ok_or_else(|| AppError::Validation("Archive contains an unsafe path.".into()))?;
            let safe_note_path = sanitize_note_path(&safe_name.to_string_lossy())?;
            let output_path = destination.join(safe_note_path);
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut output = File::create(output_path)?;
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer)?;
            output.write_all(&buffer)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use tempfile::tempdir;

    use super::ArchiveService;

    #[test]
    fn round_trips_zip_archive_workspace() {
        let root = tempdir().expect("tempdir");
        let notes_dir = root.path().join("notes");
        fs::create_dir_all(notes_dir.join("nested")).expect("nested dir");
        fs::write(notes_dir.join("alpha.gpg"), "alpha").expect("alpha");
        fs::write(notes_dir.join("nested").join("beta.gpg"), "beta").expect("beta");

        let archive_path = root.path().join("vault.zip");
        ArchiveService::write_archive(&archive_path, &notes_dir).expect("write archive");

        let workspace = ArchiveService::prepare_workspace(&archive_path).expect("prepare");
        let alpha = fs::read_to_string(PathBuf::from(&workspace.root).join("alpha.gpg")).expect("read alpha");
        let beta = fs::read_to_string(
            PathBuf::from(&workspace.root)
                .join("nested")
                .join("beta.gpg"),
        )
        .expect("read beta");

        assert_eq!(alpha, "alpha");
        assert_eq!(beta, "beta");

        ArchiveService::cleanup_workspace(&workspace.root).expect("cleanup");
    }
}
