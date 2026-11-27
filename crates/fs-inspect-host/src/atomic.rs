//! Files written whole or not at all: [`AtomicFile`] streams into a temporary file next to the
//! target and renames it into place on [`AtomicFile::commit`]. The target then holds either its
//! old content or all of the new one, also after a crash or power loss (the temporary file and
//! the directory are flushed).
//!
//! The temporary file is `NAME.PID.SEQ.tmp~`, unique to its writer, so concurrent writers of
//! one target never share one.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A file operation that failed, with the file it was on.
#[derive(Debug, thiserror::Error)]
#[error("{}: {source}", path.display())]
pub struct FileError {
    pub path: PathBuf,
    #[source]
    pub source: std::io::Error,
}

impl FileError {
    fn new(path: &Path, source: std::io::Error) -> Self {
        FileError { path: path.to_path_buf(), source }
    }
}

/// A file being written to a temporary file next to its target. [`commit`](Self::commit)
/// flushes it and renames it into place; dropped without a successful commit (an error, a
/// cancel, a panic), it removes the temporary file.
#[derive(Debug)]
pub struct AtomicFile {
    /// Declared before `tmp`: closed before the removal (Windows).
    file: std::io::BufWriter<std::fs::File>,
    tmp: TempPath,
    path: PathBuf,
}

/// The temporary file, removed when dropped unless it was renamed into place.
#[derive(Debug)]
struct TempPath(PathBuf);

impl Drop for TempPath {
    fn drop(&mut self) {
        if !self.0.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

impl AtomicFile {
    /// Starts writing `path` (created or replaced on commit).
    pub fn create(path: &Path) -> Result<Self, FileError> {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(format!(".{}.{}.tmp~", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
        let tmp = PathBuf::from(tmp);
        let file = std::fs::File::create_new(&tmp).map_err(|e| FileError::new(&tmp, e))?;
        Ok(AtomicFile { file: std::io::BufWriter::new(file), tmp: TempPath(tmp), path: path.to_path_buf() })
    }

    /// The target.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Flushes the file and renames it into place, durably.
    pub fn commit(self) -> Result<(), FileError> {
        let AtomicFile { mut file, mut tmp, path } = self;
        let flushed = file.flush().and_then(|()| file.get_ref().sync_all());
        drop(file); // closed before the rename (Windows)
        flushed.map_err(|e| FileError::new(&tmp.0, e))?;
        std::fs::rename(&tmp.0, &path).map_err(|e| FileError::new(&path, e))?;
        tmp.0 = PathBuf::new(); // nothing left to remove
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        sync_dir(dir).map_err(|e| FileError::new(dir, e))
    }
}

impl Write for AtomicFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.file.write_all(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// Makes the entries of directory `dir` (files created, renamed or removed in it) durable.
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    let d = {
        // A directory opens with backup semantics, writable for FlushFileBuffers.
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        std::fs::OpenOptions::new().read(true).write(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(dir)?
    };
    #[cfg(not(windows))]
    let d = std::fs::File::open(dir)?;
    d.sync_all()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn scratch(tag: &str) -> tempfile::TempDir {
        tempfile::Builder::new().prefix(&format!("fsi-atomic-{tag}-")).tempdir().unwrap()
    }

    #[test]
    fn atomic_writes_leave_no_temporary_files() {
        let tmp = scratch("write");
        let dir = tmp.path();
        let p = dir.join("x.state");
        // Concurrent writers each use their own temporary file.
        std::thread::scope(|s| {
            for i in 0..8u8 {
                let p = p.clone();
                s.spawn(move || {
                    let mut f = AtomicFile::create(&p).unwrap();
                    f.write_all(&[i; 4096]).unwrap();
                    f.commit().unwrap();
                });
            }
        });
        let b = std::fs::read(&p).unwrap();
        assert!(b.len() == 4096 && b.iter().all(|&x| x == b[0]), "one writer's content, whole");
        let names: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names.len(), 1, "{names:?}");
    }

    #[test]
    fn an_uncommitted_file_leaves_the_target_alone() {
        let tmp = scratch("drop");
        let dir = tmp.path();
        let p = dir.join("out.jsonl");
        std::fs::write(&p, b"old").unwrap();
        let mut f = AtomicFile::create(&p).unwrap();
        f.write_all(b"new").unwrap();
        drop(f);
        assert_eq!(std::fs::read(&p).unwrap(), b"old");
        let mut f = AtomicFile::create(&p).unwrap();
        f.write_all(b"new").unwrap();
        f.commit().unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"new");
        assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1);
    }

    /// A target in a directory that does not exist: the error names the temporary file it
    /// could not create.
    #[test]
    fn a_missing_directory_is_reported_with_the_file() {
        let tmp = scratch("missing");
        let p = tmp.path().join("no-dir").join("out.json");
        let e = AtomicFile::create(&p).unwrap_err();
        assert_eq!(e.source.kind(), std::io::ErrorKind::NotFound);
        assert!(e.path.starts_with(tmp.path().join("no-dir")) && e.path.to_string_lossy().ends_with(".tmp~"));
        assert!(e.to_string().starts_with(&e.path.display().to_string()), "{e}");
    }

    /// A rename that fails (the target is a directory) fails the commit naming the target, and
    /// leaves neither the target changed nor the temporary file behind.
    #[test]
    fn a_failed_commit_names_the_target_and_cleans_up() {
        let tmp = scratch("commit");
        let dir = tmp.path();
        let p = dir.join("taken");
        std::fs::create_dir(&p).unwrap();
        std::fs::write(p.join("inside"), b"kept").unwrap();
        let mut f = AtomicFile::create(&p).unwrap();
        assert_eq!(f.path(), p);
        f.write_all(b"new").unwrap();
        f.flush().unwrap();
        let e = f.commit().unwrap_err();
        assert_eq!(e.path, p);
        assert_eq!(std::fs::read(p.join("inside")).unwrap(), b"kept");
        let names: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, ["taken"], "the temporary file is removed");
    }
}
