//! Exporting into a directory of the host.
//!
//! Kept: content (with holes where [`Sparse::Preserve`](super::Sparse) leaves them: a
//! Windows file is marked sparse first); directories; hard links (as hard links); symbolic
//! links (Windows: file or directory links by the source's directory attribute; making one
//! may need a privilege, and a refusal is reported); the modification, access and (Windows)
//! creation times; the Unix permission bits (Unix hosts); the Windows read-only, hidden,
//! system, archive and not-indexed attributes (Windows hosts). Named streams are alternate
//! data streams on Windows (`file:name`) and extended attributes
//! `user.fsinspect.stream.NAME` on Unix; extended attributes are kept on Unix hosts, POSIX
//! ACLs (`system.posix_acl_*`) on Linux, a Windows security descriptor's DACL on Windows;
//! so are, when running as root on Unix, owners (as tar does) and device nodes (FIFOs and
//! sockets need no root). Not kept: what the host cannot represent (extended attributes on
//! Windows, a Windows DACL on Unix, the other host's mode bits), device nodes, FIFOs and
//! sockets on Windows (reported). What could not be kept of an entry that was written is
//! noted in the export's report ([`ExportReport::notes`](super::ExportReport::notes)): the
//! facet and what the host answered, the entry's path in the export.
//!
//! The metadata of each entry is written by the steps of
//! [`FsHandle::restore_metadata`](crate::fs::FsHandle::restore_metadata) (its named streams,
//! extended attributes and POSIX ACLs, then its times, owner, mode and Windows DACL); a
//! directory's ACL, times, owner and mode once the whole export is written, innermost first.
//!
//! Nothing that exists is replaced: an entry whose path exists fails.

use super::restore::{self, Meta, MetaFacets};
use super::{Content, Entry, ExportSink, Item, Note};
use crate::fs::{NodeKind, Security, Stat};
#[cfg(test)]
use fs_inspect_core::StatExt;
use fs_inspect_core::{Error, Name, Result};
use fs_inspect_host::write as host;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

/// An export into the directory `root` (which must exist).
#[derive(Debug)]
pub struct DirSink {
    root: PathBuf,
    /// Directories' metadata, set after what they hold is written (writing a file in a
    /// directory changes its times; a read-only one, or one whose ACL takes away this
    /// process's access, could not be written into).
    dirs: Vec<DirMeta>,
    notes: Vec<Note>,
    /// Running as root on Unix: owners are set.
    owners: bool,
}

/// A directory written, its metadata set once the export is.
#[derive(Debug)]
struct DirMeta {
    /// Its path in the export.
    rel: String,
    path: PathBuf,
    stat: Stat,
    security: Option<Security>,
    /// Its times, owner and mode are kept ([`Entry::metadata`]).
    metadata: bool,
}

fn err(path: &Path, e: std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::Unsupported {
        Error::unsupported(format!("{}: {e}", path.display()))
    } else {
        Error::file(path.display(), e)
    }
}

impl DirSink {
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = std::path::absolute(root.as_ref()).map_err(|e| err(root.as_ref(), e))?;
        if !root.is_dir() {
            return Err(Error::invalid_argument(format!("{}: not a directory", root.display())));
        }
        Ok(DirSink { root, dirs: Vec::new(), notes: Vec::new(), owners: host::privileged() })
    }

    fn path(&self, rel: &str) -> PathBuf {
        let mut p = self.root.clone();
        p.extend(rel.split('/'));
        p
    }

    /// The times, owner (as tar does: only when running as root, as others may not give
    /// files away) and mode: what [`Entry::metadata`] asks for.
    fn attrs(&self) -> MetaFacets {
        let mut f = MetaFacets::TIMES | MetaFacets::MODE;
        if self.owners {
            f |= MetaFacets::OWNER;
        }
        f
    }

    /// Restore `what` of `stat` and `e` (with named streams `streams`) onto `path` through
    /// [`restore::apply`], what it does not take as notes.
    #[allow(clippy::too_many_arguments)] // the entry's parts, as each caller has them
    fn restore(
        &mut self,
        rel: &str,
        path: &Path,
        what: MetaFacets,
        e: Option<&Entry<'_>>,
        stat: &Stat,
        streams: &[(Name, Content<'_>)],
    ) -> Result<()> {
        let m =
            Meta { stat, xattrs: e.map_or(&[], |e| &e.xattrs), security: e.and_then(|e| e.security.as_ref()), streams };
        for s in restore::apply(path, what, &m)? {
            self.notes.push(Note::new(rel, s.note()));
        }
        Ok(())
    }

    fn file(
        &mut self,
        e: &Entry<'_>,
        path: &Path,
        content: &Content<'_>,
        streams: &[(Name, Content<'_>)],
    ) -> Result<()> {
        let mut f = OpenOptions::new().write(true).create_new(true).open(path).map_err(|x| err(path, x))?;
        let written = restore::write_into(&mut f, content).and_then(|r| r.map_err(|x| Error::file(path.display(), x)));
        drop(f);
        let mut what = MetaFacets::STREAMS | MetaFacets::XATTRS | MetaFacets::ACL;
        if e.metadata {
            what |= self.attrs();
        }
        if let Err(failed) = written.and_then(|()| self.restore(e.path, path, what, Some(e), e.stat, streams)) {
            // Left out, not left half written (the file was made here: create_new).
            if let Err(x) = std::fs::remove_file(path) {
                return Err(failed.context(format!("{} stays half written ({x})", path.display())));
            }
            return Err(failed);
        }
        Ok(())
    }
}

impl DirSink {
    /// A device node, FIFO or socket (Unix; device nodes need root).
    fn special(&mut self, e: &Entry<'_>, path: &Path) -> Result<()> {
        let kind = match e.stat.kind {
            NodeKind::Fifo => 0o010000,
            NodeKind::CharDev => 0o020000,
            NodeKind::BlockDev => 0o060000,
            NodeKind::Socket => 0o140000,
            k => return Err(Error::unsupported(format!("a node of kind {k:?} in a directory export"))),
        };
        let u = e.stat.unix;
        let perm = u.map_or(0o644, |u| u.mode & 0o7777);
        let rdev = u.and_then(|u| u.rdev).unwrap_or(0);
        let (major, minor) = ((rdev >> 32) as u32, rdev as u32);
        host::make_node(path, kind | perm, major, minor)
            .map_err(|x| Error::unsupported(format!("a node of kind {:?}: {}: {x}", e.stat.kind, path.display())))?;
        if e.metadata {
            // Its mode is made with it.
            let what = if self.owners { MetaFacets::TIMES | MetaFacets::OWNER } else { MetaFacets::TIMES };
            self.restore(e.path, path, what, Some(e), e.stat, &[])?;
        }
        Ok(())
    }
}

impl ExportSink for DirSink {
    fn add(&mut self, e: &Entry<'_>, item: Item<'_>) -> Result<Vec<Note>> {
        self.add_entry(e, item)?;
        Ok(std::mem::take(&mut self.notes))
    }

    fn finish(&mut self) -> Result<Vec<Note>> {
        self.finish_dirs()?;
        Ok(std::mem::take(&mut self.notes))
    }
}

impl DirSink {
    fn add_entry(&mut self, e: &Entry<'_>, item: Item<'_>) -> Result<()> {
        fs_inspect_io::cancel::check_call()?;
        let path = self.path(e.path);
        match item {
            Item::Dir => {
                std::fs::create_dir(&path).map_err(|x| err(&path, x))?;
                self.restore(e.path, &path, MetaFacets::XATTRS, Some(e), e.stat, &[])?;
                self.dirs.push(DirMeta {
                    rel: e.path.to_string(),
                    path,
                    stat: e.stat.clone(),
                    security: e.security.clone(),
                    metadata: e.metadata,
                });
                Ok(())
            }
            Item::File { content, streams } => self.file(e, &path, &content, &streams),
            Item::Symlink { target, dir } => {
                #[cfg(unix)]
                let r = {
                    let _ = dir;
                    std::os::unix::fs::symlink(&target, &path)
                };
                #[cfg(windows)]
                let r = {
                    let t = target.replace('/', "\\");
                    if dir {
                        std::os::windows::fs::symlink_dir(&t, &path)
                    } else {
                        std::os::windows::fs::symlink_file(&t, &path)
                    }
                };
                #[cfg(not(any(unix, windows)))]
                let r: std::io::Result<()> = Err(std::io::Error::from(std::io::ErrorKind::Unsupported));
                r.map_err(|x| Error::unsupported(format!("a symbolic link to {target}: {x}")))
            }
            Item::HardLink { to } => {
                let to = self.path(&to);
                std::fs::hard_link(&to, &path).map_err(|x| err(&path, x))
            }
            Item::Special => self.special(e, &path),
        }
    }

    fn finish_dirs(&mut self) -> Result<()> {
        // Innermost first: setting a directory's times does not change its parent's.
        let dirs = std::mem::take(&mut self.dirs);
        for d in dirs.iter().rev() {
            let mut what = MetaFacets::ACL;
            if d.metadata {
                what |= self.attrs();
            }
            let m = Meta { stat: &d.stat, xattrs: &[], security: d.security.as_ref(), streams: &[] };
            for s in restore::apply(&d.path, what, &m)? {
                self.notes.push(Note::new(&d.rel, s.note()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::export::tar::tests::FailingReader;
    use fs_inspect_core::ByteRange;
    use fs_inspect_core::ns::NodeId;

    #[test]
    fn a_file_failing_part_way_is_not_left_half_written() {
        let tmp = tempfile::tempdir().unwrap();
        let mut sink = DirSink::new(tmp.path()).unwrap();
        let data = vec![7u8; 3 << 20];
        let bad = FailingReader { data: data.clone(), fail_at: 3 << 19 };
        let good = FailingReader { data: b"after it".to_vec(), fail_at: u64::MAX };
        let st = Stat::new(NodeId::new(0, 1), NodeKind::File, data.len() as u64);
        let entry = |path| Entry { path, stat: &st, xattrs: vec![], security: None, metadata: false, cloud: None };
        let whole = Content {
            ahead: 4,
            reader: &bad,
            size: data.len() as u64,
            data: vec![ByteRange::new(0, data.len() as u64)],
            prefetched: None,
        };
        assert!(sink.add(&entry("bad"), Item::File { content: whole, streams: vec![] }).is_err());
        assert!(!tmp.path().join("bad").exists());
        let ok = Content { ahead: 4, reader: &good, size: 8, data: vec![ByteRange::new(0, 8)], prefetched: None };
        sink.add(&entry("ok"), Item::File { content: ok, streams: vec![] }).unwrap();
        sink.finish().unwrap();
        assert_eq!(std::fs::read(tmp.path().join("ok")).unwrap(), b"after it");
    }
}
