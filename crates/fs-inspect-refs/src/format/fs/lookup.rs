//! Files: the walk over every directory table, a file's clusters, the VSS storage. Browsing is
//! the [namespace](super::ns).

use super::RefsFs;
use crate::format::files::{DirEntry, FileEntry, dir_entry, object};
use fs_inspect_core::Scope;
use fs_inspect_core::range::sort_coalesce;
use fs_inspect_core::{ByteRange, DiagCode, Error, Result};
use std::ops::ControlFlow;

impl RefsFs {
    /// Every file record of the volume (directories excluded) goes to `f`, or, as an `Err`,
    /// damage that hides some: a directory table or a record that cannot be read (the walk
    /// goes on). An error from `f`, a damaged Object ID table and other errors end the walk.
    pub fn walk_files(&self, f: &mut dyn FnMut(Result<FileEntry>) -> Result<()>) -> Result<()> {
        let _span = tracing::debug_span!("refs.walk").entered();
        let r = self.file_reader();
        // The directories' root pages are read together.
        r.roots(&self.directories()?, &mut |d, root| {
            // An error of `f`, kept apart from the damage `rows` reports.
            let mut stop: Option<Error> = None;
            let res = root.and_then(|root| {
                r.rows_from(d, root, &mut |k, v| {
                    let file = match dir_entry(k, v) {
                        Ok(DirEntry::File { name, record }) => r.file(d.id, name.clone(), record).map_err(|e| {
                            let name = name.as_deref().unwrap_or("(kept by id)");
                            e.context(format!("refs: directory {:#x}, file {name}", d.id))
                        }),
                        Ok(_) => return Ok(ControlFlow::Continue(())),
                        Err(e) => Err(e.context(format!("refs: directory {:#x}", d.id))),
                    };
                    let out = match file {
                        Err(e) if e.scope() != Scope::Unit => return Err(e),
                        file => f(file),
                    };
                    out.inspect_err(|e| stop = Some(e.clone())).map(ControlFlow::Continue)
                })
            });
            match (res, stop) {
                (_, Some(e)) => Err(e),
                (Ok(()), None) => Ok(()),
                (Err(e), None) if e.scope() == Scope::Unit => f(Err(e.context(format!("refs: directory {:#x}", d.id)))),
                (Err(e), None) => Err(e),
            }
        })?;
        Ok(())
    }

    /// The clusters of the VSS shadow-copy storage files and catalog in System Volume
    /// Information (see [`fs_inspect_core::vss`]), sorted and coalesced. VSS writes them below the
    /// file system (no time stamp moves) and a snapshot never needs them. A missing directory
    /// yields nothing; so does an error other than a cancel (reported: nothing is excluded).
    pub fn vss_storage(&self) -> Result<Vec<ByteRange>> {
        let found = (|| -> Result<Vec<ByteRange>> {
            let r = self.file_reader();
            let dirs = self.directories()?;
            let Some(root) = dirs.iter().find(|d| d.id == object::ROOT) else { return Ok(Vec::new()) };
            let mut svi = None;
            r.rows(root, &mut |k, v| {
                if let DirEntry::Directory { name, id } = dir_entry(k, v)?
                    && name.eq_ignore_ascii_case(fs_inspect_core::vss::DIRECTORY)
                {
                    svi = Some(id);
                    return Ok(ControlFlow::Break(()));
                }
                Ok(ControlFlow::Continue(()))
            })?;
            let Some(d) = svi.and_then(|id| dirs.iter().find(|d| d.id == id)) else { return Ok(Vec::new()) };
            let mut out = Vec::new();
            r.rows(d, &mut |k, v| {
                if let DirEntry::File { name: Some(name), record } = dir_entry(k, v)?
                    && fs_inspect_core::vss::is_vss_storage_name(&name)
                {
                    out.extend(self.file_ranges(&r.file(d.id, Some(name), record)?));
                }
                Ok(ControlFlow::Continue(()))
            })?;
            Ok(sort_coalesce(out))
        })();
        match found {
            Err(e) if !e.is_cancelled() => {
                self.diag.warn(
                    DiagCode::ExclusionSkipped,
                    format!("cannot enumerate the VSS shadow storage ({e}); it is not excluded"),
                );
                Ok(Vec::new())
            }
            r => r,
        }
    }

    /// Volume ranges of the clusters of `e`'s streams, sorted and coalesced.
    pub fn file_ranges(&self, e: &FileEntry) -> Vec<ByteRange> {
        let c = u64::from(self.reader.cluster_bytes());
        let v = e.streams.iter().flat_map(|s| &s.extents).map(|x| ByteRange::new(x.lcn * c, x.clusters * c)).collect();
        sort_coalesce(v)
    }
}
