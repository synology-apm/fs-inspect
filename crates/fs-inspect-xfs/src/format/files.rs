//! The regular files of an XFS volume: every in-use inode of every inode chunk, found
//! through each AG's inode B+tree, and the data mapping of the regular ones.

use crate::format::fs::XfsFs;
use crate::format::geom::{Geom, INCOMPAT_NEEDSREPAIR};
use crate::format::inobt::{self, INODES_PER_CHUNK, InoRec};
use crate::format::inode::{self, Dinode, Limits};
use fs_inspect_core::Scope;
use fs_inspect_core::files::zero_flagged;
use fs_inspect_core::{ByteRange, Error, FileInfo, FileMap, Result};
use fs_inspect_io::batch::{self, BATCH_BYTES, GAP_BYTES};

/// Most bmbt blocks read for one file, whatever the caller's `max_tree_nodes`: a hostile
/// image cannot make every inode cost millions of reads.
const MAX_BMBT_NODES: u64 = 1 << 22;
/// Bytes `[start, end)` of the present inodes of chunk `r`, `None` when it holds no inode in
/// use or lies (in part) outside the AG.
fn chunk_span(g: &Geom, agno: u32, r: &InoRec) -> Option<(u64, u64)> {
    if !(0..INODES_PER_CHUNK).any(|k| r.in_use(k)) {
        return None;
    }
    let first = (0..INODES_PER_CHUNK).find(|&k| r.present(k))?;
    let last = (0..INODES_PER_CHUNK).rev().find(|&k| r.present(k))?;
    let start = g.agino_byte(agno, r.startino + first)?;
    let end = g.agino_byte(agno, r.startino + last)? + u64::from(g.sb().inodesize);
    Some((start, end))
}

impl XfsFs {
    /// The superblock with its inode geometry, checked at open: what reading inodes needs.
    pub(crate) fn geometry(&self) -> &Geom {
        &self.geom
    }

    /// Bounds of one file's extent list and bmbt walk.
    pub(crate) fn file_limits(&self) -> Limits {
        let l = self.limits();
        Limits { max_extents: l.max_file_extents as u64, max_nodes: l.max_tree_nodes.min(MAX_BMBT_NODES) }
    }

    /// Whether the inode cores are what XFS writes, current or not: mkfs finished, no repair
    /// is pending and the superblock checksum holds. Otherwise no file-level zero; with a log
    /// to replay, it is not settled (the log may hold the conversion of an unwritten extent to
    /// written).
    fn inodes_written(&self) -> bool {
        let sb = self.superblock();
        sb.inprogress == 0 && sb.features_incompat & INCOMPAT_NEEDSREPAIR == 0 && self.superblock_crc_ok()
    }

    /// Every in-use inode, AG by AG in inobt order, as `(ino, raw bytes)`. What cannot be read
    /// (an AGI or inobt that is damaged, an inode chunk outside its AG or unreadable) is
    /// skipped with a message and the number of inodes it holds through `warn`; errors of `f`
    /// stop the walk.
    ///
    /// Returns the inode chunks of the AGs whose inobt was read whole: their byte ranges (in
    /// order) and the LSN of the inobt leaf holding their record (see
    /// `settled` in `track::stamp`).
    pub(crate) fn walk_inodes(
        &self,
        warn: &mut dyn FnMut(String, u64),
        f: &mut dyn FnMut(u64, &[u8]) -> Result<()>,
    ) -> Result<Vec<(ByteRange, u64)>> {
        let _span = tracing::debug_span!("xfs.inodes").entered();
        let g = self.geometry();
        let src = self.source();
        let max_nodes = self.limits().max_tree_nodes;
        let len = u64::from(INODES_PER_CHUNK) * u64::from(g.sb().inodesize);
        let mut chunks = Vec::new();
        for agno in 0..g.sb().agcount {
            let agi = match inobt::read_agi(src, g, agno) {
                Ok(a) => a,
                Err(e) if e.scope() != Scope::Unit => return Err(e),
                Err(e) => {
                    warn(format!("AGI of AG {agno} is damaged ({e}); its inodes are not reported"), 0);
                    continue;
                }
            };
            // The AG's chunk records first (the inobt is small next to the chunks), so the
            // chunks are read ahead of their parsing.
            let mut ag = Vec::new();
            let mut recs = Vec::new();
            let res = inobt::walk(src, g, agno, &agi, max_nodes, &mut |r: InoRec| {
                if let Some(off) = g.agino_byte(agno, r.startino) {
                    ag.push((ByteRange::new(off, len), r.leaf_lsn));
                }
                recs.push(r);
                Ok(())
            });
            // The tree's damage reported before its chunks are read (the records found stay).
            let whole = match res {
                Ok(()) => true,
                Err(e) if e.scope() != Scope::Unit => return Err(e),
                Err(e) => {
                    warn(
                        format!("inode btree of AG {agno} is damaged ({e}); the rest of its inodes are not reported"),
                        0,
                    );
                    false
                }
            };
            // Inode chunks close together on disk (inobt order is disk order) read together.
            let mut spanned = Vec::with_capacity(recs.len());
            for r in recs {
                match chunk_span(g, agno, &r) {
                    Some((s, e)) => spanned.push((s, e - s, r)),
                    // Nothing to read (no inode in use), or a chunk the reading reports.
                    None => self.chunk(g, agno, r, None, warn, f)?,
                }
            }
            let mut each = |r: InoRec, b: Option<&[u8]>| {
                let pre = b.and_then(|b| Some((chunk_span(g, agno, &r)?.0, b)));
                self.chunk(g, agno, r, pre, warn, f)
            };
            batch::read_runs(&**src, batch::runs(spanned, BATCH_BYTES, GAP_BYTES), &mut each)?;
            if whole {
                chunks.extend(ag);
            }
        }
        Ok(chunks)
    }

    /// Read one inode chunk (from `pre`, bytes read already at an offset, when it holds them)
    /// and hand its in-use inodes to `f`.
    fn chunk(
        &self,
        g: &Geom,
        agno: u32,
        r: InoRec,
        pre: Option<(u64, &[u8])>,
        warn: &mut dyn FnMut(String, u64),
        f: &mut dyn FnMut(u64, &[u8]) -> Result<()>,
    ) -> Result<()> {
        let isize = usize::from(g.sb().inodesize);
        // Runs of present (non-sparse) inodes, read in one piece each.
        let mut i = 0u32;
        while i < INODES_PER_CHUNK {
            if !r.present(i) {
                i += 1;
                continue;
            }
            let mut j = i;
            while j < INODES_PER_CHUNK && r.present(j) {
                j += 1;
            }
            if (i..j).any(|k| r.in_use(k)) {
                let agino = r.startino + i;
                let off = g.agino_byte(agno, agino).filter(|_| g.agino_byte(agno, r.startino + j - 1).is_some());
                let buf = match off {
                    None => Err(format!("inode chunk {agino} outside the AG")),
                    Some(off) => match pre
                        .and_then(|(at, d)| d.get(off.checked_sub(at)? as usize..)?.get(..(j - i) as usize * isize))
                    {
                        Some(b) => Ok(std::borrow::Cow::Borrowed(b)),
                        None => match self.source().read_vec(off, (j - i) as usize * isize) {
                            Ok(b) => Ok(std::borrow::Cow::Owned(b)),
                            Err(e) => {
                                let e = e;
                                if e.scope() != Scope::Unit {
                                    return Err(e);
                                }
                                Err(e.to_string())
                            }
                        },
                    },
                };
                let buf = match buf {
                    Ok(b) => b,
                    Err(e) => {
                        warn(format!("AG {agno} inodes {agino}..: {e}"), u64::from(j - i));
                        i = j;
                        continue;
                    }
                };
                for k in i..j {
                    if r.in_use(k) {
                        let o = (k - i) as usize * isize;
                        f(g.ino(agno, r.startino + k), &buf[o..o + isize])?;
                    }
                }
            }
            i = j;
        }
        Ok(())
    }

    /// The inode `ino` (raw bytes `raw`) and its file data, when it is a regular file in use
    /// that is not file-system metadata (`Ok(None)` otherwise). `Err`: the file cannot be used
    /// ([`Scope::Unit`]: a damaged inode or mapping, a realtime file, one an unfinished
    /// `ATTRI` changes), or the scan cannot go on.
    pub(crate) fn file_info(&self, ino: u64, raw: &[u8]) -> Result<Option<(Dinode, FileInfo)>> {
        let g = self.geometry();
        let Some(d) = self.parse_inode(ino, raw)? else { return Ok(None) };
        if !d.is_reg() || d.nlink == 0 || g.is_system_inode(ino) || d.flags2 & inode::DIFLAG2_METADATA != 0 {
            return Ok(None);
        }
        if d.flags & inode::DIFLAG_REALTIME != 0 {
            return Err(Error::unsupported("xfs realtime file"));
        }
        self.check_finished(ino)?;
        let extents = self.fork_extents(ino, raw, &d, false)?;
        let zero_as_read =
            if self.inodes_written() { zero_flagged(&extents, inode::EXTENT_UNWRITTEN) } else { Vec::new() };
        let settled = fs_inspect_core::Filesystem::consistency(self).is_clean();
        Ok(Some((d, FileInfo { key: ino, extents, zero_as_read, settled })))
    }
}

impl FileMap for XfsFs {
    /// Regular files that cannot be used are left out (their blocks count as metadata).
    fn for_each(&self, f: &mut dyn FnMut(FileInfo) -> Result<()>) -> Result<()> {
        self.walk_inodes(&mut |_, _| {}, &mut |ino, raw| match self.file_info(ino, raw) {
            Ok(Some((_, info))) => f(info),
            Ok(None) => Ok(()),
            Err(e) if e.scope() == Scope::Unit => Ok(()),
            Err(e) => Err(e),
        })
        .map(drop)
    }
}
