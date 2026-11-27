//! Change tracking for APFS containers.
//!
//! The source is the container (offset 0 = block 0, `NXSB`). `format` finds the newest
//! usable checkpoint and the used blocks; from that checkpoint (read through the opened
//! [`ApfsFs`]) [`ApfsScanner`] reads the container object map, every volume superblock
//! (`nx_fs_oid[]`), each volume's object map and live FS tree (and a sealed volume's file
//! extent tree), and emits every regular file and every extended-attribute data stream with
//! its extents. Everything else that is used is dated without reading it, by the transaction
//! of its chunk's bitmap, of the object, or of the checkpoint; what cannot be dated is dirty:
//!
//! - Every object (container and volume object maps and their nodes, volume superblocks, FS
//!   tree nodes, chunk-info blocks) is immutable once written: one whose `o_xid` is not after
//!   the previous checkpoint holds what it held then.
//! - A chunk's `ci_xid` changes whenever its bitmap does. Objects are written to newly
//!   allocated blocks and their old blocks freed, so a chunk whose `ci_xid` is not after the
//!   previous checkpoint had no block allocated or freed since: its used blocks belong to the
//!   same objects, extents or snapshots, unchanged but for in-place writes of file data. When
//!   every file was listed those are reported with the files, so the chunk is tracked;
//!   otherwise only dated objects are. Its bitmap block is unchanged too.
//! - The checkpoint areas and the internal pool are rewritten without chunk changes: tracked
//!   only when the checkpoint is the previous one (but the dated bitmaps and chunk-info
//!   blocks in the pool). Block 0 is a fixed region.
//! - Volume snapshots are not walked. Blocks only a snapshot holds are never rewritten, so they
//!   are tracked in a chunk dated as above and dirty in any other.
//! - A sealed volume's integrity metadata and hash blocks are not read either: dated by their
//!   chunk like snapshot blocks.
//!
//! An encrypted volume (no `APFS_FS_UNENCRYPTED`, or FS-tree nodes marked
//! `OMAP_VAL_ENCRYPTED`) cannot be told apart into data and metadata: everything used outside
//! the files of the other volumes is dirty on every run, and nothing is compared.

#![forbid(unsafe_code)]

use fs_inspect_core::DiagnosticExt;
pub mod codes;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use crate::ApfsFs;
use crate::format::btree::ObjectLog;
use crate::format::extent::extents_of;
use crate::format::files::{Candidate, Collected, VolumeOutcome, walk_volume};
use crate::format::layout::XP_TREE_FLAG;
use crate::format::records::UF_COMPRESSED;
use crate::format::volumes::{Container, Slot, Volume};
use fs_inspect_change::Warnings;
use fs_inspect_change::hash::CanonHasher;
use fs_inspect_change::{
    Continuity, Degrade, DegradeCode, DriverExtra, Evidence, Extent, FileState, FsScanner, Identity, Opened, Reason,
    Result, ScanContext, TaggedRange, TypedScanner, rewind,
};
use fs_inspect_core::ByteRange;
use fs_inspect_core::Filesystem;
use fs_inspect_core::Scope;
use fs_inspect_core::range::list::{normalize, subtract};
use fs_inspect_core::{DiagCode, Diagnostic};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

/// Track changes on `fs`, the opened APFS container, as of the checkpoint it uses.
pub fn open(fs: Arc<dyn Filesystem>) -> Result<Box<dyn FsScanner>> {
    let fs = Opened::<ApfsFs>::new(fs)?;
    let log = ObjectLog::recording();
    let c = crate::format::volumes::Container::open_logged(&fs, log.clone())?;
    Ok(Box::new(ApfsScanner::new(fs, c, log)))
}

/// Object ids are packed below the volume index: `(volume << 56) | id`.
pub const KEY_SHIFT: u32 = 56;
const ID_MASK: u64 = (1 << KEY_SHIFT) - 1;
/// The APFS change-tracking driver.
#[derive(Debug)]
pub struct ApfsScanner {
    fs: Opened<ApfsFs>,
    c: Container,
    /// The objects `c`'s reader reads.
    log: ObjectLog,
}

impl ApfsScanner {
    /// `c` opened on `fs` with its reader logging to `log`.
    pub fn new(fs: Opened<ApfsFs>, c: Container, log: ObjectLog) -> Self {
        ApfsScanner { fs, c, log }
    }
}

/// The `FS_STATE` blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// Transaction of the checkpoint in use.
    pub xid: u64,
    /// `nx_next_xid` of that checkpoint.
    pub next_xid: u64,
    /// The volumes whose superblock could be read.
    pub volumes: Vec<VolState>,
}

/// One volume in [`State`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolState {
    /// Index in `nx_fs_oid[]`.
    pub index: usize,
    /// Volume UUID, upper case.
    pub uuid: String,
    /// Transaction of the volume superblock.
    pub xid: u64,
}

impl State {
    fn of(c: &Container) -> Self {
        let volumes = c
            .slots
            .iter()
            .filter_map(|s| match s {
                Slot::Ok(v) => Some(VolState { index: v.index, uuid: uuid_str(&v.sb.uuid), xid: v.xid }),
                Slot::Bad { .. } => None,
            })
            .collect();
        State { xid: c.xid, next_xid: c.next_xid, volumes }
    }
}

fn uuid_str(u: &[u8; 16]) -> String {
    fs_inspect_core::guid::format_uuid(u).to_uppercase()
}

impl ApfsScanner {
    /// The [`FileState`] of a regular file or xattr data stream:
    ///
    /// - `key`: `(volume index << KEY_SHIFT) | object id` (an id too large is cut to its low bits
    ///   and reported whole-file). Inode and xattr stream ids share one allocator.
    /// - `generation`: the volume UUID and the file's `create_time` (plus the xattr name), so a
    ///   volume recreated at the same index makes every file `Created`.
    /// - `meta`: a token part users cannot set back (`change_time`,
    ///   `write_generation_counter`, the stream's `total_bytes_written`) and an attribute part
    ///   (`mod_time`, flags, mode, owner, link count, stream id, size, allocated size, xattr
    ///   name). Access time and bytes read stay out, so reading a file never marks it.
    /// - `evidence` is `None`: APFS rewrites unshared extents in place. `no_narrow` for
    ///   `decmpfs`-compressed files (`UF_COMPRESSED`).
    fn file_state(&self, v: &Volume, c: &Candidate, extents: Vec<Extent>, warn: &mut Warnings) -> FileState {
        let ino = &c.ino;
        let vol = v.index as u64;
        let mut evidence = Evidence::None;
        if c.id > ID_MASK {
            warn.push(Diagnostic::warning(
                DiagCode::Fallback,
                format!("volume {}: object id {:#x} does not fit the key; reported as whole-file", v.index, c.id),
            ));
            evidence = Evidence::WholeFile;
        }
        let key = (vol << KEY_SHIFT) | (c.id & ID_MASK);
        let mut g = CanonHasher::new(b"apfs.gen");
        g.raw(&v.sb.uuid).u64(ino.create_time);
        let mut t = CanonHasher::new(b"apfs.token");
        t.u64(ino.change_time).u32(ino.write_generation_counter);
        let mut a = CanonHasher::new(b"apfs.attr");
        a.u64(ino.mod_time).u64(ino.internal_flags).u32(ino.bsd_flags).u16(ino.mode);
        a.u32(ino.uid).u32(ino.gid).u32(ino.nlink).u64(c.data_id);
        let ds = match &c.stream {
            None => {
                let ds = ino.dstream.unwrap_or_default();
                t.u8(0).u64(ds.total_bytes_written);
                a.u8(0);
                ds
            }
            Some(x) => {
                g.u8(1).bytes(x.name.as_bytes());
                t.u8(1).u64(x.dstream.total_bytes_written);
                a.u8(1).bytes(x.name.as_bytes());
                x.dstream
            }
        };
        a.u64(ds.size).u64(ds.alloced_size);
        FileState {
            key,
            generation: g.finish(),
            meta: CanonHasher::new(b"apfs.meta").u64(a.finish()).u64(t.finish()).finish(),
            aux: [0; 2],
            no_narrow: ino.bsd_flags & UF_COMPRESSED != 0,
            extents,
            // APFS has no unwritten extents: unwritten space is a hole.
            zero: Vec::new(),
            evidence,
        }
    }
}

impl ApfsScanner {
    /// The used space outside the files, dated against checkpoint `prev_xid` (see the module
    /// documentation). `complete`: every file of every volume was listed.
    fn track_space(&self, prev_xid: u64, complete: bool, extra: &mut DriverExtra) -> Result<()> {
        let _span = tracing::debug_span!("apfs.space").entered();
        let fs = &*self.fs;
        let geo = fs.geometry();
        let bs = geo.block_size as u64;
        let blk = |a: u64, n: u64| ByteRange::new(a.saturating_mul(bs), n.saturating_mul(bs));
        if prev_xid == self.c.xid {
            // The same checkpoint: nothing was written.
            extra.tracked = subtract(&[blk(0, geo.block_count)], &extra.fixed);
            return Ok(());
        }
        let sb = fs.superblock();
        let sm = fs.spaceman();
        let mut special = vec![
            blk(0, 1),
            blk(sb.xp_desc_base, (sb.xp_desc_blocks & !XP_TREE_FLAG) as u64),
            blk(sb.xp_data_base, (sb.xp_data_blocks & !XP_TREE_FLAG) as u64),
            blk(sm.ip_base, sm.ip_block_count),
            blk(sm.ip_bm_base, sm.ip_bm_block_count as u64),
        ];
        normalize(&mut special);
        let mut chunks_used = Vec::new();
        let mut dated = Vec::new();
        let chunks = fs.chunks();
        for ci in chunks.list.iter().filter(|ci| ci.xid <= prev_xid) {
            chunks_used.push(blk(ci.addr, ci.block_count as u64));
            if ci.bitmap_addr != 0 {
                dated.push(blk(ci.bitmap_addr, 1));
            }
        }
        dated.extend(chunks.objects.iter().filter(|o| o.xid <= prev_xid).map(|o| blk(o.paddr, o.blocks)));
        self.log
            .with(|objects| dated.extend(objects.iter().filter(|o| o.xid <= prev_xid).map(|o| blk(o.paddr, o.blocks))));
        let mut tracked = if complete {
            normalize(&mut chunks_used);
            subtract(&chunks_used, &special)
        } else {
            Vec::new()
        };
        tracked.extend(dated);
        normalize(&mut tracked);
        extra.tracked = subtract(&tracked, &extra.fixed);
        Ok(())
    }
}

impl TypedScanner for ApfsScanner {
    type State = State;
    const STATE_VERSION: u32 = 1;
    const STATE_CODE: DegradeCode = codes::STATE;

    fn identity(&self) -> Identity {
        Identity::new(
            fs_inspect_core::FsKind::Apfs,
            self.fs.info().uuid.clone(),
            u64::from(self.c.reader.geo.block_size),
        )
    }

    fn current(&self) -> Result<State> {
        Ok(State::of(&self.c))
    }

    fn continuity(&self, prev: &State, cur: &State, _offline: bool) -> Continuity {
        if let Some(broken) = rewind(codes::XID_REWIND, "the container checkpoint xid", prev.xid, cur.xid) {
            return broken;
        }
        for p in &prev.volumes {
            if let Some(c) = cur.volumes.iter().find(|c| c.index == p.index && c.uuid == p.uuid)
                && let Some(broken) = rewind(codes::VOLUME_REWIND, &format!("volume {} xid", p.index), p.xid, c.xid)
            {
                return broken;
            }
        }
        Continuity::Ok
    }

    fn scan_files(
        &self,
        cx: &ScanContext<'_>,
        prev: Option<&State>,
        _cur: &mut State,
        emit: &mut dyn FnMut(FileState),
    ) -> Result<DriverExtra> {
        // Block 0: the container superblock copy, written in place.
        let bs = self.c.reader.geo.block_size as u64;
        let mut extra = DriverExtra { fixed: vec![ByteRange::new(0, bs)], ..DriverExtra::default() };
        // Every file of every volume listed: in-place writes are all seen.
        let mut complete = true;
        let mut warn = Warnings::default();
        let mut keys: HashSet<u64> = HashSet::new();
        let mut data: Vec<ByteRange> = Vec::new();
        let mut encrypted: Vec<String> = Vec::new();
        for slot in &self.c.slots {
            let v = match slot {
                Slot::Ok(v) => v,
                Slot::Bad { index, oid, error } => {
                    warn.push(Diagnostic::warning(
                        DiagCode::CountedAsChanged,
                        format!("volume {index} (oid {oid:#x}) skipped, its data counts as changed: {error}"),
                    ));
                    complete = false;
                    continue;
                }
            };
            let col = match walk_volume(&self.c.reader, self.c.xid, v) {
                Ok(VolumeOutcome::Walked(c)) => c,
                Ok(VolumeOutcome::Encrypted(why)) => {
                    encrypted.push(format!("volume {} ({}): {why}", v.index, v.sb.name));
                    continue;
                }
                Err(e) if e.scope() != Scope::Unit => return Err(e),
                Err(e) => {
                    warn.push(Diagnostic::warning(
                        DiagCode::CountedAsChanged,
                        format!("volume {} ({}) skipped, its data counts as changed: {e}", v.index, v.sb.name),
                    ));
                    complete = false;
                    continue;
                }
            };
            if col.bad_inodes > 0 || col.orphan_streams > 0 {
                warn.push(Diagnostic::warning(
                    DiagCode::CountedAsChanged,
                    format!(
                        "volume {}: {} inodes and {} xattr streams not parsed; their data counts as changed",
                        v.index, col.bad_inodes, col.orphan_streams
                    ),
                ));
                complete = false;
            }
            let Collected { cands, extents, bad_ids, .. } = col;
            let mut skipped = 0u64;
            for c in &cands {
                if bad_ids.contains(&c.data_id) {
                    skipped += 1;
                    complete = false;
                    continue;
                }
                let exts = match extents_of(&self.c.reader, &extents, c.data_id) {
                    Ok(e) => e,
                    Err(why) => {
                        warn.push(Diagnostic::warning(
                            DiagCode::CountedAsChanged,
                            format!(
                                "volume {}: object {:#x} skipped ({why}); its data counts as changed",
                                v.index, c.id
                            ),
                        ));
                        complete = false;
                        continue;
                    }
                };
                let f = self.file_state(v, c, exts, &mut warn);
                if !keys.insert(f.key) {
                    warn.push(Diagnostic::warning(
                        DiagCode::CountedAsChanged,
                        format!("volume {}: duplicate object {:#x} skipped; its data counts as changed", v.index, c.id),
                    ));
                    complete = false;
                    continue;
                }
                fs_inspect_core::files::all_physical(&f.extents, &mut data);
                emit(f);
            }
            if skipped > 0 {
                warn.push(Diagnostic::warning(
                    DiagCode::CountedAsChanged,
                    format!("volume {}: {skipped} objects with unreadable extents skipped", v.index),
                ));
            }
        }

        if !encrypted.is_empty() {
            // An encrypted volume's data and metadata cannot be told apart: everything used
            // that is not data of a reported file is dirty on every run, and nothing is read.
            let used = cx.allocated();
            normalize(&mut data);
            let rest = subtract(&used, &data);
            extra.dirty = TaggedRange::tag_all(rest.iter().copied(), Reason::Fallback).collect();
            extra.tracked = rest;
            for e in encrypted {
                extra.degraded.push(Degrade::new(
                    codes::ENCRYPTED_VOLUME,
                    format!("{e}; every used block outside reported files is dirty"),
                ));
            }
        } else if let Some(p) = prev {
            // (Without a previous state nothing is tracked.)
            self.track_space(p.xid, complete, &mut extra)?;
        }
        extra.known_misses.push(Diagnostic::not_seen(
            "data rewritten in place without a change to change_time, write_generation_counter, \
             total_bytes_written, mod_time or size is not seen",
        ));
        // macOS writes a file's unshared blocks in place at fsync (or at once with F_NOCACHE)
        // and commits the inode update with the next checkpoint (`sync`, F_FULLFSYNC, unmount);
        // a capture in between shows the new data under the old inode and checkpoint, which
        // nothing on disk tells apart from a quiet container.
        extra.known_misses.push(Diagnostic::not_seen(
            "data written in place whose inode update no checkpoint had committed when the image \
             was taken (a capture of a mounted container) is not seen; the next scan reports the \
             file once the update is committed, never if the system stopped first",
        ));
        extra.warnings = warn;
        Ok(extra)
    }
}
