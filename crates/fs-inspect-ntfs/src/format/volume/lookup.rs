//! Directory lookups: `$UpCase` and the index blocks of a directory (the namespace, `ns`,
//! browses with them).
//!
//! - A listing reads the `$I30` B+tree a level at a time (every block of a level together,
//!   [`batch::read_runs`]): one batch per level, so on a source with round trips (a remote
//!   backup) the tree's depth sets the listing's time. It then walks the tree in key order
//!   from the blocks read: each child's subtree before the entry that follows it, with the
//!   checks a walk makes (a VCN reached twice, the node and depth limits) made as each block is
//!   reached. Held at once: the directory's blocks, and the VCNs visited.
//! - A lookup descends the tree. An index that is not sound on the way (a block that does not
//!   parse, a VCN out of the allocation, a node mixing leaf and branch entries, too deep) is
//!   reported ([`DiagCode::Fallback`]) and the name is looked for in every block in use
//!   instead (`$BITMAP:$I30`). A miss in a sound index is the answer. `$UpCase` collates every
//!   name exactly, so every name takes the index.

use super::{NtfsVolume, map_stream_bytes, system_records};
use crate::format::attr::{AttrType, Frn, attr_flags};
use crate::format::entry::{FileEntry, Stream, StreamBody};
use crate::format::error::{Error, Result};
use crate::format::index::{IndexEntry, parse_index_block, parse_index_root};
use crate::format::record::record_header;
use crate::format::upcase::UpCase;
use fs_inspect_core::DiagCode;
use fs_inspect_core::Scope;
use fs_inspect_io::batch::{self, BATCH_BYTES, GAP_BYTES};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;

/// The `$I30` index of a directory: its root node's entries, block size and allocation.
struct I30<'a> {
    block_size: u32,
    root: Vec<IndexEntry>,
    alloc: Option<&'a Stream>,
    bitmap: Option<&'a Stream>,
}

impl NtfsVolume {
    /// The volume's `$UpCase` table (falls back to a built-in table).
    pub fn upcase(&self) -> &UpCase {
        self.upcase.get_or_init(|| {
            let table = self
                .entry(system_records::UPCASE)
                .ok()
                .flatten()
                .and_then(|e| e.unnamed_data().and_then(|s| self.read_stream_all(s).ok()));
            match table {
                Some(t) if t.len() >= 2 => UpCase::from_bytes(&t),
                _ => {
                    self.diag.warn(DiagCode::Fallback, "$UpCase unavailable; names compared with the built-in table");
                    UpCase::default_table()
                }
            }
        })
    }

    /// Bytes per index-block VCN: the cluster size, or 512 bytes when index blocks are smaller
    /// than a cluster (NTFS's fixed block unit; not the sector size, which differs on 4Kn
    /// disks).
    pub fn index_block_unit(&self, block_size: u32) -> u64 {
        if block_size >= self.geometry.cluster_size { self.geometry.cluster_size as u64 } else { 512 }
    }

    /// Whether `frn` names a record in use with its sequence number, by the record's header
    /// alone (its attributes, extension records and streams not read).
    pub fn in_use_as(&self, frn: Frn) -> Result<bool> {
        if frn.record >= self.record_count() {
            return Ok(false);
        }
        let mut buf = self.read_record_raw(frn.record)?;
        Ok(record_header(&mut buf).is_some_and(|h| h.in_use() && !h.is_extension() && h.seq == frn.seq))
    }

    fn i30<'a>(&self, dir: &'a FileEntry) -> Result<I30<'a>> {
        let i30: Vec<u16> = "$I30".encode_utf16().collect();
        let root = dir
            .stream(AttrType::INDEX_ROOT, &i30)
            .ok_or_else(|| Error::not_found(format!("record {} has no $I30 index", dir.frn.record)))?;
        let StreamBody::Resident { data } = &root.body else {
            return Err(Error::corrupt("non-resident $INDEX_ROOT"));
        };
        let (info, root) = parse_index_root(data)?;
        Ok(I30 {
            block_size: info.block_size,
            root,
            alloc: dir.stream(AttrType::INDEX_ALLOCATION, &i30),
            bitmap: dir.stream(AttrType::BITMAP, &i30),
        })
    }

    /// The entries of index block `vcn` of `ix`, read alone.
    fn read_index_block(&self, ix: &I30<'_>, vcn: u64) -> Result<Vec<IndexEntry>> {
        let alloc = ix.alloc.ok_or_else(|| Error::corrupt("index subnode without $INDEX_ALLOCATION"))?;
        let unit = self.index_block_unit(ix.block_size);
        let off = vcn.checked_mul(unit).ok_or_else(|| Error::corrupt("index VCN overflow"))?;
        let mut buf = self.read_stream(alloc, off, ix.block_size as u64)?;
        if buf.len() != ix.block_size as usize {
            return Err(Error::corrupt(format!("index block VCN {vcn} beyond $INDEX_ALLOCATION")));
        }
        parse_block(&mut buf, vcn)
    }

    /// Where index block `vcn` lies on the volume, when it is read there in one piece (mapped,
    /// initialized, not compressed).
    fn index_block_at(&self, ix: &I30<'_>, vcn: u64) -> Option<u64> {
        let alloc = ix.alloc?;
        let StreamBody::NonResident { size, initialized, runs, .. } = &alloc.body else { return None };
        if alloc.flags & attr_flags::COMPRESSED != 0 {
            return None;
        }
        let len = ix.block_size as u64;
        let off = vcn.checked_mul(self.index_block_unit(ix.block_size))?;
        if off.checked_add(len)? > (*size).min(*initialized) {
            return None;
        }
        match map_stream_bytes(runs, self.geometry.cluster_size, off, len)?.as_slice() {
            [one] => Some(one.offset),
            _ => None,
        }
    }

    /// The entries of index blocks `vcns` of `ix`, in that order: those that lie in one piece
    /// read together in disk order ([`batch::read_runs`]), the others (and those of a merged
    /// read that failed) alone. Each block's error is its own; only a cancel is an error of
    /// them all.
    fn read_index_blocks(&self, ix: &I30<'_>, vcns: &[u64]) -> Result<Vec<Result<Vec<IndexEntry>>>> {
        let len = ix.block_size as u64;
        let mut out: Vec<Option<Result<Vec<IndexEntry>>>> = vcns.iter().map(|_| None).collect();
        let items = vcns.iter().enumerate().filter_map(|(i, &v)| Some((self.index_block_at(ix, v)?, len, i))).collect();
        batch::read_runs::<_, Error>(&*self.source, batch::plan(items, BATCH_BYTES, GAP_BYTES), &mut |i, b| {
            if let Some(b) = b {
                out[i] = Some(parse_block(&mut b.to_vec(), vcns[i]));
            }
            Ok(())
        })?;
        vcns.iter()
            .zip(out)
            .map(|(&vcn, e)| match e.unwrap_or_else(|| self.read_index_block(ix, vcn)) {
                Err(e) if e.is_cancelled() => Err(e),
                e => Ok(e),
            })
            .collect()
    }

    /// Every entry of the `$I30` index of a directory, in key order ([`Self::walk_dir`]).
    pub fn dir_entries(&self, dir: &FileEntry) -> Result<Vec<IndexEntry>> {
        let mut out = Vec::new();
        self.walk_dir(dir, &mut |e| {
            out.push(e);
            ControlFlow::Continue(())
        })?;
        Ok(out)
    }

    /// Hand `f` each entry of the `$I30` index of a directory (the nodes' last entries left
    /// out) in key order, from the index read a level at a time (`read_levels`); a
    /// break stops the entries handed, not the reading. A block that does not parse, or one
    /// reached twice, fails the walk when it is reached.
    pub fn walk_dir(&self, dir: &FileEntry, f: &mut dyn FnMut(IndexEntry) -> ControlFlow<()>) -> Result<()> {
        let mut ix = self.i30(dir)?;
        let root = std::mem::take(&mut ix.root);
        let mut read = self.read_levels(&ix, &root)?;
        self.walk_node(&ix, root, 0, &mut HashSet::new(), &mut read, f).map(drop)
    }

    /// The index blocks below `root`, read a level at a time. Reading ahead stops at a level
    /// past the node or depth limits or one naming a VCN twice; the walk reads what is left
    /// when it reaches it, and fails there.
    fn read_levels(&self, ix: &I30<'_>, root: &[IndexEntry]) -> Result<HashMap<u64, Result<Vec<IndexEntry>>>> {
        let mut read = HashMap::new();
        if ix.alloc.is_none() {
            return Ok(read);
        }
        let mut level: Vec<u64> = root.iter().filter_map(|e| e.subnode).collect();
        let mut depth = 0;
        while !level.is_empty()
            && depth < self.limits.max_tree_depth
            && read.len() + level.len() <= self.limits.max_tree_nodes as usize
        {
            let mut seen = HashSet::new();
            if level.iter().any(|v| read.contains_key(v) || !seen.insert(*v)) {
                break;
            }
            let blocks = self.read_index_blocks(ix, &level)?;
            let mut next = Vec::new();
            for (&vcn, block) in level.iter().zip(blocks) {
                if let Ok(entries) = &block {
                    next.extend(entries.iter().filter_map(|e| e.subnode));
                }
                read.insert(vcn, block);
            }
            level = next;
            depth += 1;
        }
        Ok(read)
    }

    /// Walk the subtree of the node of `entries` at `depth`; `visited`: the VCNs reached so far;
    /// `read`: blocks read ahead ([`Self::read_levels`]), taken as they are reached.
    fn walk_node(
        &self,
        ix: &I30<'_>,
        entries: Vec<IndexEntry>,
        depth: usize,
        visited: &mut HashSet<u64>,
        read: &mut HashMap<u64, Result<Vec<IndexEntry>>>,
        f: &mut dyn FnMut(IndexEntry) -> ControlFlow<()>,
    ) -> Result<ControlFlow<()>> {
        let vcns: Vec<u64> = entries.iter().filter_map(|e| e.subnode).collect();
        for &vcn in &vcns {
            if !visited.insert(vcn) {
                return Err(Error::corrupt(format!("index block VCN {vcn} referenced twice")));
            }
        }
        if !vcns.is_empty()
            && (visited.len() > self.limits.max_tree_nodes as usize || depth >= self.limits.max_tree_depth)
        {
            return Err(Error::limit("ntfs index tree nodes or depth"));
        }
        if !vcns.is_empty() && ix.alloc.is_none() {
            return Err(Error::corrupt("index subnode without $INDEX_ALLOCATION"));
        }
        let missing: Vec<u64> = vcns.iter().copied().filter(|v| !read.contains_key(v)).collect();
        for (&vcn, block) in missing.iter().zip(self.read_index_blocks(ix, &missing)?) {
            read.insert(vcn, block);
        }
        // Each VCN once (checked above), each now read.
        let mut children = vcns.iter().filter_map(|v| read.remove(v)).collect::<Vec<_>>().into_iter();
        for e in entries {
            // One block was read per subnode, in their order.
            if e.subnode.is_some()
                && let Some(child) = children.next()
                && self.walk_node(ix, child?, depth + 1, visited, read, f)?.is_break()
            {
                return Ok(ControlFlow::Break(()));
            }
            if !e.last && f(e).is_break() {
                return Ok(ControlFlow::Break(()));
            }
        }
        Ok(ControlFlow::Continue(()))
    }

    /// Case-insensitive lookup of `name` in directory `dir`: down the B+tree, or through every
    /// block in use when the tree is not sound (see the module documentation).
    pub fn lookup(&self, dir: &FileEntry, name: &[u16]) -> Result<Option<IndexEntry>> {
        let ix = self.i30(dir)?;
        match self.descend(&ix, name) {
            Err(e) if e.scope() == Scope::Unit => {
                self.diag.warn(
                    DiagCode::Fallback,
                    format!("record {}: $I30 index unsound ({e}); its blocks scanned for a name", dir.frn.record),
                );
                self.scan_lookup(&ix, name)
            }
            r => r,
        }
    }

    /// `name` down the B+tree of `ix`.
    fn descend(&self, ix: &I30<'_>, name: &[u16]) -> Result<Option<IndexEntry>> {
        let up = self.upcase();
        let mut owned;
        let mut entries = &ix.root;
        for _depth in 0..self.limits.max_tree_depth {
            // A node's entries all lead down, or none do.
            let branch = entries.first().is_some_and(|e| e.subnode.is_some());
            if entries.iter().any(|e| e.subnode.is_some() != branch) {
                return Err(Error::corrupt("index node mixes leaf and branch entries"));
            }
            let mut descend = None;
            for e in entries {
                if e.last {
                    descend = e.subnode;
                    break;
                }
                let Some(fname) = e.file_name() else { continue };
                match up.compare(name, fname.name.units()) {
                    Ordering::Equal => return Ok(Some(e.clone())),
                    Ordering::Less => {
                        descend = e.subnode;
                        break;
                    }
                    Ordering::Greater => {}
                }
            }
            let Some(vcn) = descend else { return Ok(None) };
            owned = self.read_index_block(ix, vcn)?;
            entries = &owned;
        }
        Err(Error::corrupt("index tree too deep"))
    }

    /// `name` in the root node and every index block in use (`$BITMAP:$I30`; all of the
    /// allocation when it cannot be read), in VCN order; a block that does not parse is passed
    /// over. The tree's links are not followed.
    fn scan_lookup(&self, ix: &I30<'_>, name: &[u16]) -> Result<Option<IndexEntry>> {
        let up = self.upcase();
        let hit = |entries: &[IndexEntry]| {
            entries
                .iter()
                .find(|e| !e.last && e.file_name().is_some_and(|n| up.eq_ignore_case(name, n.name.units())))
                .cloned()
        };
        if let Some(e) = hit(&ix.root) {
            return Ok(Some(e));
        }
        let Some(alloc) = ix.alloc else { return Ok(None) };
        let (bs, unit) = (ix.block_size as u64, self.index_block_unit(ix.block_size));
        let blocks = alloc.size().checked_div(bs).unwrap_or(0);
        let bitmap = match ix.bitmap.map(|b| self.read_stream_all(b)) {
            Some(Err(e)) if e.is_cancelled() => return Err(e),
            Some(Ok(b)) => Some(b),
            _ => None,
        };
        let in_use =
            |i: u64| bitmap.as_ref().is_none_or(|b| b.get((i / 8) as usize).is_some_and(|x| x & (1 << (i % 8)) != 0));
        let vcns: Vec<u64> = (0..blocks).filter(|&i| in_use(i)).map(|i| i * bs / unit).collect();
        for chunk in vcns.chunks((BATCH_BYTES / bs.max(1)).max(1) as usize) {
            for entries in self.read_index_blocks(ix, chunk)?.into_iter().flatten() {
                if let Some(e) = hit(&entries) {
                    return Ok(Some(e));
                }
            }
        }
        Ok(None)
    }
}

/// The entries of INDX block `vcn` in `buf` (fixups applied in it); a torn block is damaged.
fn parse_block(buf: &mut [u8], vcn: u64) -> Result<Vec<IndexEntry>> {
    let (entries, torn) = parse_index_block(buf, vcn)?;
    if torn {
        return Err(Error::corrupt(format!("index block VCN {vcn} is torn (fixup mismatch)")));
    }
    Ok(entries)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::synth::{Placement, ROOT, SyntheticVolume, VolumeSpec};
    use fs_inspect_core::{Diagnostics, Limits};
    use fs_inspect_io::test_util::CountingSource;
    use fs_inspect_io::{DynSource, MemSource};
    use std::sync::Arc;

    /// A volume with directory `big` of `n` files (several index levels) and a subdirectory.
    fn big(n: u64) -> (SyntheticVolume, u64) {
        let mut v = SyntheticVolume::format(VolumeSpec { clusters: 32768, ..Default::default() });
        let d = v.create_dir(ROOT, "big");
        v.batch(|v| {
            for i in 0..n {
                v.create_file(d, &format!("file-name-number-{i:06}"), 0, i, Placement::FirstFit);
            }
        });
        let sub = v.create_dir(d, "Sub");
        v.create_file(sub, "inner.txt", 10, 1, Placement::FirstFit);
        (v, d)
    }

    fn open(src: DynSource) -> NtfsVolume {
        NtfsVolume::open_with(src, Limits::default(), Diagnostics::new()).unwrap()
    }

    fn name_of(e: &IndexEntry) -> Vec<u16> {
        e.file_name().unwrap().name.units().to_vec()
    }

    /// For every directory of `vol`: the index's lookup and the scan agree on each listed name,
    /// the same in upper case, and names that are not there. The directories checked.
    fn lookups_agree(vol: &NtfsVolume) -> usize {
        let up = vol.upcase();
        let mut todo = vec![vol.entry(system_records::ROOT).unwrap().unwrap()];
        let mut seen = HashSet::from([system_records::ROOT]);
        let mut rng = 0x2545_f491_4f6c_dd1du64;
        let mut dirs = 0;
        while let Some(d) = todo.pop() {
            dirs += 1;
            let ix = vol.i30(&d).unwrap();
            let mut probes = Vec::new();
            for e in vol.dir_entries(&d).unwrap() {
                let n = name_of(&e);
                probes.push(n.iter().map(|&u| up.up(u)).collect());
                probes.push([n.as_slice(), &[0x7e, 0x71]].concat());
                probes.push(n);
                if e.file_name().unwrap().attributes & crate::format::files::NAME_OF_DIRECTORY != 0
                    && seen.insert(e.frn.record)
                    && let Some(c) = vol.entry_frn(e.frn).unwrap().filter(FileEntry::is_dir)
                {
                    todo.push(c);
                }
            }
            for _ in 0..32 {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                let len = 1 + (rng % 24) as usize;
                probes.push((0..len).map(|i| 0x21 + ((rng >> (i % 8 * 8)) as u16 % 0x5d)).collect());
            }
            for p in probes {
                let (a, b) = (vol.descend(&ix, &p).unwrap(), vol.scan_lookup(&ix, &p).unwrap());
                assert_eq!(a, b, "{} in record {}", String::from_utf16_lossy(&p), d.frn.record);
                assert_eq!(vol.lookup(&d, &p).unwrap(), a);
            }
        }
        assert!(vol.diagnostics().all().iter().all(|d| d.code != DiagCode::Fallback));
        dirs
    }

    #[test]
    fn index_lookup_is_the_scan_on_synthetic_volumes() {
        let (v, _) = big(1500);
        assert!(lookups_agree(&open(Arc::new(v.source()))) >= 4);
        let v =
            SyntheticVolume::format(VolumeSpec { cluster_size: 1024, index_block_size: 4096, ..Default::default() });
        lookups_agree(&open(Arc::new(v.source())));
    }

    #[test]
    fn index_lookup_is_the_scan_on_windows_volumes() {
        use fs_inspect_testkit::SparseSource;
        for f in ["browse/ntfs-browse", "windows/ntfs-4k", "windows/ntfs-64k"] {
            let path = fs_inspect_testkit::fixture("ntfs").join(format!("{f}.fsbs"));
            let dirs = lookups_agree(&open(Arc::new(SparseSource::open(path))));
            assert!(dirs > 1, "{f}");
        }
    }

    /// The walk is in key order and reads each level of the tree together (a few merged reads
    /// for the whole index); a break stops the entries handed; two walks give the same entries.
    #[test]
    fn a_walk_reads_blocks_together_in_key_order() {
        let (v, d) = big(4000);
        let src = CountingSource::new(Arc::new(v.source()));
        let vol = open(src.clone());
        let dir = vol.entry(d).unwrap().unwrap();
        let ix = vol.i30(&dir).unwrap();
        let blocks = ix.alloc.unwrap().size() / u64::from(ix.block_size);
        let before = src.stats();
        let all = vol.dir_entries(&dir).unwrap();
        let full = src.stats().since(&before).reads;
        assert_eq!(all.len(), 4001);
        let up = vol.upcase();
        assert!(all.windows(2).all(|w| up.compare(&name_of(&w[0]), &name_of(&w[1])) == Ordering::Less));
        assert_eq!(vol.dir_entries(&dir).unwrap(), all);
        let before = src.stats();
        let mut got = 0;
        vol.walk_dir(&dir, &mut |_| {
            got += 1;
            ControlFlow::Break(())
        })
        .unwrap();
        let first = src.stats().since(&before).reads;
        assert_eq!(got, 1);
        eprintln!("{} entries, {blocks} index blocks: {full} reads for all, {first} up to the first", all.len());
        assert!(blocks > 100 && full * 10 <= blocks && first <= full, "{full} {first}");
    }

    /// Reading ahead stops at a level that names a block twice or passes a limit; the walk
    /// then fails where it reaches the fault, after the entries before it.
    #[test]
    fn a_bad_tree_fails_the_walk_where_it_is_reached() {
        let (v, d) = big(4000);
        let vol = open(Arc::new(v.source()));
        let dir = vol.entry(d).unwrap().unwrap();
        let ix = vol.i30(&dir).unwrap();
        // A node below the root with several children, duplicated into one of them.
        let top = ix.root.iter().find_map(|e| e.subnode).unwrap();
        let mut root = vol.read_index_block(&ix, top).unwrap();
        let subs: Vec<usize> = root.iter().enumerate().filter_map(|(i, e)| e.subnode.map(|_| i)).collect();
        assert!(subs.len() >= 2);
        root[subs[1]].subnode = root[subs[0]].subnode;
        assert!(vol.read_levels(&ix, &root).unwrap().is_empty());
        let mut read = vol.read_levels(&ix, &root).unwrap();
        let mut got = 0;
        let e = vol
            .walk_node(&ix, root, 0, &mut HashSet::new(), &mut read, &mut |_| {
                got += 1;
                ControlFlow::Continue(())
            })
            .unwrap_err();
        assert!(e.to_string().contains("referenced twice"), "{e}");
        assert_eq!(got, 0, "the duplicate is met before the first subtree is walked");

        let all = vol.dir_entries(&dir).unwrap().len();
        for limits in [Limits::default().with_max_tree_nodes(8), Limits::default().with_max_tree_depth(1)] {
            let small = NtfsVolume::open_with(Arc::new(v.source()), limits, Diagnostics::new()).unwrap();
            let dir = small.entry(d).unwrap().unwrap();
            let ix = small.i30(&dir).unwrap();
            let read = small.read_levels(&ix, &ix.root).unwrap();
            assert!(read.len() <= 8);
            let mut got = 0;
            let e = small
                .walk_dir(&dir, &mut |_| {
                    got += 1;
                    ControlFlow::Continue(())
                })
                .unwrap_err();
            assert!(e.to_string().contains("ntfs index tree nodes or depth"), "{e}");
            assert!(got < all);
        }
    }

    /// An index block that does not parse: a lookup through it scans the blocks in use (and
    /// says so), finding every name but those of the block itself.
    #[test]
    fn a_damaged_index_falls_back_to_a_scan() {
        let (v, d) = big(1500);
        let sound = open(Arc::new(v.source()));
        let dir = sound.entry(d).unwrap().unwrap();
        let ix = sound.i30(&dir).unwrap();
        let vcn = ix.root.iter().find_map(|e| e.subnode).unwrap();
        let lost: Vec<_> = sound.read_index_block(&ix, vcn).unwrap().into_iter().filter(|e| !e.last).collect();
        let at = sound.index_block_at(&ix, vcn).unwrap() as usize;
        let mut img = v.image.clone();
        img[at..at + 4].copy_from_slice(b"XXXX");
        let vol = open(Arc::new(MemSource::new(img)));
        let dir = vol.entry(d).unwrap().unwrap();
        let mut found = 0;
        for e in sound.dir_entries(&sound.entry(d).unwrap().unwrap()).unwrap() {
            let hit = vol.lookup(&dir, &name_of(&e)).unwrap();
            match hit {
                Some(h) => {
                    assert_eq!(h, e);
                    found += 1;
                }
                None => assert!(lost.contains(&e)),
            }
        }
        assert_eq!(found, 1501 - lost.len());
        assert!(vol.diagnostics().all().iter().any(|d| d.code == DiagCode::Fallback));
        assert!(vol.lookup(&dir, &"nope".encode_utf16().collect::<Vec<_>>()).unwrap().is_none());
        // A listing fails at the block.
        assert_eq!(vol.dir_entries(&dir).unwrap_err().kind(), fs_inspect_core::ErrorKind::Corrupt);
    }
}
