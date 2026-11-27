//! The user files of an NTFS volume: every MFT record from the first user one, classified, and
//! the data mapping of each non-resident `$DATA` stream.

use crate::format::attr::{AttrType, Frn, attr_flags};
use crate::format::entry::{FileEntry, StreamBody};
use crate::format::fs::NtfsFs;
use crate::format::record::ParsedRecord;
use crate::format::runlist::Run;
use crate::format::volume::{ChunkFn, MftChunk, NtfsVolume, system_records};
use fs_inspect_core::Scope;
use fs_inspect_core::files::zero_from;
use fs_inspect_core::windows::is_paging_io_file;
use fs_inspect_core::{FileExtent, FileInfo, FileMap, Filesystem, Result};
use smallvec::SmallVec;
use std::collections::{HashMap, HashSet};

/// `FILE_ATTRIBUTE_ENCRYPTED` in `$STANDARD_INFORMATION`.
const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x4000;

/// One MFT record from the first user one, as [`NtfsFs::walk_user_records`] finds it.
#[derive(Debug)]
#[cfg_attr(not(any(test, feature = "change")), allow(dead_code, reason = "read by change tracking (`track`)"))]
pub(crate) enum UserRecord {
    /// A file (not a directory) with non-resident data, outside `$Extend`.
    File(Box<FileEntry>),
    /// A file with non-resident data under `$Extend` (file system metadata, not a file to
    /// report: `$RmMetadata`'s repair and transaction logs, ...).
    Extend(Box<FileEntry>),
    /// The record could not be read.
    Unreadable(u64),
    /// The record is damaged (torn, attribute list gap, bad runlist) or has no
    /// `$STANDARD_INFORMATION`.
    Damaged(u64),
    /// A parent directory chain does not resolve to the root (known when the walk met it).
    Orphan(u64),
    /// A file reported as [`File`](Self::File) whose parent chain, checked after the walk,
    /// does not resolve to the root. It lies outside the `$Extend` tree, so its own record
    /// says whether its data changed.
    Unrooted(u64),
}

/// Where [`NtfsFs::walk_user_records`] hands the user records.
pub(crate) trait UserRecords {
    /// What stands for a file until it is known where it lives: as small as the file's
    /// output allows (the walk may hold tens of thousands).
    type Held;
    /// A record, classified.
    fn record(&mut self, r: UserRecord) -> Result<()>;
    /// File `e`, whose parent chain goes through a directory the walk has not passed yet.
    fn hold(&mut self, e: &FileEntry) -> Self::Held;
    /// A held file, after the walk: `Some(true)` under `$Extend`, `Some(false)` outside it,
    /// `None` when a parent chain does not resolve to the root.
    fn resolved(&mut self, h: Self::Held, under: Option<bool>) -> Result<()>;
}

/// The data of one non-resident `$DATA` stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamData {
    pub extents: Vec<FileExtent>,
    /// Valid data length (bytes before it hold data; after it read as zeros).
    pub vdl: u64,
    /// Compressed or encrypted: clusters do not map one to one to file bytes.
    pub no_narrow: bool,
    /// Logical ranges past the valid data length that read as zeros (clusters wholly past it;
    /// none for compressed, encrypted or paging-file streams). Not gated by the log state.
    pub zero: Vec<fs_inspect_core::ByteRange>,
}

impl NtfsFs {
    /// Every user record (`skip`: one to leave out, the USN journal's), classified, to `out`;
    /// directories and records without non-resident data are left out. Errors of `out` stop
    /// the walk. The MFT is read once ([`NtfsVolume::walk_entries`]: a file whose extension
    /// records lie ahead comes when the walk has passed them), in chunks, each one handed to
    /// `seen` (the system records' too) before its records are walked.
    ///
    /// Whether a file lives under `$Extend` comes from the directories of the `$Extend` tree,
    /// listed from their indexes first ([`extend_dirs`]): a file is metadata when one of its
    /// names lies in one of them, so it is classified when the walk meets it. Whether its
    /// parent chain reaches the root is checked after the walk (most directories lie after
    /// many of their files in the MFT); a file whose chain does not is reported
    /// [`Unrooted`](UserRecord::Unrooted). When the `$Extend` tree cannot be listed (damage),
    /// a file whose chain goes through a directory not walked past yet is
    /// [held](UserRecords::hold) and [resolved](UserRecords::resolved) after the walk, from
    /// the directories it saw; past [`MAX_HELD`] of them, the directory is read.
    pub(crate) fn walk_user_records<R: UserRecords>(
        &self,
        skip: Option<u64>,
        seen: Option<&mut ChunkFn<'_>>,
        out: &mut R,
    ) -> Result<()> {
        let extend = extend_dirs(self.volume())?;
        self.walk_with(extend.as_ref(), skip, seen, out)
    }

    /// [`walk_user_records`](Self::walk_user_records) with the directories of the `$Extend`
    /// tree, or without them (`None`: files wait for their parents).
    fn walk_with<R: UserRecords>(
        &self,
        extend: Option<&HashSet<Frn>>,
        skip: Option<u64>,
        mut seen: Option<&mut ChunkFn<'_>>,
        out: &mut R,
    ) -> Result<()> {
        let vol = self.volume();
        let mut parents = ParentWalker::new(vol.limits().max_path_depth);
        let mut held: Vec<(SmallVec<[Frn; 2]>, R::Held)> = Vec::new();
        // Files classified at once whose chain goes through a directory not walked past yet:
        // (record, that parent).
        let mut unchecked: Vec<(u64, Frn)> = Vec::new();
        // `seen` comes before the chunk's records are walked: the space dater hashes the raw
        // chunk, and after the walk it is slower (a 1M-record incremental scan by 15-25%); it
        // borrows the records, so it copies the few runlists it keeps (indexes, system streams).
        let mut no_seen = |_: u64, _: MftChunk<'_>, _: &[Option<ParsedRecord>]| {};
        let seen: &mut ChunkFn<'_> = match seen.as_mut() {
            Some(s) => s,
            None => &mut no_seen,
        };
        vol.walk_entries(system_records::FIRST_USER, seen, &mut |n, e| {
            let e = match e {
                Ok(Some(e)) => e,
                Ok(None) => return Ok(()),
                Err(e) if e.scope() != Scope::Unit => return Err(e),
                Err(_) => return out.record(UserRecord::Unreadable(n)),
            };
            if e.is_dir() {
                parents.note_dir(&e);
                return Ok(());
            }
            if Some(n) == skip || !e.streams.iter().any(|s| s.kind == AttrType::DATA && !s.is_resident()) {
                return Ok(());
            }
            if e.has_problem() || e.std_info.is_none() {
                return out.record(UserRecord::Damaged(n));
            }
            let of: SmallVec<[Frn; 2]> = e.names.iter().map(|n| n.parent).collect();
            let under = match extend {
                _ if of.is_empty() => None,
                Some(dirs) if of.iter().any(|p| dirs.contains(p)) => Some(true),
                Some(_) => {
                    for &p in &of {
                        match parents.under_extend(&[p], Unseen::Defer)? {
                            Some(Some(_)) => {}
                            Some(None) => return out.record(UserRecord::Orphan(e.frn.record)),
                            None => unchecked.push((e.frn.record, p)),
                        }
                    }
                    Some(false)
                }
                None => match parents.under_extend(&of, Unseen::Defer)? {
                    Some(under) => under,
                    None if held.len() < MAX_HELD => {
                        held.push((of, out.hold(&e)));
                        return Ok(());
                    }
                    None => parents.under_extend(&of, Unseen::Read(vol))?.unwrap_or(None),
                },
            };
            out.record(match under {
                Some(false) => UserRecord::File(Box::new(e)),
                Some(true) => UserRecord::Extend(Box::new(e)),
                None => UserRecord::Orphan(e.frn.record),
            })
        })?;
        let mut last = None;
        for (record, p) in unchecked {
            if last != Some(record) && parents.under_extend(&[p], Unseen::Unresolved)?.unwrap_or(None).is_none() {
                last = Some(record);
                out.record(UserRecord::Unrooted(record))?;
            }
        }
        for (of, h) in held {
            let under = parents.under_extend(&of, Unseen::Unresolved)?.unwrap_or(None);
            out.resolved(h, under)?;
        }
        Ok(())
    }

    /// Where the data of a non-resident stream of `e` lies and how much of it is valid.
    pub(crate) fn stream_data(
        &self,
        e: &FileEntry,
        flags: u16,
        size: u64,
        initialized: u64,
        compression_unit: u8,
        runs: &[Run],
    ) -> StreamData {
        let cs = u64::from(self.volume().geometry().cluster_size);
        let encrypted_file = e.std_info.as_ref().is_some_and(|si| si.attributes & FILE_ATTRIBUTE_ENCRYPTED != 0);
        let compressed = flags & attr_flags::COMPRESSED != 0 && compression_unit != 0;
        let encrypted = flags & attr_flags::ENCRYPTED != 0 || encrypted_file;
        let no_narrow = compressed || encrypted;
        let vdl = initialized.min(size);
        let extents: Vec<FileExtent> = runs
            .iter()
            .map(|r| match r.lcn() {
                Some(l) => FileExtent::mapped(r.vcn() * cs, l * cs, r.len() * cs),
                None => FileExtent::hole(r.vcn() * cs, r.len() * cs),
            })
            .collect();
        // Clusters wholly past the valid data length read as zeros. Not for compressed or
        // encrypted streams (their clusters do not map one to one to file bytes), nor paging
        // files.
        let zero =
            if !is_paging_file(e) && !no_narrow { zero_from(&extents, vdl.div_ceil(cs) * cs) } else { Vec::new() };
        StreamData { extents, vdl, no_narrow, zero }
    }
}

impl FileMap for NtfsFs {
    /// Each non-resident `$DATA` stream of each user file (key: the record number, with the
    /// stream's position in the record above bit 48). The ranges past the valid data length
    /// read as zeros, settled only when the volume is clean: its `$LogFile` says so, or this
    /// instance reads it over the log's replay.
    fn for_each(&self, f: &mut dyn FnMut(FileInfo) -> Result<()>) -> Result<()> {
        let mut out = FileInfos { fs: self, clean: self.consistency().is_clean(), f };
        self.walk_user_records(None, None, &mut out)
    }
}

/// [`FileMap::for_each`]'s walk: the streams of the files outside `$Extend`.
struct FileInfos<'a> {
    fs: &'a NtfsFs,
    clean: bool,
    f: &'a mut dyn FnMut(FileInfo) -> Result<()>,
}

impl FileInfos<'_> {
    fn infos(&self, e: &FileEntry) -> Vec<FileInfo> {
        e.streams
            .iter()
            .filter(|s| s.kind == AttrType::DATA)
            .filter_map(|s| match &s.body {
                StreamBody::NonResident { size, initialized, compression_unit, runs, .. } => {
                    Some(self.fs.stream_data(e, s.flags, *size, *initialized, *compression_unit, runs))
                }
                StreamBody::Resident { .. } => None,
            })
            .enumerate()
            .map(|(i, d)| {
                let key = e.frn.record | ((i as u64) << 48);
                FileInfo { key, extents: d.extents, zero_as_read: d.zero, settled: self.clean }
            })
            .collect()
    }
}

impl UserRecords for FileInfos<'_> {
    type Held = Vec<FileInfo>;
    fn record(&mut self, r: UserRecord) -> Result<()> {
        let UserRecord::File(e) = r else { return Ok(()) };
        self.infos(&e).into_iter().try_for_each(|i| (self.f)(i))
    }
    fn hold(&mut self, e: &FileEntry) -> Vec<FileInfo> {
        self.infos(e)
    }
    fn resolved(&mut self, h: Vec<FileInfo>, under: Option<bool>) -> Result<()> {
        if under != Some(false) {
            return Ok(());
        }
        h.into_iter().try_for_each(|i| (self.f)(i))
    }
}

/// Files the memory manager or the boot loader write with paging I/O, in the root directory.
pub(crate) fn is_paging_file(e: &FileEntry) -> bool {
    e.names.iter().any(|n| n.parent.record == system_records::ROOT && is_paging_io_file(&n.name.to_string_lossy()))
}

/// Most files a walk over the records holds back until it has seen every directory.
/// Most files [`NtfsFs::walk_user_records`] holds for a parent the walk has not passed, when
/// the `$Extend` tree cannot be listed. A quarter of the files of a system volume can wait
/// (a few hundred bytes each); past this, their directories are read.
const MAX_HELD: usize = 1 << 14;

/// Most directories in the `$Extend` tree (a handful on Windows: `$RmMetadata`, `$Txf`, ...).
const MAX_EXTEND_DIRS: usize = 256;

/// `$FILE_NAME` attribute bit of a directory (`FILE_ATTRIBUTE_DUP_FILE_NAME_INDEX_PRESENT`).
pub(crate) const NAME_OF_DIRECTORY: u32 = 0x1000_0000;

/// The directories of the `$Extend` tree, `$Extend` included, from their indexes (a child is a
/// directory by its `$FILE_NAME` in the index; its record confirms it). `None` when the tree
/// cannot be listed (a damaged or missing record or index, or more than [`MAX_EXTEND_DIRS`]);
/// a source failure or a cancel is an error.
pub(crate) fn extend_dirs(vol: &NtfsVolume) -> Result<Option<HashSet<Frn>>> {
    let listed = (|| -> Result<Option<HashSet<Frn>>> {
        let Some(root) = vol.entry(system_records::EXTEND)?.filter(FileEntry::is_dir) else { return Ok(None) };
        let mut dirs = HashSet::from([root.frn]);
        let mut todo = vec![root];
        while let Some(dir) = todo.pop() {
            for c in vol.dir_entries(&dir)? {
                let Some(name) = c.file_name() else { return Ok(None) };
                if name.attributes & NAME_OF_DIRECTORY == 0 || dirs.contains(&c.frn) {
                    continue;
                }
                let Some(d) = vol.entry_frn(c.frn)?.filter(FileEntry::is_dir) else { return Ok(None) };
                if dirs.len() >= MAX_EXTEND_DIRS {
                    return Ok(None);
                }
                dirs.insert(d.frn);
                todo.push(d);
            }
        }
        Ok(Some(dirs))
    })();
    match listed {
        Err(e) if e.scope() == Scope::Unit => Ok(None),
        r => r,
    }
}

/// What [`ParentWalker`] does with a directory a walk has not seen.
#[derive(Clone, Copy)]
pub(crate) enum Unseen<'a> {
    /// The answer waits for the walk to see it.
    Defer,
    /// Read it.
    Read(&'a NtfsVolume),
    /// No such directory: the walk saw every one.
    Unresolved,
}

/// Resolves whether a file lives in the `$Extend` tree (file system metadata), with a cache of
/// directories.
pub(crate) struct ParentWalker {
    /// Most directories in a chain.
    max_depth: usize,
    /// Directory record -> under `$Extend` (or `$Extend` itself); `None`: unresolvable.
    dirs: HashMap<u64, Option<bool>>,
    /// Directory record -> its sequence number and the parent of its first name (`None`: no
    /// name), as a walk over the records saw it: a chain through it needs no read.
    seen: HashMap<u64, (u16, Option<Frn>)>,
}

impl ParentWalker {
    pub(crate) fn new(max_depth: usize) -> Self {
        ParentWalker { max_depth, dirs: HashMap::new(), seen: HashMap::new() }
    }

    /// Note directory `e`, met by a walk over the records.
    pub(crate) fn note_dir(&mut self, e: &FileEntry) {
        self.seen.insert(e.frn.record, (e.frn.seq, e.names.first().map(|n| n.parent)));
    }

    /// `Some(true)` when any of the `parents` of a file's names is under `$Extend`, `None`
    /// when a parent chain does not resolve to the root (or the file has no name); the outer
    /// `None` when it goes through a directory not seen and `unseen` is [`Unseen::Defer`]. A
    /// directory that cannot be read (damage) does not resolve; a source failure or a cancel is
    /// an error.
    pub(crate) fn under_extend(&mut self, parents: &[Frn], unseen: Unseen<'_>) -> Result<Option<Option<bool>>> {
        if parents.is_empty() {
            return Ok(Some(None));
        }
        let mut any = false;
        for &p in parents {
            match self.dir(p, unseen)? {
                Some(Some(u)) => any |= u,
                Some(None) => return Ok(Some(None)),
                None => return Ok(None),
            }
        }
        Ok(Some(Some(any)))
    }

    fn dir(&mut self, start: Frn, unseen: Unseen<'_>) -> Result<Option<Option<bool>>> {
        let mut chain: Vec<u64> = Vec::new();
        let mut cur = start;
        let result = loop {
            if cur.record == system_records::EXTEND {
                break Some(true);
            }
            if cur.record == system_records::ROOT {
                break Some(false);
            }
            if let Some(r) = self.dirs.get(&cur.record) {
                break *r;
            }
            if chain.len() >= self.max_depth || chain.contains(&cur.record) {
                break None;
            }
            chain.push(cur.record);
            if let Some(&(seq, parent)) = self.seen.get(&cur.record) {
                match parent {
                    Some(p) if seq == cur.seq => cur = p,
                    _ => break None,
                }
                continue;
            }
            match unseen {
                Unseen::Defer => return Ok(None),
                Unseen::Unresolved => break None,
                // A parent past the MFT is damage, as one that cannot be read.
                Unseen::Read(vol) if cur.record >= vol.record_count() => break None,
                Unseen::Read(vol) => match vol.entry(cur.record) {
                    Ok(Some(d)) if d.is_dir() && d.frn.seq == cur.seq => match d.names.first() {
                        Some(n) => cur = n.parent,
                        None => break None,
                    },
                    Ok(_) => break None,
                    Err(e) if e.scope() == Scope::Unit => break None,
                    Err(e) => return Err(e),
                },
            }
        };
        for r in chain {
            self.dirs.insert(r, result);
        }
        Ok(Some(result))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::synth::{Placement, SyntheticVolume, VolumeSpec};
    use fs_inspect_core::DriverContext;
    use fs_inspect_io::test_util::CountingSource;
    use std::sync::Arc;

    /// The records of the files outside `$Extend` a walk finds; any other record fails.
    #[derive(Default)]
    struct Files(Vec<u64>);

    impl UserRecords for Files {
        type Held = u64;
        fn record(&mut self, r: UserRecord) -> Result<()> {
            let UserRecord::File(e) = r else { panic!("{r:?}") };
            self.0.push(e.frn.record);
            Ok(())
        }
        fn hold(&mut self, e: &FileEntry) -> u64 {
            e.frn.record
        }
        fn resolved(&mut self, h: u64, under: Option<bool>) -> Result<()> {
            assert_eq!(under, Some(false), "record {h}");
            self.0.push(h);
            Ok(())
        }
    }

    /// A walk over files in nested directories reads the MFT in batches and resolves their
    /// parents from the directories it walked past, with no read of its own for them.
    #[test]
    fn a_walk_reads_no_parent_directory_it_walked_past() {
        let mut synth = SyntheticVolume::format(VolumeSpec { clusters: 16384, ..Default::default() });
        for d in 0..20 {
            let top = synth.create_dir(system_records::ROOT, &format!("d{d}"));
            let sub = synth.create_dir(top, "sub");
            for f in 0..5 {
                synth.create_file(sub, &format!("f{f}"), 3000, d * 5 + f, Placement::FirstFit);
            }
        }
        let counter = CountingSource::new(Arc::new(synth.source()));
        let fs = NtfsFs::open(counter.clone(), &DriverContext::default()).unwrap();
        let reads = || counter.stats().reads;
        let before = reads();
        let mut files = Files::default();
        fs.walk_user_records(None, None, &mut files).unwrap();
        assert_eq!(files.0.len(), 100);
        // One read per run of $MFT the walk crosses (it grows in pieces).
        let walk = reads() - before;
        let runs = fs.volume().mft().runs.len() as u64;
        assert!(walk <= runs, "{walk} reads, {runs} runs");
    }

    /// Files linked into directories after them in the MFT are resolved once the walk has seen
    /// those: no read for them either.
    #[test]
    fn parents_after_their_files_are_resolved_without_reads() {
        let mut synth = SyntheticVolume::format(VolumeSpec { clusters: 16384, ..Default::default() });
        let files: Vec<u64> = (0..20)
            .map(|i| synth.create_file(system_records::ROOT, &format!("f{i}"), 3000, i, Placement::FirstFit))
            .collect();
        for (i, &f) in files.iter().enumerate() {
            let d = synth.create_dir(system_records::ROOT, &format!("d{i}"));
            assert!(d > f);
            synth.add_link(f, d, "link");
        }
        let counter = CountingSource::new(Arc::new(synth.source()));
        let fs = NtfsFs::open(counter.clone(), &DriverContext::default()).unwrap();
        let before = counter.stats().reads;
        let mut found = Files::default();
        fs.walk_user_records(None, None, &mut found).unwrap();
        let mut found = found.0;
        found.sort_unstable();
        assert_eq!(found, files);
        let walk = counter.stats().reads - before;
        let runs = fs.volume().mft().runs.len() as u64;
        assert!(walk <= runs, "{walk} reads, {runs} runs");
    }

    /// Where held files land: outside `$Extend`, under it, or nowhere (a parent deleted).
    #[derive(Default)]
    struct Outcomes {
        file: Vec<u64>,
        extend: Vec<u64>,
        orphan: Vec<u64>,
        unrooted: Vec<u64>,
        held: usize,
    }

    impl UserRecords for Outcomes {
        type Held = u64;
        fn record(&mut self, r: UserRecord) -> Result<()> {
            match r {
                UserRecord::File(e) => self.file.push(e.frn.record),
                UserRecord::Extend(e) => self.extend.push(e.frn.record),
                UserRecord::Orphan(n) => self.orphan.push(n),
                UserRecord::Unrooted(n) => self.unrooted.push(n),
                r => panic!("{r:?}"),
            }
            Ok(())
        }
        fn hold(&mut self, e: &FileEntry) -> u64 {
            self.held += 1;
            e.frn.record
        }
        fn resolved(&mut self, h: u64, under: Option<bool>) -> Result<()> {
            match under {
                Some(false) => self.file.push(h),
                Some(true) => self.extend.push(h),
                None => self.orphan.push(h),
            }
            Ok(())
        }
    }

    /// Files linked, after the files, into a directory under `$Extend`, into a later
    /// directory, and into a deleted one; the walk's reads after opening.
    fn linked_late() -> (SyntheticVolume, [u64; 3]) {
        let mut synth = SyntheticVolume::format(VolumeSpec { clusters: 16384, ..Default::default() });
        let plain = synth.create_file(system_records::ROOT, "plain", 3000, 1, Placement::FirstFit);
        let meta = synth.create_file(system_records::ROOT, "meta", 3000, 2, Placement::FirstFit);
        let lost = synth.create_file(system_records::ROOT, "lost", 3000, 3, Placement::FirstFit);
        let later = synth.create_dir(system_records::ROOT, "later");
        let under = synth.create_dir(system_records::EXTEND, "under");
        let gone = synth.create_dir(system_records::ROOT, "gone");
        synth.add_link(plain, later, "link");
        synth.add_link(meta, under, "link");
        synth.delete(gone);
        synth.add_link(lost, gone, "link");
        (synth, [plain, meta, lost])
    }

    /// With the `$Extend` tree listed, every file is classified when the walk meets it (none
    /// held, no read): one in a directory under `$Extend` is metadata, one whose chain does
    /// not resolve after the walk is reported as a file and unrooted.
    #[test]
    fn files_are_classified_by_the_extend_tree() {
        let (synth, [plain, meta, lost]) = linked_late();
        let counter = CountingSource::new(Arc::new(synth.source()));
        let fs = NtfsFs::open(counter.clone(), &DriverContext::default()).unwrap();
        let extend = extend_dirs(fs.volume()).unwrap().expect("listed");
        assert_eq!(extend.len(), 2, "$Extend and under");
        let before = counter.stats().reads;
        let mut out = Outcomes::default();
        fs.walk_with(Some(&extend), None, None, &mut out).unwrap();
        out.file.sort_unstable();
        assert_eq!(
            (out.file, out.extend, out.orphan, out.unrooted, out.held),
            (vec![plain, lost], vec![meta], vec![], vec![lost], 0)
        );
        let walk = counter.stats().reads - before;
        assert!(walk <= fs.volume().mft().runs.len() as u64, "{walk} reads");
    }

    /// Without the `$Extend` tree, files wait for their parents and resolve after the walk to
    /// where they put them: metadata, a file, or an orphan.
    #[test]
    fn held_files_resolve_under_extend_and_as_orphans() {
        let (synth, [plain, meta, lost]) = linked_late();
        let counter = CountingSource::new(Arc::new(synth.source()));
        let fs = NtfsFs::open(counter.clone(), &DriverContext::default()).unwrap();
        let before = counter.stats().reads;
        let mut out = Outcomes::default();
        fs.walk_with(None, None, None, &mut out).unwrap();
        assert_eq!(
            (out.file, out.extend, out.orphan, out.unrooted, out.held),
            (vec![plain], vec![meta], vec![lost], vec![], 3)
        );
        let walk = counter.stats().reads - before;
        assert!(walk <= fs.volume().mft().runs.len() as u64, "{walk} reads");
    }

    /// A parent chain read from the volume (directories a walk has not seen): to the root, to
    /// `$Extend`, or nowhere (a deleted directory, a stale sequence number, a file, a record
    /// past the MFT, a chain deeper than the limit); not read when deferred or unresolved.
    #[test]
    fn parent_chains_read_from_the_volume() {
        let mut synth = SyntheticVolume::format(VolumeSpec { clusters: 16384, ..Default::default() });
        let a = synth.create_dir(system_records::ROOT, "a");
        let b = synth.create_dir(a, "b");
        let under = synth.create_dir(system_records::EXTEND, "under");
        let file = synth.create_file(a, "f", 3000, 1, Placement::FirstFit);
        let gone = synth.create_dir(system_records::ROOT, "gone");
        let frn = |s: &SyntheticVolume, r: u64| s.file(r).frn();
        let (fb, funder, ffile, fgone) = (frn(&synth, b), frn(&synth, under), frn(&synth, file), frn(&synth, gone));
        synth.delete(gone);
        let fs = NtfsFs::open(Arc::new(synth.source()), &DriverContext::default()).unwrap();
        let vol = fs.volume();
        let read = Unseen::Read(vol);
        let mut w = ParentWalker::new(16);
        assert_eq!(w.under_extend(&[], read).unwrap(), Some(None));
        assert_eq!(w.under_extend(&[fb], Unseen::Defer).unwrap(), None);
        assert_eq!(w.under_extend(&[fb], read).unwrap(), Some(Some(false)));
        assert_eq!(w.under_extend(&[fb, funder], read).unwrap(), Some(Some(true)));
        // Cached: answered without the volume.
        assert_eq!(w.under_extend(&[funder], Unseen::Unresolved).unwrap(), Some(Some(true)));
        for p in [fgone, Frn::new(b, fb.seq.wrapping_add(1)), ffile, Frn::new(1 << 40, 1)] {
            assert_eq!(ParentWalker::new(16).under_extend(&[p], read).unwrap(), Some(None), "{p:?}");
        }
        assert_eq!(ParentWalker::new(16).under_extend(&[fb], Unseen::Unresolved).unwrap(), Some(None));
        assert_eq!(ParentWalker::new(1).under_extend(&[fb], read).unwrap(), Some(None));
        // A directory a walk saw with another sequence number, or without a name.
        let mut w = ParentWalker::new(16);
        w.seen.insert(b, (fb.seq.wrapping_add(1), Some(frn(&synth, a))));
        assert_eq!(w.under_extend(&[fb], read).unwrap(), Some(None));
        let mut w = ParentWalker::new(16);
        w.seen.insert(b, (fb.seq, None));
        assert_eq!(w.under_extend(&[fb], read).unwrap(), Some(None));
    }
}
