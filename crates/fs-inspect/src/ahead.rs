//! Reading a folder's small files ahead together, once a client opens one of them
//! ([`FsHandle::read_ahead`]).

use crate::CancelToken;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fs_inspect_core::memo::Lru;
use fs_inspect_core::ns::NodeId;

use crate::Result;
use crate::fs::{FsHandle, Listing};

/// How [`ReadAhead`] reads a folder's small files ahead.
///
/// The defaults were measured on a Windows `System32` folder (4316 files). A smaller
/// `file_max` reads more often; a larger one reads files whole that the client does not
/// want. A larger `batch_bytes` saves few reads and takes longer. `kept_bytes` matters only
/// when a client opens a folder out of volume order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReadAheadOptions {
    /// The largest file read ahead, in bytes (default 256 KiB).
    pub file_max: u64,
    /// Files read together at most (default 256).
    pub batch_files: usize,
    /// Bytes read together at most (default 8 MiB).
    pub batch_bytes: u64,
    /// Bytes of files read ahead kept until opened (default 64 MiB), within the process's
    /// [cache budget](crate::set_cache_budget); past it the least recently read go first.
    pub kept_bytes: u64,
}

fs_inspect_core::with_setters! { ReadAheadOptions {
    file_max / with_file_max: u64,
    batch_files / with_batch_files: usize,
    batch_bytes / with_batch_bytes: u64,
    kept_bytes / with_kept_bytes: u64,
} }

impl Default for ReadAheadOptions {
    fn default() -> Self {
        ReadAheadOptions { file_max: 256 << 10, batch_files: 256, batch_bytes: 8 << 20, kept_bytes: 64 << 20 }
    }
}

/// An entry of the folder a file is opened in, in its listing's order (the order the
/// entries are on the volume): what [`ReadAhead::read`] reads ahead, as a [`Listing`]
/// gives them ([`Listing::siblings`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Sibling {
    pub node: NodeId,
    /// The size of its main stream.
    pub size: u64,
    /// Whether it is a regular file whose content is there to read (not a folder, a link,
    /// a file kept only in the cloud).
    pub readable: bool,
}

impl Sibling {
    pub(crate) fn new(node: NodeId, size: u64, readable: bool) -> Sibling {
        Sibling { node, size, readable }
    }
}

fs_inspect_io::tagged_enum! {
    /// What [`ReadAhead::try_open`] says of a file being opened, without reading.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Answer ("read-ahead answer") kind AnswerKind {
        /// It was read ahead: its content. The read-ahead drops its own copy.
        Kept(Arc<[u8]>) = 1 => "kept",
        /// It is not read ahead: the caller reads it alone.
        Alone = 2 => "alone",
        /// It is read with the next batch of its folder's small files: [`ReadAhead::read`] reads
        /// it (and blocks on the volume's reads); call it after this answer only.
        Batch = 3 => "batch",
    }
}

/// What a [`ReadAhead`] did so far.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReadAheadStats {
    /// Openings that found their file kept, read ahead by an earlier one.
    pub hits: u64,
    /// The other openings: read with a batch, or not read ahead.
    pub misses: u64,
    /// Batches read.
    pub batches: u64,
    /// Files read in batches (each opened one included).
    pub files_read: u64,
    /// Bytes of them.
    pub bytes_read: u64,
    /// Bytes read ahead and dropped (past [`kept_bytes`](ReadAheadOptions::kept_bytes) or the
    /// cache budget, or by [`clear`](ReadAhead::clear)) before
    /// their file was opened.
    pub evicted_unread_bytes: u64,
    /// Files read ahead kept now, until opened.
    pub kept_files: u64,
    /// Bytes of them.
    pub kept_bytes: u64,
}

/// How the files of one folder are being opened.
#[derive(Debug)]
struct Opening {
    /// The place in the listing of the first file opened (read alone).
    first: usize,
    /// Where the next batch starts: what is before it was read.
    next: usize,
}

/// What opening a file comes to without reading.
enum Settled {
    Kept(Arc<[u8]>),
    Alone,
    /// Read with a batch of the folder being opened so.
    Batch(Arc<Mutex<Opening>>),
}

/// Folders' openings remembered at most (each a few dozen bytes).
const OPENINGS: usize = 1 << 14;

/// A file system's small files read ahead of their opening ([`FsHandle::read_ahead`]).
///
/// A client copying a folder (`cp -r`, robocopy, Finder) opens its files one after another,
/// each costing a record read and a data read, in an order of its own (FUSE and NFS list by
/// file id, ProjFS by name). The first file of a folder opened is read alone. Once another
/// is, the folder's small files not read yet are read in listing order (the order they are
/// on the volume), [`batch_files`](ReadAheadOptions::batch_files) files and
/// [`batch_bytes`](ReadAheadOptions::batch_bytes) bytes at a time with the one opened, read
/// together (their records in one pass, their data in merged windows), and kept until opened.
/// Each opening not found kept reads the next batch, so a whole folder is read once in volume
/// order whatever order the client asks in. A batch reads ahead only into the room left of
/// [`kept_bytes`](ReadAheadOptions::kept_bytes): a client opening a folder out of volume order
/// gets its file read alone once that is full, rather than files read ahead and not opened yet
/// pushed out to be read again.
///
/// A folder's batches are read one at a time: an opening meanwhile waits, and then finds its
/// file kept, so no file is read twice. Cheap to share between threads (`Send + Sync`). A
/// batch reads under both the read-ahead's token (given to [`FsHandle::read_ahead`]) and the
/// token of the call reading: either one's cancel stops it.
#[derive(Debug)]
pub struct ReadAhead {
    fs: FsHandle,
    opts: ReadAheadOptions,
    kept: Mutex<Lru<NodeId, Arc<[u8]>>>,
    openings: Mutex<Lru<NodeId, Arc<Mutex<Opening>>>>,
    hits: AtomicU64,
    misses: AtomicU64,
    batches: AtomicU64,
    files_read: AtomicU64,
    bytes_read: AtomicU64,
    /// Bytes kept and then taken by their opening.
    taken: AtomicU64,
    /// Its token (the handle's and the one given to [`FsHandle::read_ahead`]): a batch reads
    /// under it and the token of the call reading.
    call: Option<fs_inspect_io::CancelToken>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl FsHandle {
    /// Read this file system's small files ahead of their opening, as `opts` say.
    pub fn read_ahead(&self, opts: &ReadAheadOptions, cancel: Option<&CancelToken>) -> ReadAhead {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || {
            let kept = usize::try_from(opts.kept_bytes).unwrap_or(usize::MAX);
            ReadAhead {
                fs: self.clone(),
                opts: opts.clone(),
                kept: Mutex::new(Lru::new(kept)),
                openings: Mutex::new(Lru::new(OPENINGS * size_of::<Opening>())),
                hits: AtomicU64::new(0),
                misses: AtomicU64::new(0),
                batches: AtomicU64::new(0),
                files_read: AtomicU64::new(0),
                bytes_read: AtomicU64::new(0),
                taken: AtomicU64::new(0),
                call: fs_inspect_io::cancel::call_token(),
            }
        })
    }
}

impl ReadAhead {
    /// The content of entry `index` of `listing`, a file being opened.
    ///
    /// A file already read ahead is returned at once. A small file that is not the first one
    /// opened in its folder is read with the next batch of the folder's small files
    /// ([`Listing::siblings`]); the others in the batch are kept for their opening. Otherwise,
    /// or if the batch could not read it, the result is `None` and the caller reads the file
    /// alone (and gets the error, if any). Pass the same listing of a folder (or one with the
    /// same entries in the same order) for every file opened in it.
    ///
    /// Errors: an `index` out of the listing
    /// ([`InvalidArgument`](crate::ErrorKind::InvalidArgument)); a batch cancelled by the
    /// read-ahead's token or `cancel` ([`Cancelled`](crate::ErrorKind::Cancelled)), which
    /// leaves the folder's next batch to start where this one did.
    pub fn read(&self, listing: &Listing, index: u64, cancel: Option<&CancelToken>) -> Result<Option<Arc<[u8]>>> {
        let index = usize::try_from(index).unwrap_or(usize::MAX);
        let (dir, siblings) = (listing.dir(), &**listing.siblings());
        let me = Self::sibling(siblings, index)?;
        let (got, hit) = match self.settle(dir, index, me) {
            Settled::Kept(data) => (Some(data), true),
            Settled::Alone => (None, false),
            Settled::Batch(opening) => fs_inspect_io::cancel::with_handle(self.call.as_ref(), cancel, || {
                self.batch(&opening, siblings, index, me)
            })?,
        };
        let counter = if hit { &self.hits } else { &self.misses };
        counter.fetch_add(1, Ordering::Relaxed);
        Ok(got)
    }

    /// What [`read`](Self::read) would do with entry `index` of `listing`, decided without
    /// reading. [`Answer::Kept`] hands over the content read ahead. [`Answer::Alone`] means the
    /// caller reads the file itself. Only after [`Answer::Batch`] does the caller call `read`,
    /// which reads the file with the next batch.
    ///
    /// A caller that must not block (an async runtime's thread) calls this first and moves
    /// only `Batch` to a thread that may block. [`stats`](Self::stats) counts this call as it
    /// counts `read`; a `Batch` is counted by the `read` that follows.
    ///
    /// Errors: as [`read`](Self::read).
    pub fn try_open(&self, listing: &Listing, index: u64) -> Result<Answer> {
        let index = usize::try_from(index).unwrap_or(usize::MAX);
        let me = Self::sibling(listing.siblings(), index)?;
        Ok(match self.settle(listing.dir(), index, me) {
            Settled::Kept(data) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Answer::Kept(data)
            }
            Settled::Alone => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                Answer::Alone
            }
            Settled::Batch(_) => Answer::Batch,
        })
    }

    fn sibling(siblings: &[Sibling], index: usize) -> Result<&Sibling> {
        siblings.get(index).ok_or_else(|| {
            crate::Error::invalid_argument(format!(
                "read ahead: index {index} of a folder of {} entries",
                siblings.len()
            ))
        })
    }

    fn take(&self, node: NodeId) -> Option<Arc<[u8]>> {
        let data = lock(&self.kept).remove(&node)?;
        self.taken.fetch_add(data.len() as u64, Ordering::Relaxed);
        Some(data)
    }

    fn small(&self, s: &Sibling) -> bool {
        s.readable && s.size <= self.opts.file_max
    }

    /// What can be settled of opening `me` (`index` in folder `dir`) without reading. The
    /// first opening of a folder is remembered here.
    fn settle(&self, dir: NodeId, index: usize, me: &Sibling) -> Settled {
        if !me.readable {
            return Settled::Alone;
        }
        if let Some(data) = self.take(me.node) {
            return Settled::Kept(data);
        }
        let mut openings = lock(&self.openings);
        let Some(opening) = openings.get(&dir) else {
            let o = Arc::new(Mutex::new(Opening { first: index, next: 0 }));
            openings.insert(dir, o, size_of::<Opening>());
            return Settled::Alone;
        };
        if self.small(me) { Settled::Batch(opening) } else { Settled::Alone }
    }

    /// `me` read with the next batch of its folder (`opening`), the others kept; and whether
    /// it was found kept, read by the batch this one waited for.
    fn batch(
        &self,
        opening: &Mutex<Opening>,
        siblings: &[Sibling],
        index: usize,
        me: &Sibling,
    ) -> Result<(Option<Arc<[u8]>>, bool)> {
        let small = |s: &Sibling| self.small(s);
        let mut walk = lock(opening);
        // Read by the batch this one waited for.
        if let Some(data) = self.take(me.node) {
            return Ok((Some(data), true));
        }
        let mut run = vec![me.node];
        let mut next = walk.next;
        {
            let kept = lock(&self.kept);
            // Read ahead only into the room left to keep: what is read ahead past it would
            // push out files read ahead and not opened yet, to be read again (a client
            // opening a folder out of volume order). The rest is read once room is freed.
            let room = self.opts.kept_bytes.saturating_sub(kept.bytes() as u64);
            let mut ahead = 0;
            let limit = room.min(self.opts.batch_bytes.saturating_sub(me.size));
            while next < siblings.len() && run.len() < self.opts.batch_files {
                let s = &siblings[next];
                if small(s) && next != index && next != walk.first && !kept.contains(&s.node) {
                    if ahead + s.size > limit {
                        break;
                    }
                    ahead += s.size;
                    run.push(s.node);
                }
                next += 1;
            }
        }
        let start = std::mem::replace(&mut walk.next, next);
        let mut out: Vec<Option<Vec<u8>>> = vec![None; run.len()];
        for (i, content) in self.fs.read_many(&run, None) {
            match content {
                // Failed as a whole: the next batch starts where this one did.
                Err(e) if e.is_cancelled() => {
                    walk.next = start;
                    return Err(e);
                }
                // `read_many` hands each index of `run` once.
                content => out[i] = content.ok(),
            }
        }
        self.batches.fetch_add(1, Ordering::Relaxed);
        let mut wanted = None;
        let mut kept = lock(&self.kept);
        for (node, data) in run.into_iter().zip(out) {
            let Some(data) = data else { continue };
            self.files_read.fetch_add(1, Ordering::Relaxed);
            self.bytes_read.fetch_add(data.len() as u64, Ordering::Relaxed);
            let data: Arc<[u8]> = data.into();
            if node == me.node {
                wanted = Some(data);
            } else {
                let cost = data.len();
                kept.insert(node, data, cost);
            }
        }
        if let Some(data) = &wanted {
            self.taken.fetch_add(data.len() as u64, Ordering::Relaxed);
        }
        Ok((wanted, false))
    }

    /// Let go of how folder `dir` is being opened: its next opening is a first one again.
    /// Its files kept stay until opened or dropped.
    pub fn forget(&self, dir: NodeId) {
        lock(&self.openings).remove(&dir);
    }

    /// Let go of every folder and everything kept.
    pub fn clear(&self) {
        lock(&self.openings).clear();
        lock(&self.kept).clear();
    }

    /// Whether `node`'s content is kept, read ahead and not opened yet.
    pub fn is_kept(&self, node: NodeId) -> bool {
        lock(&self.kept).contains(&node)
    }

    /// What it did so far.
    pub fn stats(&self) -> ReadAheadStats {
        let (kept_files, held) = {
            let kept = lock(&self.kept);
            (kept.len() as u64, kept.bytes() as u64)
        };
        let bytes_read = self.bytes_read.load(Ordering::Relaxed);
        ReadAheadStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            batches: self.batches.load(Ordering::Relaxed),
            files_read: self.files_read.load(Ordering::Relaxed),
            bytes_read,
            evicted_unread_bytes: bytes_read.saturating_sub(self.taken.load(Ordering::Relaxed) + held),
            kept_files,
            kept_bytes: held,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testns::MemNs;

    /// A folder made by [`folder`].
    type Folder = (FsHandle, Vec<Sibling>, Vec<Vec<u8>>, Arc<fs_inspect_io::CountingSource>);

    /// A folder (node 1) of `sizes.len()` files (nodes 100...), each of its size, laid out
    /// one after another on a 4 MiB volume in listing order; the handle, the folder's
    /// siblings, each file's bytes, and the volume's read counter.
    fn folder(sizes: &[u64]) -> Folder {
        let mut ns = MemNs::new();
        let mut at = 64 << 10;
        let mut datas = Vec::new();
        for (i, &size) in sizes.iter().enumerate() {
            let id = 100 + i as u64;
            let data: Vec<u8> = (0..size).map(|b| (b * 7 + id * 13) as u8).collect();
            ns.file(1, &format!("f{i}"), id, &data).place(id, at);
            at += size.next_multiple_of(4096);
            datas.push(data);
        }
        let counting = std::cell::OnceCell::new();
        ns.volume(4 << 20, |s| {
            let c = fs_inspect_io::CountingSource::new(s);
            counting.set(c.clone()).unwrap();
            c
        });
        let siblings: Vec<Sibling> = sizes
            .iter()
            .enumerate()
            .map(|(i, &size)| Sibling::new(NodeId::new(0, 100 + i as u64), size, true))
            .collect();
        (ns.handle(), siblings, datas, counting.into_inner().unwrap())
    }

    const DIR: NodeId = NodeId::new(0, 1);

    /// Folder `DIR` listed as `siblings`.
    fn listing(siblings: &[Sibling]) -> Listing {
        Listing::of_siblings(DIR, siblings.to_vec())
    }

    fn kept(ahead: &ReadAhead, siblings: &[Sibling]) -> Vec<usize> {
        (0..siblings.len()).filter(|&i| ahead.is_kept(siblings[i].node)).collect()
    }

    /// Opened backwards: the first alone, from the second on the folder's small files read
    /// together in listing order and kept until opened.
    #[test]
    fn small_files_of_a_folder_opened_are_read_ahead_together() {
        let (fs, siblings, datas, _) = folder(&[0, 3000, 5000, 7000]);
        let ahead = fs.read_ahead(&ReadAheadOptions::default(), None);
        assert_eq!(ahead.read(&listing(&siblings), 3, None).unwrap(), None, "the first opened, alone");
        assert!(kept(&ahead, &siblings).is_empty());
        assert_eq!(&*ahead.read(&listing(&siblings), 2, None).unwrap().unwrap(), &datas[2][..]);
        assert_eq!(kept(&ahead, &siblings), [0, 1]);
        assert_eq!(&*ahead.read(&listing(&siblings), 1, None).unwrap().unwrap(), &datas[1][..]);
        assert_eq!(&*ahead.read(&listing(&siblings), 0, None).unwrap().unwrap(), &datas[0][..]);
        assert!(kept(&ahead, &siblings).is_empty());
        let s = ahead.stats();
        assert_eq!((s.hits, s.misses, s.batches, s.files_read, s.bytes_read), (2, 2, 1, 3, 8000));
        assert_eq!(s.evicted_unread_bytes, 0);
        // The folder read to its end: opened again, each is read in a batch of its own.
        assert_eq!(&*ahead.read(&listing(&siblings), 1, None).unwrap().unwrap(), &datas[1][..]);
        assert!(kept(&ahead, &siblings).is_empty());
        // Forgotten, its next opening is a first one.
        ahead.forget(DIR);
        assert_eq!(ahead.read(&listing(&siblings), 2, None).unwrap(), None);
        assert!(ahead.read(&listing(&siblings), 1, None).unwrap().is_some());
    }

    /// `try_open` settles all but a batch without reading, counted as `read` counts.
    #[test]
    fn answers_settle_all_but_a_batch_without_reading() {
        let (fs, mut siblings, datas, counting) = folder(&[3000, 3000, 3000, 1 << 20, 3000]);
        siblings[1].readable = false;
        let ahead = fs.read_ahead(&ReadAheadOptions::default(), None);
        let before = counting.stats().reads;
        assert_eq!(ahead.try_open(&listing(&siblings), 0).unwrap(), Answer::Alone, "the first opened");
        assert_eq!(ahead.try_open(&listing(&siblings), 1).unwrap(), Answer::Alone, "not readable");
        assert_eq!(ahead.try_open(&listing(&siblings), 3).unwrap(), Answer::Alone, "too large");
        assert_eq!(ahead.try_open(&listing(&siblings), 2).unwrap(), Answer::Batch);
        assert_eq!(counting.stats().reads, before, "nothing read");
        assert_eq!(&*ahead.read(&listing(&siblings), 2, None).unwrap().unwrap(), &datas[2][..]);
        let Answer::Kept(data) = ahead.try_open(&listing(&siblings), 4).unwrap() else { panic!("kept") };
        assert!(*data == datas[4][..]);
        assert!(ahead.try_open(&listing(&siblings), 9).is_err());
        let s = ahead.stats();
        assert_eq!((s.hits, s.misses, s.batches, s.files_read), (1, 4, 1, 2));
    }

    /// A batch stops at its byte and file bounds, passes files too large or not readable,
    /// and a file too large is opened alone.
    #[test]
    fn reading_ahead_stops_at_its_bounds() {
        let (fs, mut siblings, datas, _) = folder(&[1000, 9000, 1000, 1000, 1000, 1000]);
        siblings[2].readable = false;
        let opts = ReadAheadOptions::default().with_file_max(4096).with_batch_bytes(3000).with_batch_files(3);
        let ahead = fs.read_ahead(&opts, None);
        assert_eq!(ahead.read(&listing(&siblings), 0, None).unwrap(), None);
        assert_eq!(ahead.read(&listing(&siblings), 1, None).unwrap(), None, "too large");
        assert_eq!(ahead.read(&listing(&siblings), 2, None).unwrap(), None, "not readable");
        // 3000 bytes: itself, then 4 and 5 (0 the first, 1 too large, 2 not readable).
        assert_eq!(&*ahead.read(&listing(&siblings), 3, None).unwrap().unwrap(), &datas[3][..]);
        assert_eq!(kept(&ahead, &siblings), [4, 5]);
        let opts = opts.with_batch_bytes(1 << 20).with_batch_files(2);
        let ahead = fs.read_ahead(&opts, None);
        ahead.read(&listing(&siblings), 5, None).unwrap();
        ahead.read(&listing(&siblings), 4, None).unwrap();
        assert_eq!(kept(&ahead, &siblings), [0], "two files: itself and one more");
    }

    /// Openings at once: one batch reads the folder, the others wait for it and find their
    /// file kept; no file is read twice.
    #[test]
    fn files_opened_at_once_are_each_read_once() {
        let sizes = [2000u64; 16];
        let (fs, siblings, datas, _) = folder(&sizes);
        let ahead = fs.read_ahead(&ReadAheadOptions::default(), None);
        assert_eq!(ahead.read(&listing(&siblings), 0, None).unwrap(), None);
        std::thread::scope(|s| {
            for (i, data) in datas.iter().enumerate().skip(1) {
                let (ahead, siblings) = (&ahead, &siblings);
                s.spawn(move || {
                    assert_eq!(&*ahead.read(&listing(siblings), i as u64, None).unwrap().unwrap(), &data[..])
                });
            }
        });
        let st = ahead.stats();
        assert_eq!((st.hits, st.misses, st.batches, st.files_read), (14, 2, 1, 15));
        assert!(kept(&ahead, &siblings).is_empty());
    }

    /// What is read ahead is read in few merged reads, never past the room left to keep (a
    /// folder opened out of order pushes out nothing read ahead), and what is dropped unread
    /// counted.
    #[test]
    fn a_batch_reads_merged_into_the_room_left_and_dropping_it_is_counted() {
        let (fs, siblings, datas, counting) = folder(&[3000; 64]);
        let ahead = fs.read_ahead(&ReadAheadOptions::default().with_kept_bytes(10_000), None);
        ahead.read(&listing(&siblings), 0, None).unwrap();
        let before = counting.stats().reads;
        ahead.read(&listing(&siblings), 1, None).unwrap().unwrap();
        assert!(counting.stats().reads - before <= 2, "{} reads", counting.stats().reads - before);
        // 10 000 bytes to keep: three files of 3000 read ahead with the one opened.
        assert_eq!(kept(&ahead, &siblings), [2, 3, 4]);
        // Out of order with no room left: read alone, nothing pushed out.
        assert_eq!(&*ahead.read(&listing(&siblings), 40, None).unwrap().unwrap(), &datas[40][..]);
        assert_eq!(kept(&ahead, &siblings), [2, 3, 4]);
        // Room freed: the next batch reads into it, from where the last one stopped.
        ahead.read(&listing(&siblings), 2, None).unwrap().unwrap();
        ahead.read(&listing(&siblings), 50, None).unwrap().unwrap();
        assert_eq!(kept(&ahead, &siblings), [3, 4, 5]);
        let s = ahead.stats();
        assert_eq!((s.hits, s.files_read, s.evicted_unread_bytes), (1, 7, 0));
        assert_eq!((s.kept_files, s.kept_bytes), (3, 9000));
        ahead.clear();
        assert_eq!(ahead.stats().evicted_unread_bytes, 9000);
        assert_eq!(ahead.read(&listing(&siblings), 5, None).unwrap(), None, "a first opening again");
        assert!(ahead.read(&listing(&siblings), 70, None).is_err());
    }
}
