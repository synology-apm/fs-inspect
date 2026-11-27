//! Directory listings (a cursor paged and seeked, or a whole listing held) and walking a tree
//! (a cursor pulled a batch at a time).

use super::*;
use crate::errors::{FsInspectItemErrors, ItemError, clear_item_errors, put_item_errors};
use crate::support::{StridedStruct, put_strided, strided_struct};
use fs_inspect::fs::{Listing, WalkEntry, Walker};
use std::collections::VecDeque;

/// `fs_inspect_dir_entry.encoding`: what `raw` holds.
/// Bytes as stored (Unix file systems: usually UTF-8, not checked).
pub const FS_INSPECT_NAME_BYTES: u32 = 1;
/// UTF-16 code units, little-endian (NTFS, ReFS, FAT, exFAT); maybe unpaired surrogates.
pub const FS_INSPECT_NAME_UTF16: u32 = 2;

/// A directory entry, handed in an array of the caller's whose elements are `elem_size` bytes
/// apart. Its pointers are the library's: a cursor's are valid until the next call on its
/// handle that is not a `_get_*` (or `fs_inspect_dir_free`), a listing's until
/// `fs_inspect_listing_free`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectDirEntry {
    /// The name as UTF-8 text, NUL terminated: what is not valid Unicode escaped (`\xHH`,
    /// `\u{XXXX}`) and a backslash doubled. `fs_inspect_fs_lookup` takes it back.
    pub name: *const c_char,
    /// The name as stored, `raw_len` bytes (`encoding`).
    pub raw: *const u8,
    /// The bytes at `raw`.
    pub raw_len: usize,
    /// `FS_INSPECT_NAME_*`.
    pub encoding: u32,
    /// `FS_INSPECT_NODE_*` when the directory records it (0: unknown, stat it).
    pub kind: u32,
    /// The directory records it as a cloud file or placeholder.
    pub cloud: bool,
    /// The node it names.
    pub node: FsInspectNode,
    /// With `FS_INSPECT_DIR_FLAG_STAT`: the node's metadata, read with its neighbours'; NULL when
    /// not asked for or not read (the call's item errors say why).
    pub stat: *const FsInspectStat,
    /// Which of the directory's identical names this is, in the listing's order. It is 1 for
    /// the first, which is every name on a sound file system; 2, 3, ... are repeats on a damaged
    /// one. The entry's identity in its directory is `name`, followed by `\#{occurrence}` from 2
    /// on (`\#` is not an escape, so no name ends that way). `fs_inspect_dir_find` and
    /// `fs_inspect_listing_find` take this identity.
    pub occurrence: u32,
}

strided_struct!(FsInspectDirEntry, occurrence);

/// `fs_inspect_dir_options.flags`, `fs_inspect_walk_options.flags`: also read each entry's
/// `fs_inspect_stat` (the entry's `stat`), what `ls -l` and `readdirplus` need. The stats of a
/// batch are read together, in the order their records are on the volume: far fewer reads than
/// a `fs_inspect_fs_stat` of each entry.
pub const FS_INSPECT_DIR_FLAG_STAT: u32 = 1;

/// How a directory is listed; all-zero (or NULL) is names only.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectDirOptions {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_DIR_FLAG_*` bits.
    pub flags: u32,
    /// Set to 0.
    pub reserved: u32,
}

crate::sized_struct!(FsInspectDirOptions, reserved);

impl Default for FsInspectDirOptions {
    fn default() -> Self {
        FsInspectDirOptions { struct_size: size_of::<Self>(), flags: 0, reserved: 0 }
    }
}

/// What an entry's info is read with (`FS_INSPECT_DIR_FLAG_STAT` in `flags`, the field `what`;
/// `allowed`: the flags the call knows): [`Want::NONE`] names only.
fn listing_want(what: &str, flags: u32, allowed: u32) -> FfiResult<Want> {
    unknown_bits(what, flags, allowed)?;
    Ok(if flags & FS_INSPECT_DIR_FLAG_STAT != 0 { Want::STAT } else { Want::NONE })
}

/// An entry for C, with what its pointers point at.
#[derive(Debug, Default)]
struct EntryC {
    name: CString,
    raw: Vec<u8>,
    encoding: u32,
    stat: Option<FsInspectStat>,
    occurrence: u32,
}

type Info = Option<fs_inspect::Result<fs_inspect::fs::NodeInfo>>;

impl EntryC {
    /// Hold `e`, its stat (if read) and its occurrence (0: not counted).
    fn new(e: &DirEntry, info: &Info, occurrence: u32) -> Self {
        let (raw, encoding) = name_raw(&e.name);
        let stat = match info {
            Some(Ok(i)) => Some(stat_c(&i.stat)),
            _ => None,
        };
        EntryC { name: cstring(&e.name.escape()), raw, encoding, stat, occurrence }
    }

    /// `e` as C sees it, pointing into `self`.
    fn c(&self, e: &DirEntry) -> FsInspectDirEntry {
        FsInspectDirEntry {
            name: self.name.as_ptr(),
            raw: self.raw.as_ptr(),
            raw_len: self.raw.len(),
            encoding: self.encoding,
            kind: opt_code(e.kind),
            cloud: e.cloud,
            node: e.node.into(),
            stat: self.stat.as_ref().map_or(std::ptr::null(), |s| s as *const FsInspectStat),
            occurrence: self.occurrence,
        }
    }
}

/// The item errors of entries whose info could not be read, by their index.
fn info_errors<'a>(infos: impl Iterator<Item = &'a Info>) -> Vec<ItemError> {
    infos.enumerate().filter_map(|(i, info)| info.as_ref()?.as_ref().err().map(|e| ItemError::new(i, e))).collect()
}

/// A name as stored, and its `FS_INSPECT_NAME_*`.
pub(super) fn name_raw(n: &Name) -> (Vec<u8>, u32) {
    match n {
        Name::Bytes(b) => (b.clone(), FS_INSPECT_NAME_BYTES),
        Name::Utf16(u) => (u.iter().flat_map(|c| c.to_le_bytes()).collect(), FS_INSPECT_NAME_UTF16),
    }
}

/// `out` (`n` elements `stride` bytes apart, `stride` at least `min`) checked: non-null unless
/// `n` is 0.
fn strided<T>(out: *mut T, n: usize, stride: usize, min: usize, name: &str) -> FfiResult {
    if stride < min {
        return Err(FfiError::invalid(format!("{name}: element size {stride}, below {min}")));
    }
    if out.is_null() && n > 0 {
        return Err(FfiError::null(name));
    }
    Ok(())
}

/// The arguments of a batch call checked: `entries` room for `cap` elements `elem_size` apart
/// (NULL allowed when `cap` is 0), `n_written` non-null.
fn batch_args<T: StridedStruct>(entries: *mut T, cap: usize, elem_size: usize, n_written: *mut usize) -> FfiResult {
    strided(entries, cap, elem_size, T::MIN_SIZE, "entries")?;
    if n_written.is_null() {
        return Err(FfiError::null("n_written"));
    }
    Ok(())
}

// ---- cursor ---------------------------------------------------------------------------------

/// Opaque handle: a cursor over a directory's entries, read a batch at a time with
/// `fs_inspect_dir_read`. One thread at a time may use it.
///
/// Entries have positions 0, 1, ... in the order handed, the same each time for the same
/// image. `fs_inspect_dir_seek` goes to any position, as a FUSE `readdirplus` at an offset or a
/// page of a listing needs. The names are listed once and kept while the handle lives, so
/// seeking costs nothing. A handle seeked past 0 before its first read lists the names before
/// that position again, but not their stats.
#[derive(Debug)]
pub struct FsInspectDir {
    /// The cursor, its token the `cancel` it was opened with.
    cursor: fs_inspect::fs::DirCursor,
    /// The last batch, held for C.
    held: Vec<EntryC>,
}

impl FsInspectDir {
    /// Run `f` on the cursor with the call's `cancel` (composed with the handle's token).
    fn run<T>(
        &mut self,
        cancel: *const FsInspectCancel,
        f: impl FnOnce(&mut fs_inspect::fs::DirCursor, Option<&CancelToken>) -> T,
    ) -> T {
        let token = crate::cancel::token(cancel);
        f(&mut self.cursor, token.as_ref())
    }
}

/// Open a cursor on directory `dir`, at its first entry, listing as `opts` says (NULL: names
/// only). Nothing is read here: `fs_inspect_dir_read`, `fs_inspect_dir_find` and
/// `fs_inspect_dir_collect` read. `cancel` (NULL: none) becomes the handle's token. Free `*out`
/// with `fs_inspect_dir_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_dir_open(
    fs: *const FsInspectFs,
    dir: FsInspectNode,
    opts: *const FsInspectDirOptions,
    out: *mut *mut FsInspectDir,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let o = if opts.is_null() { FsInspectDirOptions::default() } else { read_sized(opts, "opts")? };
        let want = listing_want("fs_inspect_dir_options.flags", o.flags, FS_INSPECT_DIR_FLAG_STAT)?;
        let cursor = fs_ref(fs)?.fs.dir(
            dir.into(),
            &DirOptions::default().with_want(want),
            crate::cancel::token(cancel).as_ref(),
        );
        boxed(out, FsInspectDir { cursor, held: Vec::new() })
    })
}

fn dir_mut<'a>(dir: *mut FsInspectDir) -> FfiResult<&'a mut FsInspectDir> {
    // SAFETY: NULL or a live handle from fs_inspect_dir_open, used by one thread at a time.
    unsafe { dir.as_mut() }.ok_or_else(|| FfiError::null("dir"))
}

/// Read the next entries, up to `cap`, into `entries`: an array of `cap` elements `elem_size`
/// bytes apart (`sizeof(fs_inspect_dir_entry)`). `*n_written` is how many; 0 past the last
/// entry. A `cap` of 0 reads nothing.
///
/// With `FS_INSPECT_DIR_FLAG_STAT`, the batch's stats are read together. An entry whose stat
/// could not be read has a NULL `stat` and is in `*errors` (NULL: not wanted), by index in the
/// batch; the listing goes on. A directory that cannot be listed, or not to its end, fails here
/// after the entries it gave.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_dir_read(
    dir: *mut FsInspectDir,
    entries: *mut FsInspectDirEntry,
    cap: usize,
    elem_size: usize,
    n_written: *mut usize,
    errors: *mut *mut FsInspectItemErrors,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    clear_item_errors(errors);
    guard(|| {
        let d = dir_mut(dir)?;
        batch_args(entries, cap, elem_size, n_written)?;
        d.held.clear();
        if cap == 0 {
            return put(n_written, "n_written", 0);
        }
        let batch = d.run(cancel, |c, t| c.read(cap, t))?;
        d.held = batch.iter().map(|l| EntryC::new(&l.entry, &l.info, l.occurrence)).collect();
        for (i, (l, h)) in batch.iter().zip(&d.held).enumerate() {
            put_strided(entries, elem_size, i, h.c(&l.entry));
        }
        put(n_written, "n_written", batch.len())?;
        put_item_errors(errors, info_errors(batch.iter().map(|l| &l.info)));
        Ok(())
    })
}

/// Go to position `pos` (0: the first entry; past the last: the end). Reads nothing.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_dir_seek(dir: *mut FsInspectDir, pos: u64) -> FsInspectStatus {
    guard(|| {
        let d = dir_mut(dir)?;
        d.held.clear();
        d.cursor.seek(pos);
        Ok(())
    })
}

/// Find the entry whose identity is `id` (NUL-terminated UTF-8; see
/// `fs_inspect_dir_entry.occurrence`) and set `*out` to its position. `FS_INSPECT_E_NOT_FOUND`
/// when there is none. Lists the whole directory (names only); the handle stays where it was.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_dir_find(
    dir: *mut FsInspectDir,
    id: *const c_char,
    out: *mut u64,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let d = dir_mut(dir)?;
        let id = str_arg(id, "id")?;
        out_arg(out, "out")?;
        let found = match id.parse::<fs_inspect::fs::EntryId>() {
            Ok(id) => d.run(cancel, |c, t| c.find(&id, t))?,
            Err(_) => None,
        };
        let at = found.ok_or_else(|| fs_inspect::Error::not_found(format!("no entry {id:?}")))?;
        put(out, "out", at)
    })
}

/// `*out` = the position of the next entry `fs_inspect_dir_read` gives.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_dir_get_position(dir: *const FsInspectDir, out: *mut u64) -> FsInspectStatus {
    guard(|| put(out, "out", handle(dir, "dir")?.cursor.position()))
}

/// `*out` = the directory the handle lists.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_dir_get_node(dir: *const FsInspectDir, out: *mut FsInspectNode) -> FsInspectStatus {
    guard(|| put(out, "out", handle(dir, "dir")?.cursor.dir().into()))
}

/// Read every entry from the handle's position to the end as one batch, and hold them in a
/// listing (from position 0: the whole directory, what a cache of listings keeps). `*errors`
/// (NULL: not wanted) holds the entries whose stat could not be read, by index in the listing.
/// The handle is then at the end; on failure it stays where it was. Free `*out` with
/// `fs_inspect_listing_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_dir_collect(
    dir: *mut FsInspectDir,
    out: *mut *mut FsInspectListing,
    errors: *mut *mut FsInspectItemErrors,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    clear_item_errors(errors);
    guard(|| {
        let d = dir_mut(dir)?;
        d.held.clear();
        out_arg(out, "out")?;
        let listing = d.run(cancel, |c, t| c.collect(t))?;
        let errs = info_errors(listing.entries().iter().map(|l| &l.info));
        boxed(out, FsInspectListing::new(listing))?;
        put_item_errors(errors, errs);
        Ok(())
    })
}

/// Free a directory cursor (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_dir_free(dir: *mut FsInspectDir) {
    free(dir);
}

// ---- listing --------------------------------------------------------------------------------

/// Opaque handle: a directory's entries held in memory (`fs_inspect_dir_collect`), in the order
/// the directory hands them. Thread-safe. Its entries' pointers are valid until
/// `fs_inspect_listing_free`.
#[derive(Debug)]
pub struct FsInspectListing {
    pub(super) listing: Listing,
    /// Each entry as C sees it.
    held: Vec<EntryC>,
}

impl FsInspectListing {
    fn new(listing: Listing) -> Self {
        let held = listing.entries().iter().map(|l| EntryC::new(&l.entry, &l.info, l.occurrence)).collect();
        FsInspectListing { listing, held }
    }
}

pub(super) fn listing_ref<'a>(l: *const FsInspectListing) -> FfiResult<&'a FsInspectListing> {
    handle(l, "listing")
}

/// What a listing is (`fs_inspect_listing_get_info`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectListingInfo {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// The directory listed.
    pub dir: FsInspectNode,
    /// About the memory it holds (for a cache's budget).
    pub memory_bytes: usize,
    /// It holds every entry of the directory (collected from position 0).
    pub whole: bool,
    pub reserved: [u8; 7],
}

crate::sized_struct!(FsInspectListingInfo, reserved);

/// The directory listed, whether the listing is whole, and its memory.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_listing_get_info(
    l: *const FsInspectListing,
    out: *mut FsInspectListingInfo,
) -> FsInspectStatus {
    guard(|| {
        let h = listing_ref(l)?;
        let own: usize = h.held.iter().map(|e| e.name.as_bytes().len() + e.raw.len() + size_of::<EntryC>()).sum();
        let r = FsInspectListingInfo {
            struct_size: size_of::<FsInspectListingInfo>(),
            dir: h.listing.dir().into(),
            memory_bytes: h.listing.memory_bytes() + own,
            whole: h.listing.is_whole(),
            reserved: [0; 7],
        };
        put_sized(out, "out", r)
    })
}

/// How many entries the listing holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_listing_count(l: *const FsInspectListing, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", listing_ref(l)?.listing.len()))
}

/// Copy up to `cap` entries, from position `start`, into `entries`: an array of `cap` elements
/// `elem_size` bytes apart (`sizeof(fs_inspect_dir_entry)`). `*n_written` is how many; 0 at or
/// past the end.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_listing_read(
    l: *const FsInspectListing,
    start: u64,
    entries: *mut FsInspectDirEntry,
    cap: usize,
    elem_size: usize,
    n_written: *mut usize,
) -> FsInspectStatus {
    guard(|| {
        let h = listing_ref(l)?;
        batch_args(entries, cap, elem_size, n_written)?;
        let all = h.listing.entries();
        let from = usize::try_from(start).unwrap_or(usize::MAX).min(all.len());
        let to = from.saturating_add(cap).min(all.len());
        for (i, (e, c)) in all[from..to].iter().zip(&h.held[from..to]).enumerate() {
            put_strided(entries, elem_size, i, c.c(&e.entry));
        }
        put(n_written, "n_written", to - from)
    })
}

/// Find the entry whose identity is `id` (see `fs_inspect_dir_entry.occurrence`) and set `*out`
/// to its position. `FS_INSPECT_E_NOT_FOUND` when there is none.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_listing_find(
    l: *const FsInspectListing,
    id: *const c_char,
    out: *mut u64,
) -> FsInspectStatus {
    guard(|| {
        let id = str_arg(id, "id")?;
        out_arg(out, "out")?;
        let listing = &listing_ref(l)?.listing;
        let found = id.parse::<fs_inspect::fs::EntryId>().ok().and_then(|e| listing.find(&e));
        let at = found.ok_or_else(|| fs_inspect::Error::not_found(format!("no entry {id:?}")))?;
        put(out, "out", at)
    })
}

/// Set `*out` to the position of `node`'s entry; the first one when the node has several names
/// in the directory. `FS_INSPECT_E_NOT_FOUND` when there is none.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_listing_position(
    l: *const FsInspectListing,
    node: FsInspectNode,
    out: *mut u64,
) -> FsInspectStatus {
    guard(|| {
        let at = listing_ref(l)?
            .listing
            .position(node.into())
            .ok_or_else(|| fs_inspect::Error::not_found(format!("no entry of {}:{}", node.root, node.id)))?;
        put(out, "out", at)
    })
}

/// Copy the positions of the listing's entries, sorted by `order`, into `buf`: up to `cap`
/// items from item `start` of that order. `order` is `FS_INSPECT_DIR_ORDER_*`; 0 is
/// `FS_INSPECT_DIR_ORDER_IDS`, the identities in code point order. `*n_written` is how many; 0
/// at or past the end.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_listing_order_read(
    l: *const FsInspectListing,
    order: u32,
    start: usize,
    buf: *mut u64,
    cap: usize,
    n_written: *mut usize,
) -> FsInspectStatus {
    guard(|| {
        let order = opt_enum_arg::<fs_inspect::fs::DirOrder>(order, "order")?.unwrap_or_default();
        let order = listing_ref(l)?.listing.order(order);
        crate::copy_out(&order, start, buf, cap, n_written, |p| *p)
    })
}

/// Copy up to `cap` entries, from position `start`, into `buf`, as a read-ahead sees them
/// (`fs_inspect_read_ahead_read`). `*n_written` is how many; 0 at or past the end. A file is
/// `readable` when it was listed with its stat and its content is on the volume.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_listing_siblings_read(
    l: *const FsInspectListing,
    start: u64,
    buf: *mut FsInspectSibling,
    cap: usize,
    n_written: *mut usize,
) -> FsInspectStatus {
    guard(|| {
        let s = listing_ref(l)?.listing.siblings();
        let start = usize::try_from(start).unwrap_or(usize::MAX);
        crate::copy_out(s, start, buf, cap, n_written, |s| FsInspectSibling {
            node: s.node.into(),
            size: s.size,
            readable: s.readable,
            ..Default::default()
        })
    })
}

/// Free a listing (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_listing_free(l: *mut FsInspectListing) {
    free(l);
}

// ---- walking --------------------------------------------------------------------------------

/// `fs_inspect_walk_options.flags`: a directory that cannot be listed is handed again with
/// `failed` set and its error in the batch's item errors, and the walk goes on.
pub const FS_INSPECT_WALK_FLAG_KEEP_GOING: u32 = 1 << 1;

/// How a tree is walked; all-zero (or NULL) is every level, `FS_INSPECT_WALK_DIRS_AFTER`, names
/// only.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectWalkOptions {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// Levels of directories to list (1: only the top one); 0: all.
    pub max_depth: u32,
    /// `FS_INSPECT_WALK_*`; 0 is `FS_INSPECT_WALK_DIRS_AFTER`. `_DIRS_AFTER` hands all of a
    /// directory's entries, then enters its subdirectories in turn, holding no whole listing.
    /// `_PREORDER` enters a directory right after its own entry, as `tree` prints.
    pub order: u32,
    /// `FS_INSPECT_DIR_FLAG_STAT`, `FS_INSPECT_WALK_FLAG_KEEP_GOING`.
    pub flags: u32,
    /// The most entries a batch holds when stats are read (a batch's stats are read together);
    /// 0: the default.
    pub batch: u32,
}

crate::sized_struct!(FsInspectWalkOptions, batch);

impl Default for FsInspectWalkOptions {
    fn default() -> Self {
        FsInspectWalkOptions { struct_size: size_of::<Self>(), max_depth: 0, order: 0, flags: 0, batch: 0 }
    }
}

/// One entry of a walk (`fs_inspect_walk_next_batch`), handed in an array of the caller's whose
/// elements are `elem_size` bytes apart. Its pointers are valid until the next call on the walk
/// that is not a `_get_*` (or `fs_inspect_walk_free`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectWalkEntry {
    /// Levels below the top (the top directory's entries: 0).
    pub depth: usize,
    /// Its path from the top: names escaped as `name`, each after a `/`. NUL terminated.
    pub path: *const c_char,
    /// The name, as `fs_inspect_dir_entry.name`.
    pub name: *const c_char,
    /// The name as stored, `raw_len` bytes (`encoding`).
    pub raw: *const u8,
    /// The bytes at `raw`.
    pub raw_len: usize,
    /// `FS_INSPECT_NAME_*`.
    pub encoding: u32,
    /// `FS_INSPECT_NODE_*` when the directory records it (0: unknown).
    pub kind: u32,
    /// The directory records it as a cloud file or placeholder.
    pub cloud: bool,
    /// With `FS_INSPECT_WALK_FLAG_KEEP_GOING`: this directory, handed before, could not be
    /// listed, or not to its end. It is handed again, with its error in the batch's item errors.
    pub failed: bool,
    /// The node it names.
    pub node: FsInspectNode,
    /// With `FS_INSPECT_DIR_FLAG_STAT`: its metadata; NULL when not asked for or not read (the
    /// batch's item errors say why; the walk goes on).
    pub stat: *const FsInspectStat,
}

strided_struct!(FsInspectWalkEntry, stat);

/// Opaque handle: a walk of a tree (`fs_inspect_fs_walk`), pulled a batch at a time with
/// `fs_inspect_walk_next_batch`; one thread at a time. Freeing it stops the walk.
#[derive(Debug)]
pub struct FsInspectWalk {
    walker: Walker,
    /// Entries of the last batch not handed yet.
    pending: VecDeque<WalkEntry>,
    /// The walk has ended.
    done: bool,
    /// The entries handed by the last call, with their path, held for C.
    held: Vec<(EntryC, CString)>,
}

/// Walk the tree under directory `dir` as `opts` says (NULL: every level, names only). A
/// directory reached twice is entered once. Entries come from `fs_inspect_walk_next_batch`;
/// the walk reads ahead on a thread of its own while the caller handles a batch. `cancel`
/// (NULL: none) becomes the handle's token. Free `*out` with `fs_inspect_walk_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_fs_walk(
    fs: *const FsInspectFs,
    dir: FsInspectNode,
    opts: *const FsInspectWalkOptions,
    out: *mut *mut FsInspectWalk,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let f = fs_ref(fs)?;
        out_arg(out, "out")?;
        let o = if opts.is_null() { FsInspectWalkOptions::default() } else { read_sized(opts, "opts")? };
        let mut wo = WalkOptions::default()
            .with_max_depth((o.max_depth != 0).then_some(o.max_depth as usize))
            .with_want(listing_want(
                "fs_inspect_walk_options.flags",
                o.flags,
                FS_INSPECT_DIR_FLAG_STAT | FS_INSPECT_WALK_FLAG_KEEP_GOING,
            )?)
            .with_on_error(if o.flags & FS_INSPECT_WALK_FLAG_KEEP_GOING != 0 {
                fs_inspect::fs::OnError::SkipAndReport
            } else {
                fs_inspect::fs::OnError::Abort
            });
        if let Some(order) = opt_enum_arg::<Order>(o.order, "opts.order")? {
            wo = wo.with_order(order);
        }
        if o.batch != 0 {
            wo = wo.with_batch(o.batch as usize);
        }
        let walker = crate::cancel::under(cancel, |c| f.fs.walker(dir.into(), &wo, c))?;
        boxed(out, FsInspectWalk { walker, pending: VecDeque::new(), done: false, held: Vec::new() })
    })
}

fn walk_mut<'a>(walk: *mut FsInspectWalk) -> FfiResult<&'a mut FsInspectWalk> {
    // SAFETY: NULL or a live handle from fs_inspect_fs_walk, used by one thread at a time.
    unsafe { walk.as_mut() }.ok_or_else(|| FfiError::null("walk"))
}

/// Read the walk's next entries, up to `cap`, into `entries`: an array of `cap` elements
/// `elem_size` bytes apart (`sizeof(fs_inspect_walk_entry)`). `*n_written` is how many; 0 once
/// the walk has ended. A `cap` of 0 reads nothing. The entries of one call come from one batch
/// of the walk: a call hands the rest of a batch before the next batch is read.
///
/// `*errors` (NULL: not wanted) holds the entries handed with an error, by index in this call's
/// entries: a stat that could not be read, or a directory handed again with `failed`. A
/// directory that cannot be listed ends the walk with its error, after the entries handed
/// before it; with `FS_INSPECT_WALK_FLAG_KEEP_GOING` it is handed again with `failed` set
/// instead. Cancelling this call also ends the walk.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_walk_next_batch(
    walk: *mut FsInspectWalk,
    entries: *mut FsInspectWalkEntry,
    cap: usize,
    elem_size: usize,
    n_written: *mut usize,
    errors: *mut *mut FsInspectItemErrors,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    clear_item_errors(errors);
    guard(|| {
        let w = walk_mut(walk)?;
        batch_args(entries, cap, elem_size, n_written)?;
        w.held.clear();
        if cap == 0 {
            return put(n_written, "n_written", 0);
        }
        if w.pending.is_empty() && !w.done {
            let mut batch = Vec::new();
            match crate::cancel::under(cancel, |c| w.walker.next_batch(&mut batch, c)) {
                Ok(more) => w.done = !more,
                Err(e) => {
                    w.done = true;
                    return Err(e.into());
                }
            }
            w.pending.extend(batch);
        }
        let take = cap.min(w.pending.len());
        let handed: Vec<WalkEntry> = w.pending.drain(..take).collect();
        w.held = handed.iter().map(|e| (EntryC::new(&e.entry, &e.info, 0), cstring(&e.path))).collect();
        let mut errs = Vec::new();
        for (i, (e, (c, path))) in handed.iter().zip(&w.held).enumerate() {
            let d = c.c(&e.entry);
            let r = FsInspectWalkEntry {
                depth: e.depth,
                path: path.as_ptr(),
                name: d.name,
                raw: d.raw,
                raw_len: d.raw_len,
                encoding: d.encoding,
                kind: d.kind,
                cloud: d.cloud,
                failed: e.failed.is_some(),
                node: d.node,
                stat: d.stat,
            };
            put_strided(entries, elem_size, i, r);
            if let Some(err) = e.failed.as_ref().or_else(|| e.info.as_ref().and_then(|r| r.as_ref().err())) {
                errs.push(ItemError::new(i, err));
            }
        }
        put(n_written, "n_written", handed.len())?;
        put_item_errors(errors, errs);
        Ok(())
    })
}

/// Do not enter directory `node`, an entry the last `fs_inspect_walk_next_batch` handed. Call
/// it before the next `fs_inspect_walk_next_batch`: a directory is entered only once the caller
/// asks for the entries after the batch holding it. This is how a caller filters the tree.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_walk_skip(walk: *mut FsInspectWalk, node: FsInspectNode) -> FsInspectStatus {
    guard(|| {
        let w = walk_mut(walk)?;
        let id: NodeId = node.into();
        w.walker.skip(id);
        Ok(())
    })
}

/// Stop and free a walk (NULL allowed). A read under way ends first.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_walk_free(walk: *mut FsInspectWalk) {
    free(walk);
}
