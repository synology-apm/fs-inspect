//! Directories, file records and data streams of ReFS 3.x.
//!
//! The Object ID table (checkpoint root 0, table 2) maps the object id of every directory (the
//! root is 0x600, user directories follow from 0x701, system tables lie below 0x600) to the
//! root of its directory table: key `{u64 0, u64 id}`, value with a page reference at
//! `8 + u32 @ 8`. A directory table (table id: the directory's object id, virtual addresses)
//! has rows keyed by a u16 type:
//! - 0x10: the directory's own record;
//! - 0x20: file id (u64 @ 8) to name;
//! - 0x30: a name (UTF-16, key + 4) with a u16 kind at +2: 1, a file whose record is the
//!   value; 2, a link `{u64 file id, u64 directory id, ...}`: a subdirectory when the file id
//!   is 0, else a file whose record another directory keeps by id (a file moved there or a
//!   hard link);
//! - 0x40: a file record kept by id (`{u16 0x40, u16, u32, u64 id, u64 directory}`): a file
//!   moved to another directory keeps its record, and its id, where it was created.
//!
//! A file record is a node embedded in the value (index root at 0, 0xA8 bytes: the times at
//! 0x28, attributes 0x48, the security key 0x50 (`{u32 hash, u32 index}` of a row of the
//! security table, object 0x530), size 0x58, allocated 0x60, the USN and the change journal's
//! id at 0x68 and 0x70 (zero with no journal), the reparse tag 0x7C, the file id 0x80). Its
//! entries are the attributes; when they do not fit, the entries reference pages of the
//! directory's table. A directory's own record (row 0x10) has the same layout.
//!
//! A name row of a subdirectory or a link (kind 2) repeats what a listing needs of its target:
//! the attributes at 0x40 and the reparse tag at 0x44.
//!
//! An attribute key starts with a u64 (the value's length). Through ReFS 3.4 the type is the
//! u16 at +8, and a named stream (0xB0, the name from +0x0C) is resident, at most 128 KiB:
//! its value (header, then data, as from 3.5) is split over attributes of that name, the
//! u32 at +4 of each key giving the piece's offset. From 3.5 a u32 at +8 with bit 31 set
//! precedes the type (+0x0C); the unnamed data stream (0x80) is either resident (16-byte key:
//! a header, then the data) or two attributes with 40-byte keys whose u64 at +0x10 tells them
//! apart: 0x1000 is its extent table. A named stream (0xB0, the name in the key from +0x10)
//! has a header attribute; when non-resident its extent table is an attribute with a composite
//! key (field count at +8, descriptors from +0x10:
//! `{u16, u16 kind, u16 size, u16 offset from +8}`) holding the stream id (the 8-byte field,
//! also at the end of the header) and the same 0x18-byte tail as the unnamed stream's.
//!
//! From 3.5 a reparse point is attribute 0xC0: the reparse buffer at `u32 @ 8` of the value,
//! `u32 @ 4` bytes long. A record kept by id has an attribute 0x39 for each of its names: the
//! parent directory's id at +0x10 of the key, the UTF-16 name from +0x20.
//!
//! An extent table is a node embedded in the value: a 0x88-byte root holding the stream sizes,
//! inner entries referencing pages of the directory's table, and leaves of 24-byte records
//! `{u64 virtual LCN, u32, u64 VCN, u32 clusters}`.

use crate::format::container::ContainerMap;
use crate::format::dirkey::{Key, collate};
use crate::format::layout::PageRef;
use crate::format::tree::{Addressing, Index, Node, Page, PageReader, TreeWalk};
use fs_inspect_core::bytes::{slice, u16_at, u32_at, u64_at};
use fs_inspect_core::{Error, Limits, Result};
use std::cmp::Ordering;
use std::ops::ControlFlow;

/// Object ids.
pub mod object {
    /// The root directory.
    pub const ROOT: u64 = 0x600;
    /// The security table: `{u64 length, u32 index, u32 hash}` to `{u32 hash, u32 index, u32
    /// length, then the self-relative security descriptor}` (the length counts from the value's
    /// start).
    pub const SECURITY: u64 = 0x530;
    /// The File System Metadata directory (the change journal).
    pub const FS_METADATA: u64 = 0x520;
    /// The Logfile Information Table and its copy.
    pub const LOG_INFO: u64 = 0x9;
    pub const LOG_INFO_COPY: u64 = 0xA;
}

/// Row types of a directory table (the format's, used or not).
#[allow(dead_code)]
pub mod row {
    pub const SELF: u16 = 0x10;
    pub const ID: u16 = 0x20;
    pub const NAME: u16 = 0x30;
    pub const BY_ID: u16 = 0x40;
    /// Kinds of a name row.
    pub const FILE: u16 = 1;
    pub const LINK: u16 = 2;
}

const ATTR_DATA: u16 = 0x80;
const ATTR_NAMED_DATA: u16 = 0xB0;
const ATTR_REPARSE: u16 = 0xC0;
const ATTR_LINK: u16 = 0x39;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
pub const REPARSE_POINT: u32 = 0x400;
/// A 3.5+ key's u32 at +8 has this bit when the type follows it.
const KEY_TYPED: u32 = 0x8000_0000;
/// The unnamed stream's attribute holding its extent table (u64 at +0x10 of its key).
const SUB_EXTENTS: u64 = 0x1000;
/// A named stream's header: non-resident.
const STREAM_NON_RESIDENT: u32 = 0x1000_0000;
const RECORD_ROOT: usize = 0xA8;
const EXTENT_ROOT: u32 = 0x88;
const EXTENT_RECORD: usize = 24;

/// How attribute keys and stream headers are laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// ReFS 3.0 to 3.4.
    V3_1,
    /// ReFS 3.5 and later.
    V3_5,
}

impl Format {
    pub fn of(major: u8, minor: u8) -> Self {
        if major > 3 || minor >= 5 { Format::V3_5 } else { Format::V3_1 }
    }

    /// Offset of the stream sizes in an extent table's root.
    fn sizes(self) -> usize {
        match self {
            Format::V3_1 => 0x34,
            Format::V3_5 => 0x30,
        }
    }
}

/// A run of a stream: `clusters` clusters from VCN `vcn` at physical LCN `lcn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub vcn: u64,
    pub lcn: u64,
    pub clusters: u64,
}

/// A data stream of a file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Stream {
    /// `None` for the unnamed data stream.
    pub name: Option<String>,
    pub resident: bool,
    /// Bytes allocated (rounded up to clusters), of data, valid (written) and actually
    /// allocated (less for a sparse stream).
    pub allocation: u64,
    pub size: u64,
    pub valid: u64,
    pub allocated: u64,
    /// Where a non-resident stream's data lies (physical), by VCN.
    pub extents: Vec<Extent>,
    /// A resident stream's data.
    pub data: Vec<u8>,
}

/// A file: its identity, record fields and data streams.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileEntry {
    /// The directory table keeping the record and the file id in it: the file's identity,
    /// kept across renames and moves.
    pub dir: u64,
    pub id: u64,
    /// The name it is kept under; `None` for a record kept by id (its names are links in
    /// other directories).
    pub name: Option<String>,
    /// FILETIMEs.
    pub created: u64,
    pub modified: u64,
    pub changed: u64,
    pub accessed: u64,
    pub attributes: u32,
    /// The key of its security descriptor in the security table.
    pub security: SecurityKey,
    /// The reparse tag (0 without a reparse point) and, from 3.5, the reparse buffer.
    pub reparse_tag: u32,
    pub reparse: Option<Vec<u8>>,
    /// The names of a record kept by id: (parent directory, UTF-16 name). Empty for one kept
    /// under its name (and through 3.4).
    pub links: Vec<(u64, Vec<u16>)>,
    pub size: u64,
    pub allocated: u64,
    /// The update sequence number of the last change and the change journal's id: zero
    /// without a change journal.
    pub usn: u64,
    pub usn_journal: u64,
    /// The unnamed stream first (when the file has one), then the named ones.
    pub streams: Vec<Stream>,
    /// The file has a stream this reader does not read (a non-resident named stream through
    /// ReFS 3.4, which Windows does not write): its clusters are not in `streams`.
    pub incomplete: bool,
}

impl FileEntry {
    /// The unnamed data stream.
    pub fn data(&self) -> Option<&Stream> {
        self.streams.first().filter(|s| s.name.is_none())
    }
}

/// The key of a security descriptor in the security table (object 0x530).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SecurityKey {
    pub hash: u32,
    pub index: u32,
}

/// What a listing knows of a name row's target without reading its record: its attributes and
/// reparse tag (0: none).
pub fn row_attributes(key: &[u8], value: &[u8]) -> Option<(u32, u32)> {
    let at = match (u16_at(key, 0).ok()?, u16_at(key, 2).ok()?) {
        (row::NAME, row::FILE) => (0x48, 0x7C),
        (row::NAME, row::LINK) => (0x40, 0x44),
        _ => return None,
    };
    let attrs = u32_at(value, at.0).ok()?;
    Some((attrs, if attrs & REPARSE_POINT != 0 { u32_at(value, at.1).ok()? } else { 0 }))
}

/// A directory table: its object id and root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Directory {
    pub id: u64,
    pub root: PageRef,
}

/// What a directory table row holds.
#[derive(Debug)]
pub enum DirEntry<'a> {
    /// A file record and the name it is kept under (`None`: kept by id).
    File {
        name: Option<String>,
        record: &'a [u8],
    },
    /// A subdirectory.
    Directory {
        name: String,
        id: u64,
    },
    /// A file whose record directory `dir` keeps by id.
    Link {
        dir: u64,
        id: u64,
    },
    Other,
}

fn utf16(b: &[u8]) -> String {
    let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    String::from_utf16_lossy(&units)
}

/// The name of a name row (key + 4) as stored: UTF-16 code units, unpaired surrogates kept.
pub fn name_units(key: &[u8]) -> Vec<u16> {
    key.get(4..).unwrap_or_default().as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect()
}

/// Classify a directory table row.
pub fn dir_entry<'a>(key: &[u8], value: &'a [u8]) -> Result<DirEntry<'a>> {
    let t = u16_at(key, 0)?;
    Ok(match t {
        row::NAME => {
            let name = utf16(slice(key, 4, key.len().saturating_sub(4))?);
            match u16_at(key, 2)? {
                row::FILE => DirEntry::File { name: Some(name), record: value },
                row::LINK => match u64_at(value, 0)? {
                    0 => DirEntry::Directory { name, id: u64_at(value, 8)? },
                    id => DirEntry::Link { dir: u64_at(value, 8)?, id },
                },
                k => return Err(Error::corrupt(format!("name row of kind {k}"))),
            }
        }
        row::BY_ID => DirEntry::File { name: None, record: value },
        _ => DirEntry::Other,
    })
}

/// A visitor of (key, value) table entries.
pub type Visit<'a> = dyn FnMut(&[u8], &[u8]) -> Result<()> + 'a;

/// A visitor of (key, value) rows of a table, until it breaks.
pub type RowVisit<'a> = dyn FnMut(&[u8], &[u8]) -> Result<ControlFlow<()>> + 'a;

/// Reads directories and files through a checkpoint's tables.
#[derive(Debug, Clone)]
pub struct FileReader<'a> {
    pub reader: &'a PageReader,
    pub map: &'a ContainerMap,
    pub format: Format,
    pub clusters: u64,
    pub limits: &'a Limits,
}

impl FileReader<'_> {
    /// The tables listed in the Object ID table at `root` whose id passes `keep`, by id.
    pub fn objects(&self, root: PageRef, keep: &dyn Fn(u64) -> bool) -> Result<Vec<Directory>> {
        let mut walk = TreeWalk::new(
            self.reader.clone(),
            root,
            Addressing::Virtual,
            crate::format::layout::table::OBJECT_ID,
            self.limits,
        );
        let mut out = Vec::new();
        while let Some((node, i)) = walk.next_with(&mut |_| {})? {
            let (k, v) = (node.key(i), node.value(i));
            let id = u64_at(k, 8)?;
            if !keep(id) {
                continue;
            }
            let off = 8usize.saturating_add(u32_at(v, 8)? as usize);
            let len = u32_at(v, 0x0C)? as usize;
            let root =
                PageRef::parse(slice(v, off, len)?).map_err(|e| Error::corrupt(format!("object {id:#x}: {e}")))?;
            if out.len() as u64 >= self.limits.max_dir_entries {
                return Err(Error::limit("Object ID table too large"));
            }
            out.push(Directory { id, root });
        }
        Ok(out)
    }

    /// The first row of table `d` (a directory's own record, row 0x10, when it has one).
    pub fn first_row(&self, d: &Directory) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let mut walk = TreeWalk::new(self.reader.clone(), d.root, Addressing::Virtual, d.id, self.limits);
        Ok(walk.next_with(&mut |_| {})?.map(|(node, i)| (node.key(i).to_vec(), node.value(i).to_vec())))
    }

    /// Call `f` with the rows of directory `d` in order, until it breaks: no page is read
    /// after that.
    pub fn rows(&self, d: &Directory, f: &mut RowVisit<'_>) -> Result<()> {
        let mut walk = TreeWalk::new(self.reader.clone(), d.root, Addressing::Virtual, d.id, self.limits);
        self.rows_on(&mut walk, d, f).map(drop)
    }

    /// The root pages of the tables `dirs`, close ones read together: `f` gets each
    /// directory and its root page (or why it cannot be had), in order.
    pub fn roots(&self, dirs: &[Directory], f: &mut dyn FnMut(&Directory, Result<Page>) -> Result<()>) -> Result<()> {
        let refs: Vec<_> = dirs.iter().map(|d| (d.root, d.id)).collect();
        self.reader.read_nodes_of(&refs, Addressing::Virtual, &|want, t| t == want, &mut |i, page| f(&dirs[i], page))
    }

    /// [`rows`](Self::rows) of `d` from its root page, read by [`roots`](Self::roots).
    pub fn rows_from(&self, d: &Directory, root: Page, f: &mut RowVisit<'_>) -> Result<()> {
        let mut walk = TreeWalk::from_page(self.reader.clone(), d.root, root, Addressing::Virtual, d.id, self.limits);
        self.rows_on(&mut walk, d, f).map(drop)
    }

    /// The rows of directory `d` from where `walk` is on, through `f` until it breaks
    /// (`Ok(true)`: the walk stops after the row `f` broke at, and goes on from the next) or
    /// the rows end.
    pub fn rows_on(&self, walk: &mut TreeWalk, d: &Directory, f: &mut RowVisit<'_>) -> Result<bool> {
        let mut n = 0u64;
        while let Some((node, i)) = walk.next_with(&mut |_| {})? {
            n += 1;
            if n > self.limits.max_dir_entries {
                return Err(Error::limit(format!(
                    "directory {:#x}: more than {} rows",
                    d.id, self.limits.max_dir_entries
                )));
            }
            if f(node.key(i), node.value(i))?.is_break() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The rows of directory `d` from the first not below `probe` ([`collate`]) on, through
    /// `f` until it breaks, found by a descent of its B+ tree (the pages on one path, then the
    /// leaves after as far as `f` goes). Keys out of order in a node of the path, or outside
    /// the range its parent gives it, are damage (an error, before `f` gets a row).
    /// `Ok(false)`: the order of `probe` against a key on the path cannot be told: `f` got
    /// nothing, the rows are to be scanned.
    pub fn seek(&self, d: &Directory, probe: &Key<'_>, f: &mut RowVisit<'_>) -> Result<bool> {
        let Some(mut walk) = self.seek_walk(d, probe)? else { return Ok(false) };
        self.rows_on(&mut walk, d, f)?;
        Ok(true)
    }

    /// The descent of [`seek`](Self::seek): a walk whose rows start at the first not below
    /// `probe` ([`rows_on`](Self::rows_on) gives them). `Ok(None)`: the order of `probe`
    /// against a key on the path cannot be told.
    pub fn seek_walk(&self, d: &Directory, probe: &Key<'_>) -> Result<Option<TreeWalk>> {
        let mut walk = TreeWalk::new(self.reader.clone(), d.root, Addressing::Virtual, d.id, self.limits);
        let mut unsure = false;
        // The keys the node descended into lies between (the parent's): low, high.
        let (mut low, mut high): (Option<Vec<u8>>, Option<Vec<u8>>) = (None, None);
        walk.seek(&mut |node| {
            let keys = (0..node.len()).map(|i| Key::parse(node.key(i))).collect::<Option<Vec<_>>>();
            let keys = keys.ok_or_else(|| Error::corrupt(format!("directory {:#x}: a key too short", d.id)))?;
            check_order(d.id, &keys, probe, low.as_deref(), high.as_deref())?;
            // A leaf: its first row not below `probe`. An inner node (each child keyed by its
            // last key): the first child whose key is not below `probe`.
            let mut at = keys.len();
            for (i, k) in keys.iter().enumerate() {
                match collate(k, probe) {
                    Some(Ordering::Less) => {}
                    Some(_) => {
                        at = i;
                        break;
                    }
                    None => {
                        unsure = true;
                        return Ok(node.len());
                    }
                }
            }
            if node.level > 0 && at < keys.len() {
                if at > 0 {
                    low = Some(node.key(at - 1).to_vec());
                }
                if keys[at] != Key::Max {
                    high = Some(node.key(at).to_vec());
                }
            }
            Ok(at)
        })?;
        Ok((!unsure).then_some(walk))
    }

    /// The rows of directory `d` whose key collates equal to `probe`, through `f` until it
    /// breaks: [`seek`](Self::seek) then the rows while they match. `Ok(false)`: the order of
    /// `probe` against a key met cannot be told: what `f` got is void, the rows are to be
    /// scanned.
    pub fn seek_rows(&self, d: &Directory, probe: &Key<'_>, f: &mut RowVisit<'_>) -> Result<bool> {
        let mut told = true;
        let sought = self.seek(d, probe, &mut |k, v| {
            let k2 = Key::parse(k).ok_or_else(|| Error::corrupt(format!("directory {:#x}: a key too short", d.id)))?;
            match collate(&k2, probe) {
                Some(Ordering::Equal) => f(k, v),
                Some(Ordering::Greater) => Ok(ControlFlow::Break(())),
                Some(Ordering::Less) => Err(Error::corrupt(format!("directory {:#x}: keys out of order", d.id))),
                None => {
                    told = false;
                    Ok(ControlFlow::Break(()))
                }
            }
        })?;
        Ok(sought && told)
    }

    /// Call `f` with the (key, value) leaf entries of the node embedded at the start of `value`,
    /// reading the pages of table `table` it references.
    fn embedded(&self, value: &[u8], table: u64, f: &mut Visit<'_>) -> Result<()> {
        let mut nodes = 0u64;
        let root = Node::parse_at(Page { data: value.to_vec(), physical: Vec::new() }, 0)?;
        self.descend(root, table, 0, &mut nodes, f)
    }

    fn descend(&self, node: Node, table: u64, depth: usize, nodes: &mut u64, f: &mut Visit<'_>) -> Result<()> {
        if node.level == 0 {
            for i in 0..node.len() {
                f(node.key(i), node.value(i))?;
            }
            return Ok(());
        }
        let refs = self.children(&node, table, depth, nodes)?;
        self.read_children(&refs, node.level, table, &mut |page| {
            self.descend(Node::parse(page)?, table, depth + 1, nodes, f)
        })
    }

    /// The child page references of `node` (at `depth`), counted against the limits.
    fn children(&self, node: &Node, table: u64, depth: usize, nodes: &mut u64) -> Result<Vec<PageRef>> {
        *nodes += node.len() as u64;
        if *nodes > self.limits.max_tree_nodes {
            return Err(Error::limit(format!("table {table:#x}: more than {} nodes", self.limits.max_tree_nodes)));
        }
        if depth + 1 >= self.limits.max_tree_depth {
            return Err(Error::limit(format!("table {table:#x}: deeper than {}", self.limits.max_tree_depth)));
        }
        (0..node.len()).map(|i| PageRef::parse(node.value(i))).collect()
    }

    /// Read the child pages `refs` of a node of `level`, close ones together, each checked
    /// one level below, in order.
    fn read_children(
        &self,
        refs: &[PageRef],
        level: u8,
        table: u64,
        f: &mut dyn FnMut(Page) -> Result<()>,
    ) -> Result<()> {
        // A file record's pages belong to the table of the directory they were written for: on
        // ReFS 3.1 a moved file's record goes to the new directory and keeps them.
        let refs: Vec<_> = refs.iter().map(|&r| (r, table)).collect();
        self.reader.read_nodes_of(&refs, Addressing::Virtual, &|_, t| t >= object::FS_METADATA, &mut |_, page| {
            let page = page?;
            let child = Index::parse(&page.data, crate::format::layout::PAGE_HEADER_LEN)?;
            if level.checked_sub(1) != Some(child.level) {
                return Err(Error::corrupt(format!(
                    "table {table:#x}: node of level {} under level {level}",
                    child.level
                )));
            }
            f(page)
        })
    }

    /// The extents of the extent table embedded at the start of `value`, sorted by VCN.
    fn extents(&self, value: &[u8], table: u64) -> Result<Vec<Extent>> {
        let mut out = Vec::new();
        let mut nodes = 0u64;
        self.extent_node(value, 0, table, 0, &mut nodes, &mut out)?;
        out.sort_unstable_by_key(|e| e.vcn);
        for w in out.windows(2) {
            if w[0].vcn + w[0].clusters > w[1].vcn {
                return Err(Error::corrupt(format!("extents overlap at VCN {:#x}", w[1].vcn)));
            }
        }
        Ok(out)
    }

    fn extent_node(
        &self,
        p: &[u8],
        ir: usize,
        table: u64,
        depth: usize,
        nodes: &mut u64,
        out: &mut Vec<Extent>,
    ) -> Result<()> {
        let idx = Index::parse(p, ir)?;
        if idx.level > 0 {
            let node = Node::parse_at(Page { data: p.to_vec(), physical: Vec::new() }, ir)?;
            let refs = self.children(&node, table, depth, nodes)?;
            return self.read_children(&refs, node.level, table, &mut |page| {
                self.extent_node(&page.data, crate::format::layout::PAGE_HEADER_LEN, table, depth + 1, nodes, out)
            });
        }
        for e in idx.entries {
            if e < idx.area.start || e + EXTENT_RECORD > idx.area.end {
                return Err(Error::corrupt(format!("extent record at {e:#x} outside the data area")));
            }
            let r = slice(p, e, EXTENT_RECORD)?;
            let (vlcn, vcn, n) = (u64_at(r, 0)?, u64_at(r, 0x0C)?, u64::from(u32_at(r, 0x14)?));
            if n == 0 {
                continue;
            }
            let lcn = self.map.translate_run(vlcn, n)?;
            let c = u64::from(self.reader.cluster_bytes());
            let past = vcn.checked_add(n).and_then(|end| end.checked_mul(c)).is_none();
            if lcn.checked_add(n).is_none_or(|end| end > self.clusters) || past {
                return Err(Error::corrupt(format!("extent {vcn:#x}+{n:#x} at LCN {lcn:#x} past the volume")));
            }
            if out.len() >= self.limits.max_file_extents {
                return Err(Error::limit(format!("more than {} extents", self.limits.max_file_extents)));
            }
            out.push(Extent { vcn, lcn, clusters: n });
        }
        Ok(())
    }

    /// A non-resident stream from its extent table `value`.
    fn extent_stream(&self, name: Option<String>, value: &[u8], table: u64) -> Result<Stream> {
        if u32_at(value, 0)? != EXTENT_ROOT {
            return Err(Error::corrupt(format!("extent table root of {:#x} bytes", u32_at(value, 0)?)));
        }
        let s = self.format.sizes();
        Ok(Stream {
            name,
            resident: false,
            allocation: u64_at(value, s)?,
            size: u64_at(value, s + 8)?,
            valid: u64_at(value, s + 0x10)?,
            allocated: u64_at(value, s + 0x18)?,
            extents: self.extents(value, table)?,
            data: Vec::new(),
        })
    }

    /// Parse the file record `record` of directory `dir` (kept under `name`).
    pub fn file(&self, dir: u64, name: Option<String>, record: &[u8]) -> Result<FileEntry> {
        let root = u32_at(record, 0)? as usize;
        if root < RECORD_ROOT {
            return Err(Error::corrupt(format!("file record root of {root:#x} bytes")));
        }
        let mut e = FileEntry {
            dir,
            id: u64_at(record, 0x80)?,
            name,
            created: u64_at(record, 0x28)?,
            modified: u64_at(record, 0x30)?,
            changed: u64_at(record, 0x38)?,
            accessed: u64_at(record, 0x40)?,
            attributes: u32_at(record, 0x48)?,
            security: SecurityKey { hash: u32_at(record, 0x50)?, index: u32_at(record, 0x54)? },
            reparse_tag: 0,
            reparse: None,
            links: Vec::new(),
            size: u64_at(record, 0x58)?,
            allocated: u64_at(record, 0x60)?,
            usn: u64_at(record, 0x68)?,
            usn_journal: u64_at(record, 0x70)?,
            streams: Vec::new(),
            incomplete: false,
        };
        if e.attributes & REPARSE_POINT != 0 {
            e.reparse_tag = u32_at(record, 0x7C)?;
        }
        let (mut reparse, mut links) = (None, Vec::new());
        let mut incomplete = false;
        let mut data: Option<Stream> = None;
        // Named streams: (stream id or none when resident, the stream) and extent tables by id.
        let mut named: Vec<(Option<u64>, Stream)> = Vec::new();
        let mut tables: Vec<(u64, Vec<u8>)> = Vec::new();
        // 3.1 named streams: (name, offset, chunk).
        let mut chunks: Vec<(String, u32, Vec<u8>)> = Vec::new();
        let format = self.format;
        self.embedded(record, dir, &mut |k, v| {
            match format {
                Format::V3_1 => match u16_at(k, 8)? {
                    ATTR_DATA => set_once(&mut data, self.extent_stream(None, v, dir)?)?,
                    ATTR_NAMED_DATA => {
                        let (name, off) = (utf16(slice(k, 0x0C, k.len().saturating_sub(0x0C))?), u32_at(k, 4)?);
                        // Always resident in Windows' volumes (at most 128 KiB, in chunks); one
                        // that is not cannot be read here.
                        incomplete |= off == 0 && u32_at(v, 0)? == EXTENT_ROOT;
                        chunks.push((name, off, v.to_vec()));
                    }
                    _ => {}
                },
                Format::V3_5 if u32_at(k, 8)? & KEY_TYPED != 0 => match u16_at(k, 0x0C)? {
                    ATTR_DATA if k.len() <= 0x10 => set_once(&mut data, resident(None, v)?)?,
                    ATTR_DATA if u64_at(k, 0x10)? == SUB_EXTENTS => {
                        set_once(&mut data, self.extent_stream(None, v, dir)?)?;
                    }
                    ATTR_REPARSE => {
                        reparse = Some(slice(v, u32_at(v, 8)? as usize, u32_at(v, 4)? as usize)?.to_vec());
                    }
                    ATTR_LINK => {
                        let name = slice(k, 0x20, k.len().saturating_sub(0x20))?;
                        links.push((
                            u64_at(k, 0x10)?,
                            name.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect(),
                        ));
                    }
                    ATTR_NAMED_DATA => {
                        let name = Some(utf16(slice(k, 0x10, k.len().saturating_sub(0x10))?));
                        if u32_at(v, 0)? & STREAM_NON_RESIDENT != 0 {
                            named.push((Some(u64_at(v, header_len(v)?)?), Stream { name, ..Stream::default() }));
                        } else {
                            named.push((None, resident(name, v)?));
                        }
                    }
                    _ => {}
                },
                Format::V3_5 => {
                    if let Some((id, sub)) = composite(k)
                        && sub == SUB_EXTENTS
                    {
                        tables.push((id, v.to_vec()));
                    }
                }
            }
            Ok(())
        })?;
        e.incomplete = incomplete;
        (e.reparse, e.links) = (reparse, links);
        e.streams.extend(data);
        if !incomplete {
            e.streams.extend(chunked(chunks)?);
        }
        for (id, mut s) in named {
            if let Some(id) = id {
                let Some((_, v)) = tables.iter().find(|(t, _)| *t == id) else {
                    return Err(Error::corrupt(format!("stream {:?}: no extent table {id:#x}", s.name)));
                };
                s = self.extent_stream(s.name, v, dir)?;
            }
            e.streams.push(s);
        }
        Ok(e)
    }
}

/// The keys of a node of directory table `dir` in order, and between `low` and `high` (from
/// its parent: the key of the child before, the node's own; either may equal a key here: rows
/// equal by upper case), where it can be told: keys of other types than `probe`'s are checked
/// by type only. An inner node's last key may be [`Key::Max`]: its last child goes on to
/// `high`.
fn check_order(dir: u64, keys: &[Key<'_>], probe: &Key<'_>, low: Option<&[u8]>, high: Option<&[u8]>) -> Result<()> {
    let bad = || Error::corrupt(format!("directory {dir:#x}: keys out of order"));
    let told = |a: &Key<'_>, b: &Key<'_>| {
        if a.ty() == b.ty() && a.ty() != probe.ty() { None } else { collate(a, b) }
    };
    if keys.windows(2).any(|w| told(&w[0], &w[1]) == Some(Ordering::Greater)) {
        return Err(bad());
    }
    if let (Some(l), Some(first)) = (low, keys.first()) {
        let l = Key::parse(l).ok_or_else(bad)?;
        if told(first, &l) == Some(Ordering::Less) {
            return Err(bad());
        }
    }
    if let (Some(h), Some(last)) = (high, keys.iter().rfind(|k| **k != Key::Max)) {
        let h = Key::parse(h).ok_or_else(bad)?;
        if told(last, &h) == Some(Ordering::Greater) {
            return Err(bad());
        }
    }
    Ok(())
}

/// ReFS 3.1 to 3.4 named streams: resident, the value (a 3.5-style header, then the data)
/// split over attributes of the same name whose key gives each piece's offset in it.
fn chunked(mut chunks: Vec<(String, u32, Vec<u8>)>) -> Result<Vec<Stream>> {
    chunks.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
    let mut out = Vec::new();
    let mut i = 0;
    while i < chunks.len() {
        let name = chunks[i].0.clone();
        let mut value: Vec<u8> = Vec::new();
        while i < chunks.len() && chunks[i].0 == name {
            if chunks[i].1 as usize != value.len() {
                return Err(Error::corrupt(format!(
                    "stream {name}: piece at {:#x}, {:#x} expected",
                    chunks[i].1,
                    value.len()
                )));
            }
            value.extend_from_slice(&chunks[i].2);
            i += 1;
        }
        out.push(resident(Some(name), &value)?);
    }
    Ok(out)
}

fn set_once(slot: &mut Option<Stream>, s: Stream) -> Result<()> {
    if slot.replace(s).is_some() {
        return Err(Error::corrupt("two unnamed data streams"));
    }
    Ok(())
}

/// Length of a 3.5 stream header: the data (or a non-resident stream's id) follows it.
fn header_len(v: &[u8]) -> Result<usize> {
    Ok((u32_at(v, 8)? as usize).saturating_add(u32_at(v, 0x0C)? as usize))
}

/// A resident stream (3.5; 3.1 named streams once their pieces are joined): sizes at 0x18
/// (allocation, size, valid, allocated), then the data.
fn resident(name: Option<String>, v: &[u8]) -> Result<Stream> {
    let size = u64_at(v, 0x20)?;
    let data = slice(v, header_len(v)?, usize::try_from(size).unwrap_or(usize::MAX))?.to_vec();
    Ok(Stream {
        name,
        resident: true,
        allocation: u64_at(v, 0x18)?,
        size,
        valid: u64_at(v, 0x28)?,
        allocated: u64_at(v, 0x30)?,
        extents: Vec::new(),
        data,
    })
}

/// A 3.5 composite key: the stream id (its 8-byte field) and the u64 starting its 0x18-byte
/// field; `None` for another shape (including descriptors or fields outside the key).
fn composite(k: &[u8]) -> Option<(u64, u64)> {
    let count = u32_at(k, 8).ok()? as usize;
    if count > 8 {
        return None;
    }
    let (mut id, mut sub) = (None, None);
    for i in 0..count {
        let d = 0x10 + 8 * i;
        let (size, off) = (u16_at(k, d + 4).ok()?, 8 + usize::from(u16_at(k, d + 6).ok()?));
        match size {
            8 => id = Some(u64_at(k, off).ok()?),
            0x18 => sub = Some(u64_at(k, off).ok()?),
            _ => {}
        }
    }
    id.zip(sub)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn composite_keys() {
        let mut k = vec![0u8; 0x50];
        k[8] = 3;
        for (i, (kind, size, off)) in [(0x0Cu16, 2u16, 0x20u16), (1, 8, 0x28), (0x0E, 0x18, 0x30)].iter().enumerate() {
            let d = 0x10 + 8 * i;
            k[d + 2..d + 4].copy_from_slice(&kind.to_le_bytes());
            k[d + 4..d + 6].copy_from_slice(&size.to_le_bytes());
            k[d + 6..d + 8].copy_from_slice(&off.to_le_bytes());
        }
        k[0x30..0x38].copy_from_slice(&0xF000u64.to_le_bytes());
        k[0x38..0x40].copy_from_slice(&SUB_EXTENTS.to_le_bytes());
        assert_eq!(composite(&k), Some((0xF000, SUB_EXTENTS)));
        k[8] = 2;
        assert_eq!(composite(&k), None);
        k[8] = 0x40;
        assert_eq!(composite(&k), None);
        // Descriptors past a short key: another shape, not damage.
        k[8] = 3;
        assert_eq!(composite(&k[..0x14]), None);
    }

    #[test]
    fn rows() {
        let mut key = vec![0x30, 0, 2, 0];
        key.extend("d1".encode_utf16().flat_map(u16::to_le_bytes));
        let mut v = vec![0u8; 0x48];
        v[8..16].copy_from_slice(&0x702u64.to_le_bytes());
        assert!(matches!(dir_entry(&key, &v).unwrap(), DirEntry::Directory { ref name, id: 0x702 } if name == "d1"));
        v[0] = 3;
        assert!(matches!(dir_entry(&key, &v).unwrap(), DirEntry::Link { dir: 0x702, id: 3, .. }));
        key[2] = 1;
        assert!(matches!(dir_entry(&key, &v).unwrap(), DirEntry::File { name: Some(_), .. }));
        key[2] = 9;
        assert!(dir_entry(&key, &v).is_err());
        assert!(matches!(dir_entry(&[0x40, 0, 0, 0x80], &v).unwrap(), DirEntry::File { name: None, .. }));
        assert!(matches!(dir_entry(&[0x20, 0, 0, 0x80], &v).unwrap(), DirEntry::Other));
    }

    /// A 3.5-style resident value: header, then `data`.
    fn resident_value(data: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 0x38];
        v[8..12].copy_from_slice(&0x38u32.to_le_bytes());
        v[0x18..0x20].copy_from_slice(&4096u64.to_le_bytes());
        v[0x20..0x28].copy_from_slice(&(data.len() as u64).to_le_bytes());
        v[0x28..0x30].copy_from_slice(&(data.len() as u64).to_le_bytes());
        v.extend_from_slice(data);
        v
    }

    /// ReFS 3.1 named streams: pieces joined in offset order whatever order they come in, one
    /// stream per name; a piece that does not follow the one before it is damage.
    #[test]
    fn named_stream_pieces_join_in_order() {
        let v = resident_value(b"abcdef");
        let pieces = vec![
            ("s".to_string(), 0x20, v[0x20..].to_vec()),
            ("a".to_string(), 0, resident_value(b"z")),
            ("s".to_string(), 0, v[..0x20].to_vec()),
        ];
        let out = chunked(pieces).unwrap();
        let got: Vec<_> = out.iter().map(|s| (s.name.as_deref(), s.resident, s.size, &s.data[..])).collect();
        assert_eq!(got, [(Some("a"), true, 1, &b"z"[..]), (Some("s"), true, 6, &b"abcdef"[..])]);
        assert_eq!(out[1].allocation, 4096);

        let gap = vec![("s".to_string(), 0, v[..0x20].to_vec()), ("s".to_string(), 0x24, v[0x24..].to_vec())];
        let e = chunked(gap).unwrap_err();
        assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Corrupt);
        assert!(e.to_string().contains("stream s: piece at 0x24, 0x20 expected"), "{e}");
        // Joined, but shorter than the size its header gives.
        let short = vec![("s".to_string(), 0, v[..0x3A].to_vec())];
        assert!(chunked(short).is_err());
        assert!(chunked(Vec::new()).unwrap().is_empty());
    }
}
