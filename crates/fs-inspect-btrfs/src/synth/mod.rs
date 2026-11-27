//! Synthetic single-device btrfs images: chunk tree, root tree, extent tree (metadata and
//! data extent items), FS trees with inode, inode ref, file extent and directory entry
//! items, and an optional tree log. [`encode`] has the encoders (shared with the format tests'
//! own builder).
// Test tooling: a broken synthetic image should stop the test that builds it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod encode;

use crate::format::chunk::{CHUNK_ITEM_KEY, bg};
use crate::format::csum::CsumType;
use crate::format::fs::keys;
use crate::format::superblock::{
    BACKUP_ROOT_SIZE, BACKUP_ROOTS_OFFSET, SUPER_OFFSETS, SUPER_SIZE, SYS_CHUNK_ARRAY_OFFSET,
};
use crate::format::tree::{HEADER_SIZE, ITEM_SIZE, Key};
use fs_inspect_core::bytes::{put_u16, put_u32, put_u64};
use std::collections::BTreeMap;

pub const MIB: u64 = 1 << 20;
/// `BTRFS_ROOT_REF_KEY`, `BTRFS_ROOT_BACKREF_KEY`.
const ROOT_REF: u8 = 156;
const ROOT_BACKREF: u8 = 144;
/// `BTRFS_ROOT_TREE_DIR_OBJECTID`.
const ROOT_TREE_DIR: u64 = 6;
pub const KIB: u64 = 1 << 10;
pub use encode::{FSID, NS};
pub const DEV: u64 = 24 * MIB;
pub const SYS_L: u64 = MIB;
pub const META_L: u64 = 4 * MIB;
pub const META_LEN: u64 = MIB;
pub const DATA_L: u64 = 16 * MIB;
/// Device offset of data copy 0 and (DUP) copy 1.
pub const DATA_P: u64 = 4 * MIB;
pub const DATA_P2: u64 = 12 * MIB;

/// Logical address `x` bytes into the data chunk.
pub fn d(x: u64) -> u64 {
    DATA_L + x
}
/// Device offset of `d(x)`, copy 0 / copy 1.
pub fn p(x: u64) -> u64 {
    DATA_P + x
}
pub fn p2(x: u64) -> u64 {
    DATA_P2 + x
}

#[derive(Clone, Debug)]
pub enum Fe {
    Inline {
        off: u64,
        generation: u64,
        len: u64,
    },
    Reg {
        off: u64,
        generation: u64,
        prealloc: bool,
        compressed: bool,
        bytenr: u64,
        disk_len: u64,
        offset: u64,
        len: u64,
    },
}

/// A whole plain extent.
pub fn reg(off: u64, generation: u64, bytenr: u64, len: u64) -> Fe {
    Fe::Reg { off, generation, prealloc: false, compressed: false, bytenr, disk_len: len, offset: 0, len }
}
/// Part `[offset, offset + len)` of a disk extent of `disk_len` bytes.
pub fn part(off: u64, generation: u64, bytenr: u64, disk_len: u64, offset: u64, len: u64) -> Fe {
    Fe::Reg { off, generation, prealloc: false, compressed: false, bytenr, disk_len, offset, len }
}

impl Fe {
    fn end(&self) -> u64 {
        match *self {
            Fe::Inline { off, len, .. } => off + len,
            Fe::Reg { off, len, .. } => off + len,
        }
    }
    /// Its file extent item.
    pub fn bytes(&self) -> Vec<u8> {
        match *self {
            Fe::Inline { generation, len, .. } => {
                let mut b = vec![0u8; 21 + len as usize];
                put_u64(&mut b, 0, generation);
                put_u64(&mut b, 8, len);
                b
            }
            Fe::Reg { generation, prealloc, compressed, bytenr, disk_len, offset, len, .. } => {
                let mut b = vec![0u8; 53];
                put_u64(&mut b, 0, generation);
                put_u64(&mut b, 8, if compressed { (offset + len).max(disk_len) } else { disk_len });
                b[16] = u8::from(compressed);
                b[20] = if prealloc { 2 } else { 1 };
                put_u64(&mut b, 21, bytenr);
                put_u64(&mut b, 29, disk_len);
                put_u64(&mut b, 37, offset);
                put_u64(&mut b, 45, len);
                b
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct File {
    pub ino: u64,
    pub generation: u64,
    pub transid: u64,
    pub size: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub flags: u64,
    pub nlink: u32,
    pub mode: u32,
    pub name: String,
    /// The directory holding it (its inode ref).
    pub parent: u64,
    pub extents: Vec<Fe>,
}

impl File {
    pub fn new(ino: u64, extents: Vec<Fe>) -> Self {
        let size = extents.iter().map(Fe::end).max().unwrap_or(0);
        File {
            ino,
            generation: 3,
            transid: 5,
            size,
            mtime: 100,
            ctime: 100,
            flags: 0,
            nlink: 1,
            mode: 0o100_644,
            name: format!("f{ino}"),
            parent: 256,
            extents,
        }
    }
    pub fn with_flags(mut self, flags: u64) -> Self {
        self.flags = flags;
        self
    }

    /// Its inode item.
    pub fn inode_item(&self) -> Vec<u8> {
        let mut b = vec![0u8; 160];
        put_u64(&mut b, 0, self.generation);
        put_u64(&mut b, 8, self.transid);
        put_u64(&mut b, 16, self.size);
        put_u64(&mut b, 24, self.size);
        put_u32(&mut b, 40, self.nlink);
        put_u32(&mut b, 52, self.mode);
        put_u64(&mut b, 64, self.flags);
        put_u64(&mut b, 124, self.ctime);
        put_u64(&mut b, 136, self.mtime);
        b
    }

    fn items(&self) -> Vec<(Key, Vec<u8>, u64)> {
        self.items_at(2)
    }

    /// Its items, its inode ref naming directory index `index`.
    fn items_at(&self, index: u64) -> Vec<(Key, Vec<u8>, u64)> {
        let mut v = vec![(Key::new(self.ino, keys::INODE_ITEM, 0), self.inode_item(), 0)];
        let mut r = vec![0u8; 10 + self.name.len()];
        put_u64(&mut r, 0, index);
        put_u16(&mut r, 8, self.name.len() as u16);
        r[10..].copy_from_slice(self.name.as_bytes());
        v.push((Key::new(self.ino, keys::INODE_REF, self.parent), r, 0));
        for fe in &self.extents {
            let off = match *fe {
                Fe::Inline { off, .. } | Fe::Reg { off, .. } => off,
            };
            v.push((Key::new(self.ino, keys::EXTENT_DATA, off), fe.bytes(), 0));
        }
        v
    }
}

#[derive(Clone, Debug)]
pub struct Subvol {
    pub id: u64,
    pub uuid: [u8; 16],
    pub refs: u32,
    pub files: Vec<File>,
    /// Directory entries: (directory inode, name, the inode named, its `BTRFS_FT_*`), each a
    /// `DIR_INDEX` item (numbered from 2 in order) and part of a `DIR_ITEM` (by name hash).
    pub entries: Vec<(u64, String, u64, u8)>,
    /// Other items of its tree (extended attributes, extended refs, ...).
    pub items: Vec<(Key, Vec<u8>)>,
}

impl Subvol {
    pub fn new(id: u64, files: Vec<File>) -> Self {
        let mut uuid = [0u8; 16];
        uuid[..8].copy_from_slice(&id.to_le_bytes());
        Subvol { id, uuid, refs: 1, files, entries: Vec::new(), items: Vec::new() }
    }

    /// The `DIR_ITEM` and `DIR_INDEX` items of [`entries`](Self::entries).
    fn entry_items(&self) -> Vec<(Key, Vec<u8>, u64)> {
        let mut hashed: BTreeMap<Key, Vec<u8>> = BTreeMap::new();
        let mut out = Vec::new();
        for (i, (dir, name, ino, ty)) in self.entries.iter().enumerate() {
            let mut d = vec![0u8; 30 + name.len()];
            d[..17].copy_from_slice(&encode::key_bytes(Key::new(*ino, keys::INODE_ITEM, 0)));
            put_u64(&mut d, 17, 1);
            put_u16(&mut d, 27, name.len() as u16);
            d[29] = *ty;
            d[30..].copy_from_slice(name.as_bytes());
            let hash = crate::format::lookup::name_hash(name.as_bytes());
            hashed.entry(Key::new(*dir, 84, hash)).or_default().extend_from_slice(&d);
            out.push((Key::new(*dir, 96, i as u64 + 2), d, 0));
        }
        out.extend(hashed.into_iter().map(|(k, d)| (k, d, 0)));
        out
    }
    pub fn file_mut(&mut self, ino: u64) -> &mut File {
        self.files.iter_mut().find(|f| f.ino == ino).unwrap()
    }
}

#[derive(Clone, Debug)]
pub struct Img {
    pub generation: u64,
    pub data_dup: bool,
    pub subvols: Vec<Subvol>,
    /// Extent item generation per data extent (default: the oldest file extent item
    /// referencing it).
    pub extent_gens: BTreeMap<u64, u64>,
    /// Extra data extent items `(bytenr, len, generation)`.
    pub extra_extents: Vec<(u64, u64, u64)>,
    /// Files in the tree log: `(root id, file)`.
    pub log: Vec<(u64, File)>,
    /// Other items in the tree log: `(root id, key, data)`.
    pub log_items: Vec<(u64, Key, Vec<u8>)>,
    /// Inodes of the root tree (the v1 free space cache).
    pub root_files: Vec<File>,
    /// Logical data ranges with crc32c checksums (a csum tree when not empty), and the
    /// generation of its blocks (0: the image's). Each sum is the crc32c of a zero 4 KiB
    /// block, as the image's data is zeros.
    pub csums: Vec<(u64, u64)>,
    pub csum_gen: u64,
    /// Superblock backup roots `(tree root, generation)`.
    pub backups: Vec<(u64, u64)>,
    /// Where subvolumes hang: `(subvolume, the subvolume holding it, the directory there,
    /// name)`, each a `ROOT_REF` and a `ROOT_BACKREF` item.
    pub root_refs: Vec<(u64, u64, u64, String)>,
    /// The subvolume the root tree's `default` entry names (none: no entry).
    pub default_subvol: Option<u64>,
}

/// `(logical, node)` pairs.
type Nodes = Vec<(u64, Vec<u8>)>;

struct Tree {
    nodes: Vec<(u64, Vec<u8>)>,
    root: u64,
    level: u8,
    generation: u64,
}

pub use encode::root_item;
use encode::{chunk_item as chunk_item_on, internal, key_bytes, leaf};

fn chunk_item(length: u64, ty: u64, phys: &[u64]) -> Vec<u8> {
    chunk_item_on(length, ty, phys, 1)
}

/// Leaves of at most one node's worth of items, then internal levels of up to 100 pointers.
/// `fixed_gen`: every node's generation; otherwise the newest item generation below it.
fn build_tree(items: &[(Key, Vec<u8>, u64)], owner: u64, alloc: &mut u64, fixed_gen: Option<u64>) -> Tree {
    let cap = NS - HEADER_SIZE;
    let mut groups: Vec<&[(Key, Vec<u8>, u64)]> = Vec::new();
    let mut start = 0;
    let mut used = 0;
    for (i, it) in items.iter().enumerate() {
        let need = ITEM_SIZE + it.1.len();
        if used + need > cap {
            groups.push(&items[start..i]);
            start = i;
            used = 0;
        }
        used += need;
    }
    groups.push(&items[start..]);
    let mut nodes = Vec::new();
    // (first key, logical, generation) of the current level.
    let mut level_nodes: Vec<(Key, u64, u64)> = Vec::new();
    for g in groups {
        let l = *alloc;
        *alloc += NS as u64;
        let generation = fixed_gen.unwrap_or_else(|| g.iter().map(|x| x.2).max().unwrap_or(1).max(1));
        nodes.push((l, leaf(l, owner, generation, g.iter().map(|(k, d, _)| (*k, d.as_slice())))));
        level_nodes.push((g.first().map_or(Key::default(), |x| x.0), l, generation));
    }
    let mut level = 0u8;
    while level_nodes.len() > 1 {
        level += 1;
        let mut next = Vec::new();
        for g in level_nodes.chunks(100) {
            let l = *alloc;
            *alloc += NS as u64;
            let generation = fixed_gen.unwrap_or_else(|| g.iter().map(|x| x.2).max().unwrap_or(1));
            nodes.push((l, internal(l, level, owner, generation, g)));
            next.push((g[0].0, l, generation));
        }
        level_nodes = next;
    }
    let (_, root, generation) = level_nodes[0];
    Tree { nodes, root, level, generation }
}

impl Img {
    pub fn new(generation: u64, subvols: Vec<Subvol>) -> Self {
        Img {
            generation,
            data_dup: false,
            subvols,
            extent_gens: BTreeMap::new(),
            extra_extents: Vec::new(),
            log: Vec::new(),
            log_items: Vec::new(),
            root_files: Vec::new(),
            csums: Vec::new(),
            csum_gen: 0,
            backups: Vec::new(),
            root_refs: Vec::new(),
            default_subvol: None,
        }
    }

    pub fn subvol(&mut self, id: u64) -> &mut Subvol {
        self.subvols.iter_mut().find(|s| s.id == id).unwrap()
    }

    fn chunks(&self) -> Vec<(u64, u64, u64, Vec<u64>)> {
        let data = if self.data_dup {
            (DATA_L, 8 * MIB, bg::DATA | bg::DUP, vec![DATA_P, DATA_P2])
        } else {
            (DATA_L, 16 * MIB, bg::DATA, vec![DATA_P])
        };
        vec![
            (SYS_L, 256 * KIB, bg::SYSTEM | bg::DUP, vec![MIB, MIB + 512 * KIB]),
            (META_L, META_LEN, bg::METADATA | bg::DUP, vec![2 * MIB, 3 * MIB]),
            data,
        ]
    }

    /// Data extent items `(bytenr, len, generation)` of the committed trees.
    pub fn data_extents(&self) -> Vec<(u64, u64, u64)> {
        let mut m: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
        for f in self.subvols.iter().flat_map(|s| &s.files).chain(&self.root_files) {
            {
                for fe in &f.extents {
                    if let Fe::Reg { generation, bytenr, disk_len, .. } = *fe
                        && bytenr != 0
                    {
                        let e = m.entry(bytenr).or_insert((disk_len, generation));
                        e.1 = e.1.min(generation);
                    }
                }
            }
        }
        let mut v: Vec<(u64, u64, u64)> =
            m.into_iter().map(|(b, (l, g))| (b, l, self.extent_gens.get(&b).copied().unwrap_or(g))).collect();
        v.extend(self.extra_extents.iter().copied());
        v.sort();
        v
    }

    /// Every tree node and the superblock fields: (nodes, root tree, log root).
    fn trees(&self) -> (Nodes, Tree, Option<Tree>) {
        let generation = self.generation;
        let mut alloc = META_L;
        let mut nodes: Vec<(u64, Vec<u8>)> = Vec::new();

        // Chunk tree.
        let mut dev_item = vec![0u8; 98];
        put_u64(&mut dev_item, 0, 1);
        put_u64(&mut dev_item, 8, DEV);
        let mut chunk_items = vec![(Key::new(1, keys::DEV_ITEM, 1), dev_item, 0)];
        for (l, len, ty, phys) in self.chunks() {
            chunk_items.push((Key::new(256, CHUNK_ITEM_KEY, l), chunk_item(len, ty, &phys), 0));
        }
        let mut sys_alloc = SYS_L;
        let chunk = build_tree(&chunk_items, 3, &mut sys_alloc, Some(generation));
        nodes.extend(chunk.nodes);

        // FS trees.
        let mut root_items: Vec<(Key, Vec<u8>, u64)> = Vec::new();
        for s in &self.subvols {
            let mut dir = vec![0u8; 160];
            put_u64(&mut dir, 0, 1);
            put_u32(&mut dir, 40, 1);
            put_u32(&mut dir, 52, 0o40_755);
            // The root directory and its ref to itself (`..`, index 0).
            let mut dotdot = vec![0u8; 12];
            put_u16(&mut dotdot, 8, 2);
            dotdot[10..].copy_from_slice(b"..");
            let mut items =
                vec![(Key::new(256, keys::INODE_ITEM, 0), dir, 0), (Key::new(256, keys::INODE_REF, 256), dotdot, 0)];
            for f in &s.files {
                // Its ref names the index of its entry (when the subvolume lists one).
                let index = s
                    .entries
                    .iter()
                    .position(|(d, n, i, _)| (*d, n, *i) == (f.parent, &f.name, f.ino))
                    .map_or(2, |p| p as u64 + 2);
                items.extend(f.items_at(index));
            }
            items.extend(s.entry_items());
            items.extend(s.items.iter().map(|(k, d)| (*k, d.clone(), 0)));
            items.sort_by_key(|x| x.0);
            let t = build_tree(&items, s.id, &mut alloc, Some(generation));
            nodes.extend(t.nodes);
            root_items.push((
                Key::new(s.id, keys::ROOT_ITEM, 0),
                root_item(t.root, t.level, t.generation, s.refs, s.uuid),
                0,
            ));
        }

        for f in &self.root_files {
            root_items.extend(f.items());
        }
        for (sub, holder, dir, name) in &self.root_refs {
            let mut r = vec![0u8; 18 + name.len()];
            put_u64(&mut r, 0, *dir);
            put_u64(&mut r, 8, 2);
            put_u16(&mut r, 16, name.len() as u16);
            r[18..].copy_from_slice(name.as_bytes());
            root_items.push((Key::new(*holder, ROOT_REF, *sub), r.clone(), 0));
            root_items.push((Key::new(*sub, ROOT_BACKREF, *holder), r, 0));
        }
        if let Some(sub) = self.default_subvol {
            let name = b"default";
            let mut d = vec![0u8; 30 + name.len()];
            d[..17].copy_from_slice(&key_bytes(Key::new(sub, keys::ROOT_ITEM, u64::MAX)));
            put_u64(&mut d, 17, 1);
            put_u16(&mut d, 27, name.len() as u16);
            d[29] = 2;
            d[30..].copy_from_slice(name);
            let hash = crate::format::lookup::name_hash(name);
            root_items.push((Key::new(ROOT_TREE_DIR, 84, hash), d, 0));
        }
        if !self.csums.is_empty() {
            let cgen = if self.csum_gen == 0 { generation } else { self.csum_gen };
            let zero_block_sum = CsumType::Crc32c.compute(&[0u8; 4096]).unwrap()[..4].to_vec();
            let items: Vec<(Key, Vec<u8>, u64)> = self
                .csums
                .iter()
                .map(|&(l, n)| {
                    (
                        Key::new(keys::EXTENT_CSUM_OBJECTID, keys::EXTENT_CSUM, l),
                        zero_block_sum.repeat((n / 4096) as usize),
                        cgen,
                    )
                })
                .collect();
            let t = build_tree(&items, keys::CSUM_TREE_OBJECTID, &mut alloc, Some(cgen));
            nodes.extend(t.nodes);
            root_items.push((
                Key::new(keys::CSUM_TREE_OBJECTID, keys::ROOT_ITEM, 0),
                root_item(t.root, t.level, t.generation, 1, [0; 16]),
                0,
            ));
        }

        // Tree log (not in the extent tree).
        let mut log_addrs: Vec<u64> = Vec::new();
        let log = if self.log.is_empty() && self.log_items.is_empty() {
            None
        } else {
            let lgen = generation + 1;
            let mut by_root: BTreeMap<u64, Vec<(Key, Vec<u8>, u64)>> = BTreeMap::new();
            for (r, f) in &self.log {
                by_root.entry(*r).or_default().extend(f.items());
            }
            for (r, k, d) in &self.log_items {
                by_root.entry(*r).or_default().push((*k, d.clone(), 0));
            }
            let mut log_root_items = Vec::new();
            for (r, mut items) in by_root {
                items.sort_by_key(|x| x.0);
                let t = build_tree(&items, keys::TREE_LOG_OBJECTID, &mut alloc, Some(lgen));
                log_addrs.extend(t.nodes.iter().map(|n| n.0));
                nodes.extend(t.nodes);
                log_root_items.push((
                    Key::new(keys::TREE_LOG_OBJECTID, keys::ROOT_ITEM, r),
                    root_item(t.root, t.level, lgen, 1, [0; 16]),
                    0,
                ));
            }
            let t = build_tree(&log_root_items, keys::TREE_LOG_OBJECTID, &mut alloc, Some(lgen));
            log_addrs.extend(t.nodes.iter().map(|n| n.0));
            nodes.extend(t.nodes.iter().cloned());
            Some(t)
        };

        // Root tree: its node count depends only on its items (the extent root item has a
        // fixed size), so reserve its addresses before the extent tree is laid out.
        root_items.push((Key::new(keys::EXTENT_TREE_OBJECTID, keys::ROOT_ITEM, 0), root_item(0, 0, 0, 1, [0; 16]), 0));
        root_items.sort_by_key(|x| x.0);
        let root_count = build_tree(&root_items, 1, &mut 0, Some(generation)).nodes.len() as u64;
        let root_start = alloc;
        alloc += root_count * NS as u64;

        // Extent tree: metadata items for every committed node (its own included).
        let meta_item = |l: u64| {
            let mut d = vec![0u8; 33];
            put_u64(&mut d, 0, 1);
            put_u64(&mut d, 8, generation);
            put_u64(&mut d, 16, 2);
            (Key::new(l, keys::METADATA_ITEM, 0), d, generation)
        };
        // Log nodes are not in the extent tree.
        let mut committed: Vec<u64> = nodes.iter().map(|(l, _)| *l).filter(|l| !log_addrs.contains(l)).collect();
        committed.extend((0..root_count).map(|i| root_start + i * NS as u64));
        let ext_start = alloc;
        let mut k = 1u64;
        let ext = loop {
            let mut items: Vec<(Key, Vec<u8>, u64)> = committed.iter().map(|&l| meta_item(l)).collect();
            items.extend((0..k).map(|i| meta_item(ext_start + i * NS as u64)));
            for (b, len, g) in self.data_extents() {
                let mut e = vec![0u8; 53];
                put_u64(&mut e, 0, 1);
                put_u64(&mut e, 8, g);
                put_u64(&mut e, 16, 1);
                items.push((Key::new(b, keys::EXTENT_ITEM, len), e, g));
            }
            items.sort_by_key(|x| x.0);
            let mut a = ext_start;
            let t = build_tree(&items, 2, &mut a, None);
            if t.nodes.len() as u64 == k {
                break t;
            }
            k = t.nodes.len() as u64;
        };
        nodes.extend(ext.nodes.iter().cloned());
        let i = root_items.iter().position(|x| x.0.objectid == 2).unwrap();
        root_items[i].1 = root_item(ext.root, ext.level, ext.generation, 1, [0; 16]);
        let mut a = root_start;
        let root = build_tree(&root_items, 1, &mut a, Some(generation));
        nodes.extend(root.nodes.iter().cloned());
        assert!(alloc + k * NS as u64 <= META_L + META_LEN, "metadata chunk full");
        (nodes, root, log)
    }

    fn phys_of(&self, logical: u64) -> Vec<u64> {
        let (l, _, _, phys) =
            self.chunks().into_iter().find(|(l, len, _, _)| logical >= *l && logical < l + len).unwrap();
        phys.iter().map(|p| p + (logical - l)).collect()
    }

    fn superblock(&self, root: &Tree, log: Option<&Tree>) -> Vec<u8> {
        let mut b = vec![0u8; SUPER_SIZE];
        b[0x20..0x30].copy_from_slice(&FSID);
        put_u64(&mut b, 0x30, SUPER_OFFSETS[0]);
        b[0x40..0x48].copy_from_slice(b"_BHRfS_M");
        put_u64(&mut b, 0x48, self.generation);
        put_u64(&mut b, 0x50, root.root);
        put_u64(&mut b, 0x58, SYS_L);
        put_u64(&mut b, 0x60, log.map_or(0, |t| t.root));
        put_u64(&mut b, 0x70, DEV);
        put_u64(&mut b, 0x88, 1);
        put_u32(&mut b, 0x90, 4096);
        put_u32(&mut b, 0x94, NS as u32);
        put_u32(&mut b, 0x98, NS as u32);
        put_u32(&mut b, 0x9c, 4096);
        let (l, len, ty, phys) = self.chunks().remove(0);
        let mut arr = key_bytes(Key::new(256, CHUNK_ITEM_KEY, l)).to_vec();
        arr.extend(chunk_item(len, ty, &phys));
        put_u32(&mut b, 0xa0, arr.len() as u32);
        put_u64(&mut b, 0xa4, self.generation);
        b[0xc6] = root.level;
        b[0xc8] = log.map_or(0, |t| t.level);
        put_u64(&mut b, 0xc9, 1);
        put_u64(&mut b, 0xc9 + 8, DEV);
        b[0xc9 + 66..0xc9 + 82].copy_from_slice(&[7u8; 16]);
        b[0x12b..0x130].copy_from_slice(b"synth");
        b[SYS_CHUNK_ARRAY_OFFSET..SYS_CHUNK_ARRAY_OFFSET + arr.len()].copy_from_slice(&arr);
        for (i, (r, g)) in self.backups.iter().enumerate().take(4) {
            put_u64(&mut b, BACKUP_ROOTS_OFFSET + i * BACKUP_ROOT_SIZE, *r);
            put_u64(&mut b, BACKUP_ROOTS_OFFSET + i * BACKUP_ROOT_SIZE + 8, *g);
        }
        sign(&mut b);
        b
    }

    /// The root tree address this image will have.
    pub fn root_addr(&self) -> u64 {
        self.trees().1.root
    }

    pub fn image(&self) -> Vec<u8> {
        let (nodes, root, log) = self.trees();
        let mut img = vec![0u8; DEV as usize];
        for (l, n) in &nodes {
            let mut n = n.clone();
            sign(&mut n);
            for p in self.phys_of(*l) {
                img[p as usize..p as usize + NS].copy_from_slice(&n);
            }
        }
        let o = SUPER_OFFSETS[0] as usize;
        img[o..o + SUPER_SIZE].copy_from_slice(&self.superblock(&root, log.as_ref()));
        img
    }
}

fn sign(b: &mut [u8]) {
    encode::sign(b, CsumType::Crc32c);
}
