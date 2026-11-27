//! Synthetic APFS volumes for tests, built from a [`Model`] on a container of the
//! [container builder](super) (superblocks, checkpoint, space manager, chunk bitmaps):
//! the container object map, one volume superblock, the volume object map and an FS tree (one
//! leaf, or a root index node over two leaves) with inodes, xattr streams and extents; or, sealed
//! ([`Sealing`]), a header-less hashed FS tree, a file extent tree and integrity metadata. The
//! same model always builds the same bytes, so a test mutates the model and rebuilds.

pub use super::DESC_BASE;
use super::{Synth, put_header as header};
use crate::format::btree::SealHash;
use crate::format::checksum::seal;
use crate::format::records::{APFS_INCOMPAT_SEALED_VOLUME, BTREE_HASHED, OMAP_VAL_ENCRYPTED, OMAP_VAL_NOHEADER};
use fs_inspect_core::bytes::{put_u16, put_u32, put_u64};

pub const BS: u64 = 4096;
pub const BLOCKS: u64 = 256;
/// The container's own metadata ([`super`]) ends before this block: the chunk-info block
/// at `META_BASE` and the chunk bitmaps after it.
pub const NX_OMAP: u64 = 24;
pub const NX_OMAP_TREE: u64 = 25;
pub const VOL_SB: u64 = 26;
pub const VOL_OMAP: u64 = 27;
pub const VOL_OMAP_TREE: u64 = 28;
/// FS tree nodes: root at 29, leaves from 30 when there are several ([`Model::leaves`]).
pub const FS_ROOT: u64 = 29;
/// A sealed volume's integrity metadata and file extent tree.
pub const INTEGRITY: u64 = 32;
pub const FEXT_TREE: u64 = 33;
pub const VOL_OID: u64 = 0x402;
pub const FS_ROOT_OID: u64 = 0x500;
pub const INTEGRITY_OID: u64 = 0x503;
/// Where the integrity metadata holds the root hash (`im_root_hash_offset`).
pub const ROOT_HASH_AT: usize = 0x40;
const BPC: u32 = 128;
const PHYSICAL: u32 = 0x4000_0000;
/// Node flags of a sealed volume's FS tree: no object header, hashed (`BTNODE_HASHED`).
const SEALED_NODE: u16 = 0x10 | 0x8;

/// A sealed volume (`APFS_INCOMPAT_SEALED_VOLUME`): its FS tree's nodes have no object header
/// and the tree is hashed (an index entry holds the child's oid, relative to the root's, and the
/// hash of the child's block); its files' extents are in the file extent tree; its integrity
/// metadata holds the hash type and the root's hash.
#[derive(Debug, Clone, Copy)]
pub struct Sealing {
    /// `im_hash_type` (`APFS_HASH_*`).
    pub hash_type: u32,
    /// `APFS_SEAL_BROKEN`: written after it was sealed.
    pub broken: bool,
}

#[derive(Debug, Clone)]
pub struct XStream {
    pub name: String,
    pub obj_id: u64,
    pub size: u64,
    pub written: u64,
    /// (logical, physical block or 0 for a hole, length in bytes).
    pub extents: Vec<(u64, u64, u64)>,
}

#[derive(Debug, Clone)]
pub struct SFile {
    pub id: u64,
    pub private_id: u64,
    pub name: String,
    pub mode: u16,
    pub create: u64,
    pub modt: u64,
    pub change: u64,
    pub wgc: u32,
    pub bsd_flags: u32,
    pub size: u64,
    pub written: u64,
    pub extents: Vec<(u64, u64, u64)>,
    pub xattr: Option<XStream>,
}

impl SFile {
    pub fn new(id: u64, name: &str, blocks: &[(u64, u64)]) -> Self {
        let mut extents = Vec::new();
        let mut l = 0;
        for &(b, n) in blocks {
            extents.push((l, b, n * BS));
            l += n * BS;
        }
        SFile {
            id,
            private_id: id,
            name: name.into(),
            mode: 0o100644,
            create: 1_000 + id,
            modt: 2_000 + id,
            change: 3_000 + id,
            wgc: 1,
            bsd_flags: 0,
            size: l.saturating_sub(100),
            written: l,
            extents,
            xattr: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Model {
    /// Checkpoint transaction.
    pub xid: u64,
    pub vol_xid: u64,
    /// `apfs_fs_flags`: 1 (`APFS_FS_UNENCRYPTED`) by default, 0 for an encrypted volume.
    pub fs_flags: u64,
    /// The volume object map marks the FS tree's nodes `OMAP_VAL_ENCRYPTED` (their bytes stay
    /// plain): what software encryption leaves.
    pub encrypted_nodes: bool,
    /// FS tree leaves: 1, the root alone; more, under a root index node, the records split
    /// evenly (at most 2 when sealed: the integrity metadata follows them).
    pub leaves: u64,
    pub files: Vec<SFile>,
    /// More used blocks (outside any file).
    pub extra_used: Vec<u64>,
    /// `ci_xid` of the chunks: the transaction that last allocated or freed in them.
    pub chunk_xid: u64,
    pub sealed: Option<Sealing>,
    /// `apfs_role` of the volume superblock.
    pub role: u16,
    /// `apfs_volume_group_id` of the volume superblock.
    pub volume_group: [u8; 16],
}

impl Model {
    /// Files `a` (4 blocks), `b` (2 blocks) and `c` (a hole, then a block).
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let a = SFile::new(0x10, "a", &[(64, 4)]);
        let b = SFile::new(0x11, "b", &[(80, 2)]);
        let mut c = SFile::new(0x12, "c", &[]);
        c.extents = vec![(0, 0, BS), (BS, 96, BS)];
        c.size = 2 * BS;
        c.xattr = Some(XStream {
            name: "com.apple.ResourceFork".into(),
            obj_id: 0x13,
            size: 3000,
            written: 3000,
            extents: vec![(0, 90, BS)],
        });
        Model {
            xid: 10,
            vol_xid: 9,
            fs_flags: 1,
            encrypted_nodes: false,
            leaves: 1,
            files: vec![a, b, c],
            extra_used: Vec::new(),
            chunk_xid: 1,
            sealed: None,
            role: 0,
            volume_group: [0; 16],
        }
    }

    /// The hash a sealed model's FS tree holds of its nodes.
    fn seal_hash(&self) -> Option<SealHash> {
        self.sealed.map(|s| SealHash::from_type(s.hash_type).expect("synthetic seal: unknown hash type"))
    }

    pub fn file(&mut self, id: u64) -> &mut SFile {
        self.files.iter_mut().find(|f| f.id == id).expect("no such file")
    }

    pub fn used(&self) -> Vec<bool> {
        let mut u = vec![false; BLOCKS as usize];
        let meta_end = if self.sealed.is_some() { FEXT_TREE + 1 } else { FS_ROOT + 1 + self.leaves.max(2) };
        for x in u.iter_mut().take(meta_end as usize) {
            *x = true;
        }
        let mut mark = |ext: &[(u64, u64, u64)]| {
            for &(_, b, len) in ext {
                if b != 0 {
                    for i in 0..len.div_ceil(BS) {
                        if let Some(x) = u.get_mut((b + i) as usize) {
                            *x = true;
                        }
                    }
                }
            }
        };
        for f in &self.files {
            mark(&f.extents);
            if let Some(x) = &f.xattr {
                mark(&x.extents);
            }
        }
        for &b in &self.extra_used {
            u[b as usize] = true;
        }
        u
    }

    pub fn build(&self) -> Vec<u8> {
        let mut c = Synth::new(BLOCKS, BPC, 4);
        c.used = self.used();
        c.chunk_xid = self.chunk_xid;
        c.next_oid = 0x600;
        c.omap = NX_OMAP;
        c.fs_oids = vec![VOL_OID];
        let mut img = c.base_image();
        let sb = c.write_checkpoint(&mut img, self.xid, 0, 0);
        img[..BS as usize].copy_from_slice(&sb);

        // Container object map: the volume superblock.
        put_block(&mut img, NX_OMAP, &omap_phys(NX_OMAP, self.xid, NX_OMAP_TREE));
        let e = omap_entry(VOL_OID, self.vol_xid, VOL_SB);
        put_block(
            &mut img,
            NX_OMAP_TREE,
            &node(
                &NodeSpec {
                    oid: NX_OMAP_TREE,
                    xid: self.xid,
                    kind: PHYSICAL | 2,
                    subtype: 0x0B,
                    flags: 0x7,
                    level: 0,
                    fixed: Some((16, 16)),
                    info_flags: 0x10,
                },
                &[e],
            ),
        );

        // Volume superblock.
        let mut v = vec![0u8; BS as usize];
        header(&mut v, VOL_OID, self.vol_xid, 0x0D);
        v[0x20..0x24].copy_from_slice(b"APSB");
        put_u32(&mut v, 0x74, 2); // root tree: virtual b-tree
        put_u64(&mut v, 0x80, VOL_OMAP);
        put_u64(&mut v, 0x88, FS_ROOT_OID);
        put_u64(&mut v, 0xB0, 0x100);
        for (i, b) in v[0xF0..0x100].iter_mut().enumerate() {
            *b = 0x50 + i as u8;
        }
        put_u64(&mut v, 0x108, self.fs_flags);
        v[0x2C0..0x2C4].copy_from_slice(b"vol0");
        put_u16(&mut v, 0x3C4, self.role);
        v[0x3F0..0x400].copy_from_slice(&self.volume_group);
        if self.sealed.is_some() {
            put_u64(&mut v, 0x38, APFS_INCOMPAT_SEALED_VOLUME);
            put_u64(&mut v, 0x400, INTEGRITY_OID);
            put_u64(&mut v, 0x408, FEXT_TREE);
            put_u32(&mut v, 0x410, PHYSICAL | 2);
        }
        seal(&mut v);
        put_block(&mut img, VOL_SB, &v);

        // FS tree.
        let recs = self.records();
        let hash = self.seal_hash();
        let fs_entry = |oid: u64, blk: u64| {
            let mut e = omap_entry(oid, self.vol_xid, blk);
            let mut flags = 0;
            if hash.is_some() {
                flags |= OMAP_VAL_NOHEADER;
            }
            if self.encrypted_nodes {
                flags |= OMAP_VAL_ENCRYPTED;
            }
            put_u32(&mut e.1, 0, flags);
            e
        };
        let mut omap = vec![fs_entry(FS_ROOT_OID, FS_ROOT)];
        if self.leaves > 1 {
            assert!(self.sealed.is_none() || self.leaves == 2, "synthetic sealed volume: at most 2 leaves");
            let n = self.leaves as usize;
            let parts = (0..n).map(|i| &recs[i * recs.len() / n..(i + 1) * recs.len() / n]);
            let mut idx = Vec::new();
            for (i, part) in parts.enumerate() {
                let oid = FS_ROOT_OID + 1 + i as u64;
                let blk = FS_ROOT + 1 + i as u64;
                let leaf = fs_node(
                    hash.is_some(),
                    &NodeSpec {
                        oid,
                        xid: self.vol_xid,
                        kind: 3,
                        subtype: 0x0E,
                        flags: 0x2,
                        level: 0,
                        fixed: None,
                        info_flags: 0,
                    },
                    part,
                );
                put_block(&mut img, blk, &leaf);
                omap.push(fs_entry(oid, blk));
                // A hashed tree's child: its oid relative to the root's, the hash of its block.
                let val = match hash {
                    Some(h) => [(oid - FS_ROOT_OID).to_le_bytes().to_vec(), h.digest(&leaf)].concat(),
                    None => oid.to_le_bytes().to_vec(),
                };
                idx.push((part[0].0.clone(), val));
            }
            let root = fs_node(
                hash.is_some(),
                &NodeSpec {
                    oid: FS_ROOT_OID,
                    xid: self.vol_xid,
                    kind: 2,
                    subtype: 0x0E,
                    flags: 0x1,
                    level: 1,
                    fixed: None,
                    info_flags: 0,
                },
                &idx,
            );
            put_block(&mut img, FS_ROOT, &root);
        } else {
            let root = fs_node(
                hash.is_some(),
                &NodeSpec {
                    oid: FS_ROOT_OID,
                    xid: self.vol_xid,
                    kind: 2,
                    subtype: 0x0E,
                    flags: 0x3,
                    level: 0,
                    fixed: None,
                    info_flags: 0,
                },
                &recs,
            );
            put_block(&mut img, FS_ROOT, &root);
        }
        if let (Some(s), Some(h)) = (self.sealed, hash) {
            let mut im = vec![0u8; BS as usize];
            header(&mut im, INTEGRITY_OID, self.vol_xid, 0x1E);
            put_u32(&mut im, 0x24, u32::from(s.broken)); // APFS_SEAL_BROKEN
            put_u32(&mut im, 0x28, s.hash_type);
            put_u32(&mut im, 0x2C, ROOT_HASH_AT as u32);
            put_u64(&mut im, 0x30, if s.broken { self.vol_xid } else { 0 });
            let root_hash = h.digest(&img[(FS_ROOT * BS) as usize..((FS_ROOT + 1) * BS) as usize]);
            im[ROOT_HASH_AT..ROOT_HASH_AT + root_hash.len()].copy_from_slice(&root_hash);
            seal(&mut im);
            put_block(&mut img, INTEGRITY, &im);
            omap.push(omap_entry(INTEGRITY_OID, self.vol_xid, INTEGRITY));
            put_block(
                &mut img,
                FEXT_TREE,
                &node(
                    &NodeSpec {
                        oid: FEXT_TREE,
                        xid: self.vol_xid,
                        kind: PHYSICAL | 2,
                        subtype: 0x1F,
                        flags: 0x3,
                        level: 0,
                        fixed: Some((16, 16)),
                        info_flags: 0x10,
                    },
                    &self.file_extents(),
                ),
            );
        }
        put_block(&mut img, VOL_OMAP, &omap_phys(VOL_OMAP, self.vol_xid, VOL_OMAP_TREE));
        put_block(
            &mut img,
            VOL_OMAP_TREE,
            &node(
                &NodeSpec {
                    oid: VOL_OMAP_TREE,
                    xid: self.vol_xid,
                    kind: PHYSICAL | 2,
                    subtype: 0x0B,
                    flags: 0x7,
                    level: 0,
                    fixed: Some((16, 16)),
                    info_flags: 0x10,
                },
                &omap,
            ),
        );
        img
    }

    /// FS-tree records, sorted by (object id, type, rest of the key).
    fn records(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        type Rec = ((u64, u8, Vec<u8>), Vec<u8>, Vec<u8>);
        let mut recs: Vec<Rec> = Vec::new();
        let mut push = |id: u64, ty: u8, rest: Vec<u8>, val: Vec<u8>| {
            let mut k = (id | ((ty as u64) << 60)).to_le_bytes().to_vec();
            k.extend_from_slice(&rest);
            recs.push(((id, ty, rest), k, val));
        };
        // The root directory.
        push(2, 3, vec![], inode_val(&SFile { mode: 0o040755, size: 0, ..SFile::new(2, "root", &[]) }, false));
        for f in &self.files {
            push(f.id, 3, vec![], inode_val(f, true));
            // A sealed volume's extents are in its file extent tree.
            let in_tree = self.sealed.is_none();
            let mut ext = |id: u64, list: &[(u64, u64, u64)]| {
                for &(l, b, len) in list.iter().filter(|_| in_tree) {
                    let mut v = vec![0u8; 24];
                    put_u64(&mut v, 0, len);
                    put_u64(&mut v, 8, b);
                    push(id, 8, l.to_le_bytes().to_vec(), v);
                }
            };
            ext(f.private_id, &f.extents);
            if let Some(x) = &f.xattr {
                ext(x.obj_id, &x.extents);
                let mut rest = Vec::new();
                rest.extend_from_slice(&((x.name.len() + 1) as u16).to_le_bytes());
                rest.extend_from_slice(x.name.as_bytes());
                rest.push(0);
                let mut v = vec![0u8; 4 + 48];
                put_u16(&mut v, 0, 1);
                put_u16(&mut v, 2, 48);
                put_u64(&mut v, 4, x.obj_id);
                put_u64(&mut v, 12, x.size);
                put_u64(&mut v, 20, x.size.div_ceil(BS) * BS);
                put_u64(&mut v, 36, x.written);
                push(f.id, 4, rest, v);
            }
            // A sealed volume's data hashes: one per extent, of its blocks as built (zeros).
            if let Some(h) = self.seal_hash() {
                let streams =
                    std::iter::once((f.private_id, &f.extents)).chain(f.xattr.as_ref().map(|x| (x.obj_id, &x.extents)));
                for (id, list) in streams {
                    for &(l, _, len) in list.iter().filter(|e| e.1 != 0) {
                        let hash = h.digest(&vec![0u8; len as usize]);
                        let mut v = vec![0u8; 3];
                        put_u16(&mut v, 0, (len / BS) as u16);
                        v[2] = hash.len() as u8;
                        v.extend_from_slice(&hash);
                        push(id, 13, ((1u64 << 56) | (l / BS)).to_le_bytes().to_vec(), v);
                    }
                }
            }
        }
        recs.sort_by(|a, b| a.0.cmp(&b.0));
        recs.into_iter().map(|(_, k, v)| (k, v)).collect()
    }

    /// File extent tree records of a sealed volume (`fext_tree_key_t` + `fext_tree_val_t`),
    /// sorted by (data stream, logical offset).
    fn file_extents(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut out = Vec::new();
        for f in &self.files {
            let streams =
                std::iter::once((f.private_id, &f.extents)).chain(f.xattr.as_ref().map(|x| (x.obj_id, &x.extents)));
            for (id, list) in streams {
                for &(l, b, len) in list {
                    let k = [id.to_le_bytes(), l.to_le_bytes()].concat();
                    let v = [len.to_le_bytes(), b.to_le_bytes()].concat();
                    out.push(((id, l), k, v));
                }
            }
        }
        out.sort_by_key(|e| e.0);
        out.into_iter().map(|(_, k, v)| (k, v)).collect()
    }
}

/// An FS tree node; a sealed volume's has no object header (no checksum either) and is hashed.
fn fs_node(sealed: bool, spec: &NodeSpec, entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    if !sealed {
        return node(spec, entries);
    }
    let mut b = node(
        &NodeSpec { flags: spec.flags | SEALED_NODE, info_flags: spec.info_flags | BTREE_HASHED, ..*spec },
        entries,
    );
    b[..0x20].fill(0);
    b
}

fn inode_val(f: &SFile, dstream: bool) -> Vec<u8> {
    let mut v = vec![0u8; 0x5C];
    put_u64(&mut v, 0x00, 2);
    put_u64(&mut v, 0x08, f.private_id);
    put_u64(&mut v, 0x10, f.create);
    put_u64(&mut v, 0x18, f.modt);
    put_u64(&mut v, 0x20, f.change);
    put_u64(&mut v, 0x28, 5);
    put_u32(&mut v, 0x38, 1);
    put_u32(&mut v, 0x40, f.wgc);
    put_u32(&mut v, 0x44, f.bsd_flags);
    put_u32(&mut v, 0x48, 501);
    put_u32(&mut v, 0x4C, 20);
    put_u16(&mut v, 0x50, f.mode);
    let mut name = f.name.as_bytes().to_vec();
    name.push(0);
    let mut fields: Vec<(u8, Vec<u8>)> = vec![(4, name)];
    if dstream {
        let mut d = vec![0u8; 40];
        put_u64(&mut d, 0, f.size);
        put_u64(&mut d, 8, f.size.div_ceil(BS) * BS);
        put_u64(&mut d, 24, f.written);
        fields.push((8, d));
    }
    let mut data = Vec::new();
    let mut heads = Vec::new();
    for (ty, d) in &fields {
        heads.extend_from_slice(&[*ty, 0]);
        heads.extend_from_slice(&(d.len() as u16).to_le_bytes());
        data.extend_from_slice(d);
        data.resize(data.len().div_ceil(8) * 8, 0);
    }
    v.extend_from_slice(&(fields.len() as u16).to_le_bytes());
    v.extend_from_slice(&(data.len() as u16).to_le_bytes());
    v.extend_from_slice(&heads);
    v.extend_from_slice(&data);
    v
}

pub fn put_block(img: &mut [u8], blk: u64, b: &[u8]) {
    img[(blk * BS) as usize..((blk + 1) * BS) as usize].copy_from_slice(b);
}

pub fn omap_entry(oid: u64, xid: u64, paddr: u64) -> (Vec<u8>, Vec<u8>) {
    let mut k = oid.to_le_bytes().to_vec();
    k.extend_from_slice(&xid.to_le_bytes());
    let mut v = vec![0u8; 16];
    put_u32(&mut v, 4, BS as u32);
    put_u64(&mut v, 8, paddr);
    (k, v)
}

fn omap_phys(blk: u64, xid: u64, tree: u64) -> Vec<u8> {
    let mut b = vec![0u8; BS as usize];
    header(&mut b, blk, xid, PHYSICAL | 0x0B);
    put_u32(&mut b, 0x28, PHYSICAL | 2);
    put_u32(&mut b, 0x2C, PHYSICAL | 2);
    put_u64(&mut b, 0x30, tree);
    seal(&mut b);
    b
}

/// The header fields of a B-tree [`node`]: `kind` is the full `o_type`; `fixed` the key/value
/// sizes of a fixed-size tree; the root carries a `btree_info_t` with `info_flags`.
#[derive(Debug, Clone, Copy)]
pub struct NodeSpec {
    pub oid: u64,
    pub xid: u64,
    pub kind: u32,
    pub subtype: u32,
    pub flags: u16,
    pub level: u16,
    pub fixed: Option<(u32, u32)>,
    pub info_flags: u32,
}

/// A B-tree node holding `entries`.
pub fn node(spec: &NodeSpec, entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let NodeSpec { oid, xid, kind, subtype, flags, level, fixed, info_flags } = *spec;
    let bs = BS as usize;
    let mut b = vec![0u8; bs];
    header(&mut b, oid, xid, kind);
    put_u32(&mut b, 0x1C, subtype);
    let flags = flags | if fixed.is_some() { 0x4 } else { 0 };
    put_u16(&mut b, 0x20, flags);
    put_u16(&mut b, 0x22, level);
    put_u32(&mut b, 0x24, entries.len() as u32);
    let esz = if fixed.is_some() { 4 } else { 8 };
    let tlen = entries.len() * esz;
    put_u16(&mut b, 0x28, 0);
    put_u16(&mut b, 0x2A, tlen as u16);
    let root = flags & 1 != 0;
    let val_end = if root { bs - 0x28 } else { bs };
    let key_start = 0x38 + tlen;
    let (mut kpos, mut vpos) = (0usize, val_end);
    for (i, (k, v)) in entries.iter().enumerate() {
        b[key_start + kpos..key_start + kpos + k.len()].copy_from_slice(k);
        vpos -= v.len();
        b[vpos..vpos + v.len()].copy_from_slice(v);
        let t = 0x38 + i * esz;
        if fixed.is_some() {
            put_u16(&mut b, t, kpos as u16);
            put_u16(&mut b, t + 2, (val_end - vpos) as u16);
        } else {
            put_u16(&mut b, t, kpos as u16);
            put_u16(&mut b, t + 2, k.len() as u16);
            put_u16(&mut b, t + 4, (val_end - vpos) as u16);
            put_u16(&mut b, t + 6, v.len() as u16);
        }
        kpos += k.len();
        assert!(key_start + kpos <= vpos, "synthetic node overflows");
    }
    if root {
        let o = bs - 0x28;
        put_u32(&mut b, o, info_flags);
        put_u32(&mut b, o + 4, BS as u32);
        let (ks, vs) = fixed.unwrap_or((0, 0));
        put_u32(&mut b, o + 8, ks);
        put_u32(&mut b, o + 12, vs);
    }
    seal(&mut b);
    b
}

/// Modify block `blk` of `img` with `f`, then reseal its checksum.
pub fn patch(img: &mut [u8], blk: u64, f: impl FnOnce(&mut [u8])) {
    let b = &mut img[(blk * BS) as usize..((blk + 1) * BS) as usize];
    f(b);
    seal(b);
}
