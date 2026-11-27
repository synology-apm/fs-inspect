//! Extended attributes: the attribute fork of an inode, past `di_forkoff * 8` of its literal
//! area, in one of three forms.
//!
//! - **Shortform** (`di_aformat` local): a header (`totsize u16`, `count u8`, a pad byte), then
//!   per entry `namelen u8`, `valuelen u8`, `flags u8`, the name and the value.
//! - **Leaf / node** (extents or btree): attribute block 0 of the fork is a leaf or the root of
//!   a dabtree; the leftmost path leads to the first leaf, `forw` links the leaves. A leaf's
//!   entries (`hashval u32`, `nameidx u16`, `flags u8`, a pad byte) point at a local name
//!   (`valuelen u16`, `namelen u8`, name, value) or a remote one (`valueblk u32`, `valuelen
//!   u32`, `namelen u8`, name) whose value is in fork blocks from `valueblk` (on v5 each block
//!   starts with a 56-byte header, magic `XARM`).
//!
//! Entry flags: `ROOT` (trusted), `SECURE` (security), neither: user; `PARENT` entries (parent
//! pointers) and `INCOMPLETE` ones (a set cut short) are left out. All big-endian.
//!
//! POSIX ACLs are the trusted `SGI_ACL_FILE` and `SGI_ACL_DEFAULT` attributes in XFS's form
//! (`count u32`, then `tag u32`, `id u32`, `perm u16`, a pad); [`acl`] turns them into the
//! extended attribute form.

use crate::format::geom::Geom;
use fs_inspect_core::FileExtent as Extent;
use fs_inspect_core::StructureKind;
use fs_inspect_core::acl::{self, Entry, UNDEFINED_ID, tag};
use fs_inspect_core::bytes::{be_u16_at, be_u32_at, be_u64_at, u8_at};
use fs_inspect_core::{Error, Result};
use fs_inspect_core::{Role, Site};
use fs_inspect_io::DynSource;

const FLAG_LOCAL: u8 = 0x01;
const FLAG_ROOT: u8 = 0x02;
const FLAG_SECURE: u8 = 0x04;
const FLAG_PARENT: u8 = 0x08;
const FLAG_INCOMPLETE: u8 = 0x80;

const LEAF_MAGIC: u16 = 0xFBEE;
const LEAF3_MAGIC: u16 = 0x3BEE;
const NODE_MAGIC: u16 = 0xFEBE;
const NODE3_MAGIC: u16 = 0x3EBE;
const RMT3_MAGIC: u32 = 0x5841_524D;
/// Where a v5 dabtree block's checksum is, and its header lengths.
const DA3_CRC_OFF: usize = 12;
const LEAF_HDR: usize = 32;
const LEAF3_HDR: usize = 80;
const NODE_HDR: usize = 16;
const NODE3_HDR: usize = 64;
const RMT3_HDR: usize = 56;
/// The most levels of a dabtree, and leaves followed.
const MAX_LEVELS: u32 = 8;

/// The trusted names XFS keeps ACLs under.
pub(crate) const SGI_ACL_FILE: &[u8] = b"trusted.SGI_ACL_FILE";
pub(crate) const SGI_ACL_DEFAULT: &[u8] = b"trusted.SGI_ACL_DEFAULT";

/// One extended attribute: its full name, and its value or where it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Xattr {
    pub name: Vec<u8>,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Here(Vec<u8>),
    /// In fork blocks from `blk`, `len` bytes.
    Remote {
        blk: u32,
        len: u32,
    },
}

impl Xattr {
    pub(crate) fn size(&self) -> u64 {
        match &self.value {
            Value::Here(v) => v.len() as u64,
            Value::Remote { len, .. } => u64::from(*len),
        }
    }
}

/// The full name of `name` with entry flags `flags`; `None` for the entries left out.
fn full_name(flags: u8, name: &[u8]) -> Option<Vec<u8>> {
    if flags & (FLAG_PARENT | FLAG_INCOMPLETE) != 0 {
        return None;
    }
    let p: &[u8] = if flags & FLAG_ROOT != 0 {
        b"trusted."
    } else if flags & FLAG_SECURE != 0 {
        b"security."
    } else {
        b"user."
    };
    Some([p, name].concat())
}

/// The entries of a shortform attribute fork.
pub(crate) fn shortform(fork: &[u8]) -> Result<Vec<Xattr>> {
    let total = usize::from(be_u16_at(fork, 0)?).min(fork.len());
    let count = u8_at(fork, 2)?;
    let mut out = Vec::new();
    let mut o = 4;
    for _ in 0..count {
        let (nl, vl, fl) = (usize::from(u8_at(fork, o)?), usize::from(u8_at(fork, o + 1)?), u8_at(fork, o + 2)?);
        let end = o + 3 + nl + vl;
        if end > total {
            return Err(Error::corrupt("xfs shortform attribute past its fork"));
        }
        if let Some(name) = full_name(fl, &fork[o + 3..o + 3 + nl]) {
            out.push(Xattr { name, value: Value::Here(fork[o + 3 + nl..end].to_vec()) });
        }
        o = end;
    }
    Ok(out)
}

/// The attribute fork's blocks, read through its mapping.
pub(crate) struct Fork<'a> {
    pub src: &'a DynSource,
    pub g: &'a Geom,
    pub ino: u64,
    /// The fork's mapping: logical bytes from fork block 0.
    pub extents: &'a [Extent],
}

impl Fork<'_> {
    /// Fork block `blk`.
    fn block(&self, blk: u64) -> Result<Vec<u8>> {
        let bs = self.g.bs();
        let at = blk * bs;
        let e = self
            .extents
            .iter()
            .find(|e| e.logical <= at && at < e.logical + e.length)
            .ok_or_else(|| Error::corrupt(format!("xfs inode {}: attribute block {blk} is a hole", self.ino)))?;
        let phys = e.physical.ok_or_else(|| Error::corrupt("xfs attribute block without a location"))?;
        self.src.read_vec(phys + (at - e.logical), bs as usize)
    }

    /// A dabtree block, its magic and (v5) checksum, location and owner checked.
    fn da_block(&self, blk: u64) -> Result<(Vec<u8>, u16)> {
        let b = self.block(blk)?;
        let magic = be_u16_at(&b, 8)?;
        let site = Site::new(StructureKind::XfsAttributeBlock).id(self.ino);
        if self.g.v5() && (!self.g.crc(Role::Validate, site, &b, DA3_CRC_OFF) || be_u64_at(&b, 48)? != self.ino) {
            return Err(Error::corrupt(format!("xfs inode {}: attribute block {blk} checksum or owner", self.ino)));
        }
        Ok((b, magic))
    }

    /// Every entry of a leaf or node attribute fork.
    pub(crate) fn entries(&self) -> Result<Vec<Xattr>> {
        let (v5, bs) = (self.g.v5(), self.g.bs());
        let (leaf_magic, node_magic, leaf_hdr, node_hdr) = if v5 {
            (LEAF3_MAGIC, NODE3_MAGIC, LEAF3_HDR, NODE3_HDR)
        } else {
            (LEAF_MAGIC, NODE_MAGIC, LEAF_HDR, NODE_HDR)
        };
        // The leftmost leaf.
        let mut blk = 0u64;
        let mut levels = 0;
        let (mut b, mut magic) = self.da_block(blk)?;
        while magic == node_magic {
            levels += 1;
            if levels > MAX_LEVELS || be_u16_at(&b, if v5 { 56 } else { 12 })? == 0 {
                return Err(Error::corrupt("xfs attribute dabtree"));
            }
            blk = u64::from(be_u32_at(&b, node_hdr + 4)?);
            (b, magic) = self.da_block(blk)?;
        }
        let mut out = Vec::new();
        let max_leaves = self.extents.iter().map(|e| e.length).sum::<u64>() / bs + 1;
        for _ in 0..max_leaves {
            if magic != leaf_magic {
                return Err(Error::corrupt(format!("xfs inode {}: attribute block {blk} is no leaf", self.ino)));
            }
            leaf(&b, leaf_hdr, &mut out)?;
            let forw = be_u32_at(&b, 0)?;
            if forw == 0 {
                return Ok(out);
            }
            blk = u64::from(forw);
            (b, magic) = self.da_block(blk)?;
        }
        Err(Error::corrupt("xfs attribute leaves loop"))
    }

    /// The value of a remote attribute.
    pub(crate) fn remote(&self, blk: u32, len: u32) -> Result<Vec<u8>> {
        let len = len as usize;
        let mut out = Vec::with_capacity(len);
        let mut blk = u64::from(blk);
        while out.len() < len {
            let b = self.block(blk)?;
            let data = if self.g.v5() {
                let site = Site::new(StructureKind::XfsRemoteAttributeBlock).id(self.ino);
                if be_u32_at(&b, 0)? != RMT3_MAGIC
                    || !self.g.crc(Role::Validate, site, &b, 12)
                    || be_u64_at(&b, 32)? != self.ino
                {
                    return Err(Error::corrupt(format!("xfs inode {}: remote attribute block {blk}", self.ino)));
                }
                let n = be_u32_at(&b, 8)? as usize;
                b.get(RMT3_HDR..RMT3_HDR + n).ok_or_else(|| Error::corrupt("xfs remote attribute length"))?
            } else {
                &b[..]
            };
            let take = data.len().min(len - out.len());
            if take == 0 {
                return Err(Error::corrupt("xfs empty remote attribute block"));
            }
            out.extend_from_slice(&data[..take]);
            blk += 1;
        }
        Ok(out)
    }
}

/// The entries of one leaf block into `out`.
fn leaf(b: &[u8], hdr: usize, out: &mut Vec<Xattr>) -> Result<()> {
    // `count` follows the block info: 12 bytes, 56 on v5.
    let count = usize::from(be_u16_at(b, if hdr == LEAF3_HDR { 56 } else { 12 })?);
    for i in 0..count {
        let e = hdr + i * 8;
        let idx = usize::from(be_u16_at(b, e + 4)?);
        let flags = u8_at(b, e + 6)?;
        let get = |o: usize, n: usize| b.get(o..o + n).ok_or_else(|| Error::corrupt("xfs attribute leaf name"));
        let (name, value) = if flags & FLAG_LOCAL != 0 {
            let vl = usize::from(be_u16_at(b, idx)?);
            let nl = usize::from(u8_at(b, idx + 2)?);
            (get(idx + 3, nl)?, Value::Here(get(idx + 3 + nl, vl)?.to_vec()))
        } else {
            let blk = be_u32_at(b, idx)?;
            let len = be_u32_at(b, idx + 4)?;
            let nl = usize::from(u8_at(b, idx + 8)?);
            (get(idx + 9, nl)?, Value::Remote { blk, len })
        };
        if let Some(name) = full_name(flags, name) {
            out.push(Xattr { name, value });
        }
    }
    Ok(())
}

/// An ACL as XFS stores it, in the extended attribute form.
pub(crate) fn acl(b: &[u8]) -> Result<Vec<u8>> {
    let n = be_u32_at(b, 0)? as usize;
    if 4 + n * 12 > b.len() {
        return Err(Error::corrupt("xfs ACL count"));
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let o = 4 + i * 12;
        let t = u16::try_from(be_u32_at(b, o)?).map_err(|_| Error::corrupt("xfs ACL tag"))?;
        let id = match t {
            tag::USER | tag::GROUP => be_u32_at(b, o + 4)?,
            tag::USER_OBJ | tag::GROUP_OBJ | tag::MASK | tag::OTHER => UNDEFINED_ID,
            _ => return Err(Error::corrupt(format!("xfs ACL entry tag {t:#x}"))),
        };
        entries.push(Entry { tag: t, perm: be_u16_at(b, o + 8)?, id });
    }
    Ok(acl::to_xattr(&entries))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn shortform_entries() {
        let mut f = vec![0u8; 4];
        for (fl, n, v) in [(0u8, &b"one"[..], &b"1"[..]), (FLAG_ROOT, b"t", b"tv"), (FLAG_PARENT, b"p", b"")] {
            f.extend_from_slice(&[n.len() as u8, v.len() as u8, fl]);
            f.extend_from_slice(n);
            f.extend_from_slice(v);
        }
        let total = f.len() as u16;
        f[..2].copy_from_slice(&total.to_be_bytes());
        f[2] = 3;
        let x = shortform(&f).unwrap();
        assert_eq!(x.len(), 2);
        assert_eq!((x[0].name.as_slice(), x[0].size()), (&b"user.one"[..], 1));
        assert_eq!(x[1].name, b"trusted.t");
        f[2] = 4;
        assert!(shortform(&f).is_err());
    }

    #[test]
    fn leaf_entries() {
        let mut b = vec![0u8; 512];
        b[8..10].copy_from_slice(&LEAF_MAGIC.to_be_bytes());
        b[12..14].copy_from_slice(&2u16.to_be_bytes()); // count
        // A local entry at 400, a remote one at 450.
        b[LEAF_HDR + 4..LEAF_HDR + 6].copy_from_slice(&400u16.to_be_bytes());
        b[LEAF_HDR + 6] = FLAG_LOCAL | FLAG_SECURE;
        b[400..402].copy_from_slice(&2u16.to_be_bytes());
        b[402] = 1;
        b[403..406].copy_from_slice(b"sab");
        b[LEAF_HDR + 12..LEAF_HDR + 14].copy_from_slice(&450u16.to_be_bytes());
        b[450..454].copy_from_slice(&7u32.to_be_bytes());
        b[454..458].copy_from_slice(&9000u32.to_be_bytes());
        b[458] = 3;
        b[459..462].copy_from_slice(b"big");
        let mut out = Vec::new();
        leaf(&b, LEAF_HDR, &mut out).unwrap();
        assert_eq!(out[0], Xattr { name: b"security.s".to_vec(), value: Value::Here(b"ab".to_vec()) });
        assert_eq!(out[1], Xattr { name: b"user.big".to_vec(), value: Value::Remote { blk: 7, len: 9000 } });
    }

    #[test]
    fn acls_in_the_attribute_form() {
        let mut b = 2u32.to_be_bytes().to_vec();
        for (t, id, p) in [(1u32, 0u32, 6u16), (2, 1234, 4)] {
            b.extend_from_slice(&t.to_be_bytes());
            b.extend_from_slice(&id.to_be_bytes());
            b.extend_from_slice(&p.to_be_bytes());
            b.extend_from_slice(&[0, 0]);
        }
        let x = acl(&b).unwrap();
        assert_eq!(&x[4..12], &[1, 0, 6, 0, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(&x[12..20], &[2, 0, 4, 0, 0xD2, 0x04, 0, 0]);
        assert!(acl(&[0, 0, 0, 9]).is_err());
        // A tag no ACL has, and one past u16.
        let mut bad = 1u32.to_be_bytes().to_vec();
        bad.extend_from_slice(&[0, 0, 0, 0x40, 0, 0, 0, 0, 0, 6, 0, 0]);
        assert!(acl(&bad).unwrap_err().to_string().contains("tag 0x40"));
        bad[4..8].copy_from_slice(&0x1_0000u32.to_be_bytes());
        assert!(acl(&bad).unwrap_err().to_string().contains("ACL tag"));
    }

    const INO: u64 = 131;

    /// The geometry of a synthetic v5 or v4 volume (4 KiB blocks), and the volume.
    fn geometry(v5: bool) -> std::sync::Arc<crate::format::fs::XfsFs> {
        let w = crate::synth::World::new(crate::synth::Geo::new(v5));
        let src = std::sync::Arc::new(fs_inspect_io::MemSource::new(w.render()));
        std::sync::Arc::new(crate::format::fs::XfsFs::open(src, &fs_inspect_core::DriverContext::default()).unwrap())
    }

    /// `blocks` as the attribute fork (fork block k at byte k * 4096 of a source of its own).
    fn fork_source(blocks: &[Vec<u8>]) -> DynSource {
        std::sync::Arc::new(fs_inspect_io::MemSource::new(blocks.concat()))
    }

    /// A dabtree block: `magic` at 8, `count` where `v5` keeps it; on v5 the owner and the CRC.
    fn da(v5: bool, magic: u16, count: u16, forw: u32) -> Vec<u8> {
        let mut b = vec![0u8; 4096];
        b[0..4].copy_from_slice(&forw.to_be_bytes());
        b[8..10].copy_from_slice(&magic.to_be_bytes());
        let at = if v5 { 56 } else { 12 };
        b[at..at + 2].copy_from_slice(&count.to_be_bytes());
        b
    }

    fn sealed(v5: bool, mut b: Vec<u8>) -> Vec<u8> {
        if v5 {
            b[48..56].copy_from_slice(&INO.to_be_bytes());
            crate::synth::set_crc(&mut b, DA3_CRC_OFF);
        }
        b
    }

    /// A leaf whose one entry is local `name` = `value`, `forw` the next leaf.
    fn leaf_block(v5: bool, name: &[u8], value: &[u8], forw: u32) -> Vec<u8> {
        let (magic, hdr) = if v5 { (LEAF3_MAGIC, LEAF3_HDR) } else { (LEAF_MAGIC, LEAF_HDR) };
        let mut b = da(v5, magic, 1, forw);
        b[hdr + 4..hdr + 6].copy_from_slice(&3000u16.to_be_bytes());
        b[hdr + 6] = FLAG_LOCAL;
        b[3000..3002].copy_from_slice(&(value.len() as u16).to_be_bytes());
        b[3002] = name.len() as u8;
        b[3003..3003 + name.len()].copy_from_slice(name);
        b[3003 + name.len()..3003 + name.len() + value.len()].copy_from_slice(value);
        sealed(v5, b)
    }

    /// A node whose first child is `child`.
    fn node_block(v5: bool, child: u32) -> Vec<u8> {
        let (magic, hdr) = if v5 { (NODE3_MAGIC, NODE3_HDR) } else { (NODE_MAGIC, NODE_HDR) };
        let mut b = da(v5, magic, 1, 0);
        b[hdr + 4..hdr + 8].copy_from_slice(&child.to_be_bytes());
        sealed(v5, b)
    }

    /// The entries of a fork of blocks `blocks`, mapped from fork block 0.
    fn entries_of(v5: bool, blocks: Vec<Vec<u8>>) -> Result<Vec<Xattr>> {
        let fs = geometry(v5);
        let src = fork_source(&blocks);
        let extents = [Extent::mapped(0, 0, blocks.len() as u64 * 4096)];
        Fork { src: &src, g: fs.geometry(), ino: INO, extents: &extents }.entries()
    }

    /// A node-form fork, v5 and v4: the leftmost path from the root node leads to the first
    /// leaf, `forw` to the next; a node of no entries, a block that is neither, a loop of
    /// leaves and (v5) a block of another owner are corrupt.
    #[test]
    fn node_form_entries_follow_the_leftmost_path_and_the_leaves() {
        for v5 in [true, false] {
            let blocks = vec![node_block(v5, 1), leaf_block(v5, b"a", b"1", 2), leaf_block(v5, b"b", b"22", 0)];
            let x = entries_of(v5, blocks.clone()).unwrap();
            assert_eq!(
                x,
                [
                    Xattr { name: b"user.a".to_vec(), value: Value::Here(b"1".to_vec()) },
                    Xattr { name: b"user.b".to_vec(), value: Value::Here(b"22".to_vec()) },
                ],
                "v5 {v5}"
            );
            let corrupt = |blocks: Vec<Vec<u8>>, what: &str| {
                let e = entries_of(v5, blocks).unwrap_err();
                assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Corrupt, "{what}: {e}");
                assert!(e.to_string().contains(what), "v5 {v5}, {what}: {e}");
            };
            let node_magic = if v5 { NODE3_MAGIC } else { NODE_MAGIC };
            corrupt(vec![sealed(v5, da(v5, node_magic, 0, 0))], "dabtree");
            corrupt(vec![sealed(v5, da(v5, 0x1234, 1, 0))], "is no leaf");
            // Each leaf's `forw` the second: the leaves never end.
            corrupt(vec![leaf_block(v5, b"a", b"1", 1), leaf_block(v5, b"b", b"2", 1)], "leaves loop");
            // A node pointing at itself: past the most levels.
            corrupt(vec![node_block(v5, 0)], "dabtree");
            // A leaf past the fork's mapping.
            corrupt(vec![node_block(v5, 9)], "is a hole");
            if v5 {
                let mut other = leaf_block(v5, b"a", b"1", 0);
                other[48..56].copy_from_slice(&(INO + 1).to_be_bytes());
                crate::synth::set_crc(&mut other, DA3_CRC_OFF);
                corrupt(vec![other], "checksum or owner");
            }
        }
    }

    /// Remote values: on v5 each block's header (magic, owner, the length it holds) is checked
    /// and only its data taken; on v4 the blocks are the value. A block without a location, a
    /// hole, a length past the block and a block holding nothing are corrupt.
    #[test]
    fn remote_values_span_blocks() {
        let value: Vec<u8> = (0..6000u32).map(|i| (i % 253) as u8).collect();
        // v5: 4040 bytes per block (4096 less the 56-byte header).
        let rmt = |data: &[u8], owner: u64| {
            let mut b = vec![0u8; 4096];
            b[0..4].copy_from_slice(&RMT3_MAGIC.to_be_bytes());
            b[8..12].copy_from_slice(&(data.len() as u32).to_be_bytes());
            b[32..40].copy_from_slice(&owner.to_be_bytes());
            b[RMT3_HDR..RMT3_HDR + data.len()].copy_from_slice(data);
            crate::synth::set_crc(&mut b, 12);
            b
        };
        let fs = geometry(true);
        let read = |blocks: &[Vec<u8>], extents: &[Extent], len: u32| {
            let src = fork_source(blocks);
            Fork { src: &src, g: fs.geometry(), ino: INO, extents }.remote(1, len)
        };
        let blocks = [vec![0u8; 4096], rmt(&value[..4040], INO), rmt(&value[4040..], INO)];
        let all = [Extent::mapped(0, 0, 3 * 4096)];
        assert_eq!(read(&blocks, &all, 6000).unwrap(), value);
        let corrupt = |r: Result<Vec<u8>>, what: &str| {
            let e = r.unwrap_err();
            assert!(e.to_string().contains(what), "{what}: {e}");
        };
        corrupt(read(&[vec![0u8; 4096], rmt(&value[..4040], INO + 1)], &all, 6000), "remote attribute block 1");
        let mut no_magic = rmt(&value[..4040], INO);
        no_magic[0] = 0;
        corrupt(read(&[vec![0u8; 4096], no_magic], &all, 6000), "remote attribute block 1");
        let mut long = rmt(&value[..4040], INO);
        long[8..12].copy_from_slice(&5000u32.to_be_bytes());
        crate::synth::set_crc(&mut long, 12);
        corrupt(read(&[vec![0u8; 4096], long], &all, 6000), "remote attribute length");
        corrupt(read(&[vec![0u8; 4096], rmt(&[], INO)], &all, 6000), "empty remote attribute block");
        // Block 2 not mapped: a hole; mapped to nowhere: no location.
        corrupt(read(&blocks, &[Extent::mapped(0, 0, 2 * 4096)], 6000), "attribute block 2 is a hole");
        corrupt(read(&blocks, &[Extent::hole(0, 3 * 4096)], 6000), "without a location");

        // v4: no header, the value straight across the blocks.
        let fs = geometry(false);
        let src = fork_source(&[vec![0u8; 4096], value[..4096].to_vec(), [&value[4096..], &[0u8; 2192][..]].concat()]);
        let x = Fork { src: &src, g: fs.geometry(), ino: INO, extents: &all }.remote(1, 6000).unwrap();
        assert_eq!(x, value);
    }
}
