//! A file's attributes on bytes made here: SA buffers against their layouts, the legacy
//! znode, and the file keys.

use super::*;

const MODE: u16 = 1;
const SIZE: u16 = 2;
const SYMLINK: u16 = 3;
const LINKS: u16 = 4;
const MTIME: u16 = 5;
const DXATTR: u16 = 6;

/// The registry of the attributes used here, and layouts 2 (mode, size, symlink), 3 (mode,
/// symlink, extended attributes: two of variable size) and 4 (an attribute not registered).
fn table() -> SaTable {
    let mut t = SaTable::default();
    for (n, name, len) in [
        (MODE, "ZPL_MODE", 8),
        (SIZE, "ZPL_SIZE", 8),
        (SYMLINK, "ZPL_SYMLINK", 0),
        (LINKS, "ZPL_LINKS", 8),
        (MTIME, "ZPL_MTIME", 16),
        (DXATTR, "ZPL_DXATTR", 0),
    ] {
        t.attrs.insert(n, (name.to_string(), len));
    }
    t.layouts.insert(2, vec![MODE, SIZE, SYMLINK]);
    t.layouts.insert(3, vec![MODE, SYMLINK, DXATTR]);
    t.layouts.insert(4, vec![MODE, 99]);
    t.layouts.insert(5, vec![MODE, SIZE, LINKS, MTIME]);
    t
}

/// An SA buffer of `layout` with a header of `hdr` bytes, the variable lengths `var`, then
/// `attrs` each padded to 8 bytes (lengths that do not fit the header are written past it).
fn sa(layout: u16, hdr: usize, var: &[u16], attrs: &[&[u8]]) -> Vec<u8> {
    let mut b = vec![0u8; hdr.max(6 + 2 * var.len())];
    b[..4].copy_from_slice(&SA_MAGIC.to_le_bytes());
    b[4..6].copy_from_slice(&(layout | ((hdr / 8) as u16) << 10).to_le_bytes());
    for (i, l) in var.iter().enumerate() {
        b[6 + 2 * i..8 + 2 * i].copy_from_slice(&l.to_le_bytes());
    }
    for a in attrs {
        b.extend_from_slice(a);
        b.resize(b.len().next_multiple_of(8), 0);
    }
    b
}

fn parsed<'a>(t: &'a SaTable, b: &'a [u8]) -> Result<SaMap<'a>> {
    let mut m = HashMap::new();
    sa_attrs(t, b, &mut m)?;
    Ok(m)
}

/// The attributes come out of the buffer in their layout's order, each 8-byte aligned, the
/// variable-size ones with the lengths of the header; what is not set takes ZFS's defaults.
#[test]
fn sa_attributes_follow_their_layout() {
    let t = table();
    let mode = 0o120777u64.to_le_bytes();
    let b = sa(2, 8, &[11], &[&mode, &3u64.to_le_bytes(), b"/etc/passwd"]);
    let m = parsed(&t, &b).unwrap();
    assert_eq!(m["ZPL_SYMLINK"], b"/etc/passwd");
    let z = znode_sa(&m).unwrap();
    assert_eq!((z.mode, z.size, z.links, z.uid, z.mtime), (0o120777, 3, 1, 0, (0, 0)));
    let x = extra_sa(&m);
    assert_eq!(x.symlink.as_deref(), Some(&b"/etc/passwd"[..]));
    assert_eq!((x.dxattr, x.crtime, x.xattr_dir), (None, None, 0));

    // Fixed sizes from the registry, a time as two words.
    let b = sa(
        5,
        8,
        &[],
        &[&0o100644u64.to_le_bytes(), &5u64.to_le_bytes(), &2u64.to_le_bytes(), &[[7u8; 8], [9u8; 8]].concat()],
    );
    let z = znode_sa(&parsed(&t, &b).unwrap()).unwrap();
    assert_eq!((z.size, z.links, z.mtime), (5, 2, (u64::from_le_bytes([7; 8]), u64::from_le_bytes([9; 8]))));

    // Two variable-size attributes: a 16-byte header holds both lengths.
    let b = sa(3, 16, &[2, 5], &[&mode, b"ab", b"xattr"]);
    let m = parsed(&t, &b).unwrap();
    assert_eq!((m["ZPL_SYMLINK"], m["ZPL_DXATTR"]), (&b"ab"[..], &b"xattr"[..]));
    assert_eq!(extra_sa(&m).dxattr.as_deref(), Some(&b"xattr"[..]));
    assert!(znode_sa(&m).is_err(), "a file without ZPL_SIZE");
}

/// A damaged SA buffer fails: its magic, a layout or attribute the table does not have, a
/// header too short for its variable lengths, an attribute past the buffer.
#[test]
fn a_damaged_sa_buffer_fails() {
    let t = table();
    let mode = 0o100644u64.to_le_bytes();
    let good = sa(2, 8, &[1], &[&mode, &1u64.to_le_bytes(), b"x"]);
    assert!(parsed(&t, &good).is_ok());
    let mut bad = good.clone();
    bad[0] ^= 1;
    assert!(parsed(&t, &bad).unwrap_err().to_string().contains("magic"));
    assert!(parsed(&t, &sa(9, 8, &[], &[&mode])).unwrap_err().to_string().contains("layout 9"));
    assert!(parsed(&t, &sa(4, 8, &[], &[&mode, &mode])).unwrap_err().to_string().contains("attribute 99"));
    let short = sa(3, 8, &[2, 5], &[&mode, b"ab", b"xattr"]);
    assert!(parsed(&t, &short).unwrap_err().to_string().contains("too short"));
    let past = sa(2, 8, &[64], &[&mode, &1u64.to_le_bytes(), b"x"]);
    assert!(parsed(&t, &past).unwrap_err().to_string().contains("ZPL_SYMLINK past the buffer"));
    assert!(parsed(&t, &good[..4]).is_err(), "a header cut short");
}

/// A legacy znode: its attributes at their places, a short symlink's target right after it;
/// none when the file is empty or its target does not fit; a buffer cut short fails.
#[test]
fn a_legacy_znode_and_its_inline_symlink() {
    let mut b = vec![0u8; ZNODE_PHYS + 16];
    let put = |b: &mut Vec<u8>, at: usize, v: u64| b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    for (at, v) in [(0, 1), (8, 2), (16, 3), (24, 4), (48, 5), (56, 6), (64, 7), (72, 0o120777), (80, 6)] {
        put(&mut b, at, v);
    }
    for (at, v) in [(96, 1), (104, 33), (112, 0x0801), (120, 0x40), (128, 1000), (136, 100)] {
        put(&mut b, at, v);
    }
    b[ZNODE_PHYS..ZNODE_PHYS + 6].copy_from_slice(b"target");
    let z = znode_phys(&b).unwrap();
    assert_eq!(
        z,
        Znode {
            mode: 0o120777,
            size: 6,
            generation: 7,
            links: 1,
            flags: 0x40,
            uid: 1000,
            gid: 100,
            mtime: (3, 4),
            ctime: (0, 0),
        }
    );
    let x = extra_phys(&b, z.size).unwrap();
    assert_eq!((x.atime, x.crtime, x.rdev, x.xattr_dir), ((1, 2), Some((5, 6)), 0x0801, 33));
    assert_eq!(x.symlink.as_deref(), Some(&b"target"[..]));
    assert_eq!(extra_phys(&b, 0).unwrap().symlink, None, "an empty file");
    assert_eq!(extra_phys(&b, 17).unwrap().symlink, None, "a target in its data blocks");
    assert!(znode_phys(&b[..140]).is_err());
    assert!(extra_phys(&b[..100], 0).is_err());
}

/// A file key packs the dataset and object when they fit, and otherwise is a hash marked by
/// bit 62, so the two kinds never meet; different files keep different keys.
#[test]
fn file_keys_pack_or_hash_but_never_collide() {
    assert_eq!(file_key(5, 9), (5 << 40) | 9);
    assert_eq!(file_key((1 << 22) - 1, (1 << 40) - 1) >> 62, 0);
    let big = [(1 << 22, 1), (1, 1 << 40), (u64::MAX, u64::MAX), (1 << 22, 2)];
    let keys: Vec<u64> = big.iter().map(|&(d, o)| file_key(d, o)).collect();
    for (k, &(d, o)) in keys.iter().zip(&big) {
        assert_eq!(k >> 62, 1, "hashed key of {d}/{o}");
        assert_eq!(*k, file_key(d, o), "stable");
    }
    let mut unique = keys.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), keys.len());
}

/// A file's attributes on a real pool (`fixtures/zfs/linux/basic`) from each kind of bonus:
/// the SA buffer as the pool has it, a legacy znode in its place, a bonus of another type
/// (damage), an SA buffer without a table or without the size (in no spill block); only
/// regular files are files.
#[test]
fn attributes_from_each_kind_of_bonus() {
    use fs_inspect_core::DriverContext;
    let src = fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("zfs/linux/basic.fsbs"));
    let fs = ZfsFs::open(src, &DriverContext::default()).unwrap();
    let r = fs.reader();
    let z = fs.file_systems().unwrap().0.into_iter().find(|z| z.prefix.is_empty()).unwrap();
    let root = z.objset.dnode(r, z.root).unwrap().unwrap();
    let mut file = None;
    let mut link = None;
    for e in zap::entries(r, &root, 1 << 16).unwrap() {
        let v = e.first().unwrap();
        match v >> 60 {
            DT_REG if file.is_none() => file = Some(v & ((1 << 48) - 1)),
            10 if link.is_none() => link = Some(v & ((1 << 48) - 1)),
            _ => {}
        }
    }
    let (file, link) = (file.unwrap(), link.unwrap());
    let d = z.objset.dnode(r, file).unwrap().unwrap();
    assert_eq!(d.bonustype, ot::SA);
    let got = z.attrs(r, &d).unwrap();
    assert_eq!(z.record(r, &d).unwrap().0, got);
    assert_eq!(z.file(r, file).unwrap().unwrap().1, got);
    // Not regular files: the root directory, a symlink.
    assert!(z.file(r, z.root).unwrap().is_none());
    assert!(z.file(r, link).unwrap().is_none());

    // A legacy znode in the bonus.
    let mut legacy = d.clone();
    legacy.bonustype = ot::ZNODE;
    legacy.bonus = vec![0u8; ZNODE_PHYS];
    legacy.bonus[72..80].copy_from_slice(&(S_IFREG | 0o644).to_le_bytes());
    legacy.bonus[80..88].copy_from_slice(&42u64.to_le_bytes());
    let zn = z.attrs(r, &legacy).unwrap();
    assert_eq!((zn.mode, zn.size), (S_IFREG | 0o644, 42));
    assert_eq!(z.record(r, &legacy).unwrap().0, zn);
    // Another bonus type.
    let mut other = d.clone();
    other.bonustype = 99;
    assert!(z.attrs(r, &other).unwrap_err().to_string().contains("bonus of type 99"));
    assert!(z.record(r, &other).is_err());
    // An SA bonus in a file system without an SA table.
    let no_table = Zpl { sa: None, ..z.clone() };
    assert!(no_table.attrs(r, &d).is_err());
    assert!(no_table.record(r, &d).is_err());
    // A layout of the mode only, no spill block (or a hole): no size, damage.
    let mut t = z.sa.clone().unwrap();
    let mode = *t.attrs.iter().find(|(_, (n, _))| n == "ZPL_MODE").unwrap().0;
    t.layouts.insert(999, vec![mode]);
    let only_mode = Zpl { sa: Some(t), ..z.clone() };
    let mut short = d.clone();
    short.bonus = sa(999, 8, &[], &[&(S_IFREG | 0o600).to_le_bytes()]);
    for spill in [None, Some(crate::format::blkptr::BlkPtr::default())] {
        short.spill = spill;
        assert!(only_mode.attrs(r, &short).unwrap_err().to_string().contains("ZPL_SIZE"));
    }
}
