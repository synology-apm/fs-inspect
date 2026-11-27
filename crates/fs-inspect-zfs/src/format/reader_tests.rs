//! What a read refuses, on block pointers made from a real pool's (`fixtures/zfs/linux/basic`):
//! sizes past the format's, embedded data of another type, big-endian and encrypted blocks.

use super::*;
use fs_inspect_core::{DriverContext, ErrorKind};

/// `bp` changed by `f`.
fn with(bp: &BlkPtr, f: impl FnOnce(&mut BlkPtr)) -> BlkPtr {
    let mut b = *bp;
    f(&mut b);
    b
}

fn pool() -> crate::format::ZfsFs {
    let src = fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("zfs/linux/basic.fsbs"));
    crate::format::ZfsFs::open(src, &DriverContext::default()).unwrap()
}

/// The MOS's block pointer reads; changed, it is refused with the kind a caller tells apart:
/// a size past the largest block is damage, big-endian, encrypted or a non-data embedded
/// payload are not supported; a verification's read refuses them the same way.
#[test]
fn a_read_refuses_what_it_cannot_decode() {
    let fs = pool();
    let r = fs.reader();
    let good = fs.uberblock().rootbp;
    assert_eq!(r.read(&good).unwrap().len() as u64, good.lsize);
    assert!(r.verify_copies(&good).unwrap().is_some());

    let kind = |bp: &BlkPtr| r.read(bp).unwrap_err().kind();
    let vkind = |bp: &BlkPtr| r.verify_copies(bp).unwrap_err().kind();
    let huge = with(&good, |b| b.lsize = MAX_BLOCK + 512);
    assert_eq!(kind(&huge), ErrorKind::Corrupt);
    assert_eq!(vkind(&huge), ErrorKind::Corrupt);
    let huge_p = with(&good, |b| b.psize = MAX_BLOCK + 512);
    assert_eq!(vkind(&huge_p), ErrorKind::Corrupt);
    let be = with(&good, |b| b.little_endian = false);
    assert_eq!(kind(&be), ErrorKind::Unsupported);
    assert_eq!(vkind(&be), ErrorKind::Unsupported);
    let crypt = with(&good, |b| (b.crypt, b.level, b.ty) = (true, 0, ot::PLAIN_FILE_CONTENTS));
    assert!(encrypted_data(&crypt));
    assert_eq!(kind(&crypt), ErrorKind::Unsupported);
    // Its indirect blocks and the dnodes of an encrypted dataset are in the clear.
    assert!(!encrypted_data(&with(&crypt, |b| b.level = 1)));
    assert!(!encrypted_data(&with(&crypt, |b| b.ty = ot::DNODE)));
    let embedded = with(&good, |b| (b.embedded, b.etype) = (true, 1));
    assert_eq!(kind(&embedded), ErrorKind::Unsupported);
}

/// A hole reads as zeros of its logical size, without touching the device.
#[test]
fn a_hole_reads_as_zeros() {
    let fs = pool();
    let hole = with(&BlkPtr::default(), |b| (b.lsize, b.psize) = (4096, 4096));
    assert!(hole.is_hole());
    assert_eq!(*fs.reader().read(&hole).unwrap(), vec![0u8; 4096]);
    assert_eq!(*fs.reader().verify_copies(&hole).unwrap().unwrap(), vec![0u8; 4096]);
}
