//! A file's extents as its file extent records give them ([`extents_of`]): what path lookup
//! and the walk of change tracking (`format::files`) both map a file with.

use crate::format::btree::Reader;
use crate::format::records::FileExtent;
use fs_inspect_core::FileExtent as Extent;
use fs_inspect_core::{Error, ExtentBuilder, ExtentOrder, Result};

/// The extents of `data_id` (`exts` is sorted by id then logical offset), validated.
pub fn extents_of(r: &Reader, exts: &[FileExtent], data_id: u64) -> Result<Vec<Extent>> {
    let geo = &r.geo;
    let bs = geo.block_size as u64;
    let vol_bytes = geo.volume_bytes();
    let lo = exts.partition_point(|e| e.id < data_id);
    let hi = exts.partition_point(|e| e.id <= data_id);
    let mine = &exts[lo..hi];
    let mut out = ExtentBuilder::new(ExtentOrder::Ascending, r.limits.max_file_extents);
    for e in mine {
        if e.logical.checked_add(e.length).is_none() {
            return Err(Error::corrupt("extent end overflows"));
        }
        let physical = if e.phys_block == 0 {
            None
        } else {
            let p = e.phys_block.checked_mul(bs).filter(|p| p.checked_add(e.length).is_some_and(|x| x <= vol_bytes));
            Some(p.ok_or_else(|| Error::corrupt(format!("extent at block {} is outside the container", e.phys_block)))?)
        };
        out.push(Extent { logical: e.logical, physical, length: e.length, flags: e.flags as u32 })?;
    }
    out.finish()
}
