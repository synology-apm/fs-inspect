//! The file system drivers and the probe that picks one for a volume.

use fs_inspect_core::{
    Confidence, Diagnostics, Driver, DriverContext, FsInfo, FsKind, Limits, Result, SNIFF_BYTES, Sniff,
};
use fs_inspect_io::{BlockSource, DynSource, HeadSource};
use std::sync::Arc;

/// The drivers, in probe order: ties in confidence go to the earlier one. The one list of
/// them (a new file system also needs its `FsKind`: `docs/contributing/adding-a-file-system.md`).
static DRIVERS: &[Driver] = &[
    fs_inspect_ntfs::DRIVER,
    fs_inspect_fat::EXFAT_DRIVER,
    fs_inspect_apfs::DRIVER,
    fs_inspect_btrfs::DRIVER,
    fs_inspect_xfs::DRIVER,
    fs_inspect_ext::DRIVER,
    fs_inspect_fat::FAT_DRIVER,
    fs_inspect_refs::DRIVER,
    fs_inspect_zfs::DRIVER,
    fs_inspect_xfs::LOG_DRIVER,
    crate::drivers::swap::DRIVER,
];

/// Every driver built in, in probe order.
pub fn drivers() -> &'static [Driver] {
    DRIVERS
}

/// The driver that opens `kind` (`None` for [`FsKind::Raw`]).
pub fn driver_for(kind: FsKind) -> Option<&'static Driver> {
    DRIVERS.iter().find(|d| d.kinds.contains(&kind))
}

/// What [`probe_volume`] found: the driver most confident about the volume, the file system it
/// recognized and how sure it is, and the bytes it looked at (the volume's first
/// [`SNIFF_BYTES`], or all of a shorter one), for the open that follows.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Probe {
    pub driver: &'static Driver,
    pub kind: FsKind,
    pub confidence: Confidence,
    pub head: Arc<[u8]>,
}

/// The driver most confident about the volume at `[start, start + len)` of `disk`.
pub fn probe_volume(disk: &dyn BlockSource, start: u64, len: u64) -> Result<Option<Probe>> {
    let len = len.min(disk.size().saturating_sub(start));
    let n = (SNIFF_BYTES as u64).min(len) as usize;
    if n < 512 {
        return Ok(None);
    }
    let mut head = vec![0u8; n];
    disk.read_exact_at(start, &mut head)?;
    let sniff = Sniff { head: &head, volume_size: len };
    let mut best: Option<(&'static Driver, FsKind, Confidence)> = None;
    for d in drivers() {
        if let Some((kind, c)) = (d.probe)(&sniff)
            && c > Confidence::None
            && best.is_none_or(|(_, _, b)| c > b)
        {
            best = Some((d, kind, c));
        }
    }
    Ok(best.map(|(driver, kind, confidence)| Probe { driver, kind, confidence, head: head.into() }))
}

/// What the file system on `src` (a volume's bytes from offset 0, e.g. a snapshot device) says
/// of itself; `None` when no driver recognizes it. The driver opens it as a scan would (its
/// superblock and what checking it takes, not its allocation), alone: a file system spanning
/// several volumes (a ZFS pool, an XFS volume with an external log) may fail to open.
pub fn probe_fs(src: DynSource) -> Result<Option<FsInfo>> {
    let Some(p) = probe_volume(&*src, 0, src.size())? else { return Ok(None) };
    let ctx =
        DriverContext { limits: Limits::default(), diagnostics: Diagnostics::new(), peers: None, ..Default::default() };
    let head = Arc::new(HeadSource::new(src, p.head));
    let fs = (p.driver.open)(head.clone(), &ctx);
    head.release();
    Ok(Some(fs?.info().clone()))
}
