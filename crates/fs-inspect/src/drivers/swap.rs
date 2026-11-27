//! Linux swap areas: like a Windows paging file, their content is never needed by a backup.
//! Only the header page is used (signature, UUID and label: fstab and the initramfs find the
//! swap by them); the rest is unused. A swap holding a hibernation image (the kernel resumes
//! from it at the next boot) is all used.

use fs_inspect_core::FsInfoExt;
use fs_inspect_core::cursor::VecCursor;
use fs_inspect_core::exclude::{SwapKind as Kind, swap_signature as signature};
use fs_inspect_core::{
    ByteRange, Confidence, Driver, DriverContext, Error, Filesystem, FsInfo, FsKind, RangeCursor, Result, Sniff,
};
use fs_inspect_io::DynSource;
use std::sync::Arc;

pub(crate) static DRIVER: Driver = Driver { name: "swap", kinds: &[FsKind::LinuxSwap], probe, open, validates: false };

/// Low: the signature lies past sector 0, so it must not outrank a partition table there (a
/// disk once made a swap area whole and later partitioned keeps the old signature). A whole-disk
/// swap area without a table is still found as a bare volume.
fn probe(s: &Sniff<'_>) -> Option<(FsKind, Confidence)> {
    signature(s.head).map(|_| (FsKind::LinuxSwap, Confidence::Low))
}

fn open(src: DynSource, _ctx: &DriverContext) -> Result<Arc<dyn Filesystem>> {
    let n = (64 << 10).min(src.size()) as usize;
    let head = src.read_vec(0, n)?;
    let (page, kind) = signature(&head).ok_or_else(|| Error::format("no swap signature"))?;
    let v0 = &head[page - 10..page] == b"SWAP-SPACE";
    let page = page as u64;
    // swap header v1 (offset 1024): version, last_page, nr_badpages, uuid[16], label[16]. A
    // version 0 area has a bitmap there instead: no size, UUID or label; it fills the volume.
    let le = |o: usize| u32::from_le_bytes([head[o], head[o + 1], head[o + 2], head[o + 3]]);
    let v1 = !v0 && le(1024) == 1;
    let pages = if v1 { u64::from(le(1028)).saturating_add(1) } else { src.size() / page };
    let size = pages.saturating_mul(page).min(src.size()).max(page);
    let (uuid, label) = if v1 {
        let uuid: [u8; 16] = fs_inspect_core::bytes::bytes_at(&head, 1036)?;
        let label: Vec<u8> = head[1052..1068].iter().copied().take_while(|&b| b != 0).collect();
        ((uuid != [0u8; 16]).then(|| fs_inspect_core::guid::format_uuid(&uuid)), label)
    } else {
        (None, Vec::new())
    };
    let used = match kind {
        Kind::Swap => page,
        Kind::Hibernated => size,
    };
    Ok(Arc::new(Swap {
        info: FsInfo::new(
            FsKind::LinuxSwap,
            page,
            size,
            (!label.is_empty()).then(|| String::from_utf8_lossy(&label).into_owned()),
            uuid,
        ),
        used,
    }))
}

#[derive(Debug)]
struct Swap {
    info: FsInfo,
    used: u64,
}

impl fs_inspect_core::sealed::Fs for Swap {}

impl Filesystem for Swap {
    fn info(&self) -> &FsInfo {
        &self.info
    }

    fn allocated(self: Arc<Self>) -> Result<Box<dyn RangeCursor>> {
        Ok(Box::new(VecCursor::new(vec![ByteRange::new(0, self.used)])))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use fs_inspect_io::MemSource;

    fn area(page: usize, sig: &[u8], pages: u32) -> Vec<u8> {
        let mut b = vec![0u8; page * pages as usize];
        b[page - 10..page - 10 + sig.len()].copy_from_slice(sig);
        b[1024..1028].copy_from_slice(&1u32.to_le_bytes());
        b[1028..1032].copy_from_slice(&(pages - 1).to_le_bytes());
        b[1036..1052].copy_from_slice(&[0x11; 16]);
        b[1052..1056].copy_from_slice(b"swap");
        b
    }

    fn used(img: Vec<u8>) -> (Vec<ByteRange>, FsInfo) {
        let fs = open(Arc::new(MemSource::new(img)), &DriverContext::default()).unwrap();
        let info = fs.info().clone();
        let v = fs_inspect_core::CursorIter::new(fs.allocated().unwrap()).collect::<Result<Vec<_>>>().unwrap();
        (v, info)
    }

    #[test]
    fn header_page_only() {
        for page in fs_inspect_core::exclude::SWAP_PAGE_SIZES {
            let (u, info) = used(area(page, b"SWAPSPACE2", 8));
            assert_eq!(u, [ByteRange::new(0, page as u64)], "page {page}");
            assert_eq!(info.size, 8 * page as u64);
            assert_eq!(info.label.as_deref(), Some("swap"));
            assert!(info.uuid.is_some());
        }
    }

    /// A version 0 area: the page after the boot block is a bitmap, not a header.
    #[test]
    fn version_0_has_no_header_fields() {
        let mut b = vec![0u8; 4096 * 8];
        b[1024..4086].fill(0xFF);
        b[4086..4096].copy_from_slice(b"SWAP-SPACE");
        let (u, info) = used(b);
        assert_eq!(u, [ByteRange::new(0, 4096)]);
        assert_eq!((info.size, info.uuid, info.label), (8 * 4096, None, None));
    }

    #[test]
    fn hibernation_image_is_kept() {
        let (u, _) = used(area(4096, b"S1SUSPEND", 8));
        assert_eq!(u, [ByteRange::new(0, 8 * 4096)]);
    }

    #[test]
    fn probe_needs_the_signature_at_a_page_end() {
        let s = |b: &[u8]| probe(&Sniff { head: b, volume_size: b.len() as u64 });
        assert!(s(&area(4096, b"SWAPSPACE2", 4)).is_some());
        let mut b = vec![0u8; 8192];
        b[100..110].copy_from_slice(b"SWAPSPACE2");
        assert!(s(&b).is_none());
    }
}
