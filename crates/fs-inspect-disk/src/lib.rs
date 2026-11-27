//! Disk images without external libraries.
//!
//! * [`open_container`] / [`open_disk`]: the disk inside an image, from its content: VHDX,
//!   VHD (fixed or dynamic), or raw (one file, or split segments `disk.001`, `disk.002`, ...).
//! * [`partition::scan`]: its partition table (MBR with logical partitions, GPT, or none), with
//!   a caller-supplied file system probe for every partition.
//!
//! Refused with an `Unsupported` error that says what to do: VMDK, qcow2, E01, differencing
//! VHD/VHDX, VHDX files with a non-empty log, and VHDX files with a required region or
//! metadata item this crate does not know. A damaged container (bad checksum, offsets or
//! sizes out of bounds) is a `Corrupt` error. All input is untrusted: every offset read from
//! the image is checked against the file before use.
#![forbid(unsafe_code)]

use fs_inspect_core::FindingExt;
use fs_inspect_core::Named;
pub mod partition;
mod vhd;
mod vhdx;

use fs_inspect_core::{Diagnostic, Error, Finding, FindingKind, Integrity, Outcome, Result, Site, StructureKind};
use fs_inspect_io::{BlockSource, DynSource, FileSource, SplitFileSource};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use partition::{DiskId, DiskIdKind, Partition, PartitionScheme, Probe, Scheme, Table, disk_id, scan, verify_gpt};

pub(crate) fn corrupt(msg: impl Into<String>) -> Error {
    Error::corrupt(msg.into())
}

fs_inspect_io::named_enum! {
    /// How the disk is stored.
    pub enum ContainerFormat ("container format") {
        /// The bytes are the disk (one file, a device, a caller's reader).
        Raw = 1 => "raw",
        /// Raw bytes split over numbered segment files.
        Split = 2 => "split",
        /// A fixed VHD: the disk bytes followed by a 512-byte footer.
        VhdFixed = 3 => "vhd_fixed",
        /// A dynamic (sparse) VHD.
        VhdDynamic = 4 => "vhd_dynamic",
        /// A VHDX, fixed or dynamic.
        Vhdx = 5 => "vhdx",
    }
}

/// The disk inside an image.
#[derive(Clone)]
pub struct Disk {
    /// The disk's bytes, container metadata removed.
    pub source: DynSource,
    pub format: ContainerFormat,
    /// Logical sector size, when the container records it (VHDX) or the source reports it (a
    /// device, a caller's source).
    pub sector_size: Option<u32>,
    /// What opening the container worked around (a damaged VHD footer replaced by its copy).
    pub warnings: Vec<Diagnostic>,
    /// The container file (VHD, VHDX) the disk is read from; `None` for a raw disk.
    pub file: Option<DynSource>,
}

impl Disk {
    /// A disk without a container: `source` as it is.
    pub fn raw(source: DynSource, sector_size: Option<u32>) -> Disk {
        Disk { source, format: ContainerFormat::Raw, sector_size, warnings: Vec::new(), file: None }
    }
}

impl std::fmt::Debug for Disk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Disk")
            .field("format", &self.format)
            .field("len", &self.source.size())
            .field("sector_size", &self.sector_size)
            .finish()
    }
}

/// A verification of `disk`'s container: a VHD's footer and its copy, its dynamic header; a
/// VHDX's two headers and two region tables. Copies are checked each, a wrong one beside a
/// right one recovered. Nothing for a raw disk.
pub fn verify(disk: &Disk, integrity: &Integrity) -> Result<()> {
    match (&disk.file, disk.format) {
        (Some(f), ContainerFormat::Vhdx) => vhdx::verify(&**f, integrity),
        (Some(f), ContainerFormat::VhdFixed | ContainerFormat::VhdDynamic) => vhd::verify(&**f, integrity),
        _ => Ok(()),
    }
}

/// The copies of `structure`, each `(where it is, what is wrong with it)`: a wrong one is
/// recovered when another is right; when none is, the structure is damaged too.
pub(crate) fn copies(integrity: &Integrity, structure: StructureKind, copies: Vec<(u64, Option<String>)>) {
    let mut good = false;
    for (at, why) in &copies {
        match why {
            None => {
                integrity.checked(structure, 0);
                good = true;
            }
            Some(why) => {
                let kind = if why.contains("checksum") || why.contains("CRC") {
                    FindingKind::Mismatch
                } else {
                    FindingKind::Unreadable
                };
                let site = Site::new(structure).at(*at);
                integrity.report(Finding::new(&site, kind, Outcome::Recovered, format!("{structure} at {at}: {why}")));
            }
        }
    }
    if !good && !copies.is_empty() {
        // No place: the copies have theirs (a finding each, kept apart from this one).
        let site = Site::new(structure);
        integrity.report(Finding::new(
            &site,
            FindingKind::Unreadable,
            Outcome::Damaged,
            format!("no {structure} is right"),
        ));
    }
}

/// Formats recognized only to refuse them with a useful message.
fn unsupported_format(head: &[u8]) -> Option<&'static str> {
    if head.starts_with(b"KDMV") || head.starts_with(b"# Disk DescriptorFile") {
        Some("VMDK images are not supported; convert to raw (qemu-img convert -O raw) or VHDX")
    } else if head.starts_with(b"QFI\xFB") {
        Some("qcow2 images are not supported; convert to raw (qemu-img convert -O raw)")
    } else if head.starts_with(b"EVF\x09\x0D\x0A\xFF\x00") || head.starts_with(b"EVF2\x0D\x0A\x81\x00") {
        Some("E01 images are not supported; export to raw (ewfexport) or mount them (ewfmount) and use the raw file")
    } else {
        None
    }
}

/// The disk in one image file (or caller-supplied source), by content: VHDX by its signature
/// at offset 0, VHD by its footer in the last sector, otherwise raw. Refuses the formats listed
/// in the [crate] docs.
pub fn open_container(file: DynSource) -> Result<Disk> {
    if vhdx::is_vhdx(&*file)? {
        let (source, format, sector) = vhdx::open(file.clone())?;
        return Ok(Disk { source, format, sector_size: Some(sector), warnings: Vec::new(), file: Some(file) });
    }
    if let Some(f) = vhd::footer(&*file)? {
        // VHD records no sector size; a disk with 4 KiB sectors may still be inside.
        let (source, format) = vhd::open(file.clone(), &f.footer)?;
        return Ok(Disk { source, format, sector_size: None, warnings: f.warnings, file: Some(file) });
    }
    let mut head = vec![0u8; file.size().min(32) as usize];
    file.read_exact_at(0, &mut head)?;
    if let Some(msg) = unsupported_format(&head) {
        return Err(Error::unsupported(msg));
    }
    let sector_size = file.sector_size();
    Ok(Disk::raw(file, sector_size))
}

/// Raw image bytes: one file, or the segments of a split image in order (finding them from
/// the first: [`SplitFileSource::discover`]), read up to `queue_depth` at once
/// ([`FileSource::with_queue_depth`]). No container detection.
pub fn open_raw_files<P: AsRef<Path>>(
    paths: &[P],
    queue_depth: std::num::NonZeroUsize,
) -> Result<(DynSource, ContainerFormat)> {
    let paths: Vec<PathBuf> = paths.iter().map(|p| p.as_ref().to_path_buf()).collect();
    Ok(match paths.as_slice() {
        [] => return Err(Error::invalid_argument("no image path given")),
        [one] => (Arc::new(FileSource::open(one)?.with_queue_depth(queue_depth)), ContainerFormat::Raw),
        many => (Arc::new(SplitFileSource::open(many)?.with_queue_depth(queue_depth)), ContainerFormat::Split),
    })
}

/// The disk in an image: one file of any supported format, or the segments of a split raw
/// image (see [`open_raw_files`]). The format comes from the first file, so a VHD or VHDX
/// named like a segment (`vm.vhdx.1`) is never joined with its neighbours. Up to
/// `queue_depth` reads overlap ([`FileSource::with_queue_depth`]).
pub fn open_disk<P: AsRef<Path>>(paths: &[P], queue_depth: std::num::NonZeroUsize) -> Result<Disk> {
    let first = paths.first().ok_or_else(|| Error::invalid_argument("no image path given"))?;
    let disk = open_container(Arc::new(FileSource::open(first)?.with_queue_depth(queue_depth)))?;
    if disk.format != ContainerFormat::Raw {
        if paths.len() > 1 {
            return Err(Error::unsupported(format!(
                "a {} image is one file; only raw images are split",
                disk.format.as_str()
            )));
        }
        return Ok(disk);
    }
    let (source, format) = open_raw_files(paths, queue_depth)?;
    Ok(Disk { source, format, ..disk })
}
