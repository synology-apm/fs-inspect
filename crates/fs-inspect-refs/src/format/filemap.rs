//! What the files' records say about their data: the mapping of each non-resident stream with
//! the clusters past its valid data length, and the [`FileMap`] of the volume.

use crate::format::files::{FileEntry, Stream, object};
use crate::format::fs::RefsFs;
use fs_inspect_core::files::zero_from;
use fs_inspect_core::windows::is_paging_io_file;
use fs_inspect_core::{FileExtent, FileInfo, FileMap, Result};

/// `FILE_ATTRIBUTE_COMPRESSED`.
pub const ATTR_COMPRESSED: u32 = 0x800;

/// The data of a non-resident stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamData {
    pub extents: Vec<FileExtent>,
    /// Logical ranges past the valid data length that read as zeros (clusters wholly past it;
    /// none for compressed streams nor paging files, nor when the log holds records past the
    /// checkpoint: a valid data length extended only in the log makes them real data).
    pub zero: Vec<fs_inspect_core::ByteRange>,
    /// Compressed: clusters do not map one to one to file bytes.
    pub no_narrow: bool,
    /// A root file Windows writes by paging I/O, which updates no time stamp nor USN.
    pub paging: bool,
}

impl RefsFs {
    /// The data of stream `s` of file `f`.
    pub fn stream_data(&self, f: &FileEntry, s: &Stream) -> StreamData {
        let c = u64::from(self.reader().cluster_bytes());
        let no_narrow = f.attributes & ATTR_COMPRESSED != 0;
        let paging = f.dir == object::ROOT && s.name.is_none() && f.name.as_deref().is_some_and(is_paging_io_file);
        let extents: Vec<FileExtent> =
            s.extents.iter().map(|x| FileExtent::mapped(x.vcn * c, x.lcn * c, x.clusters * c)).collect();
        let zero = if paging || no_narrow || self.log_pending() {
            Vec::new()
        } else {
            zero_from(&extents, s.valid.min(s.size).div_ceil(c) * c)
        };
        StreamData { extents, zero, no_narrow, paging }
    }
}

impl FileMap for RefsFs {
    /// Each non-resident stream of each file outside the File System Metadata directory (key:
    /// the file id, the directory above bit 32 and the stream's position above bit 56;
    /// informational only), with the zeros of [`RefsFs::stream_data`]. Files that do not read
    /// are left out.
    fn for_each(&self, f: &mut dyn FnMut(FileInfo) -> Result<()>) -> Result<()> {
        self.walk_files(&mut |file| {
            let Ok(file) = file else { return Ok(()) };
            if file.dir == object::FS_METADATA {
                return Ok(());
            }
            for (i, s) in file.streams.iter().enumerate().filter(|(_, s)| !s.resident) {
                let d = self.stream_data(&file, s);
                let key = file.id ^ (file.dir << 32) ^ ((i as u64) << 56);
                f(FileInfo { key, extents: d.extents, zero_as_read: d.zero, settled: true })?;
            }
            Ok(())
        })
    }
}
