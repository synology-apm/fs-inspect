//! A volume without a recognized file system: every byte of it counts as used.

use fs_inspect_core::FsInfoExt;
use fs_inspect_core::cursor::VecCursor;
use fs_inspect_core::{ByteRange, Filesystem, FsInfo, FsKind, RangeCursor, Result};
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct RawVolume {
    info: FsInfo,
}

impl RawVolume {
    pub(crate) fn filesystem(len: u64) -> Arc<dyn Filesystem> {
        Arc::new(RawVolume { info: FsInfo::new(FsKind::Raw, 512, len, None, None) })
    }
}

impl fs_inspect_core::sealed::Fs for RawVolume {}

impl Filesystem for RawVolume {
    fn info(&self) -> &FsInfo {
        &self.info
    }

    fn allocated(self: Arc<Self>) -> Result<Box<dyn RangeCursor>> {
        Ok(Box::new(VecCursor::new(vec![ByteRange::new(0, self.info.size)])))
    }
}
