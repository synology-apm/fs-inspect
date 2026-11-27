//! How an async consumer (e.g. an SDK whose content source is `async fn read(offset, len)`)
//! plugs in: a small adapter implements the synchronous `BlockSource` with
//! `Handle::block_on`, and the whole pipeline runs inside `spawn_blocking`, the map read
//! from there. This checks the trait bounds (`Send + Sync + 'static`) hold up in practice.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::io::SourceError;
use fs_inspect::{BlockClass, BlockSource, DiskSet, DiskSpec, OpenOptions, VolumeMapOptions};
use fs_inspect_testkit::{Placement, ROOT, SyntheticVolume, VolumeSpec};
use std::sync::Arc;
use tokio::runtime::Handle;

/// Stand-in for an async content source (positional reads returning owned bytes).
#[derive(Debug)]
struct AsyncContent {
    data: Vec<u8>,
}

impl AsyncContent {
    async fn read(&self, offset: u64, len: u64) -> std::io::Result<Vec<u8>> {
        tokio::task::yield_now().await;
        let (s, e) = (offset as usize, (offset + len) as usize);
        self.data.get(s..e).map(<[u8]>::to_vec).ok_or_else(|| std::io::ErrorKind::UnexpectedEof.into())
    }
    fn size(&self) -> Option<u64> {
        Some(self.data.len() as u64)
    }
}

/// The adapter a consumer would write (about 30 lines).
#[derive(Debug)]
struct BlockingAdapter {
    inner: Arc<AsyncContent>,
    handle: Handle,
    len: u64,
}

impl BlockSource for BlockingAdapter {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        let data = self
            .handle
            .block_on(self.inner.read(offset, buf.len() as u64))
            .map_err(|error| SourceError::os(offset, buf.len(), error))?;
        buf.copy_from_slice(&data);
        Ok(())
    }
    fn size(&self) -> u64 {
        self.len
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_runs_in_spawn_blocking() {
    let mut v = SyntheticVolume::format(VolumeSpec { clusters: 2048, ..Default::default() });
    v.create_file(ROOT, "a.bin", 300_000, 1, Placement::MaxRun(3));
    let content = Arc::new(AsyncContent { data: v.image.clone() });
    let len = content.size().expect("disk images have a size");
    let handle = Handle::current();

    // Open and list in a blocking task (reads happen there).
    let src = Arc::new(BlockingAdapter { inner: content, handle, len });
    let (img, vols) = tokio::task::spawn_blocking(move || {
        let img = DiskSet::open(&[DiskSpec::source(src).raw()], &OpenOptions::default(), None)?;
        let vols = img.volumes(None)?.to_vec();
        Ok::<_, fs_inspect::Error>((img, vols))
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(vols.len(), 1);

    // Map in a blocking task (the reads happen there); the map is plain data after.
    let map = tokio::task::spawn_blocking(move || {
        img.open_volume(fs_inspect::VolumeIndex(0), None)?.map(&VolumeMapOptions::default(), None)
    })
    .await
    .unwrap()
    .unwrap();
    let all = map.blocks(BlockClass::Used, None).unwrap().to_vec();
    assert!(!all.is_empty());
    assert!(all.windows(2).all(|w| w[0].end() < w[1].offset), "sorted, disjoint, coalesced");
}
