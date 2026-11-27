//! Small files' content read together ([`Prefetch`]): a walk hands the exporter a batch of
//! entries, their streams opened; the streams small and mapped one to one onto the volume are
//! read a window at a time, their pieces sorted by volume offset and merged ([`plan`],
//! [`read_runs`]), instead of one file after the other.

use fs_inspect_core::ns::{DirEntry, NodeId, NodeInfo, NodeKind, StreamId};
use fs_inspect_core::read::{FileReader, SegmentKind};
#[cfg(test)]
use fs_inspect_core::{DirEntryExt, NodeInfoExt, StatExt};
use fs_inspect_core::{Error, Result};
use fs_inspect_io::DynSource;
use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, plan, read_runs};
use std::collections::{HashMap, VecDeque};

/// A stream's key: its file and which stream.
type Key = (NodeId, StreamId);

/// Streams of a batch read together, a window at a time.
#[derive(Default)]
pub(crate) struct Prefetch {
    /// The volume the segments point into (`None`: nothing is read ahead).
    src: Option<DynSource>,
    /// The batch's streams that read together, in list order, not fetched yet.
    queue: VecDeque<Planned>,
    /// Streams fetched, not taken yet: each one's bytes.
    got: HashMap<Key, Vec<u8>>,
}

/// A stream to fetch: its length and its data pieces (stream offset, length, volume offset).
struct Planned {
    key: Key,
    len: u64,
    pieces: Vec<(u64, u64, u64)>,
}

impl Prefetch {
    /// Longest stream read with others.
    pub(crate) const MAX_LEN: u64 = 256 << 10;
    /// Most bytes of streams read in one window.
    pub(super) const WINDOW: u64 = 8 << 20;

    pub(crate) fn new(src: Option<DynSource>) -> Prefetch {
        Prefetch { src, ..Prefetch::default() }
    }

    /// Plan the streams of `batch` to read together (those of the entries `keep` passes), in
    /// its order; what the batch before left is dropped.
    pub(crate) fn batch(&mut self, batch: &[(DirEntry, Option<Result<NodeInfo>>)], keep: impl Fn(&NodeInfo) -> bool) {
        self.queue.clear();
        self.got.clear();
        if self.src.is_none() {
            return;
        }
        for info in batch.iter().filter_map(|(_, i)| i.as_ref()?.as_ref().ok()) {
            if info.stat.kind != NodeKind::File || !keep(info) {
                continue;
            }
            for (id, reader) in &info.readers {
                let Ok(reader) = reader else { continue };
                let key = (info.stat.node, *id);
                if self.queue.iter().any(|p| p.key == key) {
                    // Another name of a file listed already.
                    continue;
                }
                if let Some(pieces) = pieces(&**reader) {
                    self.queue.push_back(Planned { key, len: reader.len(), pieces });
                }
            }
        }
    }

    /// The bytes of stream `key` when it reads with others: fetched with those after it in
    /// the batch, up to [`WINDOW`](Self::WINDOW) bytes (the window before dropped). `None`:
    /// not planned, or a piece of it did not read (read it as any other). Only a cancel is
    /// an error.
    pub(crate) fn take(&mut self, key: Key) -> Result<Option<Vec<u8>>> {
        if let Some(b) = self.got.remove(&key) {
            return Ok(Some(b));
        }
        let (Some(src), Some(at)) = (&self.src, self.queue.iter().position(|p| p.key == key)) else {
            return Ok(None);
        };
        self.got.clear();
        self.queue.drain(..at);
        let mut window = Vec::new();
        let mut bytes = 0;
        while let Some(p) = self.queue.front()
            && (window.is_empty() || bytes + p.len <= Self::WINDOW)
        {
            bytes += p.len;
            window.extend(self.queue.pop_front());
        }
        let mut bufs: Vec<Option<Vec<u8>>> = window.iter().map(|p| Some(vec![0; p.len as usize])).collect();
        let items = window
            .iter()
            .enumerate()
            .flat_map(|(i, p)| p.pieces.iter().map(move |&(at, len, phys)| (phys, len, (i, at as usize, len as usize))))
            .collect();
        read_runs::<_, Error>(&**src, plan(items, BATCH_BYTES, GAP_BYTES), &mut |(i, at, len), b| {
            match (b, &mut bufs[i]) {
                (Some(b), Some(buf)) => buf[at..at + len].copy_from_slice(b),
                // Not read: that stream is read as any other.
                _ => bufs[i] = None,
            }
            Ok(())
        })?;
        for (p, buf) in window.into_iter().zip(bufs) {
            if let Some(buf) = buf {
                self.got.insert(p.key, buf);
            }
        }
        Ok(self.got.remove(&key))
    }
}

/// The data pieces of `reader` (stream offset, length, volume offset) when it reads with
/// others: at most [`Prefetch::MAX_LEN`] bytes, all of them data mapped one to one onto the
/// volume, holes or zeros (`None` else, or when nothing is data).
fn pieces(reader: &dyn FileReader) -> Option<Vec<(u64, u64, u64)>> {
    let len = reader.len();
    if len == 0 || len > Prefetch::MAX_LEN {
        return None;
    }
    let mut pieces = Vec::new();
    let mut covered = 0;
    for s in reader.segments().ok()? {
        if s.logical >= len {
            break;
        }
        if s.logical != covered {
            // A gap the segments do not describe.
            return None;
        }
        let end = s.end().min(len);
        match s.kind {
            SegmentKind::Data { physical } if end > s.logical => pieces.push((s.logical, end - s.logical, physical)),
            SegmentKind::Data { .. } | SegmentKind::Hole | SegmentKind::Zero { .. } => {}
            _ => return None,
        }
        covered = end;
    }
    (covered == len && !pieces.is_empty()).then_some(pieces)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use fs_inspect_core::files::FileExtent;
    use fs_inspect_core::ns::Stat;
    use fs_inspect_core::read::{ExtentReader, MemReader};
    use fs_inspect_io::{CountingSource, MemSource};
    use std::sync::Arc;

    fn volume() -> DynSource {
        Arc::new(MemSource::new((0..64u64 << 20).map(|i| (i * 31 % 253) as u8).collect()))
    }

    /// A batch of one entry per reader, file `10 + i` each.
    fn batch(readers: Vec<Box<dyn FileReader>>) -> Vec<(DirEntry, Option<Result<NodeInfo>>)> {
        let mut out = Vec::new();
        for (i, r) in readers.into_iter().enumerate() {
            let node = NodeId::new(0, 10 + i as u64);
            let mut info = NodeInfo::new(Stat::new(node, NodeKind::File, r.len()));
            info.readers = vec![(StreamId::MAIN, Ok(r))];
            out.push((DirEntry::new(fs_inspect_core::Name::new("f"), node, Some(NodeKind::File)), Some(Ok(info))));
        }
        out
    }

    fn key(i: u64) -> Key {
        (NodeId::new(0, 10 + i), StreamId::MAIN)
    }

    #[test]
    fn holes_and_zeros_read_as_the_reader_reads_them() {
        let src = volume();
        // Data, a hole, zeros the file system holds space for, data again.
        let extents = [
            FileExtent::mapped(0, 8192, 4096),
            FileExtent { logical: 8192, physical: Some(1 << 20), length: 4096, flags: 1 },
            FileExtent::mapped(12288, 40960, 5000),
        ];
        let r = ExtentReader::new(src.clone(), 17288, &extents, 1).unwrap();
        let mut want = vec![0; 17288];
        r.read_exact_at(0, &mut want).unwrap();
        assert_eq!(pieces(&r).unwrap(), [(0, 4096, 8192), (12288, 5000, 40960)]);
        let mut p = Prefetch::new(Some(src));
        p.batch(&batch(vec![Box::new(r)]), |_| true);
        assert_eq!(p.take(key(0)).unwrap().unwrap(), want);
        // Taken once.
        assert!(p.take(key(0)).unwrap().is_none());
    }

    #[test]
    fn what_is_not_mapped_one_to_one_or_is_large_is_left_out() {
        let src = volume();
        let inline: Box<dyn FileReader> = Box::new(MemReader::new(vec![1; 100]));
        let large = ExtentReader::new(src.clone(), Prefetch::MAX_LEN + 1, &[FileExtent::mapped(0, 0, 1 << 20)], 0);
        let holes = ExtentReader::new(src.clone(), 4096, &[], 0);
        let mut p = Prefetch::new(Some(src.clone()));
        p.batch(&batch(vec![inline, Box::new(large.unwrap()), Box::new(holes.unwrap())]), |_| true);
        assert!(p.queue.is_empty());
        // Without a volume, nothing is planned.
        let mut p = Prefetch::new(None);
        let r = ExtentReader::new(src, 10, &[FileExtent::mapped(0, 0, 10)], 0).unwrap();
        p.batch(&batch(vec![Box::new(r)]), |_| true);
        assert!(p.queue.is_empty());
    }

    #[test]
    fn a_window_holds_at_most_its_bytes() {
        let counting = CountingSource::new(volume());
        let src: DynSource = counting.clone();
        // 100 streams of 200 KiB, scattered (512 KiB apart): 40 in a window.
        let size = 200 << 10;
        let readers = (0..100u64)
            .map(|i| {
                let r = ExtentReader::new(src.clone(), size, &[FileExtent::mapped(0, i * (512 << 10), size)], 0);
                Box::new(r.unwrap()) as Box<dyn FileReader>
            })
            .collect();
        let mut p = Prefetch::new(Some(src));
        p.batch(&batch(readers), |_| true);
        let per = (Prefetch::WINDOW / size) as usize;
        for i in 0..100 {
            assert!(p.take(key(i)).unwrap().is_some(), "stream {i}");
            let held: u64 = p.got.values().map(|b| b.len() as u64).sum();
            assert!(held <= Prefetch::WINDOW, "{held} bytes held");
            // A window is fetched when its first stream is taken.
            if (i as usize).is_multiple_of(per) {
                assert_eq!(p.got.len(), (per - 1).min(99 - i as usize), "after stream {i}");
            }
        }
        // Each stream read once (none merged: too far apart).
        assert_eq!(counting.stats().reads, 100);
    }
}
