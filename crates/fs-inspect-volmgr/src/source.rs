//! [`LogicalSource`]: a logical device read through its map from the members present.

use crate::map::{LogicalMap, MemberIx};
use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, read_runs, runs};
use fs_inspect_io::{BlockSource, DynSource, check_range};
use fs_inspect_io::{SourceError, SourceErrorKind};
use std::sync::Arc;

/// A logical device as a [`BlockSource`]. A mirror leg that fails is replaced by the next; a
/// parity layout's missing (or failing) data chunk is rebuilt from the rest of its row. Holes
/// between segments read as zeros.
#[derive(Debug, Clone)]
pub struct LogicalSource {
    map: Arc<LogicalMap>,
    members: Arc<Vec<Option<DynSource>>>,
}

impl LogicalSource {
    /// `members[i]`: member `i`'s slot (offset 0 is the slot's first byte), `None` when absent.
    pub fn new(map: Arc<LogicalMap>, members: Vec<Option<DynSource>>) -> Self {
        LogicalSource { map, members: Arc::new(members) }
    }

    /// The device's map.
    pub fn map(&self) -> &Arc<LogicalMap> {
        &self.map
    }

    fn member(&self, m: MemberIx) -> Option<&DynSource> {
        self.members.get(m).and_then(|s| s.as_ref())
    }

    fn read_member(&self, m: MemberIx, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        match self.member(m) {
            Some(s) => s.read_exact_at(offset, buf),
            None => Err(SourceError::new(SourceErrorKind::Corrupt, format!("member {m} is missing"))),
        }
    }
}

/// Where a piece of a read is ([`LogicalSource::place`]).
#[derive(Debug, Clone, Copy)]
enum Place {
    /// Between segments: zeros.
    Hole,
    /// On this member at this offset (its first copy).
    Member(MemberIx, u64),
    /// Its first copy's member is missing: read by `read_piece`.
    Missing,
}

impl LogicalSource {
    /// The piece of a read at logical `pos`, at most `want` bytes, inside one chunk (or one
    /// hole): its length and where it is.
    fn place(&self, pos: u64, want: u64) -> (usize, Place) {
        let segs = &self.map.segments;
        let i = segs.partition_point(|s| s.start + s.len <= pos);
        let Some(seg) = segs.get(i).filter(|s| s.start <= pos) else {
            // A hole up to the next segment.
            let next = segs.get(i).map_or(self.map.len, |s| s.start);
            return ((next - pos).min(want) as usize, Place::Hole);
        };
        let p = seg.layout.locate(pos - seg.start, seg.len);
        let first = p.copies.first().map(|&(ai, at)| (seg.layout.areas()[ai].member, at));
        let place = match first.filter(|&(m, _)| self.member(m).is_some()) {
            Some((m, at)) => Place::Member(m, at),
            None => Place::Missing,
        };
        (p.len.min(want) as usize, place)
    }

    /// Read the piece at logical `pos` placed at `place` into `piece`, alone.
    fn read_place(&self, place: Place, pos: u64, piece: &mut [u8]) -> Result<(), SourceError> {
        match place {
            Place::Hole => {
                piece.fill(0);
                Ok(())
            }
            Place::Member(m, at) => match self.read_member(m, at, piece) {
                Ok(()) => Ok(()),
                Err(e) if e.is_cancelled() => Err(e),
                Err(_) => self.read_piece(pos, piece),
            },
            Place::Missing => self.read_piece(pos, piece),
        }
    }
}

impl LogicalSource {
    /// Read `piece` (inside one chunk) at logical `pos`: from the first copy that reads, else
    /// rebuilt from the rest of its row.
    fn read_piece(&self, pos: u64, piece: &mut [u8]) -> Result<(), SourceError> {
        let segs = &self.map.segments;
        let seg = &segs[segs.partition_point(|s| s.start + s.len <= pos)];
        let p = seg.layout.locate(pos - seg.start, seg.len);
        let areas = seg.layout.areas();
        let mut last: Option<SourceError> = None;
        for &(ai, at) in &p.copies {
            match self.read_member(areas[ai].member, at, piece) {
                Ok(()) => return Ok(()),
                Err(e) if e.is_cancelled() => return Err(e),
                Err(e) => last = Some(e),
            }
        }
        let Some(rb) = p.rebuild else {
            return Err(last.unwrap_or_else(|| SourceError::new(SourceErrorKind::Corrupt, "no copy to read")));
        };
        // XOR of the row's other chunks except Q gives the missing one.
        let lost = p.copies.first().map_or(usize::MAX, |c| c.0);
        piece.fill(0);
        let mut tmp = vec![0u8; piece.len()];
        for (ai, a) in areas.iter().enumerate() {
            if ai == lost || Some(ai) == rb.q {
                continue;
            }
            self.read_member(a.member, a.start + rb.at, &mut tmp)
                .map_err(|e| e.context(format_args!("cannot rebuild a chunk at {pos} from member {}", a.member)))?;
            for (x, y) in piece.iter_mut().zip(&tmp) {
                *x ^= *y;
            }
        }
        Ok(())
    }
}

impl BlockSource for LogicalSource {
    /// The request is cut into pieces inside one chunk each. A request that is one piece (a
    /// linear or mirrored segment, a read inside one chunk) is read straight into `buf`.
    /// Otherwise the pieces one member holds close together (consecutive chunks of a stripe,
    /// across a parity chunk) are read from it in one request. A piece read alone, or one of
    /// a request that failed, takes `read_piece`.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        check_range(offset, buf.len(), self.map.len)?;
        let first = self.place(offset, buf.len() as u64);
        if first.0 == buf.len() {
            return self.read_place(first.1, offset, buf);
        }
        // `(at in buf, length, logical offset, place)` of each piece, and `(member, member
        // offset, length, piece)` of those read from a member.
        let mut pieces: Vec<(usize, usize, u64, Place)> = Vec::new();
        let mut on: Vec<(MemberIx, u64, u64, usize)> = Vec::new();
        let (mut pos, mut done) = (offset, 0usize);
        while done < buf.len() {
            let (n, place) = self.place(pos, (buf.len() - done) as u64);
            if let Place::Member(m, at) = place {
                on.push((m, at, n as u64, pieces.len()));
            }
            pieces.push((done, n, pos, place));
            done += n;
            pos += n as u64;
        }
        // By member, in member offset order: `runs` takes each member's pieces in read order.
        on.sort_unstable_by_key(|&(m, at, _, _)| (m, at));
        let max = BATCH_BYTES.max(buf.len() as u64);
        for group in on.chunk_by(|a, b| a.0 == b.0) {
            let Some(src) = self.member(group[0].0) else { continue };
            let items = group.iter().map(|&(_, at, n, k)| (at, n, k));
            read_runs::<_, SourceError>(&**src, runs(items, max, GAP_BYTES), &mut |k, bytes| {
                let (at, n, pos, _) = pieces[k];
                match bytes {
                    Some(b) => buf[at..at + n].copy_from_slice(b),
                    None => self.read_piece(pos, &mut buf[at..at + n])?,
                }
                Ok(())
            })?;
        }
        for &(at, n, pos, place) in &pieces {
            if !matches!(place, Place::Member(..)) {
                self.read_place(place, pos, &mut buf[at..at + n])?;
            }
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        self.map.len
    }
    fn queue_depth(&self) -> Option<std::num::NonZeroUsize> {
        std::num::NonZeroUsize::new(self.members.iter().flatten().map(|m| fs_inspect_io::queue_depth_of(&**m)).min()?)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::map::{Area, Layout, ParityAlgo, Segment, parity_place};
    use fs_inspect_io::MemSource;
    use proptest::prelude::*;

    /// Members holding `data` laid out by `l` (parity computed; RAID 6's Q left as garbage,
    /// which reads never use).
    fn members(l: &Layout, data: &[u8], n: usize, member_len: usize) -> Vec<Vec<u8>> {
        let mut m = vec![vec![0xEEu8; member_len]; n];
        let areas = l.areas();
        for (p, &b) in data.iter().enumerate() {
            let at = l.locate(p as u64, data.len() as u64);
            for &(ai, off) in &at.copies {
                m[areas[ai].member][off as usize] = b;
            }
        }
        if let Layout::Parity { chunk, algo, raid6, areas, first_row } = l {
            let (rd, dd) = (areas.len() as u64, areas.len() as u64 - if *raid6 { 2 } else { 1 });
            let rows = (data.len() as u64).div_ceil(chunk * dd);
            for r in 0..rows {
                let (_, p, _) = parity_place(*algo, *raid6, first_row + r, 0, rd, dd);
                for i in 0..*chunk {
                    let at = (r * chunk + i) as usize;
                    let mut x = 0u8;
                    for d in 0..dd {
                        let (dev, _, _) = parity_place(*algo, *raid6, first_row + r, d, rd, dd);
                        x ^= m[areas[dev as usize].member][at];
                    }
                    m[areas[p as usize].member][at] = x;
                }
            }
        }
        m
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(fs_inspect_testkit::cases(64)))]
        #[test]
        fn reads_back_whole_and_degraded(
            kind in 0usize..5, n in 3usize..6, algo in 0usize..ParityAlgo::ALL.len(), seed in any::<u64>(),
            missing in 0usize..6, first_row in 0u64..7,
        ) {
            let c = 512u64;
            let n = if kind == 3 { n.max(4) } else { n };
            let areas: Vec<Area> = (0..n).map(|m| Area { member: m, start: 0 }).collect();
            let algo = ParityAlgo::ALL[algo];
            let layout = match kind {
                0 => Layout::Striped { chunk: c, areas },
                1 => Layout::Mirror { legs: areas },
                2 if !algo.raid6_only() => Layout::Parity { chunk: c, algo, raid6: false, first_row, areas },
                2 | 3 => Layout::Parity { chunk: c, algo, raid6: true, first_row, areas },
                _ => Layout::Raid10 { chunk: c, near: 2, far: 1, offset: false, stride: 0, areas },
            };
            let len = 16 * 1024u64;
            let data: Vec<u8> = (0..len).map(|i| (seed.wrapping_mul(i + 1) >> 13) as u8).collect();
            let need = layout.area_bytes(len).unwrap() as usize;
            let mem = members(&layout, &data, n, need);
            let map = Arc::new(LogicalMap { len, segments: vec![Segment { start: 0, len, layout: layout.clone() }] });
            let srcs = |skip: Option<usize>| -> Vec<Option<DynSource>> {
                mem.iter().enumerate().map(|(i, b)| {
                    (Some(i) != skip).then(|| Arc::new(MemSource::new(b.clone())) as DynSource)
                }).collect()
            };
            let mut got = vec![0u8; len as usize];
            LogicalSource::new(map.clone(), srcs(None)).read_exact_at(0, &mut got).unwrap();
            prop_assert!(got == data, "whole read");
            // Degraded: one member missing, where the layout keeps a copy (RAID 6 only rebuilds
            // through P, so the missing one must not be needed with Q).
            let skip = missing % n;
            let present = |i: usize| i != skip;
            if map.readable(&present) != crate::map::Readability::No {
                let mut got = vec![0u8; len as usize];
                // Read at odd offsets and sizes to cross chunk boundaries.
                let src = LogicalSource::new(map.clone(), srcs(Some(skip)));
                let mut pos = 0u64;
                let mut step = 700u64;
                while pos < len {
                    let k = step.min(len - pos) as usize;
                    src.read_exact_at(pos, &mut got[pos as usize..pos as usize + k]).unwrap();
                    pos += k as u64;
                    step = step * 7 % 1500 + 1;
                }
                prop_assert!(got == data, "degraded read without member {}", skip);
            }
        }
    }

    /// A read inside one piece is one read of its first copy; a bad sector there is read from
    /// the next leg.
    #[test]
    fn one_piece_reads_once_and_falls_back() {
        use fs_inspect_io::test_util::{CountingSource, FaultySource, IoStats};
        let len = 1u64 << 20;
        let data: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(2654435761) >> 7) as u8).collect();
        let legs: Vec<Area> = (0..2).map(|m| Area { member: m, start: 0 }).collect();
        let map =
            Arc::new(LogicalMap { len, segments: vec![Segment { start: 0, len, layout: Layout::Mirror { legs } }] });
        let stats = IoStats::new();
        let srcs: Vec<Option<DynSource>> = (0..2)
            .map(|i| {
                let m: DynSource = Arc::new(MemSource::new(data.clone()));
                let m: DynSource = if i == 0 { Arc::new(FaultySource::new(m, 5000..5001)) } else { m };
                Some(CountingSource::with_stats(m, stats.clone()) as DynSource)
            })
            .collect();
        let src = LogicalSource::new(map, srcs);
        let mut got = vec![0u8; 4096];
        src.read_exact_at(8192, &mut got).unwrap();
        assert!(got[..] == data[8192..8192 + 4096]);
        assert_eq!(stats.counts().reads, 1);
        src.read_exact_at(4096, &mut got).unwrap();
        assert!(got[..] == data[4096..8192]);
    }

    /// A 1 MiB read of a 4-member stripe or RAID 5 (64 KiB chunks) is one read per member, the
    /// parity chunks read across; a bad sector on a member is rebuilt from the rest of its row.
    #[test]
    fn one_read_per_member() {
        use fs_inspect_io::test_util::{CountingSource, FaultySource, IoStats};
        let c = 64u64 << 10;
        let areas: Vec<Area> = (0..4).map(|m| Area { member: m, start: 0 }).collect();
        let len = 4u64 << 20;
        let data: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(2654435761) >> 7) as u8).collect();
        for (layout, members_read) in [
            (Layout::Striped { chunk: c, areas: areas.clone() }, 4),
            (Layout::Parity { chunk: c, algo: ParityAlgo::ALL[0], raid6: false, first_row: 0, areas }, 4),
        ] {
            let mem = members(&layout, &data, 4, layout.area_bytes(len).unwrap() as usize);
            let map = Arc::new(LogicalMap { len, segments: vec![Segment { start: 0, len, layout: layout.clone() }] });
            let stats = IoStats::new();
            let srcs = |bad: Option<u64>| -> Vec<Option<DynSource>> {
                mem.iter()
                    .enumerate()
                    .map(|(i, b)| {
                        let m: DynSource = Arc::new(MemSource::new(b.clone()));
                        let m: DynSource = match bad.filter(|_| i == 1) {
                            Some(at) => Arc::new(FaultySource::new(m, at..at + 1)),
                            None => m,
                        };
                        Some(CountingSource::with_stats(m, stats.clone()) as DynSource)
                    })
                    .collect()
            };
            let mut got = vec![0u8; 1 << 20];
            LogicalSource::new(map.clone(), srcs(None)).read_exact_at(1 << 20, &mut got).unwrap();
            assert!(got[..] == data[1 << 20..2 << 20]);
            assert_eq!(stats.counts().reads, members_read, "{layout:?}");
            let parity = matches!(layout, Layout::Parity { .. });
            let res = LogicalSource::new(map, srcs(Some(c * 5 + 100))).read_exact_at(1 << 20, &mut got);
            if parity {
                res.unwrap();
                assert!(got[..] == data[1 << 20..2 << 20]);
            } else {
                assert!(res.is_err());
            }
        }
    }
}
