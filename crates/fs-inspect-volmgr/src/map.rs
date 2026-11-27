//! Where a logical device's bytes lie on its members.
//!
//! A [`LogicalMap`] is a list of [`Segment`]s, each a run of the device laid out one way
//! ([`Layout`]) over areas of members. Offsets in a member are bytes from the start of that
//! member's slot (the partition or device the container claimed). Each RAID level uses md's
//! chunk placement; LVM RAID and LDM striping and RAID 5 place chunks the same way.

use fs_inspect_core::{Error, Result};

/// Index of a member in its container.
pub type MemberIx = usize;

/// A place on a member: `start` bytes from the start of its slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Area {
    pub member: MemberIx,
    pub start: u64,
}

/// Where RAID 4/5/6 put parity in each row (md `ALGORITHM_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParityAlgo {
    LeftAsymmetric,
    RightAsymmetric,
    LeftSymmetric,
    RightSymmetric,
    /// Parity on the first device (md `PARITY_0`).
    ParityFirst,
    /// Parity on the last device(s) (md `PARITY_N`; RAID 4).
    ParityLast,
    /// RAID 6 only (DDF layouts): data as right-asymmetric, Q after P ("Q D D D P" when P is
    /// last; md `ROTATING_ZERO_RESTART`, LVM's default `raid6` / `raid6_zr`).
    RotatingZeroRestart,
    /// RAID 6 only: left-asymmetric starting one row later (md `ROTATING_N_RESTART`).
    RotatingNRestart,
    /// RAID 6 only: left-symmetric with Q just before P (md `ROTATING_N_CONTINUE`).
    RotatingNContinue,
    /// RAID 6 only: a RAID 5 rotation over the first n − 1 devices, Q on the last (md
    /// `*_6`, LVM `raid6_la_6` ...).
    LeftAsymmetric6,
    RightAsymmetric6,
    LeftSymmetric6,
    RightSymmetric6,
    /// RAID 6 only: P on the first device, Q on the last (md `PARITY_0_6`).
    ParityFirst6,
}

impl ParityAlgo {
    /// Every rotation (for tests and tables).
    pub const ALL: [ParityAlgo; 14] = [
        ParityAlgo::LeftAsymmetric,
        ParityAlgo::RightAsymmetric,
        ParityAlgo::LeftSymmetric,
        ParityAlgo::RightSymmetric,
        ParityAlgo::ParityFirst,
        ParityAlgo::ParityLast,
        ParityAlgo::RotatingZeroRestart,
        ParityAlgo::RotatingNRestart,
        ParityAlgo::RotatingNContinue,
        ParityAlgo::LeftAsymmetric6,
        ParityAlgo::RightAsymmetric6,
        ParityAlgo::LeftSymmetric6,
        ParityAlgo::RightSymmetric6,
        ParityAlgo::ParityFirst6,
    ];

    /// md's layout number for a RAID 5 or 6 array (`ALGORITHM_*`; RAID 4 is always parity
    /// last). `None`: not a rotation of that level.
    pub fn from_md(level: i32, layout: u32) -> Option<ParityAlgo> {
        use ParityAlgo::*;
        let a = match (level, layout) {
            (4, _) => ParityLast,
            (5 | 6, 0) => LeftAsymmetric,
            (5 | 6, 1) => RightAsymmetric,
            (5 | 6, 2) => LeftSymmetric,
            (5 | 6, 3) => RightSymmetric,
            (5 | 6, 4) => ParityFirst,
            (5 | 6, 5) => ParityLast,
            (6, 8) => RotatingZeroRestart,
            (6, 9) => RotatingNRestart,
            (6, 10) => RotatingNContinue,
            (6, 16) => LeftAsymmetric6,
            (6, 17) => RightAsymmetric6,
            (6, 18) => LeftSymmetric6,
            (6, 19) => RightSymmetric6,
            (6, 20) => ParityFirst6,
            _ => return None,
        };
        Some(a)
    }

    /// Whether the rotation exists for RAID 6 only.
    pub const fn raid6_only(self) -> bool {
        !matches!(
            self,
            ParityAlgo::LeftAsymmetric
                | ParityAlgo::RightAsymmetric
                | ParityAlgo::LeftSymmetric
                | ParityAlgo::RightSymmetric
                | ParityAlgo::ParityFirst
                | ParityAlgo::ParityLast
        )
    }
}

/// How a segment's bytes are spread over its member areas.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Layout {
    /// The bytes in order from one area.
    Linear(Area),
    /// Chunks dealt round-robin over the areas (RAID 0, LVM striped, LDM striped).
    Striped { chunk: u64, areas: Vec<Area> },
    /// The same bytes on every leg (RAID 1, LDM mirror).
    Mirror { legs: Vec<Area> },
    /// Rows of `areas.len() - parity` data chunks plus one (RAID 4/5) or two (RAID 6) parity
    /// chunks, every member's chunk of row `r` at `start + r * chunk`. `first_row`: the array's
    /// row number of this segment's row 0 (the rotation goes on from there: a piece of an LVM
    /// RAID LV whose images continue elsewhere).
    Parity { chunk: u64, algo: ParityAlgo, raid6: bool, first_row: u64, areas: Vec<Area> },
    /// md RAID 10: `near` copies side by side, `far` copies `stride` apart (`offset`: the far
    /// copies are in the next chunk rows, `stride` = chunk).
    Raid10 { chunk: u64, near: u32, far: u32, offset: bool, stride: u64, areas: Vec<Area> },
}

/// A run of the logical device, `[start, start + len)`, laid out one way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub start: u64,
    pub len: u64,
    pub layout: Layout,
}

/// A logical device: its length and segments (sorted, disjoint, covering `[0, len)` with
/// possible holes that read as zeros).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LogicalMap {
    pub len: u64,
    pub segments: Vec<Segment>,
}

/// What a member byte holds ([`LogicalMap::logical_at`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemberByte {
    /// A copy of logical byte `offset`; the next `len` member bytes copy the logical bytes that
    /// follow it.
    Logical { offset: u64, len: u64 },
    /// None of the device's bytes, for the next `len` bytes (`u64::MAX`: up to the member's end).
    Outside { len: u64 },
}

fs_inspect_io::named_enum! {
    /// Whether a logical device can be read with the members present.
    pub enum Readability ("readability") {
        /// Every member it uses is present.
        Full = 1 => "full",
        /// Through redundancy (a mirror leg or a parity member missing).
        Degraded = 2 => "degraded",
        /// Some bytes have no copy on the members present.
        No = 3 => "no",
    }
}

/// One stream of a segment that lands on a member: which copy of the data it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Copy {
    /// Linear, or a mirror leg: the logical bytes shifted to `start`.
    Shift(u64),
    /// Stripe `i` of a striped layout.
    Stripe(usize),
    /// Area `i` of a parity layout: whole rows.
    Row(usize),
    /// md RAID 10: copy (`n` near, `f` far) on device `i`.
    R10 { dev: usize, n: u32, f: u32 },
}

impl Layout {
    /// The member areas the layout uses, in layout order (stripe, leg or RAID device order).
    pub fn areas(&self) -> Vec<Area> {
        match self {
            Layout::Linear(a) => vec![*a],
            Layout::Striped { areas, .. } | Layout::Parity { areas, .. } | Layout::Raid10 { areas, .. } => {
                areas.clone()
            }
            Layout::Mirror { legs } => legs.clone(),
        }
    }

    /// Stable lower-case name: `linear`, `striped`, `mirror`, `raid4`, `raid5`, `raid6`,
    /// `raid10`.
    pub const fn name(&self) -> &'static str {
        match self {
            Layout::Linear(_) => "linear",
            Layout::Striped { .. } => "striped",
            Layout::Mirror { .. } => "mirror",
            Layout::Parity { raid6: false, algo: ParityAlgo::ParityLast, .. } => "raid4",
            Layout::Parity { raid6: false, .. } => "raid5",
            Layout::Parity { raid6: true, .. } => "raid6",
            Layout::Raid10 { .. } => "raid10",
        }
    }

    /// The bytes of each member area a segment of `len` logical bytes covers (from the area's
    /// start), for bounds checks and the whole footprint.
    pub(crate) fn area_bytes(&self, len: u64) -> Result<u64> {
        let ceil = |a: u64, b: u64| a.div_ceil(b);
        Ok(match self {
            Layout::Linear(_) | Layout::Mirror { .. } => len,
            Layout::Striped { chunk, areas } => ceil(ceil(len, *chunk), areas.len() as u64) * chunk,
            Layout::Parity { chunk, raid6, areas, .. } => ceil(ceil(len, *chunk), data_disks(*raid6, areas)) * chunk,
            Layout::Raid10 { chunk, near, far, offset, stride, areas } => {
                let rows = ceil(ceil(len, *chunk) * u64::from(*near), areas.len() as u64);
                if *offset {
                    rows * u64::from(*far) * chunk
                } else {
                    // The last far copy starts `(far - 1) * stride` in.
                    (u64::from(*far) - 1)
                        .checked_mul(*stride)
                        .and_then(|s| s.checked_add(rows * chunk))
                        .ok_or_else(|| Error::corrupt("RAID 10 stride overflows"))?
                }
            }
        })
    }

    /// The streams a segment with this layout projects onto member `m`.
    pub(crate) fn copies_on(&self, m: MemberIx) -> Vec<Copy> {
        match self {
            Layout::Linear(a) => {
                if a.member == m {
                    vec![Copy::Shift(a.start)]
                } else {
                    vec![]
                }
            }
            Layout::Mirror { legs } => legs.iter().filter(|a| a.member == m).map(|a| Copy::Shift(a.start)).collect(),
            Layout::Striped { areas, .. } => {
                areas.iter().enumerate().filter(|(_, a)| a.member == m).map(|(i, _)| Copy::Stripe(i)).collect()
            }
            Layout::Parity { areas, .. } => {
                areas.iter().enumerate().filter(|(_, a)| a.member == m).map(|(i, _)| Copy::Row(i)).collect()
            }
            Layout::Raid10 { near, far, areas, .. } => {
                let mut v = Vec::new();
                for (dev, a) in areas.iter().enumerate() {
                    if a.member == m {
                        for n in 0..*near {
                            for f in 0..*far {
                                v.push(Copy::R10 { dev, n, f });
                            }
                        }
                    }
                }
                v
            }
        }
    }

    /// Where the bytes `[a, b)` of the segment (segment offsets) lie in copy `copy`, appended
    /// to `out` in increasing order (member slot offsets).
    pub(crate) fn place(&self, copy: Copy, a: u64, b: u64, out: &mut Vec<(u64, u64)>) {
        if a >= b {
            return;
        }
        match (self, copy) {
            (_, Copy::Shift(start)) => out.push((start + a, start + b)),
            (Layout::Striped { chunk, areas }, Copy::Stripe(i)) => {
                // The chunks of stripe `i` are consecutive rows: one contiguous run.
                let (c, n, i) = (*chunk, areas.len() as u64, i as u64);
                let (ka, kb) = (a / c, (b - 1) / c);
                let first = ka + (i + n - ka % n) % n;
                let back = (kb % n + n - i) % n;
                if first > kb || back > kb {
                    return;
                }
                let last = kb - back;
                let s = (first / n) * c + a.saturating_sub(first * c).min(c);
                let e = (last / n) * c + (b - last * c).min(c);
                out.push((areas[i as usize].start + s, areas[i as usize].start + e));
            }
            (Layout::Parity { chunk, raid6, areas, .. }, Copy::Row(i)) => {
                // Whole rows: every chunk of a row holding any of the bytes (data and parity).
                let row = chunk * data_disks(*raid6, areas);
                let (ra, rb) = (a / row, b.div_ceil(row));
                out.push((areas[i].start + ra * chunk, areas[i].start + rb * chunk));
            }
            (Layout::Raid10 { chunk, .. }, Copy::R10 { dev, n, f }) => {
                let c = *chunk;
                let mut k = a / c;
                while k * c < b {
                    let (s, e) = ((k * c).max(a), ((k + 1) * c).min(b));
                    if let Some(p) = self.r10_copy(k, n, f).filter(|&(d, _)| d == dev) {
                        let base = self.areas()[dev].start + p.1;
                        let (ps, pe) = (base + (s - k * c), base + (e - k * c));
                        match out.last_mut() {
                            Some(last) if last.1 == ps => last.1 = pe,
                            _ => out.push((ps, pe)),
                        }
                    }
                    k += 1;
                }
            }
            _ => {}
        }
    }

    /// md RAID 10: device and byte offset (in the device's area) of copy (`n`, `f`) of chunk
    /// `k`. Far sets (`far` copies kept within groups of devices) are not modelled.
    fn r10_copy(&self, k: u64, n: u32, f: u32) -> Option<(usize, u64)> {
        let Layout::Raid10 { chunk, near, far, offset, stride, areas } = self else { return None };
        let rd = areas.len() as u64;
        let first = k * u64::from(*near);
        let mut stripe = first / rd;
        let mut dev = first % rd;
        if *offset {
            stripe *= u64::from(*far);
        }
        let mut sector = stripe * chunk;
        // Near copy `n`: the next devices, wrapping to the next chunk row.
        for _ in 0..n {
            dev += 1;
            if dev >= rd {
                dev = 0;
                sector += chunk;
            }
        }
        // Far copy `f`: `near` devices further each time, `stride` further in.
        let d = (dev + u64::from(f) * u64::from(*near)) % rd;
        Some((d as usize, sector + u64::from(f) * stride))
    }

    /// For reading: the run of segment bytes from `off` that lies contiguously on each copy,
    /// as (run length, [(area index, member offset)] in preference order), and for a parity
    /// layout the row's other areas to rebuild it from.
    pub(crate) fn locate(&self, off: u64, seg_len: u64) -> Placement {
        let left = seg_len - off;
        match self {
            Layout::Linear(a) => Placement { len: left, copies: vec![(0, a.start + off)], rebuild: None },
            Layout::Mirror { legs } => Placement {
                len: left,
                copies: legs.iter().enumerate().map(|(i, a)| (i, a.start + off)).collect(),
                rebuild: None,
            },
            Layout::Striped { chunk, areas } => {
                let (k, within) = (off / chunk, off % chunk);
                let n = areas.len() as u64;
                let i = (k % n) as usize;
                Placement {
                    len: (chunk - within).min(left),
                    copies: vec![(i, areas[i].start + (k / n) * chunk + within)],
                    rebuild: None,
                }
            }
            Layout::Parity { chunk, algo, raid6, first_row, areas } => {
                let (k, within) = (off / chunk, off % chunk);
                let (dd, rd) = (data_disks(*raid6, areas), areas.len() as u64);
                let (stripe, d) = (k / dd, k % dd);
                let (dev, _, q) = parity_place(*algo, *raid6, first_row + stripe, d, rd, dd);
                let at = stripe * chunk + within;
                Placement {
                    len: (chunk - within).min(left),
                    copies: vec![(dev as usize, areas[dev as usize].start + at)],
                    rebuild: Some(Rebuild { at, q: q.map(|q| q as usize) }),
                }
            }
            Layout::Raid10 { chunk, near, far, .. } => {
                let (k, within) = (off / chunk, off % chunk);
                let mut copies = Vec::new();
                for n in 0..*near {
                    for f in 0..*far {
                        if let Some((d, p)) = self.r10_copy(k, n, f) {
                            copies.push((d, self.areas()[d].start + p + within));
                        }
                    }
                }
                Placement { len: (chunk - within).min(left), copies, rebuild: None }
            }
        }
    }

    /// Whether every byte has a copy on the present members (`Degraded`: only through
    /// redundancy).
    pub(crate) fn readable(&self, present: &dyn Fn(MemberIx) -> bool) -> Readability {
        let areas = self.areas();
        let missing = areas.iter().filter(|a| !present(a.member)).count();
        if missing == 0 {
            return Readability::Full;
        }
        let ok = match self {
            Layout::Linear(_) | Layout::Striped { .. } => false,
            Layout::Mirror { .. } => missing < areas.len(),
            // Only P is used to rebuild: RAID 6 with two missing is not read.
            Layout::Parity { .. } => missing == 1,
            Layout::Raid10 { near, far, .. } => {
                // Every chunk position must keep one copy: check one full cycle of devices.
                let rd = areas.len() as u64;
                (0..rd * u64::from(*near) * u64::from(*far)).all(|k| {
                    (0..*near).any(|n| {
                        (0..*far).any(|f| self.r10_copy(k, n, f).is_some_and(|(d, _)| present(areas[d].member)))
                    })
                })
            }
        };
        if ok { Readability::Degraded } else { Readability::No }
    }

    fn check(&self) -> Result<()> {
        let areas = self.areas();
        if areas.is_empty() {
            return Err(Error::corrupt(format!("{} segment without areas", self.name())));
        }
        let chunk_ok = |c: u64| c >= 512 && c.is_power_of_two();
        match self {
            Layout::Linear(_) | Layout::Mirror { .. } => {}
            Layout::Striped { chunk, .. } => {
                if !chunk_ok(*chunk) {
                    return Err(Error::corrupt(format!("stripe size {chunk} is not a power of two of 512 or more")));
                }
            }
            Layout::Parity { chunk, raid6, algo, .. } => {
                if !chunk_ok(*chunk) {
                    return Err(Error::corrupt(format!("chunk size {chunk} is not a power of two of 512 or more")));
                }
                if algo.raid6_only() && !raid6 {
                    return Err(Error::corrupt(format!("RAID 5 with the RAID 6 rotation {algo:?}")));
                }
                if areas.len() < if *raid6 { 4 } else { 3 } {
                    return Err(Error::corrupt(format!("{} with {} devices", self.name(), areas.len())));
                }
            }
            Layout::Raid10 { chunk, near, far, offset, stride, .. } => {
                if !chunk_ok(*chunk) {
                    return Err(Error::corrupt(format!("chunk size {chunk} is not a power of two of 512 or more")));
                }
                let copies = u64::from(*near) * u64::from(*far);
                if *near == 0 || *far == 0 || copies > areas.len() as u64 {
                    return Err(Error::corrupt(format!("RAID 10 with {near} near and {far} far copies")));
                }
                if *far > 1 && (*stride == 0 || stride % chunk != 0) && !*offset {
                    return Err(Error::corrupt(format!("RAID 10 far stride {stride}")));
                }
            }
        }
        Ok(())
    }
}

/// A read placement; see [`Layout::locate`].
#[derive(Debug, Clone)]
pub(crate) struct Placement {
    pub len: u64,
    pub copies: Vec<(usize, u64)>,
    pub rebuild: Option<Rebuild>,
}

/// How to rebuild a parity layout's data chunk: XOR of every other area at `at` but `q`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Rebuild {
    pub at: u64,
    pub q: Option<usize>,
}

/// Data chunks per row of a parity layout of `areas`.
fn data_disks(raid6: bool, areas: &[Area]) -> u64 {
    areas.len() as u64 - if raid6 { 2 } else { 1 }
}

/// md's RAID 4/5/6 placement: (data device, P device, Q device) of data chunk `d` in row
/// `stripe`, with `rd` devices of which `dd` hold data.
pub(crate) fn parity_place(
    algo: ParityAlgo,
    raid6: bool,
    stripe: u64,
    d: u64,
    rd: u64,
    dd: u64,
) -> (u64, u64, Option<u64>) {
    use ParityAlgo::*;
    if !raid6 {
        let (dev, p) = match algo {
            LeftAsymmetric => {
                let p = dd - stripe % rd;
                (if d >= p { d + 1 } else { d }, p)
            }
            RightAsymmetric => {
                let p = stripe % rd;
                (if d >= p { d + 1 } else { d }, p)
            }
            LeftSymmetric => {
                let p = dd - stripe % rd;
                ((p + 1 + d) % rd, p)
            }
            RightSymmetric => {
                let p = stripe % rd;
                ((p + 1 + d) % rd, p)
            }
            ParityFirst => (d + 1, 0),
            // ParityLast, and RAID 6 rotations (refused by `check`).
            _ => (d, dd),
        };
        return (dev, p, None);
    }
    let (dev, p, q) = match algo {
        LeftAsymmetric | RightAsymmetric => {
            let p = if algo == LeftAsymmetric { rd - 1 - stripe % rd } else { stripe % rd };
            if p == rd - 1 { (d + 1, p, 0) } else { (if d >= p { d + 2 } else { d }, p, p + 1) }
        }
        LeftSymmetric | RightSymmetric => {
            let p = if algo == LeftSymmetric { rd - 1 - stripe % rd } else { stripe % rd };
            ((p + 2 + d) % rd, p, (p + 1) % rd)
        }
        ParityFirst => (d + 2, 0, 1),
        ParityLast => (d, dd, dd + 1),
        RotatingZeroRestart | RotatingNRestart => {
            let p = if algo == RotatingZeroRestart { stripe % rd } else { rd - 1 - (stripe + 1) % rd };
            if p == rd - 1 { (d + 1, p, 0) } else { (if d >= p { d + 2 } else { d }, p, p + 1) }
        }
        RotatingNContinue => {
            let p = rd - 1 - stripe % rd;
            ((p + 1 + d) % rd, p, (p + rd - 1) % rd)
        }
        // A RAID 5 rotation over the first rd - 1 devices (dd + 1 of them), Q on the last.
        LeftAsymmetric6 | RightAsymmetric6 => {
            let p = if algo == LeftAsymmetric6 { dd - stripe % (rd - 1) } else { stripe % (rd - 1) };
            (if d >= p { d + 1 } else { d }, p, rd - 1)
        }
        LeftSymmetric6 | RightSymmetric6 => {
            let p = if algo == LeftSymmetric6 { dd - stripe % (rd - 1) } else { stripe % (rd - 1) };
            ((p + 1 + d) % (rd - 1), p, rd - 1)
        }
        ParityFirst6 => (d + 1, 0, rd - 1),
    };
    (dev, p, Some(q))
}

impl LogicalMap {
    /// A digest of where every byte lies: its length, and each segment's run, layout, chunk
    /// geometry and member areas. Two maps with the same digest put every logical byte at the
    /// same member bytes; it is stable across versions (a new layout kind only adds).
    pub fn digest(&self) -> u64 {
        let mut b: Vec<u8> = Vec::new();
        let mut put = |v: u64| b.extend_from_slice(&v.to_le_bytes());
        put(self.len);
        put(self.segments.len() as u64);
        for s in &self.segments {
            put(s.start);
            put(s.len);
            let (tag, params, areas): (u64, Vec<u64>, &[Area]) = match &s.layout {
                Layout::Linear(a) => (0, vec![], std::slice::from_ref(a)),
                Layout::Striped { chunk, areas } => (1, vec![*chunk], areas),
                Layout::Mirror { legs } => (2, vec![], legs),
                Layout::Parity { chunk, algo, raid6, first_row, areas } => {
                    let algo = ParityAlgo::ALL.iter().position(|a| a == algo).unwrap_or(usize::MAX) as u64;
                    (3, vec![*chunk, algo, u64::from(*raid6), *first_row], areas)
                }
                Layout::Raid10 { chunk, near, far, offset, stride, areas } => {
                    (4, vec![*chunk, u64::from(*near), u64::from(*far), u64::from(*offset), *stride], areas)
                }
            };
            put(tag);
            for p in params {
                put(p);
            }
            put(areas.len() as u64);
            for a in areas {
                put(a.member as u64);
                put(a.start);
            }
        }
        fs_inspect_core::checksum::xxh64(&b, 0)
    }

    /// Rejects what could not be read safely: overlapping or unsorted segments, segments past
    /// the device, chunk sizes that are not a power of two of 512 or more, too few devices or
    /// copies for the level, areas past their member (`member_len`) (all `Corrupt`), and more
    /// than `max_segments` segments (`Limit`).
    pub fn validate(&self, member_len: &dyn Fn(MemberIx) -> Option<u64>, max_segments: usize) -> Result<()> {
        if self.segments.len() > max_segments {
            return Err(Error::limit(format!("{} segments (limit {max_segments})", self.segments.len())));
        }
        let mut pos = 0u64;
        for s in &self.segments {
            let end = s.start.checked_add(s.len).ok_or_else(|| Error::corrupt("segment end overflows"))?;
            if s.start < pos || end > self.len || s.len == 0 {
                return Err(Error::corrupt(format!(
                    "segment [{}, {end}) out of order or past the device ({} bytes)",
                    s.start, self.len
                )));
            }
            pos = end;
            s.layout.check()?;
            let need = s.layout.area_bytes(s.len)?;
            for a in s.layout.areas() {
                let end = a.start.checked_add(need).ok_or_else(|| Error::corrupt("area end overflows"))?;
                match member_len(a.member) {
                    Some(l) if end > l => {
                        return Err(Error::corrupt(format!(
                            "a {} segment needs bytes [{}, {end}) of member {}, which has {l}",
                            s.layout.name(),
                            a.start,
                            a.member
                        )));
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Every member byte the device uses, per member: `(member, start, end)`, unsorted.
    pub fn footprint(&self) -> Vec<(MemberIx, u64, u64)> {
        let mut v = Vec::new();
        for s in &self.segments {
            let need = s.layout.area_bytes(s.len).unwrap_or(u64::MAX);
            for a in s.layout.areas() {
                v.push((a.member, a.start, a.start.saturating_add(need)));
            }
        }
        v
    }

    /// What member `m`'s byte at slot offset `off` holds, for reading the logical device's
    /// bytes back where its members lie: the logical byte it is a copy of, or none. Only layouts
    /// whose member bytes are copies of logical bytes (linear, mirror, striped) answer; a parity
    /// or RAID 10 area there is [`Error::unsupported`].
    pub fn logical_at(&self, m: MemberIx, off: u64) -> Result<MemberByte> {
        let mut next = u64::MAX;
        for s in &self.segments {
            let need = s.layout.area_bytes(s.len)?;
            let areas = s.layout.areas();
            for copy in s.layout.copies_on(m) {
                let start = match copy {
                    Copy::Shift(st) => st,
                    Copy::Stripe(i) | Copy::Row(i) => areas[i].start,
                    Copy::R10 { dev, .. } => areas[dev].start,
                };
                let end = start.saturating_add(need);
                if off < start {
                    next = next.min(start);
                    continue;
                }
                if off >= end {
                    continue;
                }
                let rel = off - start;
                let (logical, len) = match (&s.layout, copy) {
                    (_, Copy::Shift(_)) => (rel, s.len - rel),
                    (Layout::Striped { chunk, areas }, Copy::Stripe(i)) => {
                        let (c, n) = (*chunk, areas.len() as u64);
                        let (row, r) = (rel / c, rel % c);
                        let l = (row * n + i as u64) * c + r;
                        if l >= s.len {
                            // The stripe's padding past the segment's end.
                            return Ok(MemberByte::Outside { len: c - r });
                        }
                        (l, (c - r).min(s.len - l))
                    }
                    _ => {
                        return Err(Error::unsupported(format!(
                            "member bytes of a {} layout are not copies of the device's bytes",
                            s.layout.name()
                        )));
                    }
                };
                return Ok(MemberByte::Logical { offset: s.start + logical, len });
            }
        }
        Ok(MemberByte::Outside { len: next.saturating_sub(off).max(1) })
    }

    /// Whether the device can be read with the members `present` says are there.
    pub fn readable(&self, present: &dyn Fn(MemberIx) -> bool) -> Readability {
        self.segments.iter().map(|s| s.layout.readable(present)).fold(Readability::Full, |acc, r| match (acc, r) {
            (Readability::No, _) | (_, Readability::No) => Readability::No,
            (Readability::Degraded, _) | (_, Readability::Degraded) => Readability::Degraded,
            _ => Readability::Full,
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn areas(n: usize) -> Vec<Area> {
        (0..n).map(|m| Area { member: m, start: 0 }).collect()
    }

    #[test]
    fn a_digest_changes_with_any_placement() {
        let parity = |chunk, first_row| LogicalMap {
            len: 1 << 20,
            segments: vec![Segment {
                start: 0,
                len: 1 << 20,
                layout: Layout::Parity {
                    chunk,
                    algo: ParityAlgo::LeftSymmetric,
                    raid6: false,
                    first_row,
                    areas: areas(3),
                },
            }],
        };
        let d = parity(65536, 0).digest();
        assert_eq!(d, parity(65536, 0).digest());
        assert_ne!(d, parity(131072, 0).digest());
        assert_ne!(d, parity(65536, 1).digest());
        let mut moved = parity(65536, 0);
        if let Layout::Parity { areas, .. } = &mut moved.segments[0].layout {
            areas[2].start = 4096;
        }
        assert_ne!(d, moved.digest());
        let mirror = |legs| LogicalMap {
            len: 100,
            segments: vec![Segment { start: 0, len: 100, layout: Layout::Mirror { legs } }],
        };
        assert_ne!(mirror(areas(2)).digest(), mirror(areas(3)).digest());
    }

    #[test]
    fn member_bytes_back_to_logical() {
        // Linear on member 1 at 100, then striped over members 0 and 1 (chunk 16) from 1000.
        let map = LogicalMap {
            len: 164,
            segments: vec![
                Segment { start: 0, len: 100, layout: Layout::Linear(Area { member: 1, start: 100 }) },
                Segment {
                    start: 100,
                    len: 64,
                    layout: Layout::Striped {
                        chunk: 16,
                        areas: vec![Area { member: 0, start: 1000 }, Area { member: 1, start: 1000 }],
                    },
                },
            ],
        };
        assert_eq!(map.logical_at(1, 50).unwrap(), MemberByte::Outside { len: 50 });
        assert_eq!(map.logical_at(1, 150).unwrap(), MemberByte::Logical { offset: 50, len: 50 });
        // Member 1's stripe: logical chunks 1 and 3 of the segment.
        assert_eq!(map.logical_at(1, 1000).unwrap(), MemberByte::Logical { offset: 116, len: 16 });
        assert_eq!(map.logical_at(1, 1020).unwrap(), MemberByte::Logical { offset: 152, len: 12 });
        assert_eq!(map.logical_at(0, 1005).unwrap(), MemberByte::Logical { offset: 105, len: 11 });
        assert_eq!(map.logical_at(0, 1032).unwrap(), MemberByte::Outside { len: u64::MAX - 1032 });
        // Every logical byte read back through `place` lands where logical_at says.
        for (si, seg) in map.segments.iter().enumerate() {
            for m in 0..2 {
                for copy in seg.layout.copies_on(m) {
                    for a in 0..seg.len {
                        let mut out = Vec::new();
                        seg.layout.place(copy, a, a + 1, &mut out);
                        for (p, _) in out {
                            match map.logical_at(m, p).unwrap() {
                                MemberByte::Logical { offset, .. } => assert_eq!(offset, seg.start + a, "segment {si}"),
                                o => panic!("{o:?} at member {m} byte {p}"),
                            }
                        }
                    }
                }
            }
        }
        let parity = LogicalMap {
            len: 64,
            segments: vec![Segment {
                start: 0,
                len: 64,
                layout: Layout::Parity {
                    chunk: 16,
                    algo: ParityAlgo::LeftSymmetric,
                    raid6: false,
                    first_row: 0,
                    areas: areas(3),
                },
            }],
        };
        assert!(parity.logical_at(0, 0).is_err());
    }

    /// md's documented RAID 5 left-symmetric layout over 3 disks:
    /// row 0: D0 D1 P; row 1: D3 P D2; row 2: P D4 D5.
    #[test]
    fn raid5_left_symmetric() {
        let l =
            Layout::Parity { chunk: 512, algo: ParityAlgo::LeftSymmetric, raid6: false, first_row: 0, areas: areas(3) };
        let dev = |k: u64| l.locate(k * 512, 1 << 30).copies[0];
        assert_eq!(
            [dev(0), dev(1), dev(2), dev(3), dev(4), dev(5)],
            [(0, 0), (1, 0), (2, 512), (0, 512), (1, 1024), (2, 1024)]
        );
        assert_eq!(parity_place(ParityAlgo::LeftSymmetric, false, 0, 0, 3, 2).1, 2);
        assert_eq!(parity_place(ParityAlgo::LeftSymmetric, false, 1, 0, 3, 2).1, 1);
    }

    /// RAID 10 near 2 over 4 devices: chunk k on devices 2k%4 and 2k%4+1, row k/2.
    #[test]
    fn raid10_near_and_far() {
        let n2 = Layout::Raid10 { chunk: 512, near: 2, far: 1, offset: false, stride: 0, areas: areas(4) };
        assert_eq!(n2.locate(3 * 512, 1 << 30).copies, [(2, 512), (3, 512)]);
        // far 2 over 2 devices, each device holding 4096 bytes: copy 1 is half a device away.
        let f2 = Layout::Raid10 { chunk: 512, near: 1, far: 2, offset: false, stride: 2048, areas: areas(2) };
        assert_eq!(f2.locate(512, 4096).copies, [(1, 0), (0, 2048)]);
        // offset 2 over 2 devices: the second copy in the next row, one device on.
        let o2 = Layout::Raid10 { chunk: 512, near: 1, far: 2, offset: true, stride: 512, areas: areas(2) };
        assert_eq!(o2.locate(0, 4096).copies, [(0, 0), (1, 512)]);
        assert_eq!(o2.locate(512, 4096).copies, [(1, 0), (0, 512)]);
    }

    /// RAID 6 rotations against md's own layout tables (the comments in `raid5.c`).
    #[test]
    fn raid6_rotations() {
        // (algo, row) -> (data devices in order, P, Q) over 5 devices.
        let row = |algo, s| {
            let ds: Vec<u64> = (0..3).map(|d| parity_place(algo, true, s, d, 5, 3).0).collect();
            let (_, p, q) = parity_place(algo, true, s, 0, 5, 3);
            (ds, p, q.unwrap())
        };
        // ZR row 0: P on the first device, Q after it, then the data: P Q D D D.
        assert_eq!(row(ParityAlgo::RotatingZeroRestart, 0), (vec![2, 3, 4], 0, 1));
        // ZR row 4: P on the last device, Q wraps to the first: Q D D D P.
        assert_eq!(row(ParityAlgo::RotatingZeroRestart, 4), (vec![1, 2, 3], 4, 0));
        // NR row 0: D D D P Q.
        assert_eq!(row(ParityAlgo::RotatingNRestart, 0), (vec![0, 1, 2], 3, 4));
        // NC row 0: P on the last, Q before it, data from the first: D D D Q P.
        assert_eq!(row(ParityAlgo::RotatingNContinue, 0), (vec![0, 1, 2], 4, 3));
        // LS_6 row 0: RAID 5 left-symmetric over 4 devices (P on the 4th), Q on the 5th.
        assert_eq!(row(ParityAlgo::LeftSymmetric6, 0), (vec![0, 1, 2], 3, 4));
        assert_eq!(row(ParityAlgo::LeftSymmetric6, 1), (vec![3, 0, 1], 2, 4));
        assert_eq!(row(ParityAlgo::ParityFirst6, 7), (vec![1, 2, 3], 0, 4));
    }

    #[test]
    fn striped_projection_is_one_run_per_member() {
        let l =
            Layout::Striped { chunk: 512, areas: vec![Area { member: 0, start: 100 }, Area { member: 1, start: 0 }] };
        let mut out = Vec::new();
        // Bytes 300..1800: chunks 0 (300..512, stripe 0), 1 (stripe 1), 2 (stripe 0), 3 (..1800-1536, stripe 1).
        l.place(Copy::Stripe(0), 300, 1800, &mut out);
        assert_eq!(out, [(100 + 300, 100 + 1024)]);
        out.clear();
        l.place(Copy::Stripe(1), 300, 1800, &mut out);
        assert_eq!(out, [(0, 512 + 264)]);
    }

    #[test]
    fn readability() {
        let m = LogicalMap {
            len: 4096,
            segments: vec![Segment { start: 0, len: 4096, layout: Layout::Mirror { legs: areas(2) } }],
        };
        assert_eq!(m.readable(&|_| true), Readability::Full);
        assert_eq!(m.readable(&|i| i == 1), Readability::Degraded);
        assert_eq!(m.readable(&|_| false), Readability::No);
    }

    #[test]
    fn validate_refuses_what_cannot_be_read() {
        const M: u64 = 1 << 20;
        let member_len = |m: MemberIx| (m < 4).then_some(M);
        let one = |len: u64, start: u64, seg_len: u64, layout: Layout| LogicalMap {
            len,
            segments: vec![Segment { start, len: seg_len, layout }],
        };
        let lin = |m: MemberIx, start: u64| Layout::Linear(Area { member: m, start });
        let striped = |chunk, n| Layout::Striped { chunk, areas: areas(n) };
        let parity = |chunk, algo, raid6, n| Layout::Parity { chunk, algo, raid6, first_row: 0, areas: areas(n) };
        let r10 =
            |chunk, near, far, offset, stride, n| Layout::Raid10 { chunk, near, far, offset, stride, areas: areas(n) };
        let two = LogicalMap {
            len: 200,
            segments: vec![
                Segment { start: 0, len: 100, layout: lin(0, 0) },
                Segment { start: 50, len: 100, layout: lin(1, 0) },
            ],
        };
        let e = two.validate(&member_len, 1).unwrap_err();
        assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Limit, "{e}");
        let cases = [
            (two, "segment [50, 150) out of order"),
            (one(u64::MAX, u64::MAX - 1, 2, lin(0, 0)), "segment end overflows"),
            (one(100, 0, 200, lin(0, 0)), "segment [0, 200) out of order or past the device (100 bytes)"),
            (one(100, 0, 0, lin(0, 0)), "segment [0, 0) out of order"),
            (one(M, 0, 4096, striped(4096, 0)), "striped segment without areas"),
            (one(M, 0, 4096, Layout::Mirror { legs: vec![] }), "mirror segment without areas"),
            (one(M, 0, 4096, striped(1000, 2)), "stripe size 1000 is not a power of two"),
            (one(M, 0, 4096, parity(256, ParityAlgo::LeftSymmetric, false, 3)), "chunk size 256"),
            (
                one(M, 0, 4096, parity(4096, ParityAlgo::RotatingZeroRestart, false, 3)),
                "RAID 5 with the RAID 6 rotation RotatingZeroRestart",
            ),
            (one(M, 0, 4096, parity(4096, ParityAlgo::ParityLast, false, 2)), "raid4 with 2 devices"),
            (one(M, 0, 4096, parity(4096, ParityAlgo::LeftSymmetric, false, 2)), "raid5 with 2 devices"),
            (one(M, 0, 4096, parity(4096, ParityAlgo::RotatingZeroRestart, true, 3)), "raid6 with 3 devices"),
            (one(M, 0, 4096, r10(0, 2, 1, false, 0, 4)), "chunk size 0"),
            (one(M, 0, 4096, r10(4096, 0, 1, false, 0, 4)), "RAID 10 with 0 near and 1 far copies"),
            (one(M, 0, 4096, r10(4096, 2, 2, false, 8192, 3)), "RAID 10 with 2 near and 2 far copies"),
            (one(M, 0, 4096, r10(4096, 1, 2, false, 0, 4)), "RAID 10 far stride 0"),
            (one(M, 0, 4096, r10(4096, 1, 2, false, 6144, 4)), "RAID 10 far stride 6144"),
            (one(M, 0, 4096, r10(4096, 1, 3, false, 1 << 63, 4)), "RAID 10 stride overflows"),
            (one(M, 0, 100, lin(1, u64::MAX - 10)), "area end overflows"),
            (
                one(M, 0, 100, lin(2, M - 50)),
                "a linear segment needs bytes [1048526, 1048626) of member 2, which has 1048576",
            ),
            (one(M, 0, 3 * 4096, striped(4096, 2)), "a striped segment needs bytes [0, 8192)"),
        ];
        // Member 1 is short, for the last case.
        let small = |m: MemberIx| match m {
            1 => Some(4096),
            m => member_len(m),
        };
        for (map, why) in &cases {
            let e = map.validate(&small, 16).unwrap_err();
            assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Corrupt, "{e}");
            assert!(e.to_string().contains(why), "{why}: {e}");
        }
        // Offset far copies need no stride; a member of unknown length bounds nothing.
        one(M, 0, 4096, r10(4096, 1, 2, true, 0, 4)).validate(&member_len, 16).unwrap();
        one(M, 0, 100, lin(9, u64::MAX - 1000)).validate(&member_len, 16).unwrap();
        one(M, 0, 4096, Layout::Mirror { legs: areas(2) }).validate(&member_len, 16).unwrap();
    }
}
