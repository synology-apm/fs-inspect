//! The chunk map: logical (btrfs address space) to physical (device offset).

use fs_inspect_core::bytes::{u16_at, u64_at};
use fs_inspect_core::{ByteRange, Error, ParseError, Result};

/// Size of a chunk item without its stripes.
pub const CHUNK_ITEM_SIZE: usize = 48;
/// Size of one stripe of a chunk item.
pub const STRIPE_SIZE: usize = 32;
/// Size of a disk key in the sys_chunk_array.
pub const DISK_KEY_SIZE: usize = 17;
/// `CHUNK_ITEM` key type.
pub const CHUNK_ITEM_KEY: u8 = 228;

/// Block group / chunk type bits (all of them, as the format defines them; the tests use
/// the ones the driver does not).
#[allow(dead_code)]
pub mod bg {
    pub const DATA: u64 = 1 << 0;
    pub const SYSTEM: u64 = 1 << 1;
    pub const METADATA: u64 = 1 << 2;
    pub const RAID0: u64 = 1 << 3;
    pub const RAID1: u64 = 1 << 4;
    pub const DUP: u64 = 1 << 5;
    pub const RAID10: u64 = 1 << 6;
    pub const RAID5: u64 = 1 << 7;
    pub const RAID6: u64 = 1 << 8;
    pub const RAID1C3: u64 = 1 << 9;
    pub const RAID1C4: u64 = 1 << 10;
    pub const PROFILE_MASK: u64 = RAID0 | RAID1 | DUP | RAID10 | RAID5 | RAID6 | RAID1C3 | RAID1C4;
}

/// One copy of a chunk on a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stripe {
    pub devid: u64,
    pub offset: u64,
}

/// A chunk: `[logical, logical + length)` stored whole at each stripe (SINGLE: one copy,
/// DUP: two copies on the same device).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub logical: u64,
    pub length: u64,
    pub ty: u64,
    pub stripes: Vec<Stripe>,
}

impl Chunk {
    pub fn end(&self) -> u64 {
        self.logical.saturating_add(self.length)
    }
}

/// A stripe expanded for the walk: `[physical, physical + length)` holds
/// `[logical, logical + length)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysStripe {
    pub physical: u64,
    pub length: u64,
    pub logical: u64,
}

/// Parse a chunk item (`b` starts at the item, may extend past it) for the chunk at `logical`.
/// Returns the chunk and the item's size. Checks the profile (SINGLE or DUP only) and that
/// every stripe is on device `devid` and inside `[0, dev_bytes)`.
pub fn parse_chunk_item(b: &[u8], logical: u64, devid: u64, dev_bytes: u64) -> Result<(Chunk, usize)> {
    let length = u64_at(b, 0)?;
    let ty = u64_at(b, 24)?;
    let num_stripes = u16_at(b, 44)?;
    let size = CHUNK_ITEM_SIZE + STRIPE_SIZE * usize::from(num_stripes);
    let corrupt = |m: String| Error::corrupt(format!("chunk at logical {logical:#x}: {m}"));
    if length == 0 {
        return Err(corrupt("zero length".into()));
    }
    if logical.checked_add(length).is_none() {
        return Err(corrupt(format!("length {length:#x} overflows")));
    }
    let profile = ty & bg::PROFILE_MASK;
    let want_stripes = match profile {
        0 => 1,
        bg::DUP => 2,
        _ => return Err(Error::unsupported(format!("chunk at logical {logical:#x} has RAID profile {ty:#x}"))),
    };
    if num_stripes != want_stripes {
        return Err(corrupt(format!("{num_stripes} stripes for type {ty:#x}")));
    }
    let mut stripes = Vec::with_capacity(usize::from(num_stripes));
    for i in 0..usize::from(num_stripes) {
        let o = CHUNK_ITEM_SIZE + i * STRIPE_SIZE;
        let s = Stripe { devid: u64_at(b, o)?, offset: u64_at(b, o + 8)? };
        if s.devid != devid {
            return Err(corrupt(format!("stripe on device {} (this device is {devid})", s.devid)));
        }
        match s.offset.checked_add(length) {
            Some(end) if end <= dev_bytes => {}
            _ => return Err(corrupt(format!("stripe at {:#x} + {length:#x} beyond the device", s.offset))),
        }
        stripes.push(s);
    }
    Ok((Chunk { logical, length, ty, stripes }, size))
}

/// All chunks, sorted by logical address and non-overlapping.
#[derive(Debug, Clone, Default)]
pub struct ChunkMap {
    chunks: Vec<Chunk>,
}

impl ChunkMap {
    pub fn chunks(&self) -> &[Chunk] {
        &self.chunks
    }

    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Add a chunk. An identical chunk already present is ignored; an overlapping one is an
    /// error.
    pub fn insert(&mut self, c: Chunk) -> Result<()> {
        let i = self.chunks.partition_point(|x| x.logical < c.logical);
        if let Some(x) = self.chunks.get(i) {
            if *x == c {
                return Ok(());
            }
            if x.logical < c.end() {
                return Err(Error::corrupt(format!("chunks at {:#x} and {:#x} overlap", c.logical, x.logical)));
            }
        }
        if let Some(p) = i.checked_sub(1).and_then(|p| self.chunks.get(p))
            && p.end() > c.logical
        {
            return Err(Error::corrupt(format!("chunks at {:#x} and {:#x} overlap", p.logical, c.logical)));
        }
        self.chunks.insert(i, c);
        Ok(())
    }

    /// The chunk holding `logical`.
    pub fn lookup(&self, logical: u64) -> Option<&Chunk> {
        let i = self.chunks.partition_point(|x| x.logical <= logical);
        let c = self.chunks.get(i.checked_sub(1)?)?;
        (logical < c.end()).then_some(c)
    }

    /// Physical offsets of every copy of `[logical, logical + len)`, which must lie inside
    /// one chunk.
    pub fn map(&self, logical: u64, len: u64) -> Result<Vec<u64>> {
        let c = self
            .lookup(logical)
            .ok_or_else(|| Error::corrupt(format!("logical address {logical:#x} is not in any chunk")))?;
        let rel = logical - c.logical;
        if logical.checked_add(len).is_none_or(|e| e > c.end()) {
            return Err(Error::corrupt(format!("block {logical:#x}+{len:#x} crosses the end of its chunk")));
        }
        Ok(c.stripes.iter().map(|s| s.offset + rel).collect())
    }

    /// Physical ranges of every copy of `[logical, logical + len)`, which may span chunks.
    pub fn map_all(&self, logical: u64, len: u64, out: &mut Vec<ByteRange>) -> Result<()> {
        let end = logical.checked_add(len).ok_or_else(|| Error::corrupt("extent overflows"))?;
        let mut pos = logical;
        while pos < end {
            let c = self
                .lookup(pos)
                .ok_or_else(|| Error::corrupt(format!("logical address {pos:#x} is not in any chunk")))?;
            let n = c.end().min(end) - pos;
            for s in &c.stripes {
                out.push(ByteRange::new(s.offset + (pos - c.logical), n));
            }
            pos += n;
        }
        Ok(())
    }

    /// Every stripe of every chunk sorted by physical offset; overlapping stripes are an error.
    pub fn stripes_by_physical(&self) -> Result<Vec<PhysStripe>> {
        let mut v: Vec<PhysStripe> = self
            .chunks
            .iter()
            .flat_map(|c| {
                c.stripes.iter().map(|s| PhysStripe { physical: s.offset, length: c.length, logical: c.logical })
            })
            .collect();
        v.sort_by_key(|s| s.physical);
        for w in v.windows(2) {
            if let [a, b] = w
                && a.physical.saturating_add(a.length) > b.physical
            {
                return Err(Error::corrupt(format!(
                    "stripes of chunks {:#x} and {:#x} overlap on the device at {:#x}",
                    a.logical, b.logical, b.physical
                )));
            }
        }
        Ok(v)
    }
}

/// Bootstrap chunk map from the superblock's `sys_chunk_array`.
pub fn parse_sys_chunk_array(a: &[u8], devid: u64, dev_bytes: u64) -> Result<ChunkMap> {
    let mut map = ChunkMap::default();
    let mut pos = 0usize;
    while pos < a.len() {
        let key_ty = *a.get(pos + 8).ok_or(ParseError::Truncated { offset: pos, need: DISK_KEY_SIZE, have: 0 })?;
        let logical = u64_at(a, pos + 9)?;
        if key_ty != CHUNK_ITEM_KEY {
            return Err(Error::corrupt(format!("sys_chunk_array: key type {key_ty} at {pos}")));
        }
        let item = a.get(pos + DISK_KEY_SIZE..).unwrap_or_default();
        let (c, size) = parse_chunk_item(item, logical, devid, dev_bytes)?;
        if size > item.len() {
            return Err(Error::corrupt("sys_chunk_array: truncated chunk item"));
        }
        map.insert(c)?;
        pos += DISK_KEY_SIZE + size;
    }
    if map.is_empty() {
        return Err(Error::corrupt("sys_chunk_array is empty"));
    }
    Ok(map)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn item(length: u64, ty: u64, stripes: &[(u64, u64)]) -> Vec<u8> {
        let mut b = vec![0u8; CHUNK_ITEM_SIZE + STRIPE_SIZE * stripes.len()];
        b[0..8].copy_from_slice(&length.to_le_bytes());
        b[24..32].copy_from_slice(&ty.to_le_bytes());
        b[44..46].copy_from_slice(&(stripes.len() as u16).to_le_bytes());
        for (i, (d, o)) in stripes.iter().enumerate() {
            let p = CHUNK_ITEM_SIZE + i * STRIPE_SIZE;
            b[p..p + 8].copy_from_slice(&d.to_le_bytes());
            b[p + 8..p + 16].copy_from_slice(&o.to_le_bytes());
        }
        b
    }

    #[test]
    fn profiles() {
        let dev = 1 << 30;
        assert!(parse_chunk_item(&item(1 << 20, bg::DATA, &[(1, 0)]), 0, 1, dev).is_ok());
        assert!(parse_chunk_item(&item(1 << 20, bg::METADATA | bg::DUP, &[(1, 0), (1, 1 << 20)]), 0, 1, dev).is_ok());
        let e = parse_chunk_item(&item(1 << 20, bg::DATA | bg::RAID1, &[(1, 0), (2, 0)]), 0, 1, dev).unwrap_err();
        assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Unsupported);
        assert!(parse_chunk_item(&item(1 << 20, bg::DATA, &[(2, 0)]), 0, 1, dev).is_err());
        assert!(parse_chunk_item(&item(1 << 20, bg::DATA, &[(1, dev)]), 0, 1, dev).is_err());
        assert!(parse_chunk_item(&item(1 << 20, bg::DUP, &[(1, 0)]), 0, 1, dev).is_err());
        assert!(parse_chunk_item(&item(0, bg::DATA, &[(1, 0)]), 0, 1, dev).is_err());
        assert!(parse_chunk_item(&item(1 << 20, bg::DATA, &[(1, 0)])[..50], 0, 1, dev).is_err());
    }

    #[test]
    fn map_and_overlap() {
        let mut m = ChunkMap::default();
        let c = |l: u64, len: u64, offs: &[u64]| Chunk {
            logical: l,
            length: len,
            ty: 0,
            stripes: offs.iter().map(|&o| Stripe { devid: 1, offset: o }).collect(),
        };
        m.insert(c(100, 50, &[1000])).unwrap();
        m.insert(c(100, 50, &[1000])).unwrap();
        m.insert(c(200, 50, &[2000, 3000])).unwrap();
        assert!(m.insert(c(140, 20, &[5000])).is_err());
        assert!(m.insert(c(90, 20, &[5000])).is_err());
        assert_eq!(m.len(), 2);
        assert_eq!(m.map(110, 10).unwrap(), [1010]);
        assert_eq!(m.map(210, 40).unwrap(), [2010, 3010]);
        assert!(m.map(210, 41).is_err());
        assert!(m.map(160, 1).is_err());
        assert!(m.lookup(99).is_none());
        let s = m.stripes_by_physical().unwrap();
        assert_eq!(s.iter().map(|s| s.physical).collect::<Vec<_>>(), [1000, 2000, 3000]);
        m.insert(c(300, 50, &[1040])).unwrap();
        assert!(m.stripes_by_physical().is_err());
    }
}
