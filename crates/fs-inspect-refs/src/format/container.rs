//! The container table and virtual-to-physical address translation.
//!
//! ReFS 3 divides the volume into containers of 64 MiB. Most tables address their pages by
//! *virtual* LCN: `vlcn >> shift` is a container id and the low bits the cluster inside it,
//! with `shift = log2(clusters per container) + 1` (virtual containers are spaced twice their
//! size apart). The container table (read through physical addresses) gives each id its
//! physical start; ids 0 and 1 (the first `2 << shift` virtual clusters) map to themselves.
//! A row's key starts with the container id (u64); its value ends with the physical start LCN
//! and the cluster count (two u64). Windows lists whole containers only (it sizes the volume
//! to a multiple of 64 MiB), but a shorter one is accepted, as long as it fits the volume.

use crate::format::layout::PageRef;
use crate::format::tree::{Addressing, PageReader, TreeWalk};
use fs_inspect_core::bytes::u64_at;
use fs_inspect_core::{Error, Limits, Result};

/// Container id to physical start LCN and cluster count, sorted by id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerMap {
    clusters_per_container: u64,
    shift: u32,
    starts: Vec<(u64, u64, u64)>,
}

impl ContainerMap {
    pub fn new(clusters_per_container: u64, starts: Vec<(u64, u64, u64)>) -> Self {
        ContainerMap { clusters_per_container, shift: clusters_per_container.trailing_zeros() + 1, starts }
    }

    /// Container ids with their physical start LCNs and cluster counts, by id.
    pub fn starts(&self) -> &[(u64, u64, u64)] {
        &self.starts
    }

    /// Physical LCN of virtual `vlcn`.
    pub fn translate(&self, vlcn: u64) -> Result<u64> {
        let id = vlcn >> self.shift;
        if id < 2 {
            return Ok(vlcn);
        }
        let off = vlcn & ((1 << self.shift) - 1);
        if off >= self.clusters_per_container {
            return Err(Error::corrupt(format!("virtual LCN {vlcn:#x} is between containers")));
        }
        match self.starts.binary_search_by_key(&id, |&(i, _, _)| i) {
            Ok(i) if off < self.starts[i].2 => Ok(self.starts[i].1 + off),
            Ok(_) => Err(Error::corrupt(format!("virtual LCN {vlcn:#x} is past the end of container {id}"))),
            Err(_) => Err(Error::corrupt(format!("virtual LCN {vlcn:#x}: no container {id}"))),
        }
    }

    /// Physical LCN of the run of `n` virtual clusters from `vlcn`, which must lie in one
    /// container (virtual containers are spaced apart, so a run cannot span two).
    pub fn translate_run(&self, vlcn: u64, n: u64) -> Result<u64> {
        let start = self.translate(vlcn)?;
        if n > 1 {
            let last = vlcn.checked_add(n - 1).ok_or_else(|| Error::corrupt("virtual run overflows"))?;
            // Ids 0 and 1 map to themselves: one run may cover both.
            let same = last >> self.shift == vlcn >> self.shift || last >> self.shift < 2;
            if !same || self.translate(last)? != start + (n - 1) {
                return Err(Error::corrupt(format!("virtual run {vlcn:#x}+{n:#x} leaves its container")));
            }
        }
        Ok(start)
    }

    /// Read the container table at `root` (physical addresses).
    pub fn load(
        reader: &PageReader,
        root: PageRef,
        clusters_per_container: u64,
        clusters: u64,
        limits: &Limits,
    ) -> Result<(Self, Vec<u64>)> {
        let max_rows = (limits.max_alloc / 16) as usize;
        let mut walk =
            TreeWalk::new(reader.clone(), root, Addressing::Physical, crate::format::layout::table::CONTAINER, limits);
        let mut starts: Vec<(u64, u64, u64)> = Vec::new();
        let mut pages = Vec::new();
        while let Some((node, i)) = walk.next_with(&mut |p| pages.extend_from_slice(p))? {
            let (k, v) = (node.key(i), node.value(i));
            let id = u64_at(k, 0)?;
            if v.len() < 32 {
                return Err(Error::corrupt(format!("container {id}: row of {} bytes", v.len())));
            }
            let start = u64_at(v, v.len() - 16)?;
            let count = u64_at(v, v.len() - 8)?;
            if count == 0 || count > clusters_per_container {
                return Err(Error::corrupt(format!("container {id}: {count} clusters")));
            }
            if start.checked_add(count).is_none_or(|e| e > clusters) {
                return Err(Error::corrupt(format!("container {id}: starts at LCN {start:#x}, past the volume")));
            }
            if starts.last().is_some_and(|&(last, _, _)| last >= id) {
                return Err(Error::corrupt(format!("container table: id {id} out of order")));
            }
            if starts.len() >= max_rows {
                return Err(Error::limit("container table too large"));
            }
            starts.push((id, start, count));
        }
        Ok((ContainerMap::new(clusters_per_container, starts), pages))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn translation() {
        // 4 KiB clusters: 16384 clusters per container, shift 15.
        let m = ContainerMap::new(16384, vec![(2, 0, 16384), (3, 0x14000, 16384), (15, 0x8000, 100)]);
        assert_eq!(m.translate(0x1234).unwrap(), 0x1234);
        assert_eq!(m.translate((2 << 15) + 5).unwrap(), 5);
        assert_eq!(m.translate((3 << 15) + 0x3FFF).unwrap(), 0x17FFF);
        assert_eq!(m.translate((15 << 15) + 1).unwrap(), 0x8001);
        assert!(m.translate((15 << 15) + 100).is_err());
        assert!(m.translate((3 << 15) + 0x4000).is_err());
        assert!(m.translate(4 << 15).is_err());
        assert_eq!(m.translate_run((3 << 15) + 0x3000, 0x1000).unwrap(), 0x17000);
        assert!(m.translate_run((3 << 15) + 0x3000, 0x1001).is_err());
        assert!(m.translate_run((15 << 15) + 90, 11).is_err());
        assert_eq!(m.translate_run(0x10, 0x100).unwrap(), 0x10);
    }
}
