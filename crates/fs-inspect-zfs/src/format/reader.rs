//! Reading the block a block pointer points to: pick a copy on a leaf vdev at hand (any leg of
//! a mirror; the columns of a raidz vdev, rebuilt from parity where they are missing or
//! damaged), assemble gang blocks, verify the checksum, decompress. A copy whose checksum does
//! not match is passed over for the next one.
//!
//! Blocks of a plain vdev that lie close together are read in one request
//! ([`BlockReader::read_batch`]); one that does not read with the others or does not verify is
//! read alone. Decoded indirect, objset and dnode blocks, which later walks read again, are kept
//! in a 32 MiB cache.

use crate::format::blkptr::{BLKPTR_SIZE, BlkPtr, Dva, MAX_BLOCK, VDEV_DATA_OFFSET};
use crate::format::cksum::{self, ECK_SIZE, alg};
use crate::format::codec;
use crate::format::dnode::ot;
use crate::format::pool::{Geometry, Leaf, VdevMap};
use fs_inspect_core::FindingExt;
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::checksum::Verdict;
use fs_inspect_core::memo::Lru;
use fs_inspect_core::{DiagCode, Diagnostics, Error, Finding, FindingKind, Integrity, Outcome, Result, Role, Site};
use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, plan, read_runs};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

/// Bytes of decoded blocks kept.
const CACHE_BYTES: usize = 32 << 20;
/// Deepest gang block nesting followed.
const MAX_GANG_DEPTH: u32 = 8;
/// Gang header size without the dynamic_gang_header feature.
const GANG_HEADER: usize = 512;

/// The first copy's vdev and offset, the physical birth and the logical size.
type Key = (u64, u64, u64, u64);

/// Reads the blocks of a pool through the leaf vdevs at hand.
pub struct BlockReader {
    vdevs: VdevMap,
    /// Gang header size.
    gang_header: usize,
    diag: Diagnostics,
    integrity: Integrity,
    /// Decoded blocks of the tree (indirect, objset and dnode blocks: read again by later
    /// walks), at most `cache_bytes`.
    cache: Mutex<Lru<Key, Arc<Vec<u8>>>>,
    /// [`CACHE_BYTES`], or less
    /// ([`DriverContext::max_cache_bytes`](fs_inspect_core::DriverContext::max_cache_bytes)).
    cache_bytes: usize,
}

impl fmt::Debug for BlockReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockReader").field("vdevs", &self.vdevs).finish_non_exhaustive()
    }
}

/// Whether a block pointer's data is encrypted (keys would be needed to read it).
pub fn encrypted_data(bp: &BlkPtr) -> bool {
    bp.crypt && bp.level == 0 && ot::encrypted(bp.ty)
}

impl BlockReader {
    pub fn new(vdevs: VdevMap, gang_header: Option<usize>, diag: Diagnostics, integrity: Integrity) -> Self {
        BlockReader {
            vdevs,
            gang_header: gang_header.unwrap_or(GANG_HEADER),
            diag,
            integrity,
            cache: Mutex::new(Lru::new(CACHE_BYTES)),
            cache_bytes: CACHE_BYTES,
        }
    }

    /// This reader keeping at most `max` bytes of decoded blocks.
    pub fn with_max_cache_bytes(mut self, max: u64) -> Self {
        self.cache_bytes = CACHE_BYTES.min(usize::try_from(max).unwrap_or(usize::MAX));
        self.cache = Mutex::new(Lru::new(self.cache_bytes));
        self
    }

    pub fn vdevs(&self) -> &VdevMap {
        &self.vdevs
    }

    pub fn diagnostics(&self) -> &Diagnostics {
        &self.diag
    }

    /// What a block's checksum is for: [`Role::Validate`] when the block has one place only
    /// (one copy, not a gang block, on a vdev of one leaf), else [`Role::Select`] (it picks
    /// the copy, the mirror leg or the raidz reconstruction that is right).
    pub fn role(&self, bp: &BlkPtr) -> Role {
        let mut copies = bp.copies();
        let one = match (copies.next(), copies.next()) {
            (Some(d), None) => {
                !d.gang
                    && self
                        .vdevs
                        .top(d.vdev)
                        .is_some_and(|t| matches!(t.geometry, Geometry::Plain) && t.leaves.len() == 1)
            }
            _ => false,
        };
        if one { Role::Validate } else { Role::Select }
    }

    /// The logical content of the block (`lsize` bytes): zeros for a hole.
    pub fn read(&self, bp: &BlkPtr) -> Result<Arc<Vec<u8>>> {
        if bp.lsize > MAX_BLOCK || bp.psize > MAX_BLOCK {
            return Err(Error::corrupt(format!("block of {} / {} bytes", bp.lsize, bp.psize)));
        }
        let lsize = bp.lsize as usize;
        if bp.is_hole() {
            return Ok(Arc::new(vec![0; lsize]));
        }
        if bp.embedded {
            if bp.etype != 0 {
                return Err(Error::unsupported(format!("embedded block pointer of type {}", bp.etype)));
            }
            return Ok(Arc::new(codec::decompress(bp.comp, &bp.embedded_payload()?, lsize)?));
        }
        if !bp.little_endian {
            return Err(Error::unsupported("big-endian ZFS blocks"));
        }
        if encrypted_data(bp) {
            return Err(Error::unsupported("encrypted ZFS block"));
        }
        if let Some(b) = self.cached(key(bp)) {
            return Ok(b);
        }
        let phys = self.physical(bp, 0)?;
        self.decode(bp, &phys)
    }

    /// Read `bps` as [`read`](Self::read) does, those of one plain vdev that lie close
    /// together from its first leaf in one request; `f` gets each block's index and content
    /// (in the order read). A block that does not read with the others, or whose bytes do not
    /// verify, is read alone (other legs, other copies).
    pub fn read_batch(
        &self,
        bps: &[BlkPtr],
        f: &mut dyn FnMut(usize, Result<Arc<Vec<u8>>>) -> Result<()>,
    ) -> Result<()> {
        let mut alone = Vec::new();
        let mut on = BTreeMap::new();
        for (i, bp) in bps.iter().enumerate() {
            match self.batchable(bp) {
                Some((vdev, leaf, at)) => {
                    on.entry(vdev).or_insert_with(|| (leaf, Vec::new())).1.push((at, bp.psize, i))
                }
                None => alone.push(i),
            }
        }
        for (leaf, items) in on.into_values() {
            read_runs::<_, Error>(&*leaf.src, plan(items, BATCH_BYTES, GAP_BYTES), &mut |i, b| {
                let bp = &bps[i];
                let role = self.role(bp);
                let got =
                    match b.map(|b| self.check(bp, &bp.dvas[0], b.to_vec(), role).and_then(|p| self.decode(bp, &p))) {
                        Some(Ok(d)) => Ok(d),
                        Some(Err(e)) if e.scope() != Scope::Unit => Err(e),
                        _ => self.read(bp),
                    };
                f(i, got)
            })?;
        }
        for i in alone {
            f(i, self.read(&bps[i]))?;
        }
        Ok(())
    }

    /// The vdev, its first leaf and the device offset of `bp`'s first copy when
    /// [`read_batch`](Self::read_batch) can read it with others: a plain, verifiable, uncached
    /// block of a plain vdev.
    fn batchable(&self, bp: &BlkPtr) -> Option<(u64, &Leaf, u64)> {
        let d = &bp.dvas[0];
        let plain = !bp.is_hole() && !bp.embedded && bp.little_endian && !encrypted_data(bp) && !d.gang;
        if !plain || bp.lsize > MAX_BLOCK || bp.psize > MAX_BLOCK || self.is_cached(key(bp)) {
            return None;
        }
        let top = self.vdevs.top(d.vdev)?;
        let leaf = top.leaves.first()?;
        matches!(top.geometry, Geometry::Plain).then_some((d.vdev, leaf, d.device_offset()?))
    }

    /// The content of `bp` from its verified physical bytes; kept in the cache when later walks
    /// read it again (indirect, objset and dnode blocks).
    fn decode(&self, bp: &BlkPtr, phys: &[u8]) -> Result<Arc<Vec<u8>>> {
        #[allow(unused_mut)]
        let mut data = codec::decompress(bp.comp, phys, bp.lsize as usize)?;
        #[cfg(test)]
        hostile::apply(bp.dvas[0].offset, &mut data);
        let data = Arc::new(data);
        if bp.level > 0 || matches!(bp.ty, ot::OBJSET | ot::DNODE) {
            self.remember(key(bp), data.clone());
        }
        Ok(data)
    }

    /// The physical bytes (`psize`) of a block from the first copy (and mirror leg, or
    /// combination of raidz columns) that verifies.
    fn physical(&self, bp: &BlkPtr, depth: u32) -> Result<Vec<u8>> {
        let mut last: Option<Error> = None;
        let mut tried = 0;
        let role = self.role(bp);
        for dva in bp.copies() {
            let r = if dva.gang {
                self.gang(bp, dva, depth, &mut tried).and_then(|b| self.check(bp, dva, b, role))
            } else {
                self.try_dva(dva, bp.psize as usize, &mut tried, |b| self.check(bp, dva, b, role))
            };
            match r {
                Ok(b) => return Ok(b),
                Err(e) if e.scope() == Scope::Unit => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        if tried > 1
            && let Some(e) = &last
        {
            self.diag.warn(DiagCode::ChecksumMismatch, format!("no copy of a block verifies ({e})"));
        }
        Err(last.unwrap_or_else(|| Error::corrupt("block pointer without a copy")))
    }

    /// The `len` bytes at `dva` (not a gang block) that `accept` takes: from each leg of a
    /// mirror in turn, or assembled from a raidz vdev's columns. `accept` rejects with a damage
    /// error; `tried` counts the candidates.
    fn try_dva<T>(
        &self,
        dva: &Dva,
        len: usize,
        tried: &mut u32,
        mut accept: impl FnMut(Vec<u8>) -> Result<T>,
    ) -> Result<T> {
        let Some(top) = self.vdevs.top(dva.vdev) else {
            return Err(Error::corrupt(format!("block on vdev {}, which is not given", dva.vdev)));
        };
        let off = dva.device_offset().ok_or_else(|| Error::corrupt("block offset overflows"))?;
        match top.geometry {
            Geometry::Plain => {
                let mut last = None;
                for leg in &top.leaves {
                    *tried += 1;
                    match leg.src.read_vec(off, len).and_then(&mut accept) {
                        Ok(t) => return Ok(t),
                        Err(e) if e.scope() == Scope::Unit => last = Some(e),
                        Err(e) => return Err(e),
                    }
                }
                Err(last.unwrap_or_else(|| Error::corrupt(format!("no leaf of vdev {}", dva.vdev))))
            }
            Geometry::Raidz(g) => {
                let cols = g.columns(dva.offset, len);
                let mut bufs = Vec::with_capacity(cols.len());
                for c in &cols {
                    let b = match top.child(c.child) {
                        Some(l) => match l.src.read_vec(VDEV_DATA_OFFSET + c.offset, c.size) {
                            Ok(b) => Some(b),
                            Err(e) if e.scope() == Scope::Unit => None,
                            Err(e) => return Err(e),
                        },
                        None => None,
                    };
                    bufs.push(b);
                }
                g.assemble(&cols, &bufs, len, |b| {
                    *tried += 1;
                    accept(b)
                })
            }
        }
    }

    /// The checks the blocks read get.
    pub fn integrity(&self) -> &Integrity {
        &self.integrity
    }

    /// A verification's read of `bp`: every copy (each DVA, each leg of a mirror; a raidz
    /// vdev's columns, reconstructed when they must be) read and checked, a wrong copy beside a
    /// right one reported recovered. The content of a right copy, or `None` when none is (a
    /// finding: damaged). Embedded and encrypted blocks are read as [`read`](Self::read) does.
    pub fn verify_copies(&self, bp: &BlkPtr) -> Result<Option<Arc<Vec<u8>>>> {
        if bp.is_hole() || bp.embedded || !bp.little_endian || encrypted_data(bp) {
            return self.read(bp).map(Some);
        }
        if bp.lsize > MAX_BLOCK || bp.psize > MAX_BLOCK {
            return Err(Error::corrupt(format!("block of {} / {} bytes", bp.lsize, bp.psize)));
        }
        let role = self.role(bp);
        let outcome = if role == Role::Select { Outcome::Recovered } else { Outcome::Damaged };
        let len = bp.psize as usize;
        let mut good: Option<Vec<u8>> = None;
        for dva in bp.copies() {
            // Each place the copy is read from: its bytes checked, a failure not found by the
            // check reported.
            let mut place = |site: Site, read: Result<Vec<u8>>| -> Result<()> {
                let mark = self.integrity.damage_mark();
                match read.and_then(|b| self.check(bp, dva, b, role)) {
                    Ok(b) => {
                        good.get_or_insert(b);
                        Ok(())
                    }
                    Err(e) if e.scope() == Scope::Unit => {
                        let f = Finding::new(&site, FindingKind::Unreadable, outcome, e.to_string());
                        self.integrity.report_since(mark, f);
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            };
            let site = Site::new(StructureKind::ZfsBlock).id(dva.vdev).at(dva.offset);
            match self.vdevs.top(dva.vdev).map(|t| (t.geometry, &t.leaves)) {
                Some((Geometry::Plain, leaves)) if !dva.gang => {
                    let off = dva.device_offset().ok_or_else(|| Error::corrupt("block offset overflows"))?;
                    for leg in leaves {
                        place(site, leg.src.read_vec(off, len))?;
                    }
                }
                _ if dva.gang => place(site, self.gang(bp, dva, 0, &mut 0))?,
                _ => {
                    let mark = self.integrity.damage_mark();
                    match self.try_dva(dva, len, &mut 0, |b| self.check(bp, dva, b, role)) {
                        Ok(b) => {
                            good.get_or_insert(b);
                        }
                        Err(e) if e.scope() == Scope::Unit => {
                            let f = Finding::new(&site, FindingKind::Unreadable, outcome, e.to_string());
                            self.integrity.report_since(mark, f);
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        let Some(phys) = good else {
            if role == Role::Select {
                let d = &bp.dvas[0];
                let site = Site::new(StructureKind::ZfsBlock).id(d.vdev).at(d.offset);
                let why = format!("no copy verifies (type {}, level {}, birth {})", bp.ty, bp.level, bp.phys_birth());
                self.integrity.report(Finding::new(&site, FindingKind::Unreadable, Outcome::Damaged, why));
            }
            return Ok(None);
        };
        match self.decode(bp, &phys) {
            Ok(d) => Ok(Some(d)),
            Err(e) if e.scope() == Scope::Unit => {
                let d = &bp.dvas[0];
                let site = Site::new(StructureKind::ZfsBlock).id(d.vdev).at(d.offset);
                self.integrity.report(Finding::new(&site, FindingKind::Unreadable, Outcome::Damaged, e.to_string()));
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Verify `data` (the physical bytes) against the block pointer's checksum.
    pub fn verify(&self, bp: &BlkPtr, data: Vec<u8>) -> Result<()> {
        self.check(bp, &bp.dvas[0], data, self.role(bp)).map(drop)
    }

    /// Verify `data` (the physical bytes, read from `dva`) against the block pointer's
    /// checksum, unless the policy skips `role`.
    fn check(&self, bp: &BlkPtr, dva: &Dva, data: Vec<u8>, role: Role) -> Result<Vec<u8>> {
        let crypt = bp.crypt && bp.ty != ot::OBJSET;
        // Where: the copy's vdev (the id) and its offset in the vdev's allocatable space.
        let site = Site::new(StructureKind::ZfsBlock).id(dva.vdev).at(dva.offset).algorithms(cksum::name);
        let v = self.integrity.check(role, site, || match cksum::verify(bp.cksum_alg, &data, &bp.cksum, crypt) {
            // No checksum at all: nothing to report.
            Verdict::Unchecked(alg::OFF | alg::NOPARITY) => Verdict::Ok,
            v => v,
        });
        if v == Verdict::Mismatch {
            return Err(Error::corrupt(format!(
                "{} checksum mismatch (type {}, level {}, birth {})",
                cksum::name(bp.cksum_alg),
                bp.ty,
                bp.level,
                bp.phys_birth()
            )));
        }
        Ok(data)
    }

    /// The verified gang header of `dva` (one copy of `bp`). With dynamic gang headers active,
    /// a header is either 512 bytes or the larger size (both within one sector): the embedded
    /// checksum is looked for at the end of either.
    fn gang_header(&self, bp: &BlkPtr, dva: &Dva, tried: &mut u32) -> Result<Vec<u8>> {
        self.try_dva(dva, self.gang_header, tried, |mut h| {
            for size in [h.len(), GANG_HEADER] {
                if size <= h.len()
                    && cksum::verify_embedded(
                        alg::GANG_HEADER,
                        &h[..size],
                        size - ECK_SIZE,
                        // Every copy's header is sealed with the first copy's place
                        // (`BP_IDENTITY`).
                        &[bp.dvas[0].vdev, bp.dvas[0].offset, bp.phys_birth(), 0],
                    )
                {
                    h.truncate(size);
                    return Ok(h);
                }
            }
            Err(Error::corrupt(format!("gang header at {:#x}: checksum mismatch", dva.offset)))
        })
    }

    /// The physical bytes of a gang block: the header's member blocks, concatenated.
    fn gang(&self, bp: &BlkPtr, dva: &Dva, depth: u32, tried: &mut u32) -> Result<Vec<u8>> {
        if depth >= MAX_GANG_DEPTH {
            return Err(Error::limit("gang blocks nested too deep"));
        }
        let h = self.gang_header(bp, dva, tried)?;
        let mut out = Vec::with_capacity(bp.psize as usize);
        for i in 0..(h.len() - ECK_SIZE) / BLKPTR_SIZE {
            let m = BlkPtr::parse(&h, i * BLKPTR_SIZE)?;
            if m.is_hole() || out.len() >= bp.psize as usize {
                continue;
            }
            out.extend_from_slice(&self.physical(&m, depth + 1)?);
        }
        if out.len() < bp.psize as usize {
            return Err(Error::corrupt(format!(
                "gang block at {:#x}: {} of {} bytes",
                dva.offset,
                out.len(),
                bp.psize
            )));
        }
        out.truncate(bp.psize as usize);
        Ok(out)
    }

    /// The member block pointers of the gang header of `dva` (for the ranges a gang block
    /// takes).
    pub fn gang_members(&self, bp: &BlkPtr, dva: &Dva) -> Result<Vec<BlkPtr>> {
        let h = self.gang_header(bp, dva, &mut 0)?;
        let mut v = Vec::new();
        for i in 0..(h.len() - ECK_SIZE) / BLKPTR_SIZE {
            let m = BlkPtr::parse(&h, i * BLKPTR_SIZE)?;
            if !m.is_hole() {
                v.push(m);
            }
        }
        Ok(v)
    }

    pub fn gang_header_size(&self) -> u64 {
        self.gang_header as u64
    }

    /// Raw bytes at a DVA (intent log blocks, verified by their embedded checksum), from each
    /// leg of its vdev (or combination of raidz columns) in turn: what `check` makes of the
    /// first it accepts.
    pub fn read_raw<T>(&self, dva: &Dva, len: usize, mut check: impl FnMut(Vec<u8>) -> Option<T>) -> Result<Option<T>> {
        match self.try_dva(dva, len, &mut 0, |b| check(b).ok_or_else(|| Error::corrupt("rejected"))) {
            Ok(t) => Ok(Some(t)),
            Err(e) if e.scope() == Scope::Unit => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Whether every copy of `bp` lies on a vdev at hand, within its space.
    pub fn within(&self, bp: &BlkPtr) -> bool {
        bp.copies().all(|d| self.vdevs.within(d))
    }

    /// Forget the decoded blocks kept.
    pub fn forget(&self) {
        *self.cache.lock().unwrap_or_else(|e| e.into_inner()) = Lru::new(self.cache_bytes);
    }

    fn cached(&self, key: Key) -> Option<Arc<Vec<u8>>> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).get(&key)
    }

    fn is_cached(&self, key: Key) -> bool {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).contains(&key)
    }

    fn remember(&self, key: Key, b: Arc<Vec<u8>>) {
        if b.len() > CACHE_BYTES / 8 {
            return;
        }
        let cost = b.len();
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).insert(key, b, cost);
    }
}

/// The cache key of `bp`.
fn key(bp: &BlkPtr) -> Key {
    (bp.dvas[0].vdev, bp.dvas[0].offset, bp.phys_birth(), bp.lsize)
}

/// Tests: edits applied to decoded blocks, past their checksums (hostile metadata).
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod hostile {
    use std::cell::RefCell;

    thread_local! {
        /// (selector, byte index, value): applied to the blocks whose offset the selector picks.
        pub static EDITS: RefCell<Vec<(u64, usize, u8)>> = const { RefCell::new(Vec::new()) };
    }

    pub fn apply(offset: u64, b: &mut [u8]) {
        EDITS.with(|e| {
            for &(sel, at, v) in e.borrow().iter() {
                if !b.is_empty() && ((offset >> 9) ^ sel).is_multiple_of(4) {
                    let n = b.len();
                    b[at % n] = v;
                }
            }
        });
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "reader_tests.rs"]
mod refused;
