//! A verification's findings collected in a test ([`verifying`]).

use fs_inspect_core::{DriverContext, Finding, FindingSink, Outcome, StructureKind};
use fs_inspect_io::SourceError;
use fs_inspect_io::{BlockSource, DynSource};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

/// What a driver opened with [`verifying`] found and checked.
#[derive(Debug, Default)]
pub struct Findings {
    found: Mutex<Vec<Finding>>,
    checked: Mutex<BTreeMap<StructureKind, u64>>,
    not_covered: Mutex<Vec<(StructureKind, String)>>,
}

impl Findings {
    /// Every finding, in the order found.
    pub fn all(&self) -> Vec<Finding> {
        self.found.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// The findings with `outcome`.
    pub fn with(&self, outcome: Outcome) -> Vec<Finding> {
        self.all().into_iter().filter(|f| f.outcome == outcome).collect()
    }

    /// How many structures of kind `structure` were checked.
    pub fn checked(&self, structure: StructureKind) -> u64 {
        self.checked.lock().unwrap_or_else(PoisonError::into_inner).get(&structure).copied().unwrap_or(0)
    }

    /// What was not covered: each kind of structure, and which of them.
    pub fn not_covered(&self) -> Vec<(StructureKind, String)> {
        self.not_covered.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

impl FindingSink for Findings {
    fn finding(&self, f: Finding) {
        self.found.lock().unwrap_or_else(PoisonError::into_inner).push(f);
    }

    fn checked(&self, structure: StructureKind, _bytes: u64) {
        *self.checked.lock().unwrap_or_else(PoisonError::into_inner).entry(structure).or_default() += 1;
    }

    fn not_covered(&self, structure: StructureKind, which: &str) {
        self.not_covered.lock().unwrap_or_else(PoisonError::into_inner).push((structure, which.to_string()));
    }
}

/// A context that opens a driver to verify: every checksum computed, what is wrong collected
/// in the returned [`Findings`].
pub fn verifying() -> (DriverContext, Arc<Findings>) {
    let f = Arc::new(Findings::default());
    let sink: Arc<dyn FindingSink> = f.clone();
    (DriverContext { findings: Some(sink), ..DriverContext::default() }, f)
}

/// A source whose bytes at some offsets read with bits flipped: a structure damaged in place,
/// without a copy of the whole image.
#[derive(Debug)]
pub struct Flipped {
    inner: DynSource,
    /// Offsets and the bits flipped there.
    flips: Vec<(u64, u8)>,
}

impl Flipped {
    /// `inner` with the byte at each offset XORed with its mask.
    pub fn new(inner: DynSource, flips: &[(u64, u8)]) -> Arc<Flipped> {
        Arc::new(Flipped { inner, flips: flips.to_vec() })
    }
}

impl BlockSource for Flipped {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        self.inner.read_exact_at(offset, buf)?;
        for &(at, mask) in &self.flips {
            if let Some(b) = at.checked_sub(offset).and_then(|i| buf.get_mut(usize::try_from(i).ok()?)) {
                *b ^= mask;
            }
        }
        Ok(())
    }
    fn size(&self) -> u64 {
        self.inner.size()
    }
    fn alignment(&self) -> u32 {
        self.inner.alignment()
    }
    fn sector_size(&self) -> Option<u32> {
        self.inner.sector_size()
    }
    fn queue_depth(&self) -> Option<std::num::NonZeroUsize> {
        self.inner.queue_depth()
    }
}
