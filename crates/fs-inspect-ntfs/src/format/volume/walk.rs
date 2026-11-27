//! A walk over the records of `$MFT`, each base record's entry built with its extension
//! records, reading `$MFT` once.
//!
//! An extension record often lies far from its base (on a Windows 11 system volume, most of
//! them 16 Ki to 1 Mi records away, before or after it), so reading it where it is costs a
//! read per base. The walk takes the extension records from its own read instead:
//! - one before its base (the walk passed it) is kept, raw, until the walk reaches the base;
//! - a base with one ahead waits until the walk has passed it, its entry handed on then (out
//!   of record order).
//!
//! Both are bounded: at most [`Caps::bytes`] of records kept, raw (extension records and the
//! bases waiting, with their attribute lists). An extension record not had either way (past
//! those, in a chunk that was not read, or not an extension record of its base) is read with
//! the records that follow it, [`EXTENSION_BATCH_BYTES`] at once: extension records allocated
//! together (the files of one program written at once) are then read together.

use super::{MftChunk, NtfsVolume};
use crate::format::attr::{AttrType, RawAttrBody, parse_attr_list};
use crate::format::entry::FileEntry;
use crate::format::error::Result;
use crate::format::record::{ParsedRecord, RecordParse, parse_record};
use fs_inspect_io::batch::ItemWindow;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Most bytes of `$MFT` read at once for an extension record the walk did not keep.
const EXTENSION_BATCH_BYTES: u64 = 256 << 10;

/// What a walk keeps for the extension records it passes.
#[derive(Debug, Clone, Copy)]
pub(super) struct Caps {
    /// Most bytes of records kept. A Windows 11 system volume of 1.9 M records (51 000 of them
    /// extension records) keeps 25 MB at most: 18 000 extension records before their bases,
    /// 6 800 bases waiting.
    pub bytes: u64,
}

impl Caps {
    pub(super) const DEFAULT: Caps = Caps { bytes: 64 << 20 };
}

/// Sees each chunk of `$MFT` a walk reads: its index, the chunk, its records parsed
/// ([`NtfsVolume::parse_chunk`]).
pub type ChunkFn<'a> = dyn FnMut(u64, MftChunk<'_>, &[Option<ParsedRecord>]) + 'a;

/// The entry handed for a record: `Ok(None)` for a record that is not a base record in use.
pub type Walked = Result<Option<FileEntry>>;

/// A base record waiting for extension records ahead of it.
struct Waiting {
    /// The record, raw (past the initialized size cleared).
    raw: Box<[u8]>,
    attr_list: Option<std::result::Result<Vec<u8>, String>>,
    /// Its extension records met so far, raw.
    exts: HashMap<u64, Box<[u8]>>,
}

/// The extension records a walk keeps, and the bases waiting.
struct Extensions {
    caps: Caps,
    /// `(base, extension record)` -> the raw extension record, for bases the walk has not
    /// reached.
    held: BTreeMap<(u64, u64), Box<[u8]>>,
    waiting: HashMap<u64, Waiting>,
    /// `(the last record a waiting base needs, base)`.
    ready: BTreeSet<(u64, u64)>,
    /// Bytes of the records (and attribute lists) in `held` and in `waiting`.
    bytes: u64,
    /// The extension records read that were not kept.
    window: ItemWindow,
}

impl Extensions {
    /// Keep the extension records of a chunk (records `first..end`, `raw`) whose base lies
    /// ahead of it or waits.
    fn note(&mut self, vol: &NtfsVolume, first: u64, end: u64, raw: &[u8], parsed: &[Option<ParsedRecord>]) {
        let rs = vol.mft.record_size as usize;
        for (r, n) in parsed.iter().zip(first..) {
            let Some(r) = r else { continue };
            if !r.header.in_use() || !r.header.is_extension() {
                continue;
            }
            let base = r.header.base_record.record;
            let i = (n - first) as usize * rs;
            let fits = self.bytes + rs as u64 <= self.caps.bytes;
            if let Some(w) = self.waiting.get_mut(&base) {
                if fits {
                    self.bytes += rs as u64;
                    w.exts.insert(n, vol.cleared(n, &raw[i..i + rs]).into());
                }
            } else if base >= end && fits {
                self.bytes += rs as u64;
                self.held.insert((base, n), vol.cleared(n, &raw[i..i + rs]).into());
            }
        }
    }

    /// The extension records kept for `base`, taken out (still counted in `bytes`).
    fn take(&mut self, base: u64) -> HashMap<u64, Box<[u8]>> {
        let keys: Vec<(u64, u64)> = self.held.range((base, 0)..=(base, u64::MAX)).map(|(k, _)| *k).collect();
        keys.into_iter().filter_map(|k| Some((k.1, self.held.remove(&k)?))).collect()
    }

    /// Forget the records kept for bases before `end` (the walk passed them: they did not name
    /// these records).
    fn prune(&mut self, end: u64) {
        let rest = self.held.split_off(&(end, 0));
        let gone = std::mem::replace(&mut self.held, rest);
        self.bytes -= gone.values().map(|b| b.len() as u64).sum::<u64>();
    }
}

impl NtfsVolume {
    /// Every record from `from` on, by [`Self::mft_chunks`]: `f(n, entry)` for each, as
    /// [`Self::entry`] would build it; `seen` gets each chunk read and its records parsed
    /// first. A base waiting for extension records ahead comes when the walk has passed them;
    /// a chunk that was not read has its records read one by one. Errors of `f` stop the walk.
    pub fn walk_entries(
        &self,
        from: u64,
        seen: &mut ChunkFn<'_>,
        f: &mut dyn FnMut(u64, Walked) -> Result<()>,
    ) -> Result<()> {
        self.walk_entries_with(Caps::DEFAULT, from, seen, f)
    }

    pub(super) fn walk_entries_with(
        &self,
        caps: Caps,
        from: u64,
        seen: &mut ChunkFn<'_>,
        f: &mut dyn FnMut(u64, Walked) -> Result<()>,
    ) -> Result<()> {
        let per = self.mft_chunk() / u64::from(self.mft.record_size);
        let mut x = Extensions {
            caps,
            held: BTreeMap::new(),
            waiting: HashMap::new(),
            ready: BTreeSet::new(),
            bytes: 0,
            window: ItemWindow::new(u64::from(self.mft.record_size)),
        };
        self.mft_chunks(&mut |c, chunk| {
            let (first, end) = (c * per, ((c + 1) * per).min(self.record_count()));
            match chunk {
                None => {
                    for n in first.max(from)..end {
                        f(n, self.entry(n))?;
                    }
                }
                Some((pieces, raw)) => {
                    let parsed = self.parse_chunk(first, raw);
                    seen(c, (pieces, raw), &parsed);
                    x.note(self, first, end, raw, &parsed);
                    for n in first.max(from)..end {
                        if let Some(e) = self.chunk_entry(n, (first, end), raw, &parsed, &mut x) {
                            f(n, e)?;
                        }
                    }
                }
            }
            x.prune(end);
            self.hand_ready(&mut x, end, f)
        })?;
        self.hand_ready(&mut x, u64::MAX, f)
    }

    /// The entry of record `n` of a chunk (records `first..end`, `raw`, `parsed`); `None` when
    /// it waits for extension records ahead.
    fn chunk_entry(
        &self,
        n: u64,
        (first, end): (u64, u64),
        raw: &[u8],
        parsed: &[Option<ParsedRecord>],
        x: &mut Extensions,
    ) -> Option<Walked> {
        let in_chunk = |r: u64| parsed.get(usize::try_from(r.checked_sub(first)?).ok()?);
        let Some(Some(rec)) = in_chunk(n) else { return Some(Ok(None)) };
        if !rec.header.in_use() || rec.header.is_extension() {
            return Some(Ok(None));
        }
        let mut exts = x.take(n);
        let attr_list = match self.attr_list_data(rec) {
            Ok(a) => a,
            Err(e) => return Some(Err(e)),
        };
        let ahead = self
            .attr_list_targets(rec, attr_list.as_ref())
            .into_iter()
            .filter(|&t| t >= end && t < self.record_count() && !exts.contains_key(&t))
            .max();
        let rs = self.mft.record_size as usize;
        let cost = (rs + waiting_list_bytes(&attr_list)) as u64;
        if let Some(last) = ahead
            && x.bytes + cost <= x.caps.bytes
        {
            x.bytes += cost;
            x.ready.insert((last, n));
            let i = (n - first) as usize * rs;
            x.waiting.insert(n, Waiting { raw: self.cleared(n, &raw[i..i + rs]).into(), attr_list, exts });
            return None;
        }
        x.bytes -= exts.values().map(|b| b.len() as u64).sum::<u64>();
        Some(self.merge(rec, attr_list, &mut |r| match in_chunk(r) {
            Some(p) => Ok(p.clone()),
            None => self.extension(r, exts.remove(&r), &mut x.window),
        }))
    }

    /// Hand on the waiting bases whose extension records all lie before `end`.
    fn hand_ready(&self, x: &mut Extensions, end: u64, f: &mut dyn FnMut(u64, Walked) -> Result<()>) -> Result<()> {
        while let Some(&(last, n)) = x.ready.first()
            && last < end
        {
            x.ready.pop_first();
            let Some(mut w) = x.waiting.remove(&n) else { continue };
            x.bytes -= (w.raw.len() + waiting_list_bytes(&w.attr_list)) as u64;
            x.bytes -= w.exts.values().map(|b| b.len() as u64).sum::<u64>();
            // The bytes parsed as the walk passed them: a base record in use.
            let mut raw = w.raw.into_vec();
            let RecordParse::Ok(rec) = parse_record(n, &mut raw, self.geometry.cluster_count, &self.limits) else {
                f(n, Ok(None))?;
                continue;
            };
            let e = self.merge(&rec, w.attr_list, &mut |r| self.extension(r, w.exts.remove(&r), &mut x.window));
            f(n, e)?;
        }
        Ok(())
    }

    /// Extension record `n`, from `raw` (as the walk read it, past the initialized size
    /// cleared) or read through `window`.
    fn extension(&self, n: u64, raw: Option<Box<[u8]>>, window: &mut ItemWindow) -> Result<Option<ParsedRecord>> {
        let mut buf = match raw {
            Some(b) => b.into_vec(),
            None => self.record_in(n, window)?,
        };
        match parse_record(n, &mut buf, self.geometry.cluster_count, &self.limits) {
            RecordParse::Ok(r) => Ok(Some(r)),
            _ => Ok(None),
        }
    }

    /// Raw record `n` (as [`Self::read_record_raw`]) from `window`, refilled with up to
    /// [`EXTENSION_BATCH_BYTES`] of records from `n` on when `n` is not in it.
    fn record_in(&self, n: u64, window: &mut ItemWindow) -> Result<Vec<u8>> {
        let rs = u64::from(self.mft.record_size);
        // Records up to the initialized size (those past it read as zeros).
        let count = (EXTENSION_BATCH_BYTES / rs).min(self.mft.initialized_size.div_ceil(rs).saturating_sub(n));
        if let Some(r) = window.fetch(&*self.source, n, count, |i, k| self.mft.map_bytes(i * rs, k * rs))? {
            return Ok(self.cleared(n, r));
        }
        self.read_record_raw(n)
    }

    /// The other records the attribute list of `rec` names (its content `attr_list` when
    /// non-resident); none when it cannot be had.
    pub(super) fn attr_list_targets(
        &self,
        rec: &ParsedRecord,
        attr_list: Option<&std::result::Result<Vec<u8>, String>>,
    ) -> Vec<u64> {
        let Some(al) = rec.attributes.iter().find(|a| a.kind == AttrType::ATTRIBUTE_LIST) else { return Vec::new() };
        let data = match (&al.body, attr_list) {
            (RawAttrBody::Resident { data, .. }, _) => data.as_slice(),
            (RawAttrBody::NonResident(_), Some(Ok(d))) => d.as_slice(),
            _ => return Vec::new(),
        };
        parse_attr_list(data, self.limits.max_attr_list_entries)
            .map(|es| es.iter().map(|e| e.segment.record).filter(|&r| r != rec.number).collect())
            .unwrap_or_default()
    }
}

/// The bytes of a non-resident attribute list's content kept with a waiting base.
fn waiting_list_bytes(attr_list: &Option<std::result::Result<Vec<u8>, String>>) -> usize {
    match attr_list {
        Some(Ok(d)) => d.len(),
        _ => 0,
    }
}
