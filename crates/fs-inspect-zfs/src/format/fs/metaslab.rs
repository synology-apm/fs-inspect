//! The metaslabs of the top-level vdev: their space maps, the log space map entries not yet
//! flushed to them, and the allocated ranges they give, metaslab by metaslab.

use super::ZfsFs;
use crate::format::dnode::ot;
use crate::format::dsl::mos_object;
use crate::format::objset::read_data;
use crate::format::spacemap::{self, RangeSet, SmEntry};
use crate::format::zap;
use fs_inspect_core::Scope;
use fs_inspect_core::{ByteRange, DiagCode, Error, Result};
use std::sync::Arc;

/// Most metaslabs per vdev accepted.
const MAX_METASLABS: u64 = 1 << 20;

/// One metaslab: its space map object (0: never allocated from) and the log space map entries
/// that apply to it, in order (`None`: the log cannot be placed, the metaslab counts as used).
#[derive(Debug, Clone, Default)]
pub(super) struct Metaslab {
    sm: u64,
    log: Option<Vec<SmEntry>>,
}

impl ZfsFs {
    /// Space map objects per metaslab, and the log space map entries that apply to each. A log
    /// entry of a transaction before the metaslab's flush point is in its space map already;
    /// when the flush points cannot be read, every metaslab a log entry falls in counts as used.
    pub(super) fn load_metaslabs(&self) -> Result<Vec<Metaslab>> {
        let p = &self.pool;
        let count = p.asize >> p.ms_shift;
        if count > MAX_METASLABS {
            return Err(Error::limit(format!("{count} metaslabs")));
        }
        let mut ms = vec![Metaslab { sm: 0, log: Some(Vec::new()) }; count as usize];
        if p.ms_array != 0 {
            let a = mos_object(&self.reader, &self.mos, p.ms_array)?;
            let raw = read_data(&self.reader, &a, 0, (count * 8) as usize)?;
            for (m, c) in ms.iter_mut().zip(raw.as_chunks::<8>().0) {
                m.sm = u64::from_le_bytes(*c);
            }
        }
        let Some(logs) = self.dir_value("com.delphix:log_spacemap_zap") else { return Ok(ms) };
        // The transaction each metaslab's own space map is complete up to: log entries of
        // older transactions are already in it.
        let unflushed: Option<Vec<u64>> = self.unflushed_txgs(count).unwrap_or_else(|e| {
            self.diag.warn(DiagCode::CountedAsUsed, format!("metaslab flush points unreadable ({e})"));
            None
        });
        let z = mos_object(&self.reader, &self.mos, logs)?;
        let mut maps: Vec<(u64, u64)> = Vec::new();
        for e in zap::entries(&self.reader, &z, MAX_METASLABS)? {
            let txg = u64::from_str_radix(&e.name_str(), 16)
                .map_err(|_| Error::corrupt(format!("log space map key {}", e.name_str())))?;
            maps.push((txg, e.first().unwrap_or(0)));
        }
        maps.sort_unstable();
        for (txg, obj) in maps {
            let d = mos_object(&self.reader, &self.mos, obj)?;
            spacemap::for_each(&self.reader, &d, 0, 9, self.limits.max_tree_nodes, &mut |e| {
                if e.vdev != Some(p.top_id) {
                    return Ok(());
                }
                let i = (e.start >> p.ms_shift) as usize;
                let Some(m) = ms.get_mut(i) else {
                    return Err(Error::corrupt(format!("log space map entry at {:#x} past the vdev", e.start)));
                };
                match &unflushed {
                    Some(u) if txg < u.get(i).copied().unwrap_or(0) => {}
                    Some(_) => {
                        if let Some(l) = m.log.as_mut() {
                            l.push(e);
                        }
                    }
                    None => m.log = None,
                }
                Ok(())
            })?;
        }
        Ok(ms)
    }

    fn unflushed_txgs(&self, count: u64) -> Result<Option<Vec<u64>>> {
        if self.pool.top_zap == 0 {
            return Ok(None);
        }
        let z = mos_object(&self.reader, &self.mos, self.pool.top_zap)?;
        let Some(e) = zap::lookup(&self.reader, &z, b"com.delphix:ms_unflushed_phys_txgs", 4096)? else {
            return Ok(None);
        };
        let Some(obj) = e.first() else { return Ok(None) };
        let d = mos_object(&self.reader, &self.mos, obj)?;
        let n = count.min(d.data_bytes() / 8);
        let raw = read_data(&self.reader, &d, 0, (n * 8) as usize)?;
        let mut v: Vec<u64> = raw.as_chunks::<8>().0.iter().map(|c| u64::from_le_bytes(*c)).collect();
        v.resize(count as usize, 0);
        Ok(Some(v))
    }

    /// Allocated device ranges of metaslab `i`, ascending.
    fn metaslab_ranges(&self, i: usize, out: &mut Vec<ByteRange>) -> Result<()> {
        let p = &self.pool;
        let start = (i as u64) << p.ms_shift;
        let end = (start + (1 << p.ms_shift)).min(p.asize);
        let whole = |out: &mut Vec<ByteRange>| out.extend(self.on_device(start, end - start));
        let m = &self.metaslabs[i];
        let Some(log) = &m.log else {
            whole(out);
            return Ok(());
        };
        let mut set = RangeSet::new();
        if m.sm != 0 {
            let r = self.mos_object(m.sm).and_then(|d| {
                if d.ty != ot::SPACE_MAP {
                    return Err(Error::corrupt(format!("metaslab {i}: object {} is not a space map", m.sm)));
                }
                spacemap::for_each(&self.reader, &d, start, p.ashift, self.limits.max_tree_nodes, &mut |e| {
                    set.apply(&e);
                    Ok(())
                })
            });
            match r {
                Ok(()) => {}
                Err(e) if e.scope() == Scope::Unit => {
                    self.diag.warn(
                        DiagCode::CountedAsUsed,
                        format!("metaslab {i} space map unreadable ({e}); the metaslab counts as used"),
                    );
                    whole(out);
                    return Ok(());
                }
                Err(e) => return Err(e),
            }
        }
        for e in log {
            set.apply(e);
        }
        for (a, b) in set.iter() {
            let (a, b) = (a.max(start), b.min(end));
            if b > a {
                out.extend(self.on_device(a, b - a));
            }
        }
        Ok(())
    }
}

/// Metaslab ranges, metaslab by metaslab.
#[derive(Debug)]
pub(super) struct MetaslabIter {
    fs: Arc<ZfsFs>,
    next: usize,
    buf: std::collections::VecDeque<ByteRange>,
    done: bool,
}

impl MetaslabIter {
    pub(super) fn new(fs: Arc<ZfsFs>) -> MetaslabIter {
        MetaslabIter { fs, next: 0, buf: Default::default(), done: false }
    }
}

impl Iterator for MetaslabIter {
    type Item = Result<ByteRange>;
    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            if let Some(r) = self.buf.pop_front() {
                return Some(Ok(r));
            }
            if self.next >= self.fs.metaslabs.len() {
                self.done = true;
                return None;
            }
            let mut v = Vec::new();
            let i = self.next;
            self.next += 1;
            if let Err(e) = self.fs.metaslab_ranges(i, &mut v) {
                self.done = true;
                return Some(Err(e));
            }
            self.buf.extend(v);
        }
        None
    }
}
