//! Reading pages (address translation, checksum and header checks) and walking the B+ trees
//! of ReFS tables.
//!
//! A node page holds, after the page header, an *index root* (+0x50: its size at +0, then
//! table-specific fields) followed by the *index header*: data area start / end (+0, +4),
//! level (+0x0C, 0 for a leaf), the key index start (+0x10), entry count (+0x14) and key index
//! end (+0x20), all relative to the index header. The key index lists entry offsets in key
//! order (low 16 bits of each u32). An entry is its size (u32), key offset and length, flags
//! (4: deleted) and value offset and length (u16 each), offsets relative to the entry. In inner
//! nodes the value is the page reference of a child.
//!
//! The same layout also appears inside values (a file record, an extent table): an index root
//! at offset 0 of the value ([`Node::parse_at`]), its children pages of the directory's table.

use crate::format::container::ContainerMap;
use crate::format::layout::{MSB_PLUS, PAGE_HEADER_LEN, PageHeader, PageRef};
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{slice, u8_at, u16_at, u32_at};
use fs_inspect_core::checksum::Verdict;
use fs_inspect_core::memo::ReadLog;
use fs_inspect_core::{Error, Integrity, Limits, Result, Role, Site};
use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, plan, read_runs};

/// Most bytes of pages read together, in reads of up to [`BATCH_BYTES`] in flight at once (the
/// source's queue depth). Pages lie a page or two per read, so a 1 MiB call would leave a
/// source with round trips one read in flight at a time (listing a 200,000-file folder: 8,064
/// reads, 49 s at 20 ms a read).
const AHEAD_BYTES: u64 = 8 << 20;
use fs_inspect_io::{BlockSource, DynSource};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

/// How a page reference's LCNs are addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addressing {
    /// Physical clusters (the container tables and allocator 0x22).
    Physical,
    /// Virtual clusters, translated through the container table.
    Virtual,
}

/// A node page read and checked against its reference: where it is (physical LCNs) and its
/// checksum ([`PageRef::crc`]).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SeenPage {
    pub physical: Vec<u64>,
    pub crc: u64,
}

/// Entry flag: deleted (left in place until the node is rewritten).
const ENTRY_DELETED: u16 = 4;

/// Reads the pages of a volume.
#[derive(Debug)]
pub struct PageReader {
    src: DynSource,
    cluster: u32,
    clusters: u64,
    /// Clusters per node page (4 at 4 KiB clusters, 1 at 64 KiB).
    page_clusters: usize,
    volume_signature: u32,
    map: Option<Arc<ContainerMap>>,
    integrity: Integrity,
    /// What a page's checksum is for ([`Role::Validate`]; choosing a copy of a table kept twice).
    role: Role,
    /// Where the pages read go while [`PageReader::record`] runs.
    seen: ReadLog<SeenPage>,
    /// Pages kept while a [`batch`](PageReader::batch) runs (shared by the clones).
    pages: Arc<Mutex<PageCache>>,
}

/// Node pages that read and checked, by their physical LCNs, while a batch of lookups runs: at
/// most [`PageCache::MAX`], those past it are read each time. Each use checks a page as a read
/// does, but for its checksum when the reference gives the one it matched. Dropped when the
/// last batch ends.
#[derive(Debug, Default)]
struct PageCache {
    batches: usize,
    /// Each with the checksum it matched (`None`: none checked).
    pages: HashMap<Vec<u64>, Kept>,
}

/// A page kept: the checksum it matched (`None`: none checked) and its bytes.
type Kept = (Option<u64>, Arc<[u8]>);

impl PageCache {
    /// Most pages held.
    const MAX: usize = 512;
}

/// A batch of lookups running ([`PageReader::batch`]): the pages they read are kept until
/// the last one is dropped.
#[derive(Debug)]
pub struct Batch(Arc<Mutex<PageCache>>);

impl Drop for Batch {
    fn drop(&mut self) {
        let mut c = lock(&self.0);
        c.batches -= 1;
        if c.batches == 0 {
            c.pages = HashMap::new();
        }
    }
}

fn lock(c: &Mutex<PageCache>) -> MutexGuard<'_, PageCache> {
    c.lock().unwrap_or_else(|e| e.into_inner())
}

impl Clone for PageReader {
    fn clone(&self) -> Self {
        PageReader {
            src: self.src.clone(),
            cluster: self.cluster,
            clusters: self.clusters,
            page_clusters: self.page_clusters,
            volume_signature: self.volume_signature,
            map: self.map.clone(),
            integrity: self.integrity.clone(),
            role: self.role,
            seen: self.seen.clone(),
            pages: self.pages.clone(),
        }
    }
}

/// A page read from disk, with the physical LCNs it came from.
#[derive(Debug, Clone)]
pub struct Page {
    pub data: Vec<u8>,
    pub physical: Vec<u64>,
}

impl PageReader {
    pub fn new(
        src: DynSource,
        cluster: u32,
        clusters: u64,
        page_clusters: usize,
        volume_signature: u32,
        integrity: Integrity,
    ) -> Self {
        PageReader {
            src,
            cluster,
            clusters,
            page_clusters,
            volume_signature,
            map: None,
            integrity,
            role: Role::Validate,
            seen: ReadLog::default(),
            pages: Arc::default(),
        }
    }

    /// The same, its page checksums choosing between copies (`role`) of a table kept twice.
    pub fn with_role(&self, role: Role) -> Self {
        PageReader { role, ..self.clone() }
    }

    /// The checks the pages read get.
    pub fn integrity(&self) -> &Integrity {
        &self.integrity
    }

    /// Keep the node pages read (by this reader and its clones) until the batch returned is
    /// dropped: lookups of neighboring records share their path and leaves.
    pub fn batch(&self) -> Batch {
        lock(&self.pages).batches += 1;
        Batch(self.pages.clone())
    }

    /// Run `f`, collecting every node page read meanwhile (by this reader and its clones) whose
    /// reference carries a CRC that matched. Within another `record`, the pages go to it too.
    pub fn record<R>(&self, f: impl FnOnce() -> R) -> (R, Vec<SeenPage>) {
        self.seen.record(f)
    }

    /// Pages read earlier (`record`ed), counted as read again by a `record` running now.
    pub fn seen_again(&self, pages: &[SeenPage]) {
        self.seen.extend(pages);
    }

    /// The same reader, translating virtual addresses through `map`.
    pub fn with_map(&self, map: Arc<ContainerMap>) -> Self {
        PageReader { map: Some(map), ..self.clone() }
    }

    pub fn source(&self) -> &DynSource {
        &self.src
    }

    pub fn cluster_bytes(&self) -> u32 {
        self.cluster
    }

    pub fn page_clusters(&self) -> usize {
        self.page_clusters
    }

    /// Read cluster `lcn` (physical).
    pub fn read_cluster(&self, lcn: u64) -> Result<Vec<u8>> {
        if lcn >= self.clusters {
            return Err(Error::corrupt(format!("LCN {lcn:#x} is past the end of the volume")));
        }
        let c = u64::from(self.cluster);
        self.src.read_vec(lcn * c, self.cluster as usize)
    }

    /// Physical LCN of `lcn`, translated through the container table when virtual.
    pub fn physical(&self, lcn: u64, addr: Addressing) -> Result<u64> {
        if addr == Addressing::Physical {
            return Ok(lcn);
        }
        match &self.map {
            Some(m) => m.translate(lcn),
            None => Err(Error::corrupt("virtual address before the container table is read")),
        }
    }

    /// Read the node page `r` points to (through the container table when virtual),
    /// checking its checksum, signature, volume signature, the LCNs it was written for and its
    /// table id.
    pub fn read_node(&self, r: &PageRef, addr: Addressing, table: u64) -> Result<Page> {
        self.read_node_of(r, addr, table, &|t| t == table)
    }

    /// [`read_node`](Self::read_node), with the page's table id checked by `accept` (`table`
    /// only names it in errors).
    pub fn read_node_of(
        &self,
        r: &PageRef,
        addr: Addressing,
        table: u64,
        accept: &dyn Fn(u64) -> bool,
    ) -> Result<Page> {
        let c = self.cluster as usize;
        let physical = self.page_lcns(r, addr, table)?;
        if let Some(page) = self.kept(r, &physical, table, accept) {
            return page;
        }
        // One read per run of consecutive clusters (normally the whole page).
        let mut data = vec![0u8; self.page_clusters * c];
        let mut i = 0;
        while i < physical.len() {
            let mut n = 1;
            while i + n < physical.len() && physical[i + n] == physical[i] + n as u64 {
                n += 1;
            }
            self.src.read_exact_at(physical[i] * c as u64, &mut data[i * c..(i + n) * c])?;
            i += n;
        }
        self.check(r, physical, data, table, accept)
    }

    /// The page `r` points to (at `physical`) as a batch keeps it, checked: `None` when none is
    /// kept.
    fn kept(&self, r: &PageRef, physical: &[u64], table: u64, accept: &dyn Fn(u64) -> bool) -> Option<Result<Page>> {
        let (crc, data) = {
            let p = lock(&self.pages);
            if p.batches == 0 {
                return None;
            }
            p.pages.get(physical).cloned()?
        };
        Some(self.check_as(r, physical.to_vec(), data.to_vec(), crc, table, accept))
    }

    /// Read the node pages `refs` (each with the table it names in errors; as
    /// [`read_node_of`](Self::read_node_of), its table id checked by `accept(table, id)`),
    /// close ones together, a batch at a time, and hand `f` each one's index and page, in
    /// order. A page that does not read with the others is read alone: an error (`Err` to `f`)
    /// then belongs to it.
    pub fn read_nodes_of(
        &self,
        refs: &[(PageRef, u64)],
        addr: Addressing,
        accept: &dyn Fn(u64, u64) -> bool,
        f: &mut dyn FnMut(usize, Result<Page>) -> Result<()>,
    ) -> Result<()> {
        let c = u64::from(self.cluster);
        let page_bytes = self.page_clusters as u64 * c;
        let per = (AHEAD_BYTES / page_bytes).max(1) as usize;
        for (g, group) in refs.chunks(per).enumerate() {
            let mut lcns = Vec::with_capacity(group.len());
            let mut items = Vec::with_capacity(group.len());
            for (i, (r, table)) in group.iter().enumerate() {
                let p = self.page_lcns(r, addr, *table);
                // A page in pieces is read alone.
                if let Ok(p) = &p
                    && p.windows(2).all(|w| w[1] == w[0] + 1)
                {
                    items.push((p[0] * c, page_bytes, i));
                }
                lcns.push(p);
            }
            let mut data: Vec<Option<Vec<u8>>> = vec![None; group.len()];
            read_runs::<_, Error>(&*self.src, plan(items, BATCH_BYTES, GAP_BYTES), &mut |i, b| {
                data[i] = b.map(<[u8]>::to_vec);
                Ok(())
            })?;
            for (i, (((r, table), p), d)) in group.iter().zip(lcns).zip(data).enumerate() {
                let accept = |t| accept(*table, t);
                let page = match (p, d) {
                    (Err(e), _) => Err(e),
                    (Ok(p), Some(d)) => self.check(r, p, d, *table, &accept),
                    (Ok(_), None) => self.read_node_of(r, addr, *table, &accept),
                };
                f(g * per + i, page)?;
            }
        }
        Ok(())
    }

    /// Physical LCNs of the page `r` points to, each checked to be in the volume.
    fn page_lcns(&self, r: &PageRef, addr: Addressing, table: u64) -> Result<Vec<u64>> {
        let mut physical = Vec::with_capacity(self.page_clusters);
        for &l in &r.lcns[..self.page_clusters] {
            let p = self.physical(l, addr)?;
            if p >= self.clusters {
                return Err(Error::corrupt(format!("table {table:#x}: LCN {p:#x} is past the end of the volume")));
            }
            physical.push(p);
        }
        Ok(physical)
    }

    /// The checks of [`read_node_of`](Self::read_node_of) on a page read from `physical`.
    fn check(
        &self,
        r: &PageRef,
        physical: Vec<u64>,
        data: Vec<u8>,
        table: u64,
        accept: &dyn Fn(u64) -> bool,
    ) -> Result<Page> {
        self.check_as(r, physical, data, None, table, accept)
    }

    /// [`check`](Self::check) of a page whose bytes matched checksum `matched` before: not
    /// computed again when `r` gives the same.
    fn check_as(
        &self,
        r: &PageRef,
        physical: Vec<u64>,
        data: Vec<u8>,
        matched: Option<u64>,
        table: u64,
        accept: &dyn Fn(u64) -> bool,
    ) -> Result<Page> {
        let at = |e: Error| e.at("ReFS page", physical[0] * u64::from(self.cluster));
        let mut computed = false;
        let verdict = if matched.is_some() && matched == r.crc() {
            Verdict::Ok
        } else {
            let site = Site::new(StructureKind::RefsPage).at(physical[0] * u64::from(self.cluster)).id(table);
            self.integrity.check(self.role, site, || {
                computed = true;
                r.verify(&[&data])
            })
        };
        // Only a checksum computed (now or before) is one the page matched.
        let matched = if verdict == Verdict::Ok && (computed || matched.is_some()) { r.crc() } else { None };
        if verdict == Verdict::Mismatch {
            return Err(at(Error::corrupt(format!("table {table:#x}: page checksum mismatch"))));
        }
        let h = PageHeader::parse(&data).map_err(at)?;
        if &h.signature != MSB_PLUS {
            return Err(at(Error::corrupt(format!("table {table:#x}: no MSB+ signature"))));
        }
        if h.volume_signature != self.volume_signature {
            return Err(at(Error::corrupt(format!("table {table:#x}: page of another volume"))));
        }
        if h.lcns[..self.page_clusters] != r.lcns[..self.page_clusters] {
            return Err(at(Error::corrupt(format!("table {table:#x}: page written for other LCNs (stale)"))));
        }
        if !accept(h.table) {
            return Err(at(Error::corrupt(format!("page of table {:#x}, expected {table:#x}", h.table))));
        }
        if let Some(crc) = r.crc() {
            self.seen.push_with(|| SeenPage { physical: physical.clone(), crc });
        }
        let mut p = lock(&self.pages);
        if p.batches > 0 && p.pages.len() < PageCache::MAX && !p.pages.contains_key(&physical) {
            p.pages.insert(physical.clone(), (matched, data.as_slice().into()));
        }
        drop(p);
        Ok(Page { data, physical })
    }
}

/// The index of a node whose index root starts at `ir` of `p`: its level, its data area and
/// the offsets in `p` of its entries in key order (deleted ones included).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    pub level: u8,
    pub area: std::ops::Range<usize>,
    pub entries: Vec<usize>,
}

impl Index {
    pub fn parse(p: &[u8], ir: usize) -> Result<Self> {
        let ih = ir
            .checked_add(u32_at(p, ir)? as usize)
            .filter(|&ih| ih < p.len())
            .ok_or_else(|| Error::corrupt("node: index root past the page"))?;
        let data_start = u32_at(p, ih)? as usize;
        let data_end = u32_at(p, ih + 4)? as usize;
        let level = u8_at(p, ih + 0x0C)?;
        let kstart = u32_at(p, ih + 0x10)? as usize;
        let count = u32_at(p, ih + 0x14)? as usize;
        let kend = u32_at(p, ih + 0x20)? as usize;
        if kend.checked_sub(kstart) != count.checked_mul(4) {
            return Err(Error::corrupt(format!("node: key index of {count} entries spans {kstart:#x}..{kend:#x}")));
        }
        let area_end = ih.checked_add(data_end).filter(|&e| e <= p.len());
        let area = ih.checked_add(data_start).zip(area_end).filter(|(a, e)| a <= e);
        let Some((area_start, area_end)) = area else {
            return Err(Error::corrupt(format!("node: data area {data_start:#x}..{data_end:#x}")));
        };
        let kidx = slice(p, ih + kstart, count * 4)?;
        let entries =
            kidx.as_chunks::<4>().0.iter().map(|k| ih + usize::from(u16::from_le_bytes([k[0], k[1]]))).collect();
        Ok(Index { level, area: area_start..area_end, entries })
    }
}

/// A parsed node: its level and the (key, value) slices of its live entries, in key order.
#[derive(Debug)]
pub struct Node {
    pub page: Page,
    pub level: u8,
    entries: Vec<(std::ops::Range<usize>, std::ops::Range<usize>)>,
}

impl Node {
    /// The node of a page (its index root follows the page header).
    pub fn parse(page: Page) -> Result<Self> {
        Self::parse_at(page, PAGE_HEADER_LEN)
    }

    /// The node whose index root starts at `ir` of `page.data`: 0 for a node embedded in a
    /// value (a file record, an extent table).
    pub fn parse_at(page: Page, ir: usize) -> Result<Self> {
        let p = &page.data;
        let Index { level, area, entries: offsets } = Index::parse(p, ir)?;
        let (area_start, area_end) = (area.start, area.end);
        let mut entries = Vec::with_capacity(offsets.len());
        for e in offsets {
            let size = u32_at(p, e)? as usize;
            let end = e.checked_add(size).filter(|&end| e >= area_start && end <= area_end);
            let Some(end) = end else {
                return Err(Error::corrupt(format!("node: entry at {e:#x} of {size} bytes outside the data area")));
            };
            let field = |o: usize, l: usize| -> Result<std::ops::Range<usize>> {
                let (a, b) = (e + o, e + o + l);
                if o < 0x0E && l > 0 || b > end {
                    return Err(Error::corrupt(format!("node: entry at {e:#x}: field {o:#x}+{l:#x} outside it")));
                }
                Ok(a..b)
            };
            let flags = u16_at(p, e + 8)?;
            let key = field(usize::from(u16_at(p, e + 4)?), usize::from(u16_at(p, e + 6)?))?;
            let value = field(usize::from(u16_at(p, e + 10)?), usize::from(u16_at(p, e + 12)?))?;
            if flags & ENTRY_DELETED == 0 {
                entries.push((key, value));
            }
        }
        Ok(Node { page, level, entries })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn key(&self, i: usize) -> &[u8] {
        &self.page.data[self.entries[i].0.clone()]
    }

    pub fn value(&self, i: usize) -> &[u8] {
        &self.page.data[self.entries[i].1.clone()]
    }
}

/// Depth-first walk over the leaf entries of a table, one root-to-leaf path in memory. Leaves
/// under one parent are read together (close ones in one read, the reads in flight together), one
/// page the first time and twice as many each time after (up to a batch): a walk stopped early
/// reads little past where it stopped.
/// [`seek`](TreeWalk::seek) starts it at a key.
#[derive(Debug)]
pub struct TreeWalk {
    reader: PageReader,
    addr: Addressing,
    table: u64,
    max_depth: usize,
    max_nodes: u64,
    nodes: u64,
    /// The nodes of the current path and the next entry of each.
    stack: Vec<(Node, usize)>,
    root: Option<PageRef>,
    /// The root page, when it was read before the walk.
    root_page: Option<Page>,
    /// Pages read with a leaf before them (leaves, level-1 nodes), in walk order: physical
    /// LCNs and bytes.
    ahead: std::collections::VecDeque<(Vec<u64>, Vec<u8>)>,
    /// Pages the next read together may cover.
    ramp: usize,
}

impl TreeWalk {
    pub fn new(reader: PageReader, root: PageRef, addr: Addressing, table: u64, limits: &Limits) -> Self {
        TreeWalk {
            reader,
            addr,
            table,
            max_depth: limits.max_tree_depth,
            max_nodes: limits.max_tree_nodes,
            nodes: 0,
            stack: Vec::new(),
            root: Some(root),
            root_page: None,
            ahead: Default::default(),
            ramp: 1,
        }
    }

    /// A walk from root page `page`, read already (from `root`).
    pub fn from_page(
        reader: PageReader,
        root: PageRef,
        page: Page,
        addr: Addressing,
        table: u64,
        limits: &Limits,
    ) -> Self {
        TreeWalk { root_page: Some(page), ..Self::new(reader, root, addr, table, limits) }
    }

    /// The page at `physical` when it is next in `ahead` (pages read ahead, in walk order);
    /// else `ahead` is let go: the walk left the order it was read in.
    fn take_ahead(&mut self, physical: &[u64]) -> Option<Vec<u8>> {
        while let Some((p, data)) = self.ahead.pop_front() {
            if p == physical {
                return Some(data);
            }
        }
        None
    }

    /// The leaf page `r` (child `idx` of the level-1 node on top of the stack), from `ahead`,
    /// or read together with the pages the walk takes after it ([`pages_after`]): close ones
    /// in one read, the reads in flight together. Up to `ramp` pages, doubled each time, so a
    /// walk that stops early reads little and one that goes on keeps about the source's queue
    /// depth of reads in flight, past the ends of level-1 nodes too. A page that does not read
    /// with the others is read alone when its turn comes, so an error belongs to the page it
    /// is in.
    ///
    /// [`pages_after`]: Self::pages_after
    fn read_leaf(&mut self, r: &PageRef, idx: usize) -> Result<Page> {
        let first = self.reader.page_lcns(r, self.addr, self.table)?;
        if let Some(page) = self.reader.kept(r, &first, self.table, &|t| t == self.table) {
            return page;
        }
        if let Some(data) = self.take_ahead(&first) {
            return self.reader.check(r, first, data, self.table, &|t| t == self.table);
        }
        let c = u64::from(self.reader.cluster);
        let page_bytes = first.len() as u64 * c;
        let most = usize::try_from(AHEAD_BYTES / page_bytes).unwrap_or(usize::MAX).max(1);
        let budget = self.ramp.min(most);
        self.ramp = self.ramp.saturating_mul(2);
        let (pages, mut data): (Vec<Vec<u64>>, Vec<Option<Vec<u8>>>) =
            self.pages_after(&first, idx, budget).into_iter().unzip();
        if pages.len() > 1 {
            // The level-1 nodes among them were read already.
            let items =
                (0..pages.len()).filter(|&i| data[i].is_none()).map(|i| (pages[i][0] * c, page_bytes, i)).collect();
            read_runs::<_, Error>(&*self.reader.src, plan(items, BATCH_BYTES, GAP_BYTES), &mut |i, b| {
                data[i] = b.map(<[u8]>::to_vec);
                Ok(())
            })?;
            // In order up to the first page that did not read: one after it alone in `ahead`
            // would let go of the ones before it.
            let mut read = pages.into_iter().zip(data).map_while(|(p, d)| Some((p, d?)));
            if let Some((_, head)) = read.next() {
                self.ahead.extend(read);
                return self.reader.check(r, first, head, self.table, &|t| t == self.table);
            }
        }
        self.reader.read_node(r, self.addr, self.table)
    }

    /// The pages the walk reads from leaf `first` (child `idx` of the level-1 node on top of
    /// the stack) on, up to `budget`, in walk order: `first`, the children after it, then each
    /// level-1 node after their parent (with its bytes: read here, together, to find its
    /// children) and its children. Each page in one run of clusters, and only as far as all
    /// before it are known.
    fn pages_after(&self, first: &[u64], idx: usize, budget: usize) -> Vec<(Vec<u64>, Option<Vec<u8>>)> {
        let reader = &self.reader;
        let contiguous = |p: &[u64]| p.windows(2).all(|w| w[1] == w[0] + 1);
        let child = |node: &Node, j: usize| {
            PageRef::parse(node.value(j))
                .and_then(|r| reader.page_lcns(&r, self.addr, self.table).map(|p| (r, p)))
                .ok()
                .filter(|(_, p)| contiguous(p))
        };
        let mut pages = vec![(first.to_vec(), None)];
        // `read_leaf` runs with the parent on the stack.
        let parent = &self.stack[self.stack.len() - 1].0;
        if !contiguous(first) {
            return pages;
        }
        for j in idx + 1..parent.len() {
            if pages.len() >= budget {
                return pages;
            }
            let Some((_, p)) = child(parent, j) else { return pages };
            pages.push((p, None));
        }
        // The level-1 nodes after the parent, as many as their children (about as many as
        // the parent's each) fill the budget.
        let Some((grand, next)) = self.stack.len().checked_sub(2).and_then(|g| self.stack.get(g)) else {
            return pages;
        };
        let want = budget.saturating_sub(pages.len()).div_ceil(parent.len() + 1);
        let nodes: Vec<(PageRef, Vec<u64>)> = (*next..grand.len()).take(want).map_while(|j| child(grand, j)).collect();
        if nodes.is_empty() {
            return pages;
        }
        let c = u64::from(reader.cluster);
        let items = nodes.iter().enumerate().map(|(i, (_, p))| (p[0] * c, p.len() as u64 * c, i)).collect();
        let mut read: Vec<Option<Vec<u8>>> = vec![None; nodes.len()];
        let done = read_runs::<_, Error>(&*reader.src, plan(items, BATCH_BYTES, GAP_BYTES), &mut |i, b| {
            read[i] = b.map(<[u8]>::to_vec);
            Ok(())
        });
        if done.is_err() {
            return pages;
        }
        for ((r, p), data) in nodes.into_iter().zip(read) {
            // A node that does not read or check is read again (and its error given) when the
            // walk reaches it.
            let node = data.as_ref().and_then(|d| {
                let page = reader.check(&r, p.clone(), d.clone(), self.table, &|t| t == self.table).ok()?;
                Node::parse(page).ok().filter(|n| n.level == 1)
            });
            let (Some(node), Some(data)) = (node, data) else { return pages };
            pages.push((p, Some(data)));
            for j in 0..node.len() {
                if pages.len() >= budget {
                    return pages;
                }
                let Some((_, p)) = child(&node, j) else { return pages };
                pages.push((p, None));
            }
        }
        pages
    }

    fn push(&mut self, r: &PageRef, parent_level: Option<u8>) -> Result<()> {
        if let Some(page) = self.root_page.take() {
            self.nodes += 1;
            self.stack.push((Node::parse(page)?, 0));
            return Ok(());
        }
        self.nodes += 1;
        if self.nodes > self.max_nodes {
            return Err(Error::limit(format!("table {:#x}: more than {} nodes", self.table, self.max_nodes)));
        }
        if self.stack.len() >= self.max_depth {
            return Err(Error::limit(format!("table {:#x}: deeper than {}", self.table, self.max_depth)));
        }
        let page = match (parent_level, self.stack.last()) {
            (Some(1), Some((_, i))) => self.read_leaf(r, *i - 1)?,
            // A level-1 node read ahead with the leaves before it.
            (Some(2), _) if !self.ahead.is_empty() => {
                let physical = self.reader.page_lcns(r, self.addr, self.table)?;
                match self.take_ahead(&physical) {
                    Some(data) => self.reader.check(r, physical, data, self.table, &|t| t == self.table)?,
                    None => self.reader.read_node(r, self.addr, self.table)?,
                }
            }
            _ => self.reader.read_node(r, self.addr, self.table)?,
        };
        let node = Node::parse(page)?;
        if let Some(pl) = parent_level
            && pl.checked_sub(1) != Some(node.level)
        {
            return Err(Error::corrupt(format!(
                "table {:#x}: node of level {} under level {pl}",
                self.table, node.level
            )));
        }
        self.stack.push((node, 0));
        Ok(())
    }

    /// Start the walk (not begun yet) at a key: from the root down, `pick` is given each node
    /// and names the child to descend into (an inner node: the walk goes on with the children
    /// after it) or the first entry to give (a leaf). Past the node's entries: from the next
    /// node on.
    pub fn seek(&mut self, pick: &mut dyn FnMut(&Node) -> Result<usize>) -> Result<()> {
        let Some(r) = self.root.take() else {
            return Err(Error::invalid_argument(format!("table {:#x}: seek of a walk begun", self.table)));
        };
        self.push(&r, None)?;
        loop {
            // `push` put the node on the stack.
            let top = self.stack.len() - 1;
            let (node, i) = &mut self.stack[top];
            let at = pick(node)?.min(node.len());
            *i = at;
            if node.level == 0 || at == node.len() {
                return Ok(());
            }
            *i = at + 1;
            let (child, level) = (PageRef::parse(node.value(at))?, node.level);
            self.push(&child, Some(level))?;
        }
    }

    /// The node the next entry comes from and its index, or `None` at the end. Physical LCNs
    /// of every node read are passed to `seen`.
    pub fn next_with(&mut self, seen: &mut dyn FnMut(&[u64])) -> Result<Option<(&Node, usize)>> {
        if let Some(r) = self.root.take() {
            self.push(&r, None)?;
            seen(&self.stack[0].0.page.physical);
        }
        loop {
            let Some((node, i)) = self.stack.last_mut() else { return Ok(None) };
            if *i >= node.len() {
                self.stack.pop();
                continue;
            }
            let idx = *i;
            *i += 1;
            if node.level == 0 {
                break;
            }
            let child = PageRef::parse(node.value(idx))?;
            let level = node.level;
            self.push(&child, Some(level))?;
            // `push` put the child on the stack.
            seen(&self.stack[self.stack.len() - 1].0.page.physical);
        }
        Ok(self.stack.last().map(|(n, i)| (n, *i - 1)))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "tree_tests.rs"]
mod tests;
