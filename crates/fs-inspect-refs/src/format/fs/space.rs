//! Used space: the pages and rows of the Medium allocator and the sub-allocators.

use crate::format::alloc::{Row, RowState};
use crate::format::layout::{PageRef, table};
use crate::format::tree::{Addressing, Node, PageReader, TreeWalk};
use fs_inspect_core::Scope;
use fs_inspect_core::{ByteRange, DiagCode, Diagnostics, Error, Limits, Result, push_bit_runs, push_range};

/// Append the physical LCNs of every page of the Medium allocator, reading only its inner
/// nodes (the references to the leaves carry their addresses).
pub(super) fn medium_pages(reader: &PageReader, root: PageRef, limits: &Limits, out: &mut Vec<u64>) -> Result<()> {
    let t = table::MEDIUM_ALLOCATOR;
    let pc = reader.page_clusters();
    let mut nodes = 0u64;
    let mut stack = vec![(root, None::<u8>)];
    while let Some((r, parent)) = stack.pop() {
        nodes += 1;
        if nodes > limits.max_tree_nodes {
            return Err(Error::limit(format!("table {t:#x}: more than {} inner nodes", limits.max_tree_nodes)));
        }
        let node = Node::parse(reader.read_node(&r, Addressing::Virtual, t)?)?;
        let bad_level = parent.is_some_and(|pl| pl.checked_sub(1) != Some(node.level));
        if bad_level || usize::from(node.level) >= limits.max_tree_depth {
            return Err(Error::corrupt(format!("table {t:#x}: node of level {}", node.level)));
        }
        out.extend_from_slice(&node.page.physical);
        if node.level == 0 {
            continue;
        }
        for i in 0..node.len() {
            let child = PageRef::parse(node.value(i))?;
            if node.level == 1 {
                for &l in &child.lcns[..pc] {
                    out.push(reader.physical(l, Addressing::Virtual)?);
                }
            } else {
                stack.push((child, Some(node.level)));
            }
        }
        if out.len() > limits.max_file_extents {
            return Err(Error::limit(format!("table {t:#x}: too many pages")));
        }
    }
    Ok(())
}

/// What [`sub_allocator`] appends to.
pub(super) struct SubAllocated<'a> {
    /// The allocated ranges.
    pub(super) out: &'a mut Vec<ByteRange>,
    /// The ranges its rows cover.
    pub(super) covered: &'a mut Vec<ByteRange>,
    /// The LCNs of its pages.
    pub(super) pages: &'a mut Vec<u64>,
}

/// Append what sub-allocator table `t` (at `r`) holds to `to`.
pub(super) fn sub_allocator(
    reader: &PageReader,
    r: PageRef,
    addr: Addressing,
    t: u64,
    clusters: u64,
    limits: &Limits,
    to: SubAllocated<'_>,
) -> Result<()> {
    let SubAllocated { out, covered, pages } = to;
    let cluster = u64::from(reader.cluster_bytes());
    let mut walk = TreeWalk::new(reader.clone(), r, addr, t, limits);
    while let Some((node, i)) = walk.next_with(&mut |p| pages.extend_from_slice(p))? {
        let row = Row::parse(node.value(i))?;
        if row.end() > clusters {
            return Err(Error::corrupt(format!(
                "allocator {t:#x}: row {:#x}+{:#x} past the volume",
                row.start, row.len
            )));
        }
        emit_row(&row, cluster, clusters, out);
        covered.push(ByteRange::new(row.start * cluster, row.len * cluster));
        if out.len() + covered.len() > limits.max_file_extents {
            return Err(Error::limit(format!("allocator {t:#x}: too many ranges")));
        }
    }
    Ok(())
}

/// Append the allocated clusters of `row` below cluster `total` as byte ranges.
fn emit_row(row: &Row<'_>, cluster: u64, total: u64, out: &mut Vec<ByteRange>) {
    let end = row.end().min(total);
    if row.start >= end {
        return;
    }
    // No overflow: `total * cluster` is the volume size.
    let (base, n) = (row.start * cluster, end - row.start);
    match row.state {
        RowState::Allocated => push_range(out, base, n * cluster),
        RowState::Free => {}
        RowState::Bitmap(b) => push_bit_runs(out, b, n, base, cluster),
    }
}

/// The Medium allocator's rows in order, as used byte ranges. Clusters no row covers (the
/// containers of the log and of large files, which the container table hands out directly)
/// count as used.
#[derive(Debug)]
pub(super) struct MediumIter {
    walk: TreeWalk,
    cluster: u64,
    /// Clusters of the volume.
    total: u64,
    diag: Diagnostics,
    /// Next cluster not yet accounted for.
    pos: u64,
    buf: Vec<ByteRange>,
    next: usize,
    done: bool,
}

impl MediumIter {
    /// The rows `walk` (of the Medium allocator) gives, on a volume of `total` clusters.
    pub(super) fn new(walk: TreeWalk, cluster: u64, total: u64, diag: Diagnostics) -> MediumIter {
        MediumIter { walk, cluster, total, diag, pos: 0, buf: Vec::new(), next: 0, done: false }
    }

    /// The rest of the volume counts as used; the walk ends.
    fn rest_used(&mut self) {
        push_range(&mut self.buf, self.pos * self.cluster, (self.total - self.pos) * self.cluster);
        self.done = true;
    }

    /// Ranges of the next row, and of the clusters before it that no row covers.
    fn refill(&mut self) -> Result<()> {
        let (cluster, total) = (self.cluster, self.total);
        self.buf.clear();
        self.next = 0;
        let row = match self.walk.next_with(&mut |_| {}) {
            Ok(None) => {
                self.rest_used();
                return Ok(());
            }
            Ok(Some((node, i))) => Row::parse(node.value(i)).map(|row| {
                let (start, end) = (row.start, row.end());
                if end <= self.pos || start >= total {
                    return Some((start, row.len));
                }
                if start > self.pos {
                    push_range(&mut self.buf, self.pos * cluster, (start - self.pos) * cluster);
                }
                // Only what lies at or after `pos`: an overlapping row is clipped.
                let lo = self.pos.max(start) * cluster;
                let from = self.buf.len();
                emit_row(&row, cluster, total, &mut self.buf);
                let below = self.buf[from..].iter().take_while(|r| r.end() <= lo).count();
                self.buf.drain(from..from + below);
                if let Some(r) = self.buf.get_mut(from)
                    && r.offset < lo
                {
                    *r = ByteRange::new(lo, r.end() - lo);
                }
                self.pos = end.min(total);
                None
            }),
            Err(e) => Err(e),
        };
        match row {
            Ok(None) => Ok(()),
            Ok(Some((start, len))) => {
                self.diag.warn(
                    DiagCode::Inconsistent,
                    format!("Medium allocator row {start:#x}+{len:#x} overlaps another or is past the volume"),
                );
                Ok(())
            }
            Err(e) if e.scope() != Scope::Unit => Err(e),
            Err(e) => {
                self.diag.warn(
                    DiagCode::CountedAsUsed,
                    format!("Medium allocator unreadable after cluster {:#x} ({e}); the rest counts as used", self.pos),
                );
                self.rest_used();
                Ok(())
            }
        }
    }
}

impl Iterator for MediumIter {
    type Item = Result<ByteRange>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(&r) = self.buf.get(self.next) {
                self.next += 1;
                return Some(Ok(r));
            }
            if self.done {
                return None;
            }
            if let Err(e) = self.refill() {
                self.done = true;
                return Some(Err(e));
            }
        }
    }
}
