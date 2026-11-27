//! The namespace of an NTFS volume: one root, nodes numbered by MFT file reference.
//!
//! - A node's id is its full file reference: the record number in the low 48 bits, the
//!   record's sequence number in the high 16. A reference whose sequence does not match the
//!   record (a reused record) is not found. The root directory is record 5.
//! - Names compare without case through the volume's `$UpCase` table, as the `$I30` index
//!   collates them; a lookup also finds a file by its DOS 8.3 name. Listings give each file
//!   its long name: the 8.3-only entries of the index are left out. [`names`] gives every
//!   hard link's parent and name (DOS names left out).
//! - Nodes the file system needs are [`NodeFlags::SYSTEM`]: those of the reserved records
//!   (below the first user record: `$MFT`, `$LogFile`, `$Bitmap`, `$Extend`, ...; not the
//!   root) and those of the `$Extend` tree (`$UsnJrnl`, `$RmMetadata` and its logs, ...). They
//!   are listed and statable, never excluded.
//! - A file whose MFT entry is damaged (a torn record, a runlist that does not decode, a gap
//!   in its attribute list) is statable, but neither read nor excluded: its runs cannot be
//!   trusted to name only its own clusters.
//! - Content ([`content`](crate::format::content)): resident, sparse, LZNT1 and WOF
//!   (XPRESS, LZX) streams decode; EFS-encrypted ones are [`NodeFlags::ENCRYPTED`] and do not
//!   open. Streams: 0 the unnamed `$DATA`, `n` the `n`th named `$DATA` in name order (WOF's
//!   `WofCompressedData` is the file's content, not listed).
//! - Reparse points ([`reparse`](crate::format::reparse)): symbolic links and junctions are
//!   [`NodeKind::Symlink`] ([`read_link`]), WSL's special files their kinds, other tags but
//!   WOF, Cloud Files and deduplication [`NodeKind::Reparse`].
//! - Cloud Files placeholders ([`Stat::cloud`]): the ranges of the unnamed `$DATA` that are
//!   sparse are [`SegmentKind::Absent`](fs_inspect_core::SegmentKind): the provider holds
//!   them. Hydration is told by them: none sparse, all, some.
//! - Extended attributes are the `$EA` entries (namespace `other`); WSL's `$LX*` give the
//!   [`Stat::unix`]. Security is the `$Secure:$SDS` descriptor of the file's security id, or
//!   its own `$SECURITY_DESCRIPTOR`.
//!
//! [`names`]: NodeInfo::names
//! [`read_link`]: NodeInfo::link

use crate::format::attr::{AttrType, Frn, attr_flags};
use crate::format::content::{Wof, stream_reader};
use crate::format::ea;
use crate::format::entry::{FileEntry, Stream};
use crate::format::exclude::{clusters_to_ranges, data_clusters};
use crate::format::files::{NAME_OF_DIRECTORY, extend_dirs};
use crate::format::fs::NtfsFs;
use crate::format::index::IndexEntry;
use crate::format::name::Namespace as NameSpace;
use crate::format::record::RecordParse;
use crate::format::security::{SdsIndex, own_descriptor};
use crate::format::volume::system_records;
use fs_inspect_core::RootId;
use fs_inspect_core::ns::kit;
use fs_inspect_core::read::{ChunkedReader, FileReader, MemReader};
use fs_inspect_core::windows::reparse::{self, Reparse, kind_of_tag};
use fs_inspect_core::{
    ByteRange, CloudInfo, CloudProvider, DirEntry, Error, Hydration, LinkTarget, Name, Namespace, NodeFlags, NodeId,
    NodeInfo, NodeKind, PinState, RecallFlags, Result, RootInfo, Security, Stat, StreamId, StreamInfo, Times,
    Timestamp, Want, WinAttrs, Xattr, XattrNs,
};
use fs_inspect_core::{
    CloudInfoExt, DirEntryExt, NodeInfoExt, RootInfoExt, StatExt, StreamInfoExt, TimestampExt, WantExt, XattrExt,
};
use fs_inspect_core::{TimesExt, WinAttrsExt};
use std::collections::HashSet;
use std::ops::ControlFlow;
use std::sync::Arc;

/// `FILE_ATTRIBUTE_*` of `$STANDARD_INFORMATION` that are [`NodeFlags`] or cloud state.
const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x200;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x800;
const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x4000;
const FILE_ATTRIBUTE_PINNED: u32 = 0x8_0000;
const FILE_ATTRIBUTE_UNPINNED: u32 = 0x10_0000;
const RECALL: u32 = RecallFlags::OFFLINE.bits() | RecallFlags::ON_OPEN.bits() | RecallFlags::ON_DATA_ACCESS.bits();
/// NTFS's own mark of a file with extended attributes, in the bit Windows reports as
/// `FILE_ATTRIBUTE_RECALL_ON_OPEN` (and does not report for this).
const FILE_ATTRIBUTE_HAS_EA: u32 = 0x4_0000;
/// WOF's stream of a compressed file's data.
const WOF_STREAM: &str = "WofCompressedData";
/// Most nodes whose records [`Namespace::node_infos`] reads together: 4 MiB of records, so
/// their runs (up to `BATCH_BYTES` each) go out together at the source's queue depth.
const INFO_BATCH: usize = 4096;

impl NtfsFs {
    /// The entry of `node`, in use with a matching sequence number; a record that does not
    /// parse is damaged, not missing.
    fn node(&self, node: NodeId) -> Result<FileEntry> {
        let missing = || Error::not_found(format!("ntfs node {node}"));
        if node.root != RootId(0) {
            return Err(missing());
        }
        // Every id is a record number and sequence number (`Frn::from_raw` keeps all 64 bits).
        let frn = Frn::from_raw(node.id);
        if frn.record >= self.volume().record_count() {
            return Err(missing());
        }
        if let Some(e) = self.volume().entry_frn(frn)? {
            return Ok(e);
        }
        match self.volume().read_parsed(frn.record)? {
            RecordParse::Bad { reason } => {
                Err(Error::corrupt(format!("ntfs node {node}: MFT record {}: {reason}", frn.record)))
            }
            _ => Err(missing()),
        }
    }

    /// The entry of directory `dir` (`None`: not a directory).
    fn dir(&self, dir: NodeId) -> Result<Option<FileEntry>> {
        Ok(Some(self.node(dir)?).filter(FileEntry::is_dir))
    }

    /// Whether file `e` is one the file system needs: a reserved record, or a name in the
    /// `$Extend` tree. Never a directory.
    fn system(&self, e: &FileEntry) -> Result<bool> {
        if e.frn.record == system_records::ROOT {
            return Ok(false);
        }
        if e.frn.record < system_records::FIRST_USER {
            return Ok(true);
        }
        if let Some(dirs) = self.extend_tree()? {
            return Ok(e.names.iter().any(|n| dirs.contains(&n.parent)));
        }
        // The tree cannot be listed: follow each name's parents up to the root.
        for n in &e.names {
            if self.under_extend(n.parent)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The directories of the `$Extend` tree, listed once (`None`: it cannot be listed).
    fn extend_tree(&self) -> Result<Option<&HashSet<Frn>>> {
        if let Some(d) = self.extend.get() {
            return Ok(d.as_ref());
        }
        let d = extend_dirs(self.volume())?;
        Ok(self.extend.get_or_init(|| d).as_ref())
    }

    /// Whether directory `dir` is `$Extend` or below it, by the parents of its preferred
    /// names; `false` when the chain breaks or does not end.
    fn under_extend(&self, mut dir: Frn) -> Result<bool> {
        for _ in 0..self.volume().limits().max_path_depth {
            match dir.record {
                system_records::EXTEND => return Ok(true),
                system_records::ROOT => return Ok(false),
                _ => {}
            }
            let Some(parent) = self.volume().entry_frn(dir)?.and_then(|d| d.primary_name().map(|n| n.parent)) else {
                return Ok(false);
            };
            dir = parent;
        }
        Ok(false)
    }

    /// The reparse point of `e`.
    fn reparse(&self, e: &FileEntry) -> Result<Option<Reparse>> {
        match e.stream(AttrType::REPARSE_POINT, &[]) {
            Some(s) => Ok(Some(Reparse::parse(&self.volume().read_stream_all(s)?)?)),
            None => Ok(None),
        }
    }

    /// The extended attributes of `e`.
    fn eas(&self, e: &FileEntry) -> Result<Vec<ea::Ea>> {
        match e.stream(AttrType::EA, &[]) {
            Some(s) => ea::parse(&self.volume().read_stream_all(s)?),
            None => Ok(Vec::new()),
        }
    }

    /// The named `$DATA` streams of `e`, each with its stream id.
    fn named_streams(e: &FileEntry) -> impl Iterator<Item = (StreamId, &Stream)> {
        e.streams
            .iter()
            .filter(|s| s.kind == AttrType::DATA && !s.name.is_empty())
            .enumerate()
            .map(|(i, s)| (StreamId::new(i as u32 + 1), s))
    }

    /// The cloud state of `e` with reparse point `r`, attributes `attributes`.
    fn cloud(&self, e: &FileEntry, r: &Reparse, attributes: u32) -> Option<CloudInfo> {
        let cs = u64::from(self.volume().geometry().cluster_size);
        if !reparse::is_cloud(r.tag) {
            return None;
        }
        let hydration = match e.unnamed_data() {
            _ if e.is_dir() => Hydration::Full,
            None => Hydration::Full,
            Some(s) if s.is_resident() => Hydration::Full,
            // A compressed stream has sparse runs by design: only the attributes tell.
            Some(s) if s.flags & attr_flags::COMPRESSED != 0 => {
                if attributes & (RecallFlags::OFFLINE.bits() | RecallFlags::ON_DATA_ACCESS.bits()) != 0 {
                    Hydration::Unknown
                } else {
                    Hydration::Full
                }
            }
            Some(s) => {
                // Clusters of the stream's size on the volume, and not.
                let need = s.size().div_ceil(cs);
                let mut here = 0u64;
                for run in s.runs().iter().filter(|r| r.lcn().is_some()) {
                    here += run.end_vcn().min(need).saturating_sub(run.vcn());
                }
                match here {
                    _ if need == 0 => Hydration::Full,
                    0 => Hydration::None,
                    h if h >= need => Hydration::Full,
                    _ => Hydration::Partial,
                }
            }
        };
        let pin = if attributes & FILE_ATTRIBUTE_PINNED != 0 {
            PinState::Pinned
        } else if attributes & FILE_ATTRIBUTE_UNPINNED != 0 {
            PinState::Unpinned
        } else {
            PinState::Unspecified
        };
        let mut cloud = CloudInfo::new(CloudProvider::WindowsCloudFiles { reparse_tag: r.tag }, hydration);
        cloud.pin = pin;
        cloud.recall = RecallFlags::from_bits_truncate(attributes & RECALL);
        cloud.provider_data = Some(r.data.clone());
        Some(cloud)
    }

    /// A directory entry of an index entry with a `$FILE_NAME` key.
    fn dir_entry(e: &IndexEntry) -> Option<DirEntry> {
        let n = e.file_name()?;
        let dir = n.attributes & NAME_OF_DIRECTORY != 0;
        let reparse = n.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        let kind = if reparse {
            // The index's copy of the name holds the reparse tag.
            kind_of_tag(n.reparse_or_ea, dir)
        } else if dir {
            NodeKind::Dir
        } else {
            NodeKind::File
        };
        Some(
            DirEntry::new(Name::Utf16(n.name.0), NodeId::new(0, e.frn.to_raw()), Some(kind))
                .with_cloud(reparse && reparse::is_cloud(n.reparse_or_ea)),
        )
    }

    /// The SDS index, read once (until a trim).
    fn sds(&self) -> Result<std::sync::Arc<SdsIndex>> {
        let lock = || self.sds.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(s) = lock().clone() {
            return Ok(s);
        }
        let s = std::sync::Arc::new(SdsIndex::read(self.volume())?);
        Ok(lock().get_or_insert(s).clone())
    }
}

impl NtfsFs {
    /// The [`Stat`] of `node`: entry `e`, its reparse point `r` and extended attributes `eas`.
    fn stat_of(&self, node: NodeId, e: &FileEntry, r: Option<&Reparse>, eas: &[ea::Ea]) -> Result<Stat> {
        let mut st = Stat::new(node, kind_of(e, r), e.unnamed_data_size());
        st.nlink = Some(u32::from(e.link_count));
        st.generation = Some(u64::from(e.frn.seq));
        st.allocated = Some(e.streams.iter().filter(|s| s.kind == AttrType::DATA).map(|s| s.allocated()).sum());
        let mut attributes = 0;
        let wof = r.is_some_and(|r| r.tag == reparse::WOF);
        let has_ea = e.stream(AttrType::EA, &[]).is_some();
        if let Some(si) = &e.std_info {
            st.times = Times::new(
                Timestamp::from_filetime(si.created),
                Timestamp::from_filetime(si.modified),
                Timestamp::from_filetime(si.mft_changed),
                Timestamp::from_filetime(si.accessed),
            );
            attributes = si.attributes;
            // The attributes Windows reports: a WOF file is a plain file whose content the WOF
            // driver supplies (not the sparse reparse point that holds it on the volume).
            let mut shown = attributes;
            if wof {
                shown &= !(FILE_ATTRIBUTE_SPARSE_FILE | FILE_ATTRIBUTE_REPARSE_POINT);
            }
            if has_ea {
                shown &= !FILE_ATTRIBUTE_HAS_EA;
            }
            st.windows = Some(WinAttrs::new(shown, si.security_id, r.map(|r| r.tag)));
        }
        if let Some(s) = e.unnamed_data() {
            st.flags |= stream_flags(s);
        }
        for (attr, f) in [
            (FILE_ATTRIBUTE_COMPRESSED, NodeFlags::COMPRESSED),
            (FILE_ATTRIBUTE_ENCRYPTED, NodeFlags::ENCRYPTED),
            (FILE_ATTRIBUTE_SPARSE_FILE, NodeFlags::SPARSE),
        ] {
            if attributes & attr != 0 && !(wof && attr == FILE_ATTRIBUTE_SPARSE_FILE) {
                st.flags |= f;
            }
        }
        if wof {
            st.flags |= NodeFlags::COMPRESSED;
        }
        if self.system(e)? {
            st.flags |= NodeFlags::SYSTEM;
        }
        if let Some(r) = r {
            st.cloud = self.cloud(e, r, if has_ea { attributes & !FILE_ATTRIBUTE_HAS_EA } else { attributes });
        }
        st.unix = ea::wsl_unix(eas);
        Ok(st)
    }

    /// The security descriptor of `e`: its own, or `$Secure`'s of its security id.
    fn security_of(&self, e: &FileEntry) -> Result<Option<Security>> {
        if let Some(sd) = own_descriptor(self.volume(), e)? {
            return Ok(Some(Security::Ntfs(sd)));
        }
        let Some(id) = e.std_info.as_ref().and_then(|si| si.security_id) else { return Ok(None) };
        Ok(self.sds()?.descriptor(id).map(|sd| Security::Ntfs(sd.to_vec())))
    }
}

impl NtfsFs {
    /// The [`NodeInfo`] of `node` (entry `e`, reparse point `r`), readers aside: what
    /// `node_info` and `node_infos` give.
    fn info_of(&self, node: NodeId, e: &FileEntry, r: Option<&Reparse>, want: Want) -> Result<NodeInfo> {
        let eas = self.eas(e)?;
        let mut info = NodeInfo::new(self.stat_of(node, e, r, &eas)?);
        info.security = want.then(Want::SECURITY, || self.security_of(e));
        info.link = want.then(Want::LINK, || link_of(r));
        info.streams = want.then(Want::STREAMS, || Ok(streams_of(e, r)));
        info.names = want.then(Want::NAMES, || Ok(names_of(e)));
        info.xattrs = want.then(Want::XATTRS, || {
            eas.into_iter()
                .map(|a| Xattr::new(Name::Bytes(a.name), XattrNs::Other, a.value.len() as u64, || Ok(a.value)))
                .collect()
        });
        Ok(info)
    }

    /// A reader of stream `stream` of `node`, entry `e` with reparse point `r`.
    fn open_entry(
        self: &Arc<Self>,
        node: NodeId,
        e: &FileEntry,
        r: Option<&Reparse>,
        stream: StreamId,
    ) -> Result<Box<dyn FileReader>> {
        if e.is_dir() {
            return Err(Error::invalid_argument(format!("ntfs node {node} is a directory")));
        }
        if e.has_problem() {
            return Err(damaged(e));
        }
        if stream != StreamId::MAIN {
            let s = Self::named_streams(e)
                .find(|(id, _)| *id == stream)
                .map(|(_, s)| s.clone())
                .ok_or_else(|| Error::not_found(format!("ntfs node {node} has no stream {}", stream.get())))?;
            return stream_reader(self, &s, false);
        }
        if let Some(alg) = r.map(crate::format::wof::wof).transpose()?.flatten() {
            let wof = Self::named_streams(e)
                .find(|(_, s)| s.name.to_string_lossy() == WOF_STREAM)
                .map(|(_, s)| s.clone())
                .ok_or_else(|| Error::corrupt(format!("ntfs: WOF file {node} without its {WOF_STREAM} stream")))?;
            let size = e.unnamed_data_size();
            return Ok(Box::new(ChunkedReader::new(Wof::open(self.clone(), wof, alg, size)?)));
        }
        let Some(s) = e.unnamed_data() else { return Ok(Box::new(MemReader::new(Vec::new()))) };
        let cloud = r.is_some_and(|r| reparse::is_cloud(r.tag));
        stream_reader(self, s, cloud)
    }
}

/// Where reparse point `r` points.
fn link_of(r: Option<&Reparse>) -> Result<Option<LinkTarget>> {
    match r {
        Some(r) => Ok(Some(r.link()?.unwrap_or_else(|| LinkTarget::Other { tag: r.tag, data: r.data.clone() }))),
        None => Ok(None),
    }
}

/// The streams of `e` with reparse point `r`: none for a directory, WOF's own left out.
fn streams_of(e: &FileEntry, r: Option<&Reparse>) -> Vec<StreamInfo> {
    if e.is_dir() {
        return Vec::new();
    }
    let wof = r.is_some_and(|r| r.tag == reparse::WOF);
    let mut out = vec![StreamInfo::new(
        StreamId::MAIN,
        None,
        e.unnamed_data_size(),
        e.unnamed_data().map(stream_flags).unwrap_or_default(),
    )];
    for (id, s) in NtfsFs::named_streams(e) {
        if wof && s.name.to_string_lossy() == WOF_STREAM {
            continue;
        }
        out.push(StreamInfo::new(id, Some(Name::Utf16(s.name.0.clone())), s.size(), stream_flags(s)));
    }
    out
}

/// The parent and name of each of `e`'s `$FILE_NAME`s, DOS names left out, each once.
fn names_of(e: &FileEntry) -> Vec<(NodeId, Name)> {
    let mut out: Vec<(NodeId, Name)> = Vec::new();
    for n in e.names.iter().filter(|n| n.namespace != NameSpace::Dos) {
        let item = (NodeId::new(0, n.parent.to_raw()), Name::Utf16(n.name.0.clone()));
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

fn kind_of(e: &FileEntry, r: Option<&Reparse>) -> NodeKind {
    match r {
        Some(r) => kind_of_tag(r.tag, e.is_dir()),
        None if e.is_dir() => NodeKind::Dir,
        None => NodeKind::File,
    }
}

/// The [`NodeFlags`] of a stream's attribute flags.
fn stream_flags(s: &Stream) -> NodeFlags {
    let mut f = NodeFlags::default();
    for (sf, nf) in [
        (attr_flags::COMPRESSED, NodeFlags::COMPRESSED),
        (attr_flags::ENCRYPTED, NodeFlags::ENCRYPTED),
        (attr_flags::SPARSE, NodeFlags::SPARSE),
    ] {
        if s.flags & sf != 0 {
            f |= nf;
        }
    }
    if s.is_resident() {
        f |= NodeFlags::INLINE;
    }
    f
}

impl fs_inspect_core::sealed::Ns for NtfsFs {}

impl Namespace for NtfsFs {
    fn roots(&self) -> Result<Vec<RootInfo>> {
        let root =
            self.volume().entry(system_records::ROOT)?.ok_or_else(|| Error::corrupt("root directory not in use"))?;
        Ok(vec![RootInfo::main(NodeId::new(0, root.frn.to_raw()))])
    }

    fn node_info(&self, node: NodeId, want: Want) -> Result<NodeInfo> {
        let e = self.node(node)?;
        let r = self.reparse(&e)?;
        self.info_of(node, &e, r.as_ref(), want)
    }

    fn node_infos(
        self: Arc<Self>,
        nodes: &[NodeId],
        want: Want,
        f: &mut dyn FnMut(usize, Result<NodeInfo>) -> ControlFlow<()>,
    ) -> Result<()> {
        for (at, chunk) in nodes.chunks(INFO_BATCH).enumerate() {
            // The records of nodes that name one; the others are told apart by `node_info`.
            let records: Vec<u64> = chunk
                .iter()
                .map(|n| Frn::from_raw(n.id))
                .filter(|frn| frn.record < self.volume().record_count())
                .map(|frn| frn.record)
                .collect();
            let mut entries = self.volume().entries(&records)?.into_iter();
            for (i, &node) in chunk.iter().enumerate() {
                let frn = Frn::from_raw(node.id);
                let entry = if frn.record < self.volume().record_count() { entries.next() } else { None };
                let info = match entry {
                    Some(Ok(Some(e))) if node.root == RootId(0) && e.frn.seq == frn.seq => {
                        self.reparse(&e).and_then(|r| {
                            let mut info = self.info_of(node, &e, r.as_ref(), want)?;
                            if want.contains(Want::OPEN) {
                                info.readers = info
                                    .streams_to_open()
                                    .into_iter()
                                    .map(|s| (s, self.open_entry(node, &e, r.as_ref(), s)))
                                    .collect();
                            }
                            Ok(info)
                        })
                    }
                    // Missing, damaged, or a source failure: as `node_info` tells it.
                    _ => self.node_info(node, want).map(|mut info| {
                        if want.contains(Want::OPEN) {
                            info.readers =
                                info.streams_to_open().into_iter().map(|s| (s, self.clone().open(node, s))).collect();
                        }
                        info
                    }),
                };
                let info = match info {
                    Err(e) if e.is_cancelled() => return Err(e),
                    info => info,
                };
                if f(at * INFO_BATCH + i, info).is_break() {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn read_dir(&self, dir: NodeId, f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()> {
        let d = self.dir(dir)?.ok_or_else(|| Error::invalid_argument(format!("ntfs node {dir} is not a directory")))?;
        // Names listed: a damaged index that holds a name twice lists it once. It grows with
        // the directory (one name per entry), the one state of a listing that does.
        let mut seen = HashSet::new();
        self.volume().walk_dir(&d, &mut |e| {
            if e.file_name().is_none_or(|n| n.namespace == NameSpace::Dos) {
                return ControlFlow::Continue(());
            }
            let Some(entry) = Self::dir_entry(&e) else { return ControlFlow::Continue(()) };
            // The root directory indexes its own name, `.`.
            if entry.node == dir {
                return ControlFlow::Continue(());
            }
            let Name::Utf16(units) = &entry.name else { return ControlFlow::Continue(()) };
            if !seen.insert(units.clone()) {
                return ControlFlow::Continue(());
            }
            f(entry)
        })
    }

    fn lookup(&self, dir: NodeId, name: &Name) -> Result<Option<DirEntry>> {
        let Some(d) = self.dir(dir)? else { return Ok(None) };
        let Some(units) = kit::name_utf16(name) else { return Ok(None) };
        let Some(hit) = self.volume().lookup(&d, &units)? else { return Ok(None) };
        // A stale entry (its record freed or reused) names no file: the record's header tells
        // (one record read; its attributes, extension records and reparse data are not). The
        // kind and cloud mark are the index entry's, as a listing gives them.
        if !self.volume().in_use_as(hit.frn)? {
            return Ok(None);
        }
        Ok(Self::dir_entry(&hit))
    }

    fn read_xattr(&self, node: NodeId, name: &Name) -> Result<Option<Vec<u8>>> {
        let e = self.node(node)?;
        let Some(want) = kit::name_bytes(name) else { return Ok(None) };
        Ok(self.eas(&e)?.into_iter().find(|a| a.name.eq_ignore_ascii_case(&want)).map(|a| a.value))
    }

    fn open(self: Arc<Self>, node: NodeId, stream: StreamId) -> Result<Box<dyn FileReader>> {
        let e = self.node(node)?;
        // Only the main stream's reader depends on the reparse point.
        let r = if stream == StreamId::MAIN && !e.is_dir() && !e.has_problem() { self.reparse(&e)? } else { None };
        self.open_entry(node, &e, r.as_ref(), stream)
    }

    fn case_insensitive(&self, _: u64) -> bool {
        true
    }

    fn exclusion_ranges(&self, node: NodeId) -> Result<Vec<ByteRange>> {
        let e = self.node(node)?;
        if e.is_dir() || self.system(&e)? {
            return Ok(Vec::new());
        }
        if e.has_problem() {
            return Err(damaged(&e));
        }
        Ok(clusters_to_ranges(data_clusters(&e), u64::from(self.volume().geometry().cluster_size)))
    }
}

/// The error of a file whose MFT entry is damaged.
fn damaged(e: &FileEntry) -> Error {
    Error::corrupt(format!("ntfs: MFT record {}: its entry is damaged", e.frn.record))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::synth::content::bytes;
    use crate::synth::{EXTEND, Placement, ROOT, SyntheticVolume, VolumeSpec};
    use fs_inspect_core::read::SegmentKind;
    use fs_inspect_core::{DriverContext, ErrorKind, VolumePath, ns};

    fn names(fs: &NtfsFs, dir: NodeId) -> Vec<String> {
        ns::list(fs, dir).unwrap().iter().map(|e| e.name.to_string_lossy()).collect()
    }

    fn at(fs: &NtfsFs, path: &str) -> Option<DirEntry> {
        let root = fs.roots().unwrap()[0].node;
        ns::resolve(fs, root, &VolumePath::parse(path, 64).unwrap()).unwrap()
    }

    fn read_all(fs: &Arc<NtfsFs>, node: NodeId) -> Vec<u8> {
        let r = fs.clone().open(node, StreamId::MAIN).unwrap();
        let mut out = vec![0u8; r.len() as usize];
        r.read_exact_at(0, &mut out).unwrap();
        out
    }

    /// What `node_infos(nodes, want | OPEN)` gives, by index: each info's `Debug` with its
    /// readers taken out, and each reader's stream and bytes (or error).
    #[allow(clippy::type_complexity)]
    fn batch_infos(fs: &Arc<NtfsFs>, nodes: &[NodeId], want: Want) -> Vec<(String, Vec<(StreamId, Result<Vec<u8>>)>)> {
        let mut got: Vec<Option<_>> = nodes.iter().map(|_| None).collect();
        fs.clone()
            .node_infos(nodes, want | Want::OPEN, &mut |i, info| {
                let mut info = info.unwrap();
                let readers = std::mem::take(&mut info.readers)
                    .into_iter()
                    .map(|(s, r)| {
                        (
                            s,
                            r.and_then(|r| {
                                let mut b = vec![0u8; r.len() as usize];
                                r.read_exact_at(0, &mut b).map(|()| b)
                            }),
                        )
                    })
                    .collect();
                assert!(got[i].replace((format!("{info:?}"), readers)).is_none(), "node {i} twice");
                ControlFlow::Continue(())
            })
            .unwrap();
        got.into_iter().map(Option::unwrap).collect()
    }

    /// `node_infos` gives what `node_info` and `open` give node by node (records with extension
    /// records, sparse, resident and empty files, directories), in far fewer reads.
    #[test]
    fn node_infos_read_records_together() {
        use fs_inspect_io::test_util::CountingSource;
        let mut v = SyntheticVolume::format(VolumeSpec { clusters: 16384, ..Default::default() });
        let d = v.create_dir(ROOT, "many");
        for i in 0..150u64 {
            let f = v.create_file(d, &format!("f{i}"), [0, 10, 3000, 20_000][i as usize % 4], i, Placement::FirstFit);
            if i % 10 == 0 {
                for j in 0..8 {
                    v.add_ads(f, &format!("s{j}"), 300, i * 8 + j);
                }
            }
            if i % 7 == 0 {
                v.set_sparse(f);
            }
        }
        v.create_dir(d, "sub");
        let src = CountingSource::new(Arc::new(v.source()));
        let fs = Arc::new(NtfsFs::open(src.clone(), &DriverContext::default()).unwrap());
        let dir = at(&fs, "/many").unwrap().node;
        let nodes: Vec<NodeId> = ns::list(&*fs, dir).unwrap().iter().map(|e| e.node).collect();
        assert!(nodes.len() > 150);
        assert!(nodes.iter().any(|&n| !fs.node(n).unwrap().extension_records.is_empty()));
        // A stale reference and one past `$MFT` are told as `node_info` tells them.
        let stale = Frn::from_raw(nodes[0].id);
        let odd = [NodeId::new(0, Frn::new(stale.record, stale.seq + 1).to_raw()), NodeId::new(0, 1 << 40)];
        for (n, (info, readers)) in nodes.iter().zip(batch_infos(&fs, &nodes, Want::ALL)) {
            assert_eq!(info, format!("{:?}", fs.node_info(*n, Want::ALL).unwrap()));
            let single = fs.node_info(*n, Want::ALL).unwrap().streams_to_open();
            assert_eq!(readers.iter().map(|r| r.0).collect::<Vec<_>>(), single);
            for (s, r) in readers {
                let want = fs.clone().open(*n, s).and_then(|r| {
                    let mut b = vec![0u8; r.len() as usize];
                    r.read_exact_at(0, &mut b).map(|()| b)
                });
                assert_eq!(format!("{r:?}"), format!("{want:?}"));
            }
        }
        let mut errs = Vec::new();
        fs.clone()
            .node_infos(&odd, Want::ALL, &mut |i, r| {
                errs.push((i, r.unwrap_err().kind()));
                ControlFlow::Continue(())
            })
            .unwrap();
        assert_eq!(errs, [(0, ErrorKind::NotFound), (1, ErrorKind::NotFound)]);

        // Reads of records only: no facet that reads more, the readers made and not read.
        let want = Want::LINK | Want::STREAMS | Want::NAMES;
        let before = src.stats();
        for &n in &nodes {
            let info = fs.node_info(n, want).unwrap();
            for s in info.streams_to_open() {
                fs.clone().open(n, s).unwrap();
            }
        }
        let one = src.stats().since(&before).reads;
        let before = src.stats();
        fs.clone()
            .node_infos(&nodes, want | Want::OPEN, &mut |_, info| {
                info.unwrap();
                ControlFlow::Continue(())
            })
            .unwrap();
        let many = src.stats().since(&before).reads;
        assert!(one >= nodes.len() as u64 && many * 4 <= one, "{many} reads together, {one} node by node");
        eprintln!("{} nodes: {one} reads node by node, {many} together", nodes.len());
    }

    /// Browsing a synthetic volume: listings with kinds, case-insensitive lookups, stats,
    /// reads of resident, non-resident, sparse and partly valid data; metafiles are listed but
    /// `SYSTEM`; stale references and wrong kinds are refused.
    #[test]
    fn browse_a_synthetic_volume() {
        let mut v = SyntheticVolume::format(VolumeSpec { clusters: 4096, ..Default::default() });
        let d = v.create_dir(ROOT, "dir");
        let a = v.create_file(d, "a.bin", 100_000, 1, Placement::MaxRun(3));
        let small = v.create_file(ROOT, "small.txt", 10, 2, Placement::FirstFit);
        let sparse = v.create_file(ROOT, "sparse.bin", 64 << 10, 3, Placement::FirstFit);
        v.set_sparse(sparse);
        v.zero_data(sparse, 16 << 10, 32 << 10);
        let grown = v.create_file(ROOT, "grown.bin", 10_000, 4, Placement::FirstFit);
        v.truncate(grown, 40_000, Placement::FirstFit);
        let rm = v.create_dir(EXTEND, "$RmMetadata");
        v.create_file(rm, "$Repair", 5000, 5, Placement::FirstFit);
        let fs = Arc::new(NtfsFs::open(Arc::new(v.source()), &DriverContext::default()).unwrap());

        let root = fs.roots().unwrap()[0].node;
        assert_eq!(Frn::from_raw(root.id).record, ROOT);
        assert!(fs.case_insensitive(0));
        let listed = names(&fs, root);
        for n in ["$MFT", "$Extend", "dir", "small.txt", "sparse.bin"] {
            assert!(listed.iter().any(|l| l == n), "{n} not in {listed:?}");
        }
        assert_eq!(names(&fs, at(&fs, "/dir").unwrap().node), ["a.bin"]);
        let kinds = ns::list(&*fs, root).unwrap();
        let kind = |n: &str| kinds.iter().find(|e| e.name.eq_str(n)).unwrap().kind;
        assert_eq!((kind("dir"), kind("small.txt")), (Some(NodeKind::Dir), Some(NodeKind::File)));

        // Lookups without case; a lookup in a file finds nothing, a listing of one fails.
        let fa = at(&fs, "/DIR/A.BIN").unwrap();
        assert_eq!((Frn::from_raw(fa.node.id).record, fa.kind), (a, Some(NodeKind::File)));
        assert!(at(&fs, "/dir/a.bin/x").is_none() && at(&fs, "/nope").is_none());
        let err = ns::list(&*fs, fa.node).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidArgument);

        let st = ns::stat(&*fs, fa.node).unwrap();
        assert_eq!((st.kind, st.size, st.nlink), (NodeKind::File, 100_000, Some(1)));
        assert!(st.times.modified.is_some() && st.windows.is_some_and(|w| w.security_id == Some(0x100)));
        assert!(!st.flags.contains(NodeFlags::SYSTEM));
        assert_eq!(read_all(&fs, fa.node), bytes(1, 100_000));
        let ranges = fs.exclusion_ranges(fa.node).unwrap();
        assert_eq!(ranges.iter().map(|r| r.length).sum::<u64>(), 100_000u64.div_ceil(4096) * 4096);

        let fsmall = at(&fs, "/small.txt").unwrap().node;
        assert!(ns::stat(&*fs, fsmall).unwrap().flags.contains(NodeFlags::INLINE));
        assert_eq!(read_all(&fs, fsmall), bytes(2, 10));
        assert_eq!(Frn::from_raw(fsmall.id).record, small);

        let fsparse = at(&fs, "/sparse.bin").unwrap().node;
        assert!(ns::stat(&*fs, fsparse).unwrap().flags.contains(NodeFlags::SPARSE));
        let mut want = bytes(3, 64 << 10);
        want[16 << 10..48 << 10].fill(0);
        assert_eq!(read_all(&fs, fsparse), want);
        let segs = fs.clone().open(fsparse, StreamId::MAIN).unwrap().segments().unwrap();
        assert!(segs.iter().any(|s| s.kind == SegmentKind::Hole), "{segs:?}");

        let fgrown = at(&fs, "/grown.bin").unwrap().node;
        let mut want = bytes(4, 10_000);
        want.resize(40_000, 0);
        assert_eq!(read_all(&fs, fgrown), want);
        let segs = fs.clone().open(fgrown, StreamId::MAIN).unwrap().segments().unwrap();
        assert!(matches!(segs.last().unwrap().kind, SegmentKind::Zero { physical: Some(_) }), "{segs:?}");

        // Metafiles and the `$Extend` tree (its directories too): statable, SYSTEM, never
        // excluded; a directory is not opened.
        for p in ["/$MFT", "/$Bitmap", "/$Extend/$RmMetadata/$Repair", "/$Extend", "/$Extend/$RmMetadata"] {
            let n = at(&fs, p).unwrap().node;
            assert!(ns::stat(&*fs, n).unwrap().flags.contains(NodeFlags::SYSTEM), "{p}");
            assert!(fs.exclusion_ranges(n).unwrap().is_empty(), "{p}");
        }
        for p in ["/$Extend", "/$Extend/$RmMetadata", "/dir"] {
            let n = at(&fs, p).unwrap().node;
            assert_eq!(fs.clone().open(n, StreamId::MAIN).err().unwrap().kind(), ErrorKind::InvalidArgument);
        }
        assert!(!ns::stat(&*fs, at(&fs, "/dir").unwrap().node).unwrap().flags.contains(NodeFlags::SYSTEM));
        assert!(!ns::stat(&*fs, root).unwrap().flags.contains(NodeFlags::SYSTEM));
        let roots = ns::path_roots(&*fs).unwrap();
        assert!(ns::find_files(&*fs, &roots, &VolumePath::parse("/$MFT", 8).unwrap()).unwrap().is_empty());

        // A reference with another sequence number names nothing.
        let stale = NodeId::new(0, Frn::new(a, Frn::from_raw(fa.node.id).seq.wrapping_add(1)).to_raw());
        assert_eq!(ns::stat(&*fs, stale).unwrap_err().kind(), ErrorKind::NotFound);
        assert_eq!(ns::stat(&*fs, NodeId::new(1, fa.node.id)).unwrap_err().kind(), ErrorKind::NotFound);

        // A record that does not parse is damaged, not missing.
        let mut img = v.image.clone();
        let at = v.mft_runs[0].lcn().unwrap() * u64::from(v.spec.cluster_size) + small * u64::from(v.spec.record_size);
        img[at as usize..at as usize + 4].copy_from_slice(b"BAAD");
        let bad = NtfsFs::open(Arc::new(fs_inspect_io::MemSource::new(img)), &DriverContext::default()).unwrap();
        assert_eq!(ns::stat(&bad, fsmall).unwrap_err().kind(), ErrorKind::Corrupt);
    }

    /// A lookup reads the index blocks down to the name and the found record's header, no
    /// more; it gives the kind a listing gives; a stale entry (record reused) is not found;
    /// a listing that breaks reads only the blocks of its first entries.
    #[test]
    fn lookups_read_the_index_and_one_record() {
        use fs_inspect_io::test_util::CountingSource;
        let mut v = SyntheticVolume::format(VolumeSpec { clusters: 32768, ..Default::default() });
        let d = v.create_dir(ROOT, "big");
        v.batch(|v| {
            for i in 0..3000u64 {
                v.create_file(d, &format!("file-name-number-{i:06}"), 0, i, Placement::FirstFit);
            }
        });
        let gone = v.create_file(d, "gone.txt", 0, 1, Placement::FirstFit);
        v.create_dir(d, "sub");
        let src = CountingSource::new(Arc::new(v.source()));
        let fs = Arc::new(NtfsFs::open(src.clone(), &DriverContext::default()).unwrap());
        let dir = at(&fs, "/big").unwrap().node;
        let before = src.stats();
        let all = ns::list(&*fs, dir).unwrap();
        let full = src.stats().since(&before).reads;
        let before = src.stats();
        fs.read_dir(dir, &mut |_| ControlFlow::Break(())).unwrap();
        let first = src.stats().since(&before).reads;
        assert_eq!(all.len(), 3002);
        assert_eq!(ns::list(&*fs, dir).unwrap(), all);
        let before = src.stats();
        for e in &all {
            assert_eq!(fs.lookup(dir, &e.name).unwrap().as_ref(), Some(e));
        }
        let per = src.stats().since(&before).reads as f64 / all.len() as f64;
        eprintln!("{} entries: {full} reads to list, {first} to the first, {per:.2} per lookup", all.len());
        // The directory's record (its index root), two levels of blocks, the found record. A
        // listing reads the index a level at a time, so stopping early reads no less.
        assert!(per <= 4.0 && first <= full && full <= 4, "{per} {first} {full}");

        // The entry left behind by a record freed and reused: in the index, not found.
        let gone_seq = Frn::from_raw(fs.lookup(dir, &Name::new("gone.txt")).unwrap().unwrap().node.id).seq;
        let mut img = v.image.clone();
        let rs = u64::from(v.spec.record_size);
        let at_rec = crate::format::volume::map_stream_bytes(&v.mft_runs, v.spec.cluster_size, gone * rs, rs).unwrap()
            [0]
        .offset as usize;
        img[at_rec + 0x10..at_rec + 0x12].copy_from_slice(&gone_seq.wrapping_add(1).to_le_bytes());
        let reused = NtfsFs::open(Arc::new(fs_inspect_io::MemSource::new(img)), &DriverContext::default()).unwrap();
        assert!(reused.lookup(dir, &Name::new("gone.txt")).unwrap().is_none());
        assert!(reused.lookup(dir, &Name::new("SUB")).unwrap().is_some_and(|e| e.kind == Some(NodeKind::Dir)));
    }
}
