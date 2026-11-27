//! `FileEntry`: a base record merged with its extension records.

use crate::format::attr::{
    AttrListEntry, AttrType, FileName, Frn, NonResidentHeader, RawAttrBody, RawAttribute, StdInfo, parse_attr_list,
};
use crate::format::name::NtfsName;
use crate::format::record::{ParsedRecord, header_flags};
use crate::format::runlist::Run;
use fs_inspect_core::Limits;
use smallvec::SmallVec;
use std::collections::{HashMap, HashSet};

/// [`FileEntry::flags`]: the first four are the record header's flags, the rest what merging
/// the records found.
pub mod entry_flags {
    pub const IN_USE: u16 = 0x0001;
    pub const DIRECTORY: u16 = 0x0002;
    pub const EXTEND: u16 = 0x0004;
    pub const VIEW_INDEX: u16 = 0x0008;
    /// The base record has an `$ATTRIBUTE_LIST`.
    pub const HAS_ATTR_LIST: u16 = 0x0010;
    /// A record of the file failed its fixup check.
    pub const TORN: u16 = 0x0020;
    /// An attribute, runlist, attribute list or extension record could not be parsed or read.
    pub const PARSE_ERROR: u16 = 0x0040;
    /// The fragments of an attribute leave a gap in its VCNs.
    pub const ATTR_LIST_GAP: u16 = 0x0080;
    /// An extension record does not name this file as its base.
    pub const ORPHAN_EXTENSION: u16 = 0x0100;
}

/// What kind of problem merging a file's records found ([`Diagnostic`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiagCode {
    BadRecord,
    TornRecord,
    AttributeParse,
    Runlist,
    AttrListRead,
    AttrListParse,
    AttrListGap,
    OrphanExtension,
    MissingExtension,
    MissingAttribute,
    StdInfoParse,
    FileNameParse,
}

/// A problem found while merging a file's records, kept on its [`FileEntry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: DiagCode,
    pub detail: String,
}

impl Diagnostic {
    pub fn new(code: DiagCode, detail: impl Into<String>) -> Self {
        Diagnostic { code, detail: detail.into() }
    }
}

/// The value of an attribute: in the record, or in clusters (sizes in bytes; `initialized` is
/// the valid data length).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamBody {
    Resident { data: Vec<u8> },
    NonResident { allocated: u64, size: u64, initialized: u64, compression_unit: u8, runs: Vec<Run> },
}

/// One attribute of a file other than `$STANDARD_INFORMATION`, `$FILE_NAME` and
/// `$ATTRIBUTE_LIST`, with all fragments merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stream {
    pub kind: AttrType,
    pub name: NtfsName,
    pub flags: u16,
    pub body: StreamBody,
    /// The runlist of at least one fragment could not be decoded; `runs` holds only the
    /// fragments that could.
    pub runlist_error: bool,
}

impl Stream {
    pub fn is_resident(&self) -> bool {
        matches!(self.body, StreamBody::Resident { .. })
    }
    pub fn runs(&self) -> &[Run] {
        match &self.body {
            StreamBody::NonResident { runs, .. } => runs,
            StreamBody::Resident { .. } => &[],
        }
    }
    pub fn size(&self) -> u64 {
        match &self.body {
            StreamBody::Resident { data } => data.len() as u64,
            StreamBody::NonResident { size, .. } => *size,
        }
    }
    /// Bytes the stream holds on the volume (a resident one: its value).
    pub fn allocated(&self) -> u64 {
        match &self.body {
            StreamBody::Resident { data } => data.len() as u64,
            StreamBody::NonResident { allocated, .. } => *allocated,
        }
    }
    pub fn mapped_extents(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.runs().iter().filter_map(|r| r.lcn().map(|l| (l, r.len())))
    }
}

/// A file's `$ATTRIBUTE_LIST`: its bytes, and its runs when it is non-resident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrListInfo {
    pub data: Vec<u8>,
    /// Runs of a non-resident attribute list.
    pub runs: Option<Vec<Run>>,
    pub entry_count: usize,
}

/// A file: its base record merged with its extension records (`entry_flags` says what was
/// found doing so).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub frn: Frn,
    pub flags: u16,
    pub link_count: u16,
    pub std_info: Option<StdInfo>,
    pub names: SmallVec<[FileName; 2]>,
    pub streams: Vec<Stream>,
    pub attr_list: Option<AttrListInfo>,
    pub extension_records: SmallVec<[u64; 4]>,
    /// Problems found while merging; kept on the entry, not reported to
    /// [`fs_inspect_core::Diagnostics`].
    pub diagnostics: SmallVec<[Diagnostic; 2]>,
}

impl FileEntry {
    pub fn is_dir(&self) -> bool {
        self.flags & entry_flags::DIRECTORY != 0
    }
    /// The entry cannot be trusted whole: a torn record, a parse error, an attribute-list gap,
    /// an orphan extension record or a runlist that does not decode.
    pub fn has_problem(&self) -> bool {
        self.flags
            & (entry_flags::TORN
                | entry_flags::PARSE_ERROR
                | entry_flags::ATTR_LIST_GAP
                | entry_flags::ORPHAN_EXTENSION)
            != 0
            || self.streams.iter().any(|s| s.runlist_error)
    }
    pub fn stream(&self, kind: AttrType, name: &[u16]) -> Option<&Stream> {
        self.streams.iter().find(|s| s.kind == kind && s.name.units() == name)
    }
    pub fn unnamed_data(&self) -> Option<&Stream> {
        self.stream(AttrType::DATA, &[])
    }
    pub fn unnamed_data_size(&self) -> u64 {
        self.unnamed_data().map(|s| s.size()).unwrap_or(0)
    }
    /// All mapped extents of every non-resident attribute, including a non-resident
    /// attribute list.
    pub fn all_extents(&self) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self.streams.iter().flat_map(|s| s.mapped_extents()).collect();
        if let Some(runs) = self.attr_list.as_ref().and_then(|a| a.runs.as_ref()) {
            v.extend(runs.iter().filter_map(|r| r.lcn().map(|l| (l, r.len()))));
        }
        v
    }
    /// Preferred name for path building
    /// ([`Namespace::path_priority`](crate::format::Namespace::path_priority)).
    pub fn primary_name(&self) -> Option<&FileName> {
        self.names.iter().min_by_key(|n| n.namespace.path_priority())
    }
}

/// Assemble a [`FileEntry`] from a base record.
///
/// * `attr_list_data`: content of a non-resident `$ATTRIBUTE_LIST` (read by the caller);
///   ignored when the list is resident.
/// * `fetch`: returns an extension record by number (already parsed).
pub fn build_entry(
    base: &ParsedRecord,
    attr_list_data: Option<Result<Vec<u8>, String>>,
    fetch: &mut dyn FnMut(u64) -> Option<ParsedRecord>,
    limits: &Limits,
) -> FileEntry {
    let mut b = Builder { flags: record_flags(base.header.flags), ..Builder::default() };
    b.note_record(base);
    b.frags.extend(
        base.attributes.iter().filter(|a| a.kind != AttrType::ATTRIBUTE_LIST).map(|a| (base.number, a.clone())),
    );
    let attr_list = base
        .attributes
        .iter()
        .find(|a| a.kind == AttrType::ATTRIBUTE_LIST)
        .map(|al| b.attribute_list(base, al, attr_list_data, fetch, limits));
    let Builder { mut flags, mut diags, frags, mut extension_records } = b;
    let mut attrs = Attributes::default();
    attrs.sort(frags, &mut flags, &mut diags);
    let Attributes { std_info, names, mut streams, groups } = attrs;
    for ((kind, name), parts) in groups {
        streams.push(merge_fragments(kind, name, parts, &mut flags, &mut diags));
    }
    streams.sort_by(|a, b| (a.kind, &a.name).cmp(&(b.kind, &b.name)));
    extension_records.sort_unstable();
    FileEntry {
        frn: base.frn(),
        flags,
        link_count: base.header.link_count,
        std_info,
        names,
        streams,
        attr_list,
        extension_records,
        diagnostics: diags,
    }
}

/// The entry flags a record header's flags carry over.
fn record_flags(h: u16) -> u16 {
    [
        (header_flags::IN_USE, entry_flags::IN_USE),
        (header_flags::DIRECTORY, entry_flags::DIRECTORY),
        (header_flags::EXTEND, entry_flags::EXTEND),
        (header_flags::VIEW_INDEX, entry_flags::VIEW_INDEX),
    ]
    .iter()
    .filter(|(hf, _)| h & hf != 0)
    .fold(0, |f, (_, ef)| f | ef)
}

/// Record a problem: its entry flag and its diagnostic.
fn problem(
    flags: &mut u16,
    diags: &mut SmallVec<[Diagnostic; 2]>,
    flag: u16,
    code: DiagCode,
    detail: impl Into<String>,
) {
    *flags |= flag;
    diags.push(Diagnostic::new(code, detail));
}

/// An entry being assembled: its flags and diagnostics so far, the attribute fragments found
/// (with the record each is in) and the extension records followed.
#[derive(Default)]
struct Builder {
    flags: u16,
    diags: SmallVec<[Diagnostic; 2]>,
    frags: Vec<(u64, RawAttribute)>,
    extension_records: SmallVec<[u64; 4]>,
}

impl Builder {
    fn problem(&mut self, flag: u16, code: DiagCode, detail: impl Into<String>) {
        problem(&mut self.flags, &mut self.diags, flag, code, detail);
    }

    /// A torn record, or one whose attributes did not all parse.
    fn note_record(&mut self, rec: &ParsedRecord) {
        if rec.torn {
            self.problem(entry_flags::TORN, DiagCode::TornRecord, format!("record {}", rec.number));
        }
        if let Some(e) = &rec.attr_error {
            self.problem(entry_flags::PARSE_ERROR, DiagCode::AttributeParse, format!("record {}: {e}", rec.number));
        }
    }

    /// The attribute list `al` of `base`: its content (`attr_list_data` when non-resident),
    /// and the fragments of the extension records it names.
    fn attribute_list(
        &mut self,
        base: &ParsedRecord,
        al: &RawAttribute,
        attr_list_data: Option<Result<Vec<u8>, String>>,
        fetch: &mut dyn FnMut(u64) -> Option<ParsedRecord>,
        limits: &Limits,
    ) -> AttrListInfo {
        self.flags |= entry_flags::HAS_ATTR_LIST;
        let (data, runs) = match &al.body {
            RawAttrBody::Resident { data, .. } => (Ok(data.clone()), None),
            RawAttrBody::NonResident(nr) => {
                if nr.runs.is_err() {
                    self.problem(entry_flags::PARSE_ERROR, DiagCode::Runlist, "attribute list runlist");
                }
                let runs = nr.runs.clone().unwrap_or_default();
                (attr_list_data.unwrap_or_else(|| Err("not read".into())), Some(runs))
            }
        };
        let data = match data {
            Ok(d) => d,
            Err(e) => {
                self.problem(entry_flags::PARSE_ERROR, DiagCode::AttrListRead, e);
                return AttrListInfo { data: Vec::new(), runs, entry_count: 0 };
            }
        };
        let entries = parse_attr_list(&data, limits.max_attr_list_entries).unwrap_or_else(|e| {
            self.problem(entry_flags::PARSE_ERROR, DiagCode::AttrListParse, e.to_string());
            Vec::new()
        });
        self.follow(base, &entries, fetch);
        AttrListInfo { data, runs, entry_count: entries.len() }
    }

    /// Take the attributes the list `entries` places in extension records of `base`.
    fn follow(
        &mut self,
        base: &ParsedRecord,
        entries: &[AttrListEntry],
        fetch: &mut dyn FnMut(u64) -> Option<ParsedRecord>,
    ) {
        let mut cache: HashMap<u64, Option<ParsedRecord>> = HashMap::new();
        let mut seen: HashSet<(u64, u16, u32)> = self.frags.iter().map(|(r, a)| (*r, a.id, a.kind.0)).collect();
        for e in entries.iter().filter(|e| e.segment.record != base.number) {
            let rec = cache.entry(e.segment.record).or_insert_with(|| fetch(e.segment.record));
            let Some(rec) = rec.as_ref() else {
                self.problem(
                    entry_flags::PARSE_ERROR,
                    DiagCode::MissingExtension,
                    format!("record {}", e.segment.record),
                );
                continue;
            };
            if !(rec.header.in_use() && rec.header.base_record == base.frn() && rec.header.seq == e.segment.seq) {
                let detail = format!(
                    "record {}-{} (base {:?}, in_use {})",
                    rec.number,
                    rec.header.seq,
                    rec.header.base_record,
                    rec.header.in_use()
                );
                self.problem(entry_flags::ORPHAN_EXTENSION, DiagCode::OrphanExtension, detail);
                continue;
            }
            if !self.extension_records.contains(&rec.number) {
                self.extension_records.push(rec.number);
                self.note_record(rec);
            }
            match rec.find(e.kind, e.attr_id) {
                Some(a) if seen.insert((rec.number, a.id, a.kind.0)) => self.frags.push((rec.number, a.clone())),
                Some(_) => {}
                None => self.problem(
                    entry_flags::PARSE_ERROR,
                    DiagCode::MissingAttribute,
                    format!("{:?} id {} in record {}", e.kind, e.attr_id, rec.number),
                ),
            }
        }
    }
}

/// A non-resident fragment: its attribute flags and header.
type Fragment = (u16, NonResidentHeader);

/// The fragments of an entry sorted out: its standard information, names, resident streams,
/// and the non-resident fragments grouped by (type, name).
#[derive(Default)]
struct Attributes {
    std_info: Option<StdInfo>,
    names: SmallVec<[FileName; 2]>,
    streams: Vec<Stream>,
    groups: Vec<((AttrType, NtfsName), Vec<Fragment>)>,
}

impl Attributes {
    fn sort(&mut self, frags: Vec<(u64, RawAttribute)>, flags: &mut u16, diags: &mut SmallVec<[Diagnostic; 2]>) {
        let mut bad = |code, detail: String| problem(flags, diags, entry_flags::PARSE_ERROR, code, detail);
        for (_, a) in frags {
            match a.kind {
                AttrType::STANDARD_INFORMATION => match a.resident_data().map(StdInfo::parse) {
                    Some(Ok(si)) if self.std_info.is_none() => self.std_info = Some(si),
                    Some(Ok(_)) => {}
                    Some(Err(e)) => bad(DiagCode::StdInfoParse, e.to_string()),
                    None => bad(DiagCode::StdInfoParse, "non-resident $STANDARD_INFORMATION".into()),
                },
                AttrType::FILE_NAME => match a.resident_data().map(FileName::parse) {
                    Some(Ok(f)) => self.names.push(f),
                    Some(Err(e)) => bad(DiagCode::FileNameParse, e.to_string()),
                    None => bad(DiagCode::FileNameParse, "non-resident $FILE_NAME".into()),
                },
                _ => match a.body {
                    RawAttrBody::Resident { data, .. } => self.streams.push(Stream {
                        kind: a.kind,
                        name: a.name,
                        flags: a.flags,
                        body: StreamBody::Resident { data },
                        runlist_error: false,
                    }),
                    RawAttrBody::NonResident(nr) => {
                        let key = (a.kind, a.name);
                        match self.groups.iter_mut().find(|(k, _)| *k == key) {
                            Some((_, v)) => v.push((a.flags, nr)),
                            None => self.groups.push((key, vec![(a.flags, nr)])),
                        }
                    }
                },
            }
        }
    }
}

/// The non-resident stream `kind:name` from its fragments: their runs concatenated in VCN
/// order, the sizes of the first; a gap or an overlap between them is reported.
fn merge_fragments(
    kind: AttrType,
    name: NtfsName,
    mut parts: Vec<Fragment>,
    flags: &mut u16,
    diags: &mut SmallVec<[Diagnostic; 2]>,
) -> Stream {
    parts.sort_by_key(|(_, nr)| nr.lowest_vcn);
    let mut runs: Vec<Run> = Vec::new();
    let mut runlist_error = false;
    let mut expected_vcn = 0u64;
    let mut gap = false;
    let mut sizes = None;
    let mut stream_flags = 0u16;
    for (part_flags, nr) in &parts {
        if nr.lowest_vcn == 0 && sizes.is_none() {
            sizes = Some((nr.allocated, nr.size, nr.initialized, nr.compression_unit));
            stream_flags = *part_flags;
        }
        if nr.lowest_vcn < expected_vcn {
            // Fragments overlap: concatenated, the runs would not be in VCN order, which
            // every reader of a runlist relies on. Not usable.
            runlist_error = true;
            diags.push(Diagnostic::new(
                DiagCode::Runlist,
                format!("{:?}:{} fragment at vcn {} overlaps vcn {expected_vcn}", kind, name, nr.lowest_vcn),
            ));
        } else if nr.lowest_vcn != expected_vcn {
            gap = true;
        }
        match &nr.runs {
            Ok(r) => runs.extend_from_slice(r),
            Err(e) => {
                runlist_error = true;
                diags.push(Diagnostic::new(
                    DiagCode::Runlist,
                    format!("{:?}:{} vcn {}: {e}", kind, name, nr.lowest_vcn),
                ));
            }
        }
        // Never backwards: a fragment inside an earlier one must not make the next
        // fragment look like a gap.
        expected_vcn = expected_vcn.max((nr.highest_vcn + 1).max(0) as u64);
    }
    let (allocated, size, initialized, compression_unit) = sizes.unwrap_or_else(|| {
        gap = true;
        (0, 0, 0, 0)
    });
    // The runs must reach the end of the last fragment.
    if !runlist_error && allocated > 0 && runs.last().map_or(0, Run::end_vcn) != expected_vcn {
        gap = true;
    }
    if gap {
        problem(flags, diags, entry_flags::ATTR_LIST_GAP, DiagCode::AttrListGap, format!("{:?}:{}", kind, name));
    }
    if runlist_error {
        *flags |= entry_flags::PARSE_ERROR;
    }
    Stream {
        kind,
        name,
        flags: stream_flags,
        body: StreamBody::NonResident { allocated, size, initialized, compression_unit, runs },
        runlist_error,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::format::attr::{AttrListEntry, encode_attr_list};
    use crate::format::name::Namespace;
    use crate::format::record::{
        NonResidentSpec, RecordBuilder, RecordParse, encode_non_resident, encode_resident, parse_record,
    };

    fn rec(number: u64, seq: u16, base: Frn, attrs: Vec<Vec<u8>>) -> ParsedRecord {
        let rb = RecordBuilder {
            seq,
            link_count: 1,
            flags: header_flags::IN_USE,
            base_record: base,
            lsn: 0,
            usn: 1,
            attributes: attrs,
            next_attr_id: 10,
        };
        let mut b = rb.encode(number, 1024).unwrap();
        match parse_record(number, &mut b, 1 << 20, &Limits::default()) {
            RecordParse::Ok(r) => r,
            other => panic!("{other:?}"),
        }
    }

    fn data_frag(id: u16, lo: u64, hi: i64, lcn: u64, total: u64) -> Vec<u8> {
        encode_non_resident(&NonResidentSpec {
            kind: AttrType::DATA,
            name: &[],
            id,
            flags: 0,
            lowest_vcn: lo,
            highest_vcn: hi,
            compression_unit: 0,
            allocated: if lo == 0 { total * 4096 } else { 0 },
            size: if lo == 0 { total * 4096 } else { 0 },
            initialized: if lo == 0 { total * 4096 } else { 0 },
            compressed_size: None,
            runs: &[Run::Mapped { vcn: lo, lcn, len: (hi + 1) as u64 - lo }],
        })
    }

    fn fname(name: &str) -> Vec<u8> {
        let f = FileName {
            parent: Frn::new(5, 5),
            created: 0,
            modified: 0,
            mft_changed: 0,
            accessed: 0,
            allocated: 0,
            size: 0,
            attributes: 0,
            reparse_or_ea: 0,
            namespace: Namespace::Win32,
            name: name.into(),
        };
        encode_resident(AttrType::FILE_NAME, &[], 1, 0, &f.encode(), true)
    }

    #[test]
    fn merges_fragments_from_extensions() {
        let base_frn = Frn::new(40, 3);
        let list = encode_attr_list(&[
            AttrListEntry {
                kind: AttrType::STANDARD_INFORMATION,
                name: NtfsName::default(),
                starting_vcn: 0,
                segment: base_frn,
                attr_id: 0,
            },
            AttrListEntry {
                kind: AttrType::FILE_NAME,
                name: NtfsName::default(),
                starting_vcn: 0,
                segment: base_frn,
                attr_id: 1,
            },
            AttrListEntry {
                kind: AttrType::DATA,
                name: NtfsName::default(),
                starting_vcn: 0,
                segment: Frn::new(41, 1),
                attr_id: 0,
            },
            AttrListEntry {
                kind: AttrType::DATA,
                name: NtfsName::default(),
                starting_vcn: 10,
                segment: Frn::new(42, 1),
                attr_id: 0,
            },
        ]);
        let base = rec(
            40,
            3,
            Frn::default(),
            vec![
                encode_resident(AttrType::STANDARD_INFORMATION, &[], 0, 0, &StdInfo::default().encode(), false),
                encode_resident(AttrType::ATTRIBUTE_LIST, &[], 2, 0, &list, false),
                fname("big.bin"),
            ],
        );
        let e1 = rec(41, 1, base_frn, vec![data_frag(0, 0, 9, 1000, 20)]);
        let e2 = rec(42, 1, base_frn, vec![data_frag(0, 10, 19, 5000, 20)]);
        let mut fetch = |n: u64| match n {
            41 => Some(e1.clone()),
            42 => Some(e2.clone()),
            _ => None,
        };
        let entry = build_entry(&base, None, &mut fetch, &Limits::default());
        assert_eq!(entry.diagnostics.len(), 0, "{:?}", entry.diagnostics);
        assert!(!entry.has_problem());
        assert_eq!(entry.extension_records.as_slice(), &[41, 42]);
        let d = entry.unnamed_data().unwrap();
        assert_eq!(
            d.runs(),
            &[Run::Mapped { vcn: 0, lcn: 1000, len: 10 }, Run::Mapped { vcn: 10, lcn: 5000, len: 10 }]
        );
        assert_eq!(d.size(), 20 * 4096);
        assert_eq!(entry.names[0].name, "big.bin".into());
    }

    #[test]
    fn detects_orphans_gaps_and_missing() {
        let base_frn = Frn::new(40, 3);
        let list = encode_attr_list(&[
            AttrListEntry {
                kind: AttrType::DATA,
                name: NtfsName::default(),
                starting_vcn: 0,
                segment: Frn::new(41, 1),
                attr_id: 0,
            },
            AttrListEntry {
                kind: AttrType::DATA,
                name: NtfsName::default(),
                starting_vcn: 12,
                segment: Frn::new(42, 1),
                attr_id: 0,
            },
            AttrListEntry {
                kind: AttrType::DATA,
                name: NtfsName::default(),
                starting_vcn: 30,
                segment: Frn::new(43, 1),
                attr_id: 0,
            },
        ]);
        let base = rec(40, 3, Frn::default(), vec![encode_resident(AttrType::ATTRIBUTE_LIST, &[], 2, 0, &list, false)]);
        let e1 = rec(41, 1, base_frn, vec![data_frag(0, 0, 9, 1000, 20)]);
        // gap: starts at 12 instead of 10
        let e2 = rec(42, 1, base_frn, vec![data_frag(0, 12, 19, 5000, 20)]);
        let mut fetch = |n: u64| match n {
            41 => Some(e1.clone()),
            42 => Some(e2.clone()),
            _ => None,
        };
        let entry = build_entry(&base, None, &mut fetch, &Limits::default());
        assert!(entry.flags & entry_flags::ATTR_LIST_GAP != 0);
        assert!(entry.flags & entry_flags::PARSE_ERROR != 0); // record 43 missing
        assert!(entry.has_problem());

        // extension pointing at another base
        let list = encode_attr_list(&[AttrListEntry {
            kind: AttrType::DATA,
            name: NtfsName::default(),
            starting_vcn: 0,
            segment: Frn::new(41, 1),
            attr_id: 0,
        }]);
        let base = rec(40, 3, Frn::default(), vec![encode_resident(AttrType::ATTRIBUTE_LIST, &[], 2, 0, &list, false)]);
        let wrong = rec(41, 1, Frn::new(99, 1), vec![data_frag(0, 0, 9, 1000, 10)]);
        let entry = build_entry(&base, None, &mut |_| Some(wrong.clone()), &Limits::default());
        assert!(entry.flags & entry_flags::ORPHAN_EXTENSION != 0);
        assert!(entry.unnamed_data().is_none());

        // sequence mismatch
        let stale = rec(41, 2, base_frn, vec![data_frag(0, 0, 9, 1000, 10)]);
        let entry = build_entry(&base, None, &mut |_| Some(stale.clone()), &Limits::default());
        assert!(entry.flags & entry_flags::ORPHAN_EXTENSION != 0);
    }

    /// Fragments whose VCN ranges overlap cannot form one runlist in VCN order: the stream is
    /// marked damaged (readers of $Bitmap refuse it rather than read zeros).
    #[test]
    fn overlapping_fragments_are_a_runlist_error() {
        let base_frn = Frn::new(40, 3);
        let list = encode_attr_list(&[
            AttrListEntry {
                kind: AttrType::DATA,
                name: NtfsName::default(),
                starting_vcn: 0,
                segment: Frn::new(41, 1),
                attr_id: 0,
            },
            AttrListEntry {
                kind: AttrType::DATA,
                name: NtfsName::default(),
                starting_vcn: 50,
                segment: Frn::new(42, 1),
                attr_id: 0,
            },
            AttrListEntry {
                kind: AttrType::DATA,
                name: NtfsName::default(),
                starting_vcn: 300,
                segment: Frn::new(43, 1),
                attr_id: 0,
            },
        ]);
        let base = rec(40, 3, Frn::default(), vec![encode_resident(AttrType::ATTRIBUTE_LIST, &[], 2, 0, &list, false)]);
        let e1 = rec(41, 1, base_frn, vec![data_frag(0, 0, 299, 1000, 400)]);
        let e2 = rec(42, 1, base_frn, vec![data_frag(0, 50, 99, 5000, 400)]);
        let e3 = rec(43, 1, base_frn, vec![data_frag(0, 300, 399, 7000, 400)]);
        let mut fetch = |n: u64| match n {
            41 => Some(e1.clone()),
            42 => Some(e2.clone()),
            43 => Some(e3.clone()),
            _ => None,
        };
        let entry = build_entry(&base, None, &mut fetch, &Limits::default());
        assert!(entry.unnamed_data().unwrap().runlist_error);
        assert!(entry.has_problem());
        // The fragment after the overlap follows the end of the first one: no gap reported.
        assert!(entry.flags & entry_flags::ATTR_LIST_GAP == 0, "{:?}", entry.diagnostics);
    }

    #[test]
    fn non_resident_attr_list_needs_data() {
        let base = rec(
            40,
            3,
            Frn::default(),
            vec![encode_non_resident(&NonResidentSpec {
                kind: AttrType::ATTRIBUTE_LIST,
                name: &[],
                id: 2,
                flags: 0,
                lowest_vcn: 0,
                highest_vcn: 0,
                compression_unit: 0,
                allocated: 4096,
                size: 0x20,
                initialized: 0x20,
                compressed_size: None,
                runs: &[Run::Mapped { vcn: 0, lcn: 77, len: 1 }],
            })],
        );
        let entry = build_entry(&base, None, &mut |_| None, &Limits::default());
        assert!(entry.flags & entry_flags::PARSE_ERROR != 0);
        assert_eq!(entry.all_extents(), vec![(77, 1)]);
        let list = encode_attr_list(&[AttrListEntry {
            kind: AttrType::STANDARD_INFORMATION,
            name: NtfsName::default(),
            starting_vcn: 0,
            segment: Frn::new(40, 3),
            attr_id: 0,
        }]);
        let entry = build_entry(&base, Some(Ok(list)), &mut |_| None, &Limits::default());
        assert!(!entry.has_problem(), "{:?}", entry.diagnostics);
        assert_eq!(entry.attr_list.as_ref().unwrap().entry_count, 1);
    }
}
