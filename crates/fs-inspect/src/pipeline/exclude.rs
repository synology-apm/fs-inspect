//! What a volume leaves out of its used ranges: the files the file system's driver lists as
//! not needed by a backup (paging and swap files, spent hibernation images), the caller's
//! paths, and what the file system always leaves out (the NTFS and ReFS VSS storage).
//!
//! Paths are looked up through the file system's [`Namespace`], in every top-level root
//! ([`ns::path_roots`]: an APFS container's volumes).
//!
//! Every exclusion is best-effort: a file that is missing, cannot be looked up, or sits on a
//! file system without a namespace stays in the backup, which is never wrong, only larger.

use super::Volume;
use crate::ExcludePattern;
use fs_inspect_core::exclude::{glob_match, is_pattern};
use fs_inspect_core::files::{FileExtent, physical_in};
use fs_inspect_core::ns::{self, Namespace, RootInfo};
use fs_inspect_core::range::{list, sort_coalesce};
use fs_inspect_core::read::extents_of;
use fs_inspect_core::{
    ByteRange, DiagCode, Diagnostics, Error, ErrorKind, FsKind, HeadCheck, NodeKind, Result, StreamId, Verdict,
    VolumePath,
};
#[cfg(test)]
use fs_inspect_core::{DirEntryExt, NodeInfoExt, RootInfoExt, StatExt};
use std::collections::HashSet;
use std::ops::ControlFlow;
use std::sync::Arc;

/// Which files to leave out of the used ranges. The file system's own recommendation (the NTFS
/// and ReFS VSS shadow-copy storage) is always left out.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ExcludeOptions {
    /// The files the file system's driver lists as not needed
    /// ([`Filesystem::default_excludes`](fs_inspect_core::Filesystem::default_excludes) and
    /// [`default_ranges`](fs_inspect_core::Filesystem::default_ranges)).
    pub(crate) default_excludes: bool,
    /// More files ([`ExcludePattern`]); every volume of a whole-disk map applies them all.
    /// Patterns match where the file system lists directories. A pattern that names no file
    /// (or a volume that cannot look paths up) excludes nothing ([`DiagCode::ExclusionSkipped`],
    /// as info).
    pub(crate) excludes: Vec<ExcludePattern>,
}

/// The exclusions of `vol`, its files read from `fs` (as recovery leaves them), sorted and
/// coalesced.
pub(super) fn exclusions(
    vol: &Volume,
    fs: &Arc<dyn fs_inspect_core::Filesystem>,
    opts: &ExcludeOptions,
) -> Result<Vec<ByteRange>> {
    let kind = vol.info().fs.kind;
    let diag = vol.diag();
    let max_depth = vol.device().opts().limits.max_path_depth;
    let defaults = fs.default_excludes();
    let mut ranges = Vec::new();
    let wants_paths = !opts.excludes.is_empty() || (opts.default_excludes && !defaults.is_empty());
    match fs.clone().namespace() {
        None if !opts.excludes.is_empty() => diag.info(
            DiagCode::ExclusionSkipped,
            format!("{kind} cannot look files up by path; the exclude paths leave nothing out of it"),
        ),
        None => {}
        Some(_) if !wants_paths => {}
        Some(ns) => match ns::path_roots(&*ns) {
            Err(e) if e.is_cancelled() => return Err(e),
            Err(e) => diag.warn(
                DiagCode::ExclusionSkipped,
                format!("{kind}: cannot look files up ({e}); the exclude paths leave nothing out of it"),
            ),
            Ok(roots) => ranges.extend(by_path(&ns, &roots, opts, defaults, max_depth, kind, diag)?),
        },
    }
    if opts.default_excludes {
        match fs.default_ranges() {
            Ok(r) => ranges.extend(r),
            Err(e) if e.is_cancelled() => return Err(e),
            Err(e) => diag.warn(DiagCode::ExclusionSkipped, format!("default exclusions not listed ({e}); kept")),
        }
    }
    ranges.extend(fs.implicit_exclusions()?);
    Ok(sort_coalesce(ranges))
}

/// What the caller's paths and the driver's default paths leave out.
fn by_path(
    ns: &Arc<dyn Namespace>,
    roots: &[RootInfo],
    opts: &ExcludeOptions,
    defaults: &[fs_inspect_core::DefaultExclude],
    max_depth: usize,
    kind: FsKind,
    diag: &Diagnostics,
) -> Result<Vec<ByteRange>> {
    let mut ranges = Vec::new();
    // (path or pattern, the check of the default it is, named by the caller); the caller's
    // first, so a default the caller also names counts as the caller's.
    let mut wanted: Vec<(VolumePath, Option<HeadCheck>, bool)> = Vec::new();
    for p in &opts.excludes {
        // Deeper than the volume allows: it names no file the volume reads, like a missing one.
        if p.path().components().len() > max_depth {
            diag.warn(
                DiagCode::ExclusionSkipped,
                format!("{p}: more than {max_depth} components (the depth limit); nothing excluded"),
            );
            continue;
        }
        wanted.push((p.path().clone(), None, true));
    }
    for d in defaults.iter().filter(|_| opts.default_excludes) {
        wanted.push((VolumePath::parse(d.path, max_depth)?, d.check, false));
    }
    let mut seen = HashSet::new();
    for (pat, check, caller) in &wanted {
        let paths = if is_pattern(&pat.to_string()) {
            match expand_roots(&**ns, roots, pat) {
                Ok((paths, cut)) => {
                    if cut {
                        diag.warn(
                            DiagCode::ExclusionSkipped,
                            format!("{pat}: more than {MAX_MATCHES} matches; the rest are kept"),
                        );
                    }
                    if paths.is_empty() && *caller {
                        diag.info(DiagCode::ExclusionSkipped, format!("{pat}: no file matches"));
                    }
                    paths
                }
                Err(e) if e.is_cancelled() => return Err(e),
                Err(e) if e.kind() == ErrorKind::Unsupported && !*caller => continue,
                Err(e) => {
                    diag.warn(DiagCode::ExclusionSkipped, format!("{pat}: cannot match ({e}); nothing excluded"));
                    continue;
                }
            }
        } else {
            vec![pat.clone()]
        };
        for p in paths {
            // Paths that differ only in case are not folded together: they may be two files
            // (in an APFS container whose volumes differ in case sensitivity).
            if !seen.insert(p.to_string()) {
                continue;
            }
            // A default the caller names keeps its check, also with the defaults off
            // (hiberfil.sys is kept while it holds a hibernated system, whoever names it).
            let check = check.or_else(|| defaults.iter().find(|d| names(d.path, &p)).and_then(|d| d.check));
            if let Some(r) = exclude_file(ns, roots, &p, check, *caller, kind, diag)? {
                ranges.extend(r);
            }
        }
    }
    Ok(ranges)
}

/// Most matches a pattern takes; the rest are kept.
const MAX_MATCHES: usize = 4096;

/// A file found for exclusion: its ranges, first bytes and (one root only) node.
struct Found {
    ranges: Vec<ByteRange>,
    head: Vec<u8>,
    /// The file when only one root holds it: its mapping can keep its header.
    single: Option<fs_inspect_core::NodeId>,
}

/// The files at `p` in `roots`, merged (`None`: no root has one).
fn find(ns: &Arc<dyn Namespace>, roots: &[RootInfo], p: &VolumePath, head_len: usize) -> Result<Option<Found>> {
    let files = ns::find_files(&**ns, roots, p)?;
    let mut found: Option<Found> = None;
    for st in &files {
        let head = if head_len == 0 {
            Vec::new()
        } else {
            let r = ns.clone().open(st.node, StreamId::MAIN)?;
            let mut head = vec![0u8; r.len().min(head_len as u64) as usize];
            r.read_exact_at(0, &mut head)?;
            head
        };
        let ranges = ns.exclusion_ranges(st.node)?;
        match &mut found {
            None => found = Some(Found { ranges, head, single: Some(st.node) }),
            Some(f) => {
                if head_len > 0 && f.head != head {
                    return Err(Error::unsupported(format!("{p} differs between volumes")));
                }
                // Files of different volumes: then only ever left out whole.
                f.ranges = sort_coalesce(f.ranges.drain(..).chain(ranges).collect());
                f.single = None;
            }
        }
    }
    Ok(found)
}

/// The ranges excluding `pattern` leaves out of the volume, without the checks of the defaults:
/// those of every file it names (at most [`MAX_MATCHES`]), sorted and coalesced; `None`: it
/// names no file.
pub(crate) fn pattern_ranges(
    ns: &Arc<dyn Namespace>,
    roots: &[RootInfo],
    pattern: &ExcludePattern,
) -> Result<Option<Vec<ByteRange>>> {
    let paths =
        if pattern.is_pattern() { expand_roots(&**ns, roots, pattern.path())?.0 } else { vec![pattern.path().clone()] };
    let mut out: Option<Vec<ByteRange>> = None;
    for p in &paths {
        if let Some(f) = find(ns, roots, p, 0)? {
            out.get_or_insert_default().extend(f.ranges);
        }
    }
    Ok(out.map(sort_coalesce))
}

/// What file `p` leaves out (`None`: nothing, reported through `diag`).
fn exclude_file(
    ns: &Arc<dyn Namespace>,
    roots: &[RootInfo],
    p: &VolumePath,
    check: Option<HeadCheck>,
    caller: bool,
    kind: FsKind,
    diag: &Diagnostics,
) -> Result<Option<Vec<ByteRange>>> {
    let head_len = check.map_or(0, |c| c.head_len);
    let cannot = |e: Error| {
        diag.warn(DiagCode::ExclusionSkipped, format!("{p}: cannot look up the file ({e}); it is kept (not excluded)"));
    };
    let f = match find(ns, roots, p, head_len) {
        Ok(Some(f)) => f,
        Ok(None) => {
            if caller {
                diag.info(
                    DiagCode::ExclusionSkipped,
                    format!("{p}: no regular file to exclude (missing, a directory, or a file the file system needs)"),
                );
            }
            return Ok(None);
        }
        Err(e) if e.is_cancelled() => return Err(e),
        // Unknown state: the file is kept (for a hibernation file, rather than lose a
        // hibernated session).
        Err(e) => {
            cannot(e);
            return Ok(None);
        }
    };
    Ok(match check.map_or(Verdict::Exclude, |c| (c.verdict)(&f.head)) {
        Verdict::Exclude => Some(f.ranges),
        Verdict::Hibernated => {
            diag.warn(DiagCode::HibernationKept, format!("{p} holds a hibernated system; it is kept"));
            None
        }
        Verdict::Keep => {
            if caller {
                diag.info(DiagCode::ExclusionSkipped, format!("{p}: its content says it is needed; it is kept"));
            }
            None
        }
        Verdict::ExcludeFrom(keep) => {
            let extents = match f.single.map(|n| ns.clone().open(n, StreamId::MAIN).and_then(|r| r.segments())) {
                Some(Ok(s)) => extents_of(&s),
                None => Vec::new(),
                Some(Err(e)) if e.is_cancelled() => return Err(e),
                Some(Err(e)) => {
                    cannot(e);
                    return Ok(None);
                }
            };
            if !extents.iter().any(|e| e.physical.is_some()) {
                diag.info(
                    DiagCode::ExclusionSkipped,
                    format!("{p}: {kind} gives no file mapping to keep its header by; it is kept"),
                );
                return Ok(None);
            }
            Some(past_head(&f.ranges, &extents, keep))
        }
    })
}

/// The paths `pattern` names in any of `roots`, and whether they were cut at
/// [`MAX_MATCHES`].
fn expand_roots(ns: &dyn Namespace, roots: &[RootInfo], pattern: &VolumePath) -> Result<(Vec<VolumePath>, bool)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut cut = false;
    for r in roots {
        let (paths, c) = expand(ns, r.node, pattern, ns.case_insensitive(r.root.0))?;
        cut |= c;
        for p in paths {
            if out.len() >= MAX_MATCHES {
                return Ok((out, true));
            }
            if seen.insert(p.to_string()) {
                out.push(p);
            }
        }
    }
    Ok((out, cut))
}

/// The paths `pattern` names from directory `root` (`*` and `?` within a component), and
/// whether they were cut at [`MAX_MATCHES`].
fn expand(
    ns: &dyn Namespace,
    root: fs_inspect_core::NodeId,
    pattern: &VolumePath,
    fold: bool,
) -> Result<(Vec<VolumePath>, bool)> {
    let mut cur = vec![VolumePath::root()];
    let mut cut = false;
    for c in pattern.components() {
        let mut next = Vec::new();
        for dir in &cur {
            if !is_pattern(c) {
                next.push(dir.join(c));
                continue;
            }
            let Some(d) = ns::resolve(ns, root, dir)? else { continue };
            if d.kind.is_some_and(|k| k != NodeKind::Dir)
                || (d.kind.is_none() && ns::stat(ns, d.node)?.kind != NodeKind::Dir)
            {
                continue;
            }
            ns.read_dir(d.node, &mut |e| {
                let n = e.name.to_string_lossy();
                if n.is_empty() || e.name.is_dot() || n.contains(['/', '\\']) || !glob_match(c, &n, fold) {
                    return ControlFlow::Continue(());
                }
                if next.len() >= MAX_MATCHES {
                    cut = true;
                    return ControlFlow::Break(());
                }
                next.push(dir.join(&n));
                ControlFlow::Continue(())
            })?;
        }
        cur = next;
    }
    Ok((cur, cut))
}

/// Whether default `pattern` (a path, `*` and `?` within components) names `p`, without case.
fn names(pattern: &str, p: &VolumePath) -> bool {
    let pat: Vec<&str> = pattern.split('/').filter(|c| !c.is_empty()).collect();
    pat.len() == p.components().len() && pat.iter().zip(p.components()).all(|(a, b)| glob_match(a, b, true))
}

/// `ranges` but those holding the first `keep` logical bytes of the file mapped by `extents`.
fn past_head(ranges: &[ByteRange], extents: &[FileExtent], keep: u64) -> Vec<ByteRange> {
    let mut head = Vec::new();
    physical_in(extents, 0, keep, &mut head);
    list::normalize(&mut head);
    list::subtract(ranges, &head)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use fs_inspect_core::read::FileReader;
    use fs_inspect_core::{DirEntry, Name, NodeId, Stat};

    /// A swap file in three pieces, its header page at the start of the second: only that page
    /// stays.
    #[test]
    fn past_head_keeps_the_header_wherever_it_lies() {
        const P: u64 = 4096;
        let extents = vec![
            FileExtent::mapped(0, 100 * P, P / 2),
            FileExtent::mapped(P / 2, 40 * P, 3 * P),
            FileExtent::hole(P / 2 + 3 * P, P),
            FileExtent::mapped(P / 2 + 4 * P, 10 * P, 2 * P),
        ];
        let ranges = sort_coalesce(vec![
            ByteRange::new(100 * P, P / 2),
            ByteRange::new(40 * P, 3 * P),
            ByteRange::new(10 * P, 2 * P),
        ]);
        assert_eq!(
            past_head(&ranges, &extents, P),
            [ByteRange::new(10 * P, 2 * P), ByteRange::new(40 * P + P / 2, 2 * P + P / 2)]
        );
        assert_eq!(past_head(&ranges, &extents, 0), ranges);
    }

    /// A tree of directories: `/a/{x.sig, Y.SIG, sub/}`, `/b/{x.sig}`, `/many/` with 5000
    /// entries and `/file.sig`. Node ids: directories 1 (root) to 4, files from 100.
    struct Tree;

    const DIRS: [(&str, u64); 4] = [("/", 1), ("/a", 2), ("/b", 3), ("/many", 4)];

    impl Tree {
        fn entries(dir: u64) -> Vec<(String, u64, NodeKind)> {
            let f = |n: &str, id| (n.to_string(), id, NodeKind::File);
            let d = |n: &str, id| (n.to_string(), id, NodeKind::Dir);
            match dir {
                1 => vec![d("a", 2), d("b", 3), d("many", 4), f("file.sig", 100)],
                2 => vec![f("x.sig", 101), f("Y.SIG", 102), d("sub", 5), f("", 103)],
                3 => vec![f("x.sig", 104)],
                4 => (0..5000).map(|i| f(&format!("{i}.sig"), 1000 + i)).collect(),
                _ => Vec::new(),
            }
        }
    }

    impl fs_inspect_core::sealed::Ns for Tree {}

    impl Namespace for Tree {
        fn roots(&self) -> Result<Vec<RootInfo>> {
            Ok(vec![RootInfo::main(NodeId::new(0, 1))])
        }
        fn node_info(&self, node: NodeId, _: fs_inspect_core::Want) -> Result<fs_inspect_core::NodeInfo> {
            let dir = DIRS.iter().any(|d| d.1 == node.id) || node.id == 5;
            Ok(fs_inspect_core::NodeInfo::new(Stat::new(node, if dir { NodeKind::Dir } else { NodeKind::File }, 0)))
        }
        fn read_dir(&self, dir: NodeId, f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()> {
            for (n, id, k) in Tree::entries(dir.id) {
                if f(DirEntry::new(Name::new(&n), NodeId::new(0, id), Some(k))).is_break() {
                    break;
                }
            }
            Ok(())
        }
        fn lookup(&self, dir: NodeId, name: &Name) -> Result<Option<DirEntry>> {
            Ok(Tree::entries(dir.id)
                .into_iter()
                .find(|e| name.eq_str(&e.0))
                .map(|(n, id, k)| DirEntry::new(Name::new(&n), NodeId::new(0, id), Some(k))))
        }
        fn open(self: Arc<Self>, node: NodeId, _: StreamId) -> Result<Box<dyn FileReader>> {
            Err(Error::unsupported(format!("reading {node}")))
        }
        fn case_insensitive(&self, _: u64) -> bool {
            false
        }
    }

    fn expanded(pattern: &str, fold: bool) -> (Vec<String>, bool) {
        let (paths, cut) = expand(&Tree, NodeId::new(0, 1), &VolumePath::parse(pattern, 16).unwrap(), fold).unwrap();
        (paths.iter().map(|p| p.to_string()).collect(), cut)
    }

    #[test]
    fn patterns_expand_one_name_at_a_time() {
        assert_eq!(expanded("/a/*.sig", false), (vec!["/a/x.sig".to_string()], false));
        assert_eq!(expanded("/a/*.sig", true).0, ["/a/x.sig", "/a/Y.SIG"]);
        // A file is not searched as a directory.
        assert_eq!(expanded("/*/x.sig", false).0, ["/a/x.sig", "/b/x.sig", "/many/x.sig", "/file.sig/x.sig"]);
        assert_eq!(expanded("/?/?.sig", false).0, ["/a/x.sig", "/b/x.sig"]);
        // Empty names are never matched.
        assert_eq!(expanded("/a/*", false).0, ["/a/x.sig", "/a/Y.SIG", "/a/sub"]);
        assert_eq!(expanded("/nope/*", false).0, Vec::<String>::new());
        assert_eq!(expanded("/file.sig/*", false).0, Vec::<String>::new());
        let (many, cut) = expanded("/many/*", false);
        assert_eq!((many.len(), cut), (MAX_MATCHES, true));
    }

    #[test]
    fn files_are_found_in_their_directories() {
        let ns: Arc<dyn Namespace> = Arc::new(Tree);
        let roots = ns::path_roots(&*ns).unwrap();
        let found = |p: &str| ns::find_files(&*ns, &roots, &VolumePath::parse(p, 16).unwrap()).unwrap();
        assert_eq!(found("/a/x.sig")[0].node, NodeId::new(0, 101));
        assert!(found("/a").is_empty() && found("/a/sub").is_empty() && found("/a/x.sig/y").is_empty());
        assert!(found("/nope").is_empty());
    }

    #[test]
    fn defaults_name_paths_without_case() {
        let p = |s: &str| VolumePath::parse(s, 16).unwrap();
        assert!(names("/private/var/vm/swapfile*", &p("/private/var/vm/swapfile3")));
        assert!(names("/hiberfil.sys", &p("/HiberFil.SYS")));
        assert!(!names("/swapfile*", &p("/private/var/vm/swapfile3")));
        assert!(!names("/sleepimage", &p("/a/sleepimage")));
    }

    /// [`Tree`] with listing failing in `/a` (with `fail`), and seen from `roots` roots at once
    /// (each with the same tree).
    struct Wrap {
        fail: Option<ErrorKind>,
        roots: u64,
    }

    impl fs_inspect_core::sealed::Ns for Wrap {}

    impl Namespace for Wrap {
        fn roots(&self) -> Result<Vec<RootInfo>> {
            Ok((0..self.roots)
                .map(|r| {
                    RootInfo::new(
                        fs_inspect_core::ns::RootId(r),
                        format!("r{r}"),
                        fs_inspect_core::ns::RootKind::Main,
                        None,
                        NodeId::new(r, 1),
                    )
                })
                .collect())
        }
        fn node_info(&self, node: NodeId, want: fs_inspect_core::Want) -> Result<fs_inspect_core::NodeInfo> {
            Tree.node_info(node, want)
        }
        fn read_dir(&self, dir: NodeId, f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()> {
            match self.fail {
                Some(kind) if dir.id == 2 => Err(Error::new(kind, "listing /a")),
                _ => Tree.read_dir(dir, f),
            }
        }
        fn lookup(&self, dir: NodeId, name: &Name) -> Result<Option<DirEntry>> {
            // `/many` by its names' numbers: a lookup per match stays cheap.
            if dir.id == 4 {
                let n = name.to_string_lossy();
                let i = n.strip_suffix(".sig").and_then(|i| i.parse::<u64>().ok()).filter(|&i| i < 5000);
                return Ok(
                    i.map(|i| DirEntry::new(Name::new(&n), NodeId::new(dir.root.0, 1000 + i), Some(NodeKind::File)))
                );
            }
            Tree.lookup(dir, name)
        }
        fn open(self: Arc<Self>, node: NodeId, _: StreamId) -> Result<Box<dyn FileReader>> {
            Err(Error::unsupported(format!("reading {node}")))
        }
        fn case_insensitive(&self, _: u64) -> bool {
            false
        }
        fn exclusion_ranges(&self, node: NodeId) -> Result<Vec<ByteRange>> {
            Ok(vec![ByteRange::new(node.id * 4096, 4096)])
        }
    }

    /// `by_path` over `ns`: the ranges and each diagnostic's message.
    fn excluded(
        ns: Arc<dyn Namespace>,
        excludes: &[&str],
        defaults: &[fs_inspect_core::DefaultExclude],
        default_excludes: bool,
    ) -> (Vec<ByteRange>, Vec<String>) {
        let roots = ns::path_roots(&*ns).unwrap();
        let opts = ExcludeOptions { default_excludes, excludes: excludes.iter().map(|p| p.parse().unwrap()).collect() };
        let diag = Diagnostics::new();
        let r = by_path(&ns, &roots, &opts, defaults, 16, FsKind::Ntfs, &diag).unwrap();
        (sort_coalesce(r), diag.all().into_iter().map(|d| d.message).collect())
    }

    fn says(msgs: &[String], what: &str) -> bool {
        msgs.iter().any(|m| m.contains(what))
    }

    /// A pattern that cannot be matched (its directory does not list): the caller's is
    /// reported and excludes nothing; a default's that the file system does not support is
    /// skipped quietly, any other failure reported. A pattern matching more than 4096 files
    /// keeps the rest, with a warning; matches in two roots count once each.
    #[test]
    fn patterns_that_cannot_be_matched_or_match_too_many() {
        let wrap = |fail, roots| Arc::new(Wrap { fail, roots }) as Arc<dyn Namespace>;
        let def = |path| fs_inspect_core::DefaultExclude { path, check: None };
        for kind in [ErrorKind::Corrupt, ErrorKind::Unsupported] {
            let (r, msgs) = excluded(wrap(Some(kind), 1), &["/a/*.sig"], &[], true);
            assert!(r.is_empty() && says(&msgs, "/a/*.sig: cannot match"), "{kind:?}: {msgs:?}");
        }
        let (r, msgs) = excluded(wrap(Some(ErrorKind::Unsupported), 1), &[], &[def("/a/*.sig")], true);
        assert!(r.is_empty() && msgs.is_empty(), "{msgs:?}");
        let (_, msgs) = excluded(wrap(Some(ErrorKind::Corrupt), 1), &[], &[def("/a/*.sig")], true);
        assert!(says(&msgs, "cannot match"), "{msgs:?}");
        // The defaults off: not even tried.
        let (r, msgs) = excluded(wrap(Some(ErrorKind::Corrupt), 1), &[], &[def("/a/*.sig")], false);
        assert!(r.is_empty() && msgs.is_empty(), "{msgs:?}");

        // Two roots: /a/x.sig found in each counts once.
        let (r, msgs) = excluded(wrap(None, 2), &["/a/*.sig"], &[], true);
        assert_eq!(r, [ByteRange::new(101 * 4096, 4096)]);
        assert!(msgs.is_empty(), "{msgs:?}");
        // 5000 matches in one root, then more in the other: cut at 4096 with a warning.
        for roots in [1, 2] {
            let (r, msgs) = excluded(wrap(None, roots), &["/many/*"], &[], true);
            assert!(says(&msgs, "/many/*: more than 4096 matches; the rest are kept"), "{msgs:?}");
            let blocks: u64 = r.iter().map(|x| x.length / 4096).sum();
            assert_eq!(blocks, MAX_MATCHES as u64, "{roots} roots");
        }
    }

    /// Files whose first bytes decide (a head check): one root or two, read through readers
    /// whose mapping is given or fails.
    struct Heads {
        roots: u64,
        /// The data of `/f` in each root.
        data: Vec<Vec<u8>>,
        /// The mapping `/f`'s reader gives: `None`, it fails to.
        segments: Option<Vec<fs_inspect_core::read::Segment>>,
    }

    struct HeadReader {
        data: Vec<u8>,
        segments: Option<Vec<fs_inspect_core::read::Segment>>,
    }

    impl fs_inspect_core::sealed::Reader for HeadReader {}

    impl FileReader for HeadReader {
        fn len(&self) -> u64 {
            self.data.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
            let o = (offset as usize).min(self.data.len());
            let n = buf.len().min(self.data.len() - o);
            buf[..n].copy_from_slice(&self.data[o..o + n]);
            Ok(n)
        }
        fn segments(&self) -> Result<Vec<fs_inspect_core::read::Segment>> {
            self.segments.clone().ok_or_else(|| Error::corrupt("the mapping of /f"))
        }
    }

    impl fs_inspect_core::sealed::Ns for Heads {}

    impl Namespace for Heads {
        fn roots(&self) -> Result<Vec<RootInfo>> {
            Wrap { fail: None, roots: self.roots }.roots()
        }
        fn node_info(&self, node: NodeId, _: fs_inspect_core::Want) -> Result<fs_inspect_core::NodeInfo> {
            let kind = if node.id == 1 { NodeKind::Dir } else { NodeKind::File };
            let len = self.data.get(node.root.0 as usize).map_or(0, |d| d.len() as u64);
            Ok(fs_inspect_core::NodeInfo::new(Stat::new(node, kind, len)))
        }
        fn read_dir(&self, dir: NodeId, f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()> {
            if dir.id == 1 {
                let _ = f(DirEntry::new(Name::new("f"), NodeId::new(dir.root.0, 7), Some(NodeKind::File)));
            }
            Ok(())
        }
        fn lookup(&self, dir: NodeId, name: &Name) -> Result<Option<DirEntry>> {
            Ok((dir.id == 1 && name.eq_str("f"))
                .then(|| DirEntry::new(Name::new("f"), NodeId::new(dir.root.0, 7), Some(NodeKind::File))))
        }
        fn open(self: Arc<Self>, node: NodeId, _: StreamId) -> Result<Box<dyn FileReader>> {
            Ok(Box::new(HeadReader { data: self.data[node.root.0 as usize].clone(), segments: self.segments.clone() }))
        }
        fn case_insensitive(&self, _: u64) -> bool {
            false
        }
        fn exclusion_ranges(&self, node: NodeId) -> Result<Vec<ByteRange>> {
            Ok(vec![ByteRange::new((10 + node.root.0) * 4096, 4096)])
        }
    }

    fn verdict(head: &[u8]) -> fs_inspect_core::exclude::Verdict {
        use fs_inspect_core::exclude::Verdict;
        match head {
            b"KEEP" => Verdict::Keep,
            b"HIBR" => Verdict::Hibernated,
            b"PART" => Verdict::ExcludeFrom(2048),
            _ => Verdict::Exclude,
        }
    }

    /// A default with a head check: a file whose content says it is needed is kept (said
    /// when the caller named it); one to keep the header of is kept whole where its mapping
    /// cannot be read or holds no volume bytes, or where it is in two roots; the same path in
    /// two roots with different heads is kept, with a warning.
    #[test]
    fn head_checks_keep_what_their_content_or_mapping_says() {
        use fs_inspect_core::read::{Segment, SegmentKind};
        let check = fs_inspect_core::HeadCheck { head_len: 4, verdict };
        let defaults = [fs_inspect_core::DefaultExclude { path: "/f", check: Some(check) }];
        let heads = |roots, data: &[&[u8]], segments| {
            let data = data.iter().map(|d| d.to_vec()).collect();
            Arc::new(Heads { roots, data, segments }) as Arc<dyn Namespace>
        };
        let mapped = Some(vec![Segment { logical: 0, length: 4096, kind: SegmentKind::Data { physical: 40 << 12 } }]);

        // Named by the caller, the defaults off: the check still holds.
        let (r, msgs) = excluded(heads(1, &[b"KEEP"], mapped.clone()), &["/f"], &defaults, false);
        assert!(r.is_empty() && says(&msgs, "/f: its content says it is needed; it is kept"), "{msgs:?}");
        let (r, msgs) = excluded(heads(1, &[b"KEEP"], mapped.clone()), &[], &defaults, true);
        assert!(r.is_empty() && msgs.is_empty(), "{msgs:?}");
        let (r, msgs) = excluded(heads(1, &[b"HIBR"], mapped.clone()), &[], &defaults, true);
        assert!(r.is_empty() && says(&msgs, "holds a hibernated system"), "{msgs:?}");
        let (r, _) = excluded(heads(1, &[b"ALL!"], mapped.clone()), &[], &defaults, true);
        assert_eq!(r, [ByteRange::new(10 * 4096, 4096)]);

        // Its header kept: the mapping fails, or maps nothing on the volume.
        let (r, msgs) = excluded(heads(1, &[b"PART"], None), &[], &defaults, true);
        assert!(r.is_empty() && says(&msgs, "/f: cannot look up the file"), "{msgs:?}");
        let inline = Some(vec![Segment { logical: 0, length: 4, kind: SegmentKind::Inline }]);
        let (r, msgs) = excluded(heads(1, &[b"PART"], inline), &[], &defaults, true);
        assert!(r.is_empty() && says(&msgs, "gives no file mapping to keep its header by"), "{msgs:?}");
        // In two roots: no single mapping to keep the header by.
        let (r, msgs) = excluded(heads(2, &[b"PART", b"PART"], mapped.clone()), &[], &defaults, true);
        assert!(r.is_empty() && says(&msgs, "gives no file mapping"), "{msgs:?}");
        // Different heads in the two roots.
        let (r, msgs) = excluded(heads(2, &[b"PART", b"KEEP"], mapped), &[], &defaults, true);
        assert!(r.is_empty() && says(&msgs, "/f differs between volumes"), "{msgs:?}");
    }
}
