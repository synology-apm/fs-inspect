//! The path-lookup fixtures of `fixtures/<fs>/linux` (`tools/fsi_tools/fixtures/ext_xfs_btrfs_linux.py`)
//! and `fixtures/apfs/macos-lookup` (`tools/fsi_tools/fixtures/apfs_macos_lookup.py`): each file's
//! physical extents and each directory's names, as the OS reported them.

use fs_inspect_core::ns::{self, DirEntry, Namespace, NodeKind, StreamId};
use fs_inspect_core::range::sort_coalesce;
use fs_inspect_core::{ByteRange, ErrorKind, Result, VolumePath};
use std::sync::Arc;

/// What `expected.txt` says of one image.
#[derive(Debug, Default)]
pub struct Expected {
    /// Path, size, physical ranges (sorted, coalesced), whether its data is encoded
    /// (compressed: its first bytes cannot be read).
    pub files: Vec<(String, u64, Vec<ByteRange>, bool)>,
    /// Path, names (sorted).
    pub dirs: Vec<(String, Vec<String>)>,
}

/// The expected lookups of `image` in `fixtures/<fs>/<dir>/expected.txt`.
pub fn expected(fs: &str, dir: &str, image: &str) -> Expected {
    let path = crate::fixture(fs).join(dir).join("expected.txt");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut out = Expected::default();
    for l in text.lines() {
        let mut w = l.splitn(4, ' ');
        let (Some(img), Some(kind), Some(p), rest) = (w.next(), w.next(), w.next(), w.next()) else { continue };
        if img != image {
            continue;
        }
        let p = p.replace("%20", " ");
        match kind {
            "dir" => {
                let names = rest.unwrap_or("").split('/').filter(|n| !n.is_empty()).map(str::to_string).collect();
                out.dirs.push((p, names));
            }
            "file" => {
                let (size, ranges) = rest.unwrap_or("").split_once(' ').unwrap_or_else(|| panic!("{l}"));
                let (ranges, encoded) = match ranges.strip_suffix(" encoded") {
                    Some(r) => (r, true),
                    None => (ranges, false),
                };
                let ranges = ranges
                    .split(',')
                    .filter(|r| *r != "-")
                    .map(|r| {
                        let (o, n) = r.split_once('+').unwrap_or_else(|| panic!("{l}"));
                        ByteRange::new(
                            o.parse().unwrap_or_else(|_| panic!("{l}")),
                            n.parse().unwrap_or_else(|_| panic!("{l}")),
                        )
                    })
                    .collect();
                out.files.push((p, size.parse().unwrap_or_else(|_| panic!("{l}")), ranges, encoded));
            }
            _ => panic!("{l}"),
        }
    }
    assert!(!out.files.is_empty() && !out.dirs.is_empty(), "{image} not in {}", path.display());
    out
}

/// The regular file at `path` in the roots a path names files in, as an exclusion finds it: the
/// ranges leaving it out frees (of every root holding it) and its first `head_len` bytes (of
/// the first, read only when `head_len` is not 0); `None` when there is none.
pub fn file(ns: &Arc<dyn Namespace>, path: &VolumePath, head_len: usize) -> Result<Option<(Vec<ByteRange>, Vec<u8>)>> {
    let roots = ns::path_roots(&**ns)?;
    let files = ns::find_files(&**ns, &roots, path)?;
    let Some(first) = files.first() else { return Ok(None) };
    let mut head = Vec::new();
    if head_len > 0 {
        let r = ns.clone().open(first.node, StreamId::MAIN)?;
        head.resize(r.len().min(head_len as u64) as usize, 0);
        r.read_exact_at(0, &mut head)?;
    }
    let mut ranges = Vec::new();
    for st in &files {
        ranges.extend(ns.exclusion_ranges(st.node)?);
    }
    Ok(Some((sort_coalesce(ranges), head)))
}

/// Check `ns` against what `fixtures/<fs>/linux/expected.txt` says of `image` (see
/// [`check_in`]).
pub fn check(ns: &Arc<dyn Namespace>, fs: &str, image: &str) {
    check_in(ns, fs, "linux", image);
}

/// Check `ns` against what `fixtures/<fs>/<dir>/expected.txt` says of `image`, in every root a
/// path names files in ([`ns::path_roots`]): every file is found with its size and the OS's
/// extents (its first bytes read; when encoded, read or refused as unsupported), every directory
/// lists the OS's names (those of every root holding it); a directory is no file, a missing
/// path nothing.
pub fn check_in(ns: &Arc<dyn Namespace>, fs: &str, dir: &str, image: &str) {
    let e = expected(fs, dir, image);
    let p = |s: &str| VolumePath::parse(s, 64).unwrap_or_else(|err| panic!("{s}: {err}"));
    let roots = ns::path_roots(&**ns).unwrap_or_else(|err| panic!("{image}: roots: {err}"));
    let at = |path: &str| -> Vec<DirEntry> {
        roots
            .iter()
            .filter_map(|r| ns::resolve(&**ns, r.node, &p(path)).unwrap_or_else(|err| panic!("{image}: {path}: {err}")))
            .collect()
    };
    for (path, size, ranges, encoded) in &e.files {
        let files = ns::find_files(&**ns, &roots, &p(path)).unwrap_or_else(|err| panic!("{image}: {path}: {err}"));
        assert!(!files.is_empty(), "{image}: {path} not found");
        let mut got = Vec::new();
        for st in &files {
            assert_eq!(st.size, *size, "{image}: {path}: size");
            got.extend(ns.exclusion_ranges(st.node).unwrap_or_else(|err| panic!("{image}: {path}: {err}")));
            let mut head = vec![0u8; (*size).min(16) as usize];
            let read = ns.clone().open(st.node, StreamId::MAIN).and_then(|r| r.read_exact_at(0, &mut head));
            if *encoded {
                // Decoded where the driver has the codec, refused as unsupported where not.
                if let Err(err) = read {
                    assert_eq!(err.kind(), ErrorKind::Unsupported, "{image}: {path}: {err}");
                }
            } else {
                read.unwrap_or_else(|err| panic!("{image}: {path}: {err}"));
            }
        }
        assert_eq!(&sort_coalesce(got), ranges, "{image}: {path}");
    }
    for (path, names) in &e.dirs {
        let dirs = at(path);
        assert!(!dirs.is_empty(), "{image}: {path} not listed");
        let mut got = Vec::new();
        for d in &dirs {
            let st = ns::stat(&**ns, d.node).unwrap_or_else(|err| panic!("{image}: {path}: {err}"));
            assert_eq!(st.kind, NodeKind::Dir, "{image}: {path}");
            let entries = ns::list(&**ns, d.node).unwrap_or_else(|err| panic!("{image}: {path}: {err}"));
            got.extend(entries.iter().map(|e| e.name.to_string_lossy()));
        }
        got.sort();
        got.dedup();
        assert_eq!(&got, names, "{image}: {path}");
        assert!(ns::find_files(&**ns, &roots, &p(path)).unwrap().is_empty(), "{image}: {path} is a file");
    }
    for missing in ["/no such file", "/dir/no such file", "/dir/small.txt/below a file"] {
        assert!(at(missing).is_empty(), "{image}: {missing} found");
    }
}
