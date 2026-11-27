//! Exporting the Linux ext browse volume (`fixtures/ext/browse`) to tar, zip and a directory,
//! checked against what the kernel reported (`manifest.txt`): every file's bytes, link targets,
//! hard links, extended attributes, modes and times; the archives read back by independent
//! readers (the `tar` and `zip` crates); and `restore_metadata` onto files of the caller.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::export::{
    CloudPolicy, DirSink, ExportOptions, ExportReport, HardLinks, Sparse, Streams, TarSink, ZipCompression, ZipSink,
};
use fs_inspect::fs::{FsHandle, StreamId};
use fs_inspect::{ByteRange, CancelToken, DiskSet, DiskSpec, ErrorKind, OpenOptions};
use fs_inspect_testkit::sparse::SparseSource;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;

fn sha(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

/// The manifest: files (path without the leading `/` → sha256, mode, mtime ns), symlinks
/// (path → target), xattrs ((path, name) → sha256).
#[derive(Default)]
struct Manifest {
    files: BTreeMap<String, (String, u32, i128)>,
    links: BTreeMap<String, String>,
    xattrs: BTreeMap<(String, String), String>,
    specials: Vec<String>,
}

fn manifest() -> Manifest {
    let text = std::fs::read_to_string(fs_inspect_testkit::fixture("ext/browse").join("manifest.txt")).unwrap();
    let mut m = Manifest::default();
    for l in text.lines().filter(|l| !l.starts_with('#')) {
        let mut w = l.split(' ');
        let (Some(kind), Some(path)) = (w.next(), w.next()) else { continue };
        let path = path.trim_start_matches('/').replace("%20", " ").replace("%25", "%");
        let rest: Vec<&str> = w.collect();
        let field = |k: &str| rest.iter().find_map(|f| f.strip_prefix(&format!("{k}="))).map(str::to_string);
        match kind {
            "file" => {
                let mode = u32::from_str_radix(&field("mode").unwrap(), 8).unwrap();
                let mtime: i128 = field("mtime").unwrap().parse().unwrap();
                m.files.insert(path, (field("sha256").unwrap(), mode, mtime));
            }
            "symlink" => {
                m.links.insert(path, field("target").unwrap());
            }
            "xattr" => {
                m.xattrs.insert((path, rest[0].to_string()), field("sha256").unwrap());
            }
            "node" => m.specials.push(path),
            _ => {}
        }
    }
    m
}

fn browse() -> FsHandle {
    let src = SparseSource::open(fs_inspect_testkit::fixture("ext/browse").join("ext-browse.fsbs"));
    let img = DiskSet::open(&[DiskSpec::source(Arc::new(src)).raw()], &OpenOptions::default(), None).unwrap();
    img.open_volume(fs_inspect::VolumeIndex(0), None)
        .unwrap()
        .browse(&fs_inspect::fs::BrowseOptions::default(), None)
        .unwrap()
}

fn run(fs: &FsHandle, sink: &mut dyn fs_inspect::export::ExportSink, opts: &ExportOptions) -> ExportReport {
    let root = fs.resolve(fs.roots(None).unwrap()[0].root, "/", None).unwrap();
    let mut ticks = 0;
    let r = fs
        .export(
            &[root],
            sink,
            opts,
            Some(&mut |_| {
                ticks += 1;
                std::ops::ControlFlow::Continue(())
            }),
            None,
        )
        .unwrap();
    assert!(ticks > 0);
    r
}

/// Pax records: `LEN KEY=VALUE\n`, the length counting the whole record.
fn pax_records(mut d: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    while !d.is_empty() {
        let sp = d.iter().position(|&b| b == b' ').unwrap();
        let len: usize = std::str::from_utf8(&d[..sp]).unwrap().parse().unwrap();
        let rec = &d[sp + 1..len - 1];
        assert_eq!(d[len - 1], b'\n');
        let eq = rec.iter().position(|&b| b == b'=').unwrap();
        out.insert(String::from_utf8(rec[..eq].to_vec()).unwrap(), rec[eq + 1..].to_vec());
        d = &d[len..];
    }
    out
}

#[test]
fn tar_keeps_everything_the_kernel_reported() {
    let m = manifest();
    let fs = browse();
    let mut sink = TarSink::new(Vec::new());
    let report = run(&fs, &mut sink, &ExportOptions::default());
    // Sockets have no tar type; everything else is kept.
    assert_eq!(report.skipped.len(), 1, "{:?}", report.skipped);
    assert!(report.skipped[0].path.ends_with("socket"));
    let tar = sink.into_inner();

    let mut files = BTreeMap::new();
    let mut links = BTreeMap::new();
    let mut hard = BTreeMap::new();
    let mut xattrs = BTreeMap::new();
    let mut kinds = BTreeMap::new();
    // Raw entries: the `tar` crate splits pax records at newlines, which binary values
    // (extended attributes) hold, so the records are read here.
    let mut archive = tar::Archive::new(&tar[..]);
    let mut pending = None;
    for e in archive.entries().unwrap().raw(true) {
        let mut e = e.unwrap();
        if e.header().entry_type() == tar::EntryType::XHeader {
            let mut d = Vec::new();
            e.read_to_end(&mut d).unwrap();
            pending = Some(pax_records(&d));
            continue;
        }
        let pax = pending.take().expect("every entry has a pax header");
        let text = |k: &str| pax.get(k).map(|v| String::from_utf8(v.clone()).unwrap());
        let path = text("GNU.sparse.name").or_else(|| text("path")).unwrap().trim_end_matches('/').to_string();
        let link = text("linkpath");
        for (k, v) in &pax {
            if let Some(n) = k.strip_prefix("SCHILY.xattr.") {
                xattrs.insert((path.clone(), n.to_string()), sha(v));
            }
        }
        let kind = e.header().entry_type();
        kinds.insert(path.clone(), kind);
        match kind {
            tar::EntryType::Regular => {
                let mut data = Vec::new();
                e.read_to_end(&mut data).unwrap();
                if let Some(real) = pax.get("GNU.sparse.realsize") {
                    data = unsparse(&data, std::str::from_utf8(real).unwrap().parse().unwrap());
                }
                let mtime = e.header().mtime().unwrap();
                files.insert(path, (sha(&data), e.header().mode().unwrap(), mtime));
            }
            tar::EntryType::Symlink => {
                links.insert(path, link.unwrap());
            }
            tar::EntryType::Link => {
                hard.insert(path, link.unwrap());
            }
            _ => {}
        }
    }

    for (path, (hash, mode, mtime)) in &m.files {
        if let Some(to) = hard.get(path) {
            // The second name of a file: a link to the first, which has the bytes.
            assert_eq!(files[to].0, *hash, "{path}");
            continue;
        }
        let (h, md, mt) = &files.get(path).unwrap_or_else(|| panic!("{path} not in the tar"));
        assert_eq!(h, hash, "{path}");
        assert_eq!(*md, mode & 0o7777, "{path}");
        assert_eq!(i128::from(*mt), mtime / 1_000_000_000, "{path}");
    }
    assert_eq!(hard.len(), 1, "{hard:?}");
    assert_eq!(links, m.links);
    for (k, v) in &m.xattrs {
        assert_eq!(xattrs.get(k), Some(v), "{k:?}");
    }
    assert_eq!(kinds["dev/null"], tar::EntryType::Char);
    assert_eq!(kinds["dev/sda1"], tar::EntryType::Block);
    assert_eq!(kinds["dev/fifo"], tar::EntryType::Fifo);
    assert_eq!(kinds["dir/sub"], tar::EntryType::Directory);
    // The sparse file (2 MiB, 128 KiB of data) was stored sparse: large.bin (3 MiB) is most.
    assert!(tar.len() < 3_145_851 + (1 << 20), "{} bytes", tar.len());
}

#[test]
fn zip_keeps_content_and_links() {
    let m = manifest();
    let fs = browse();
    for compression in [ZipCompression::Deflate, ZipCompression::Store] {
        let mut sink = ZipSink::new(Vec::new(), compression);
        let opts = ExportOptions::default().with_hard_links(HardLinks::Copy);
        let report = run(&fs, &mut sink, &opts);
        // Devices, the FIFO and the socket have no zip form.
        assert_eq!(report.skipped.len(), m.specials.len(), "{:?}", report.skipped);
        let bytes = sink.into_inner();
        let mut z = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        let mut files = BTreeMap::new();
        let mut links = BTreeMap::new();
        for i in 0..z.len() {
            let mut f = z.by_index(i).unwrap();
            let name = f.name().unwrap().trim_end_matches('/').to_string();
            let mode = f.unix_mode().unwrap();
            let mut data = Vec::new();
            f.read_to_end(&mut data).unwrap();
            match mode & 0o170000 {
                0o120000 => {
                    links.insert(name, String::from_utf8(data).unwrap());
                }
                0o100000 => {
                    // The `zip` crate drops the set-id and sticky bits.
                    files.insert(name, (sha(&data), mode & 0o777));
                }
                0o040000 => assert!(f.is_dir()),
                k => panic!("{name}: mode {k:o}"),
            }
        }
        for (path, (hash, mode, _)) in &m.files {
            assert_eq!(files.get(path), Some(&(hash.clone(), mode & 0o777)), "{path} ({compression:?})");
        }
        assert_eq!(links, m.links);
    }
}

#[test]
fn a_directory_export_has_every_file() {
    let m = manifest();
    let fs = browse();
    let dest = tempfile::tempdir().unwrap();
    let mut sink = DirSink::new(dest.path()).unwrap();
    let report = run(&fs, &mut sink, &ExportOptions::default().with_sparse(Sparse::Preserve));
    for (path, (hash, mode, mtime)) in &m.files {
        let p = dest.path().join(path);
        let data = std::fs::read(&p).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(sha(&data), *hash, "{path}");
        let md = std::fs::metadata(&p).unwrap();
        let t = md.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap();
        // Windows keeps 100 ns.
        assert!((t.as_nanos() as i128 - mtime).abs() < 100, "{path}: {t:?} vs {mtime}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(md.permissions().mode() & 0o7777, mode & 0o7777, "{path}");
        }
        let _ = mode;
    }
    // What the host could not make is reported, nothing else.
    for fs_inspect::export::Skipped { path, error: why, .. } in &report.skipped {
        let special = m.specials.contains(path);
        let link = m.links.contains_key(path);
        assert!(special || (link && cfg!(windows)), "{path}: {why}");
    }
    #[cfg(unix)]
    for (path, target) in &m.links {
        assert_eq!(std::fs::read_link(dest.path().join(path)).unwrap().to_string_lossy(), *target);
    }

    // Nothing is replaced: exporting again fails on the first entry.
    let mut again = DirSink::new(dest.path()).unwrap();
    let root = fs.resolve(fs.roots(None).unwrap()[0].root, "/", None).unwrap();
    let e = fs.export(&[root], &mut again, &ExportOptions::default(), None, None).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io, "{e}");
}

#[test]
fn a_cancelled_export_stops() {
    let fs = browse();
    let cancel = CancelToken::new();
    cancel.cancel();
    let mut sink = TarSink::new(Vec::new());
    let root = fs.resolve(fs.roots(None).unwrap()[0].root, "/", None).unwrap();
    let e = fs.export(&[root], &mut sink, &ExportOptions::default(), None, Some(&cancel)).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Cancelled);
}

#[test]
fn a_subtree_exports_under_its_name() {
    let fs = browse();
    let root = fs.roots(None).unwrap()[0].root;
    let sub = fs.resolve(root, "/dir/sub", None).unwrap();
    // An item without a name, as a node id names it.
    let by_id = fs_inspect::fs::DirEntry::unnamed(sub.node, sub.kind);
    let mut sink = TarSink::new(Vec::new());
    fs.export(&[sub, by_id], &mut sink, &ExportOptions::default(), None, None).unwrap();
    let tar = sink.into_inner();
    let mut a = tar::Archive::new(&tar[..]);
    let mut names = Vec::new();
    for e in a.entries().unwrap().raw(true) {
        let mut e = e.unwrap();
        if e.header().entry_type() == tar::EntryType::XHeader {
            let mut d = Vec::new();
            e.read_to_end(&mut d).unwrap();
            names.push(String::from_utf8(pax_records(&d)["path"].clone()).unwrap());
        }
    }
    // By node id: ext keeps no names in the inode, so the node id names it.
    let id = format!("{}", fs.resolve(root, "/dir/sub", None).unwrap().node).replace(':', "-");
    assert_eq!(
        names,
        ["sub/".to_string(), "sub/Ünïcödé name.bin".into(), format!("{id}/"), format!("{id}/Ünïcödé name.bin")]
    );
}

/// The NTFS browse volume (`fixtures/ntfs/browse`, made by Windows) through the facade.
fn browse_ntfs() -> FsHandle {
    let src = SparseSource::open(fs_inspect_testkit::fixture("ntfs/browse").join("ntfs-browse.fsbs"));
    let img = DiskSet::open(&[DiskSpec::source(Arc::new(src)).raw()], &OpenOptions::default(), None).unwrap();
    img.open_volume(fs_inspect::VolumeIndex(0), None)
        .unwrap()
        .browse(&fs_inspect::fs::BrowseOptions::default(), None)
        .unwrap()
}

/// The NTFS manifest's lines: kind, path (no leading `/`), fields.
fn ntfs_manifest() -> Vec<(String, String, BTreeMap<String, String>)> {
    let text = std::fs::read_to_string(fs_inspect_testkit::fixture("ntfs/browse").join("manifest.txt")).unwrap();
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let mut w = l.split(' ');
            let kind = w.next().unwrap().to_string();
            let path = w.next().unwrap().trim_start_matches('/').replace("%20", " ").replace("%25", "%");
            let f = w.filter_map(|f| f.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect();
            (kind, path, f)
        })
        .collect()
}

type TarEntries = BTreeMap<String, (tar::EntryType, BTreeMap<String, Vec<u8>>, Vec<u8>)>;

/// A tar's entries: path → (type, pax records, content with the sparse map undone).
fn read_tar(tar: &[u8]) -> TarEntries {
    let mut out = BTreeMap::new();
    let mut archive = tar::Archive::new(tar);
    let mut pending = None;
    for e in archive.entries().unwrap().raw(true) {
        let mut e = e.unwrap();
        let mut data = Vec::new();
        e.read_to_end(&mut data).unwrap();
        if e.header().entry_type() == tar::EntryType::XHeader {
            pending = Some(pax_records(&data));
            continue;
        }
        let pax = pending.take().unwrap();
        let name = pax.get("GNU.sparse.name").or(pax.get("path")).unwrap();
        let path = String::from_utf8(name.clone()).unwrap().trim_end_matches('/').to_string();
        if let Some(real) = pax.get("GNU.sparse.realsize") {
            data = unsparse(&data, std::str::from_utf8(real).unwrap().parse().unwrap());
        }
        out.insert(path, (e.header().entry_type(), pax, data));
    }
    out
}

/// The content of a GNU sparse 1.0 entry: decimal map lines (a count, then offset and length
/// pairs), padded to a block, then the data.
fn unsparse(data: &[u8], real: usize) -> Vec<u8> {
    let mut nums = Vec::new();
    let mut at = 0;
    let mut need = 1;
    while nums.len() < need {
        let end = at + data[at..].iter().position(|&b| b == b'\n').unwrap();
        nums.push(std::str::from_utf8(&data[at..end]).unwrap().parse::<usize>().unwrap());
        at = end + 1;
        if nums.len() == 1 {
            need = 1 + 2 * nums[0];
        }
    }
    let mut src = at.div_ceil(512) * 512;
    let mut out = vec![0u8; real];
    for p in nums[1..].chunks(2) {
        out[p[0]..p[0] + p[1]].copy_from_slice(&data[src..src + p[1]]);
        src += p[1];
    }
    out
}

/// A stream list of the manifest (`NAME:SIZE:SHA256|...`, the unnamed one first).
fn streams(f: &BTreeMap<String, String>) -> Vec<(String, String)> {
    f["streams"]
        .split('|')
        .map(|s| {
            let mut p = s.split(':');
            let name = p.next().unwrap().to_string();
            let _size = p.next();
            (name, p.next().unwrap().to_string())
        })
        .collect()
}

#[test]
fn ntfs_streams_security_attributes_and_cloud_files_in_tar() {
    let m = ntfs_manifest();
    let fs = browse_ntfs();
    let root = fs.resolve(fs.roots(None).unwrap()[0].root, "/", None).unwrap();
    let opts = ExportOptions::default().with_streams(Streams::All).with_cloud(CloudPolicy::AvailableOnly);
    let mut sink = TarSink::new(Vec::new());
    let report = fs.export(std::slice::from_ref(&root), &mut sink, &opts, None, None).unwrap();
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    let tar = read_tar(&sink.into_inner());

    let mut hard = 0;
    for (kind, path, f) in &m {
        match kind.as_str() {
            "file" => {
                // A file of more than one name: one of them (the first exported) holds it,
                // the others link to that one.
                let names: Vec<String> = match f.get("names") {
                    Some(n) => n.split(',').map(|n| n.replace("%20", " ").replace("%25", "%")).collect(),
                    None => vec![path.clone()],
                };
                let links = names.iter().filter(|n| tar[*n].0 == tar::EntryType::Link).count();
                assert_eq!(links, names.len() - 1, "{names:?}");
                hard += links;
                let held = names.iter().find(|n| tar[*n].0 != tar::EntryType::Link).unwrap();
                let (_, pax, data) = &tar[held];
                for (name, hash) in streams(f) {
                    let got = if name.is_empty() {
                        sha(data)
                    } else {
                        sha(&pax[&format!("SCHILY.xattr.user.fsinspect.stream.{name}")])
                    };
                    assert_eq!(got, hash, "{path}:{name}");
                }
                let attrs = u32::from_str_radix(f["attrs"].trim_start_matches("0x"), 16).unwrap();
                let got = std::str::from_utf8(&pax["FSINSPECT.attributes"]).unwrap();
                let got = u32::from_str_radix(got.trim_start_matches("0x"), 16).unwrap();
                assert_eq!(got, attrs, "{path}");
                assert!(pax.contains_key("FSINSPECT.security.ntfs"), "{path}");
            }
            "link" => {
                let (t, pax, _) = &tar[path];
                assert_eq!(*t, tar::EntryType::Symlink, "{path}");
                let target = String::from_utf8(pax["linkpath"].clone()).unwrap().replace('\\', "/");
                assert_eq!(target, f["print"], "{path}");
            }
            "cloud" => {
                let (_, pax, data) = &tar[path];
                assert_eq!(data.len() as u64, f["size"].parse::<u64>().unwrap(), "{path}");
                let hydration = String::from_utf8(pax["FSINSPECT.cloud.hydration"].clone()).unwrap();
                assert_eq!(hydration.to_lowercase(), f["hydration"], "{path}");
                for r in f["local"].split(',').filter(|r| *r != "-") {
                    let (range, hash) = r.split_once(':').unwrap();
                    let (off, len) = range.split_once('+').unwrap();
                    let (off, len): (usize, usize) = (off.parse().unwrap(), len.parse().unwrap());
                    assert_eq!(sha(&data[off..off + len]), hash, "{path} {range}");
                }
            }
            _ => {}
        }
    }
    assert_eq!(hard, 1);
    let partial = report.cloud.iter().filter(|c| c.written).count();
    let not_full = m.iter().filter(|(k, _, f)| k == "cloud" && f["hydration"] != "full").count();
    assert_eq!(partial, not_full, "{:?}", report.cloud);

    // Served one at a time: a cloud file's local ranges are available and read as exported;
    // the whole of one not fully on the volume is not, and copying it ends with the error.
    for (kind, path, f) in &m {
        if kind != "cloud" {
            continue;
        }
        let node = fs.resolve(root.node.root, &format!("/{path}"), None).unwrap().node;
        let file = fs.open(node, StreamId::MAIN, None).unwrap();
        let st = file.stat().clone();
        let full = f["hydration"] == "full";
        assert_eq!(file.available(ByteRange::new(0, st.size), None).unwrap(), full, "{path}");
        for r in f["local"].split(',').filter(|r| *r != "-") {
            let (range, hash) = r.split_once(':').unwrap();
            let (off, len) = range.split_once('+').unwrap();
            let range = ByteRange::new(off.parse().unwrap(), len.parse().unwrap());
            assert!(file.available(range, None).unwrap(), "{path} {range:?}");
            let mut got = Vec::new();
            file.copy_range(
                range,
                &mut |_, b| {
                    got.extend_from_slice(b);
                    Ok(())
                },
                None,
            )
            .unwrap();
            assert_eq!(sha(&got), hash, "{path} {range:?}");
        }
        if !full {
            let r = file.copy_range(ByteRange::new(0, st.size), &mut |_, _| Ok(()), None);
            assert_eq!(r.unwrap_err().kind(), ErrorKind::ContentUnavailable, "{path}");
        }
    }

    // By default a cloud file not on the volume is left out and reported.
    let mut sink = TarSink::new(Vec::new());
    let report = fs.export(&[root], &mut sink, &ExportOptions::default(), None, None).unwrap();
    let tar = read_tar(&sink.into_inner());
    for (kind, path, f) in &m {
        if kind == "cloud" {
            let full = f["hydration"] == "full";
            assert_eq!(tar.contains_key(path), full, "{path}");
            assert_eq!(report.cloud.iter().any(|c| c.path == *path && !c.written), !full, "{path}");
        }
    }
}

#[cfg(windows)]
#[test]
fn ntfs_to_a_windows_directory_keeps_streams_and_attributes() {
    use std::os::windows::fs::MetadataExt;
    let m = ntfs_manifest();
    let fs = browse_ntfs();
    let root = fs.resolve(fs.roots(None).unwrap()[0].root, "/", None).unwrap();
    let dest = tempfile::tempdir().unwrap();
    let mut sink = DirSink::new(dest.path()).unwrap();
    let opts = ExportOptions::default().with_streams(Streams::All);
    let report = fs.export(&[root], &mut sink, &opts, None, None).unwrap();
    // Symbolic links need a privilege a test may not have: reported when refused.
    for fs_inspect::export::Skipped { path, error: why, .. } in &report.skipped {
        assert!(m.iter().any(|(k, p, _)| k == "link" && p == path), "{path}: {why}");
    }
    for (kind, path, f) in &m {
        if kind != "file" {
            continue;
        }
        let p = dest.path().join(path);
        for (name, hash) in streams(f) {
            let sp =
                if name.is_empty() { p.clone() } else { std::path::PathBuf::from(format!("{}:{name}", p.display())) };
            assert_eq!(sha(&std::fs::read(&sp).unwrap()), hash, "{path}:{name}");
        }
        let want = u32::from_str_radix(f["attrs"].trim_start_matches("0x"), 16).unwrap() & 0x27;
        let md = std::fs::metadata(&p).unwrap();
        assert_eq!(md.file_attributes() & 0x27, want, "{path}");
        let mtime: i128 = f["mtime"].parse().unwrap();
        let t = md.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as i128;
        assert_eq!(t, mtime, "{path}");
        if want & 1 != 0 {
            // Read-only: cleared so the temporary directory can be removed.
            let mut perm = md.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            perm.set_readonly(false);
            std::fs::set_permissions(&p, perm).unwrap();
        }
    }
    // The sparse file is sparse.
    let sparse = std::fs::metadata(dest.path().join("sparse.bin")).unwrap();
    assert_ne!(sparse.file_attributes() & 0x200, 0);
}

#[test]
fn restore_metadata_writes_a_node_s_times_and_mode_onto_a_file_of_the_caller() {
    use fs_inspect::export::MetaFacets;
    let m = manifest();
    let fs = browse();
    let root = fs.roots(None).unwrap()[0].root;
    let dest = tempfile::tempdir().unwrap();
    for (i, (path, (_, mode, mtime))) in m.files.iter().enumerate() {
        let node = fs.resolve(root, &format!("/{path}"), None).unwrap().node;
        let p = dest.path().join(i.to_string());
        std::fs::write(&p, b"written by the caller").unwrap();
        let report = fs.restore_metadata(node, &p, MetaFacets::ALL, None).unwrap();
        // What the host refuses is skipped, the rest written: the times always, the mode on
        // Unix (on Windows a Unix mode is unsupported).
        for s in &report.skipped {
            assert!(s.stream.is_none(), "{path}");
            let kind = s.reason.kind();
            match s.facet {
                MetaFacets::MODE if cfg!(windows) => {
                    assert_eq!(kind, ErrorKind::Unsupported, "{path}: {}", s.reason)
                }
                // Refused when not running as root; a Unix owner on Windows is unsupported.
                MetaFacets::OWNER => {
                    assert!(
                        [ErrorKind::PermissionDenied, ErrorKind::Unsupported].contains(&kind),
                        "{path}: {}",
                        s.reason
                    )
                }
                // Linux refuses `trusted.` and `security.` attributes without CAP_SYS_ADMIN, and a
                // value too large for the file system is an I/O or no-space error (ext4); elsewhere
                // only a host or file system without them skips them.
                MetaFacets::XATTRS | MetaFacets::ACL if cfg!(target_os = "linux") => assert!(
                    [ErrorKind::Unsupported, ErrorKind::PermissionDenied, ErrorKind::Io, ErrorKind::NoSpace]
                        .contains(&kind),
                    "{path}: {}",
                    s.reason
                ),
                MetaFacets::XATTRS | MetaFacets::ACL => {
                    assert_eq!(kind, ErrorKind::Unsupported, "{path}: {}", s.reason)
                }
                f => panic!("{path}: {f:?} skipped: {}", s.reason),
            }
        }
        let md = std::fs::metadata(&p).unwrap();
        let t = md.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap();
        // Windows keeps 100 ns.
        assert!((t.as_nanos() as i128 - mtime).abs() < 100, "{path}: {t:?} vs {mtime}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(md.permissions().mode() & 0o7777, mode & 0o7777, "{path}");
        }
        let _ = mode;
        // The content stays the caller's.
        assert_eq!(std::fs::read(&p).unwrap(), b"written by the caller");
    }
}

#[test]
fn restore_metadata_writes_only_the_facets_asked_and_fails_on_a_missing_destination() {
    use fs_inspect::export::MetaFacets;
    let m = manifest();
    let fs = browse();
    let root = fs.roots(None).unwrap()[0].root;
    let (path, _) = m.files.iter().next().unwrap();
    let node = fs.resolve(root, &format!("/{path}"), None).unwrap().node;
    let dest = tempfile::tempdir().unwrap();
    let p = dest.path().join("f");
    std::fs::write(&p, b"").unwrap();
    let before = std::fs::metadata(&p).unwrap().modified().unwrap();
    let report = fs.restore_metadata(node, &p, MetaFacets::MODE, None).unwrap();
    // A Unix mode is written on a Unix host; Windows cannot hold one and says so.
    #[cfg(unix)]
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    #[cfg(windows)]
    assert!(
        matches!(&report.skipped[..], [s] if s.facet == MetaFacets::MODE && s.reason.kind() == ErrorKind::Unsupported),
        "{:?}",
        report.skipped
    );
    assert_eq!(std::fs::metadata(&p).unwrap().modified().unwrap(), before, "times not asked");

    let e = fs.restore_metadata(node, &dest.path().join("none"), MetaFacets::ALL, None).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound, "{e}");
    let cancel = CancelToken::new();
    cancel.cancel();
    let e = fs.restore_metadata(node, &p, MetaFacets::ALL, Some(&cancel)).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Cancelled, "{e}");
}

#[cfg(windows)]
#[test]
fn restore_metadata_on_windows_writes_streams_attributes_and_times() {
    use fs_inspect::export::MetaFacets;
    use std::os::windows::fs::MetadataExt;
    let m = ntfs_manifest();
    let fs = browse_ntfs();
    let root = fs.roots(None).unwrap()[0].root;
    let dest = tempfile::tempdir().unwrap();
    for (i, (kind, path, f)) in m.iter().enumerate() {
        if kind != "file" {
            continue;
        }
        let node = fs.resolve(root, &format!("/{path}"), None).unwrap().node;
        let p = dest.path().join(i.to_string());
        std::fs::write(&p, b"").unwrap();
        // The DACL (left out here: it may take away this test's access to its own files) has
        // a test of its own.
        let report = fs.restore_metadata(node, &p, MetaFacets::ALL.without(MetaFacets::ACL), None).unwrap();
        // An extended attribute is not set on Windows; another owner needs a privilege a test
        // may not have: skipped, nothing else.
        for s in &report.skipped {
            match s.facet {
                MetaFacets::XATTRS => assert_eq!(s.reason.kind(), ErrorKind::Unsupported, "{path}: {}", s.reason),
                MetaFacets::OWNER => {
                    assert_eq!(s.reason.kind(), ErrorKind::PermissionDenied, "{path}: {}", s.reason)
                }
                f => panic!("{path}: {f:?} skipped: {}", s.reason),
            }
        }
        for (name, hash) in streams(f).into_iter().filter(|(n, _)| !n.is_empty()) {
            let sp = std::path::PathBuf::from(format!("{}:{name}", p.display()));
            assert_eq!(sha(&std::fs::read(&sp).unwrap()), hash, "{path}:{name}");
        }
        let want = u32::from_str_radix(f["attrs"].trim_start_matches("0x"), 16).unwrap() & 0x27;
        let md = std::fs::metadata(&p).unwrap();
        assert_eq!(md.file_attributes() & 0x27, want, "{path}");
        let mtime: i128 = f["mtime"].parse().unwrap();
        let t = md.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as i128;
        assert_eq!(t, mtime, "{path}");
        if want & 1 != 0 {
            // Read-only: cleared so the temporary directory can be removed.
            let mut perm = md.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            perm.set_readonly(false);
            std::fs::set_permissions(&p, perm).unwrap();
        }
    }
}

/// On Windows a file's DACL is set (its round trip: `fs-inspect-host`'s `a_dacl_round_trips`).
#[cfg(windows)]
#[test]
fn restore_metadata_on_windows_sets_the_dacl() {
    use fs_inspect::export::MetaFacets;
    let m = ntfs_manifest();
    let fs = browse_ntfs();
    let root = fs.roots(None).unwrap()[0].root;
    let dest = tempfile::tempdir().unwrap();
    for (i, (kind, path, _)) in m.iter().enumerate().filter(|(_, (k, _, _))| k == "file") {
        let node = fs.resolve(root, &format!("/{path}"), None).unwrap().node;
        let p = dest.path().join(i.to_string());
        std::fs::write(&p, b"").unwrap();
        let report = fs.restore_metadata(node, &p, MetaFacets::ACL, None).unwrap();
        assert!(report.skipped.is_empty(), "{kind} {path}: {:?}", report.skipped);
    }
}

/// The ext node of `path`, its stat's modification time as a `SystemTime` and its Unix mode.
#[cfg(unix)]
fn ext_node(fs: &FsHandle, path: &str) -> (fs_inspect::fs::NodeId, std::time::SystemTime, u32) {
    let node = fs.resolve(fs.roots(None).unwrap()[0].root, path, None).unwrap().node;
    let st = fs.stat(node, None).unwrap();
    let t = st.times.modified.unwrap();
    let mtime = std::time::UNIX_EPOCH + std::time::Duration::new(t.secs as u64, t.nanos);
    (node, mtime, st.unix.unwrap().mode)
}

/// A directory takes its times and mode.
#[cfg(unix)]
#[test]
fn restore_metadata_onto_a_directory() {
    use fs_inspect::export::MetaFacets;
    use std::os::unix::fs::PermissionsExt;
    let fs = browse();
    let (node, mtime, mode) = ext_node(&fs, "/dir/sub");
    let dest = tempfile::tempdir().unwrap();
    let d = dest.path().join("d");
    std::fs::create_dir(&d).unwrap();
    let report = fs.restore_metadata(node, &d, MetaFacets::TIMES | MetaFacets::MODE, None).unwrap();
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    let md = std::fs::metadata(&d).unwrap();
    assert_eq!(md.modified().unwrap(), mtime);
    assert_eq!(md.permissions().mode() & 0o7777, mode & 0o7777);
}

/// A symbolic link takes its own times, not its target's; its mode is set on macOS and the
/// BSDs, and is nothing to write on Linux, where a link has none: never skipped.
#[cfg(unix)]
#[test]
fn restore_metadata_onto_a_symbolic_link() {
    use fs_inspect::export::MetaFacets;
    use std::os::unix::fs::PermissionsExt;
    let fs = browse();
    let (node, mtime, mode) = ext_node(&fs, "/fast-link");
    let dest = tempfile::tempdir().unwrap();
    let target = dest.path().join("target");
    std::fs::write(&target, b"").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    let before = std::fs::metadata(&target).unwrap();
    let link = dest.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let report = fs.restore_metadata(node, &link, MetaFacets::TIMES | MetaFacets::MODE, None).unwrap();
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    let md = std::fs::symlink_metadata(&link).unwrap();
    assert_eq!(md.modified().unwrap(), mtime);
    if !cfg!(target_os = "linux") {
        assert_eq!(md.permissions().mode() & 0o7777, mode & 0o7777);
    }
    // The target is untouched.
    let after = std::fs::metadata(&target).unwrap();
    assert_eq!(after.modified().unwrap(), before.modified().unwrap());
    assert_eq!(after.permissions().mode() & 0o7777, 0o600);
}
