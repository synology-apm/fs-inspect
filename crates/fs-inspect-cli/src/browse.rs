//! Browsing a volume's file system: `roots`, `ls`, `stat`, `cat`, `xattr`, `readlink`, `tree`
//! and `export`. Paths (`--path`) are within one root (`--root`, default the main one): names as
//! `ls` prints them (escaped: `\` doubled), `/` separated; or a node id (`ROOT:ID`) as `ls`
//! prints it. Listings are JSON Lines; `cat` and `xattr NAME` write the raw bytes.

use crate::source::VolumeArgs;
use anyhow::Context;
use clap::{Args, ValueEnum};
use fs_inspect::export::{
    CloudPolicy, DirSink, ExportOptions, ExportReport, HardLinks, NamePolicy, OnError, Sparse, Streams, Symlinks,
    TarSink, ZipCompression, ZipSink,
};
use fs_inspect::fs::{
    BrowseOptions, Checksums, DirEntry, FsHandle, Name, NodeInfo, NodeKind, Order, StreamId, WalkOptions, Want,
};
use fs_inspect::{ByteRange, DiskSet, OpenOptions};
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;

/// A volume and the root of its file system to browse.
#[derive(Args, Debug)]
pub struct RootArgs {
    #[command(flatten)]
    pub volume: VolumeArgs,
    /// The root: its number, name or path as `roots` prints it (a subvolume, dataset, APFS
    /// volume or snapshot). Default: the main one.
    #[arg(long, value_name = "ROOT")]
    pub root: Option<String>,
    /// Compute every checksum while reading: a damaged structure is an error where it is read.
    /// Without it, checksums that only tell a structure without another copy is damaged are
    /// left out (faster; `fs-inspect verify` checks the whole volume).
    #[arg(long)]
    pub verify_checksums: bool,
}

impl RootArgs {
    fn open(&self, opts: &OpenOptions) -> anyhow::Result<(DiskSet, FsHandle, u64)> {
        let (set, vol) = self.volume.open(opts)?;
        let checksums = if self.verify_checksums { Checksums::Verify } else { Checksums::Trust };
        let fs = vol.browse(&BrowseOptions::default().with_checksums(checksums), None)?;
        let roots = fs.roots(None)?;
        let root = match &self.root {
            None => roots.first().map(|r| r.root),
            Some(s) => roots.iter().find(|r| r.root.to_string() == *s || r.name == *s || r.path == *s).map(|r| r.root),
        }
        .ok_or_else(|| fs_inspect::Error::not_found(format!("root {}", self.root.as_deref().unwrap_or("(main)"))))?;
        Ok((set, fs, root.0))
    }
}

fn kind_str(k: NodeKind) -> &'static str {
    match k {
        NodeKind::File => "file",
        NodeKind::Dir => "dir",
        NodeKind::Symlink => "symlink",
        NodeKind::Reparse => "reparse",
        NodeKind::BlockDev => "block",
        NodeKind::CharDev => "char",
        NodeKind::Fifo => "fifo",
        NodeKind::Socket => "socket",
        NodeKind::Whiteout => "whiteout",
        NodeKind::Other => "other",
        _ => "other",
    }
}

/// `roots`: the roots of the volume's file system.
pub fn roots(a: &VolumeArgs, opts: &OpenOptions) -> anyhow::Result<Option<DiskSet>> {
    let (set, vol) = a.open(opts)?;
    let fs = vol.browse(&BrowseOptions::default(), None)?;
    let mut out = std::io::stdout().lock();
    for r in fs.roots(None)? {
        writeln!(out, "{}", serde_json::to_string(&r)?)?;
    }
    Ok(Some(set))
}

#[derive(Args, Debug)]
pub struct LsArgs {
    #[command(flatten)]
    pub root: RootArgs,
    /// The directory (default `/`).
    #[arg(short, long, default_value = "/")]
    pub path: String,
    /// Each entry's full stat too.
    #[arg(short = 'l', long)]
    pub long: bool,
    /// The directories below too (each entry with its path).
    #[arg(short = 'R', long)]
    pub recursive: bool,
}

/// An entry as `ls` prints it: `path` with `-R`, `stat` (or `error`) with `-l`.
fn entry_json(
    path: Option<&str>,
    e: &DirEntry,
    info: Option<&fs_inspect::Result<NodeInfo>>,
) -> anyhow::Result<serde_json::Value> {
    let mut v = serde_json::to_value(e)?;
    let Some(m) = v.as_object_mut() else { return Ok(v) };
    if let Some(p) = path {
        m.insert("path".into(), json!(p));
    }
    match info {
        None => {}
        Some(Ok(info)) => {
            m.insert("stat".into(), serde_json::to_value(&info.stat)?);
        }
        Some(Err(x)) => {
            m.insert("error".into(), json!(x.to_string()));
        }
    }
    Ok(v)
}

/// `ls`: a directory's entries (with `-R` all under it), as the file system lists them; with
/// `-l` each one's metadata, read a batch of a directory's entries at a time.
pub fn ls(a: &LsArgs, opts: &OpenOptions) -> anyhow::Result<Option<DiskSet>> {
    let (set, fs, root) = a.root.open(opts)?;
    let dir = resolve(&fs, root, &a.path)?;
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    let walk = WalkOptions::default().with_max_depth(if a.recursive { None } else { Some(1) }).with_want(if a.long {
        Want::STAT
    } else {
        Want::NONE
    });
    let walker = fs.walker(dir.node, &walk, None)?;
    for batch in &walker {
        for w in batch? {
            let j = entry_json(a.recursive.then_some(w.path.as_str()), &w.entry, w.info.as_ref())?;
            writeln!(out, "{j}")?;
            // Not recursive: nothing entered (no stat of an entry whose kind is not listed).
            if !a.recursive {
                walker.skip(w.entry.node);
            }
        }
    }
    out.flush()?;
    Ok(Some(set))
}

#[derive(Args, Debug)]
pub struct PathArgs {
    #[command(flatten)]
    pub root: RootArgs,
    /// The file or directory: a path in the root, or a node id (`ROOT:ID`).
    #[arg(short, long)]
    pub path: String,
}

/// `stat`: a node's stat, names, streams, extended attributes and link target.
pub fn stat(a: &PathArgs, opts: &OpenOptions) -> anyhow::Result<Option<DiskSet>> {
    let (set, fs, root) = a.root.open(opts)?;
    let e = resolve(&fs, root, &a.path)?;
    let info = fs.info(e.node, Want::ALL, None)?;
    let mut m = serde_json::Map::new();
    m.insert("node".into(), serde_json::to_value(e.node)?);
    m.insert("stat".into(), serde_json::to_value(&info.stat)?);
    // What a driver does not keep (or could not read) is left out.
    if let Some(Ok(n)) = info.names {
        let names: Vec<_> = n.iter().map(|(dir, name)| json!({"dir": dir, "name": name.escape()})).collect();
        m.insert("names".into(), json!(names));
    }
    if let Some(Ok(s)) = info.streams {
        m.insert("streams".into(), serde_json::to_value(s)?);
    }
    if let Some(Ok(x)) = info.xattrs {
        m.insert("xattrs".into(), serde_json::to_value(x)?);
    }
    if let Some(Ok(Some(l))) = info.link {
        m.insert("link".into(), serde_json::to_value(l)?);
    }
    if let Some(Ok(Some(s))) = info.security {
        m.insert("security".into(), serde_json::to_value(s)?);
    }
    println!("{}", serde_json::Value::Object(m));
    Ok(Some(set))
}

#[derive(Args, Debug)]
pub struct CatArgs {
    #[command(flatten)]
    pub path: PathArgs,
    /// A named stream (NTFS / ReFS alternate data stream) instead of the main one.
    #[arg(long, value_name = "NAME")]
    pub stream: Option<String>,
    /// Output file; stdout when omitted.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

/// `cat`: a file's content.
pub fn cat(a: &CatArgs, opts: &OpenOptions) -> anyhow::Result<Option<DiskSet>> {
    let (set, fs, root) = a.path.root.open(opts)?;
    let e = resolve(&fs, root, &a.path.path)?;
    let id = match &a.stream {
        None => StreamId::MAIN,
        Some(n) => {
            fs.info(e.node, Want::STREAMS, None)?
                .streams
                .transpose()?
                .unwrap_or_default()
                .into_iter()
                .find(|s| s.name.as_ref().is_some_and(|x| x.eq_str(n) || x.escape() == *n))
                .ok_or_else(|| fs_inspect::Error::not_found(format!("stream {n} of {}", a.path.path)))?
                .id
        }
    };
    let f = fs.open(e.node, id, None)?;
    crate::output::with_output(a.output.as_deref(), |out| {
        // A write that fails ends the copy (as a cancel); its error is what is reported.
        let mut failed = None;
        let copied = f.copy_range(
            ByteRange::new(0, f.size()),
            &mut |_, b| {
                out.write_all(b).map_err(|e| {
                    failed = Some(e);
                    fs_inspect::Error::cancelled()
                })
            },
            None,
        );
        match failed {
            Some(e) => broken_pipe(e),
            None => copied.map(|_| ()).map_err(Into::into),
        }
    })?;
    Ok(Some(set))
}

/// A closed stdout ends the output: not an error.
fn broken_pipe(e: std::io::Error) -> anyhow::Result<()> {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        return Ok(());
    }
    // A read failure keeps its kind (the exit code).
    match e.into_inner() {
        Some(inner) => match inner.downcast::<fs_inspect::Error>() {
            Ok(fe) => Err((*fe).into()),
            Err(other) => Err(anyhow::anyhow!(other)),
        },
        None => Err(anyhow::anyhow!("write failed")),
    }
}

#[derive(Args, Debug)]
pub struct XattrArgs {
    #[command(flatten)]
    pub path: PathArgs,
    /// The attribute to write out (raw bytes); without it, the list.
    #[arg(long)]
    pub name: Option<String>,
}

/// `xattr`: a node's extended attributes, or one's value.
pub fn xattr(a: &XattrArgs, opts: &OpenOptions) -> anyhow::Result<Option<DiskSet>> {
    let (set, fs, root) = a.path.root.open(opts)?;
    let e = resolve(&fs, root, &a.path.path)?;
    match &a.name {
        None => {
            let mut out = std::io::stdout().lock();
            for x in xattrs(&fs, e.node)? {
                writeln!(out, "{}", serde_json::to_string(&x)?)?;
            }
        }
        Some(n) => {
            let name = xattrs(&fs, e.node)?
                .into_iter()
                .map(|x| x.name)
                .find(|x| x.eq_str(n) || x.escape() == *n)
                .unwrap_or_else(|| Name::new(n));
            let v = fs
                .read_xattr(e.node, &name, None)?
                .ok_or_else(|| fs_inspect::Error::not_found(format!("extended attribute {n} of {}", a.path.path)))?;
            std::io::stdout().lock().write_all(&v).or_else(|e| broken_pipe(e).map(|_| ()))?;
        }
    }
    Ok(Some(set))
}

/// `readlink`: a symbolic link's (or junction's) target.
pub fn readlink(a: &PathArgs, opts: &OpenOptions) -> anyhow::Result<Option<DiskSet>> {
    let (set, fs, root) = a.root.open(opts)?;
    let e = resolve(&fs, root, &a.path)?;
    let l = fs
        .info(e.node, Want::LINK, None)?
        .link
        .transpose()?
        .flatten()
        .ok_or_else(|| fs_inspect::Error::not_found(format!("{}: not a link", a.path)))?;
    println!("{}", serde_json::to_string(&l)?);
    Ok(Some(set))
}

#[derive(Args, Debug)]
pub struct TreeArgs {
    #[command(flatten)]
    pub root: RootArgs,
    #[arg(short, long, default_value = "/")]
    pub path: String,
    /// Levels of directories to list (1: only the directory itself).
    #[arg(long, value_name = "N")]
    pub max_depth: Option<usize>,
}

/// `tree`: every entry under a directory, indented by depth (text).
pub fn tree(a: &TreeArgs, opts: &OpenOptions) -> anyhow::Result<Option<DiskSet>> {
    let (set, fs, root) = a.root.open(opts)?;
    let dir = resolve(&fs, root, &a.path)?;
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    let opts = WalkOptions::default().with_max_depth(a.max_depth).with_order(Order::Preorder);
    for batch in &fs.walker(dir.node, &opts, None)? {
        for w in batch? {
            let kind = w.entry.kind.map_or("", kind_str);
            let mark = if kind == "dir" { "/" } else { "" };
            if let Err(e) = writeln!(out, "{}{}{mark}", "  ".repeat(w.depth), w.entry.name.escape()) {
                broken_pipe(e)?;
                return Ok(Some(set));
            }
        }
    }
    out.flush().or_else(broken_pipe)?;
    Ok(Some(set))
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloudArg {
    /// Leave out (and report) cloud files not all on the volume.
    Skip,
    /// Write what is on the volume, the rest as holes.
    Available,
    /// Fail on one.
    Error,
}

#[derive(Args, Debug)]
#[group(id = "dest", required = true, multiple = false)]
pub struct ExportDest {
    /// Into this directory (it must exist; nothing in it is replaced).
    #[arg(long, value_name = "DIR", group = "dest")]
    pub to: Option<PathBuf>,
    /// Into a pax tar archive (`-` for stdout).
    #[arg(long, value_name = "FILE", group = "dest")]
    pub tar: Option<PathBuf>,
    /// Into a zip archive (`-` for stdout).
    #[arg(long, value_name = "FILE", group = "dest")]
    pub zip: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ExportArgs {
    #[command(flatten)]
    pub root: RootArgs,
    /// What to export (repeatable; a root's `/`: what it holds).
    #[arg(short, long = "path", required = true)]
    pub paths: Vec<String>,
    #[command(flatten)]
    pub dest: ExportDest,
    /// Every stream (NTFS / ReFS alternate data streams too).
    #[arg(long)]
    pub all_streams: bool,
    /// Write holes as zeros.
    #[arg(long)]
    pub fill_sparse: bool,
    /// Every name of a hard-linked file as a copy (zip has no hard links).
    #[arg(long)]
    pub copy_hardlinks: bool,
    /// Leave symbolic links out.
    #[arg(long)]
    pub skip_symlinks: bool,
    #[arg(long)]
    pub no_xattrs: bool,
    #[arg(long)]
    pub no_security: bool,
    /// Without times, modes and attributes.
    #[arg(long)]
    pub no_metadata: bool,
    /// Files the file system needs (NTFS `$MFT` and the like) too.
    #[arg(long)]
    pub system: bool,
    #[arg(long, value_enum, default_value_t = CloudArg::Skip)]
    pub cloud: CloudArg,
    /// Go on past an entry that fails (listed in the summary).
    #[arg(long)]
    pub keep_going: bool,
    /// Refuse names a host could not hold instead of escaping them (`%XX`).
    #[arg(long)]
    pub reject_names: bool,
    /// Store zip entries without compression.
    #[arg(long)]
    pub store: bool,
}

impl ExportArgs {
    fn options(&self) -> ExportOptions {
        fn pick<T>(on: bool, yes: T, no: T) -> T {
            if on { yes } else { no }
        }
        ExportOptions::default()
            .with_streams(pick(self.all_streams, Streams::All, Streams::Main))
            .with_sparse(pick(self.fill_sparse, Sparse::Fill, Sparse::Preserve))
            .with_hard_links(pick(self.copy_hardlinks, HardLinks::Copy, HardLinks::Dedup))
            .with_symlinks(pick(self.skip_symlinks, Symlinks::Skip, Symlinks::Preserve))
            .with_xattrs(!self.no_xattrs)
            .with_security(!self.no_security)
            .with_metadata(!self.no_metadata)
            .with_system(self.system)
            .with_on_error(pick(self.keep_going, OnError::SkipAndReport, OnError::Abort))
            .with_names(pick(self.reject_names, NamePolicy::Reject, NamePolicy::Escape))
            .with_cloud(match self.cloud {
                CloudArg::Skip => CloudPolicy::SkipAndReport,
                CloudArg::Available => CloudPolicy::AvailableOnly,
                CloudArg::Error => CloudPolicy::Error,
            })
    }
}

/// An archive's output: stdout for `-`, else a file written atomically. `f` exports into
/// the writer.
fn archive_out(
    path: &std::path::Path,
    f: impl FnOnce(&mut dyn Write) -> anyhow::Result<ExportReport>,
) -> anyhow::Result<ExportReport> {
    if path == std::path::Path::new("-") {
        let mut out = std::io::BufWriter::new(std::io::stdout().lock());
        let r = f(&mut out)?;
        out.flush()?;
        return Ok(r);
    }
    let mut a = fs_inspect_host::atomic::AtomicFile::create(path)?;
    let r = f(&mut a)?;
    a.commit()?;
    Ok(r)
}

/// `export`: files into a directory, a tar or a zip archive; a summary line on stderr when the
/// archive goes to stdout, else on stdout.
pub fn export(a: &ExportArgs, opts: &OpenOptions) -> anyhow::Result<Option<DiskSet>> {
    let (set, fs, root) = a.root.open(opts)?;
    let items =
        a.paths.iter().map(|p| resolve(&fs, root, p).with_context(|| p.clone())).collect::<anyhow::Result<Vec<_>>>()?;
    let eo = a.options();
    let (report, to_stdout) = match (&a.dest.to, &a.dest.tar, &a.dest.zip) {
        (Some(dir), _, _) => {
            let mut sink = DirSink::new(dir)?;
            (fs.export(&items, &mut sink, &eo, None, None)?, false)
        }
        (None, Some(t), _) => {
            let r = archive_out(t, |w| {
                let mut sink = TarSink::new(w);
                Ok(fs.export(&items, &mut sink, &eo, None, None)?)
            })?;
            (r, t.as_os_str() == "-")
        }
        (None, None, Some(z)) => {
            let r = archive_out(z, |w| {
                let c = if a.store { ZipCompression::Store } else { ZipCompression::Deflate };
                let mut sink = ZipSink::new(w, c);
                Ok(fs.export(&items, &mut sink, &eo, None, None)?)
            })?;
            (r, z.as_os_str() == "-")
        }
        (None, None, None) => return Err(fs_inspect::Error::invalid_argument("no --to, --tar or --zip").into()),
    };
    let mut summary = json!({"type": "summary", "mode": "export"});
    if let (Some(s), serde_json::Value::Object(r)) = (summary.as_object_mut(), serde_json::to_value(&report)?) {
        s.extend(r);
    }
    if to_stdout {
        eprintln!("{summary}");
    } else {
        println!("{summary}");
    }
    Ok(Some(set))
}

/// The entry a command names: a node id as `ls` prints it (`ROOT:ID`), or a path in `root`.
fn resolve(fs: &FsHandle, root: u64, path: &str) -> fs_inspect::Result<DirEntry> {
    match path.parse::<fs_inspect::fs::NodeId>() {
        Ok(node) => {
            let st = fs.stat(node, None)?;
            Ok(DirEntry::unnamed(node, Some(st.kind)))
        }
        Err(_) => fs.resolve(fs_inspect::fs::RootId(root), path, None),
    }
}

/// `node`'s extended attributes.
fn xattrs(fs: &FsHandle, node: fs_inspect::fs::NodeId) -> fs_inspect::Result<Vec<fs_inspect::fs::Xattr>> {
    Ok(fs.info(node, Want::XATTRS, None)?.xattrs.transpose()?.unwrap_or_default())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn node_kinds_print_as_ls_names_them() {
        let kinds = [
            (NodeKind::File, "file"),
            (NodeKind::Dir, "dir"),
            (NodeKind::Symlink, "symlink"),
            (NodeKind::Reparse, "reparse"),
            (NodeKind::BlockDev, "block"),
            (NodeKind::CharDev, "char"),
            (NodeKind::Fifo, "fifo"),
            (NodeKind::Socket, "socket"),
            (NodeKind::Whiteout, "whiteout"),
            (NodeKind::Other, "other"),
        ];
        for (k, name) in kinds {
            assert_eq!(kind_str(k), name);
        }
    }

    /// A closed pipe ends the output quietly; a library error a writer carried comes back as
    /// itself; anything else fails with what it says.
    #[test]
    fn write_failures() {
        assert!(broken_pipe(std::io::ErrorKind::BrokenPipe.into()).is_ok());
        let carried = std::io::Error::other(fs_inspect::Error::invalid_argument("bad name"));
        let e = broken_pipe(carried).unwrap_err();
        let fe = e.downcast_ref::<fs_inspect::Error>().unwrap();
        assert_eq!(fe.kind(), fs_inspect::ErrorKind::InvalidArgument);
        assert!(broken_pipe(std::io::Error::other("disk full")).unwrap_err().to_string().contains("disk full"));
        assert_eq!(broken_pipe(std::io::ErrorKind::WriteZero.into()).unwrap_err().to_string(), "write failed");
    }
}
