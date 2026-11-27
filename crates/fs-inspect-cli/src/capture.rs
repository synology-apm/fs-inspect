//! `capture`: a volume's metadata, to report a problem with it or to record it as a test
//! fixture (`cargo xtask record-fixture`). Writes `capture.fsbs` (the sparse image format of
//! `fs_inspect::io::sparse`, which the test fixtures use) and `manifest.json` (what fs-inspect
//! made of the volume) in a directory.

use crate::args::parse_size;
use crate::list::set_record;
use crate::source::{VolumeArgs, open_set};
use anyhow::Context as _;
use clap::Args;
use fs_inspect::Named;
use fs_inspect::range::{sort_coalesce, subtract};
use fs_inspect::verify::VerifyOptions;
use fs_inspect::{
    BlockClass, BlockSource, ByteRange, DeviceRef, DiskSet, OpenOptions, Volume, VolumeLocation, VolumeMapOptions,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{BufWriter, Read};
use std::path::{Path, PathBuf};

use fs_inspect::io::sparse::{SparseFile, Writer};
/// What a capture reads at a time.
const CHUNK: usize = 1 << 20;

/// Arguments of `capture`.
#[derive(Args, Debug)]
pub struct CaptureArgs {
    #[command(flatten)]
    pub volume: VolumeArgs,
    /// The directory to write `capture.fsbs` and `manifest.json` to (made if missing).
    #[arg(short = 'o', long = "out", value_name = "DIR")]
    pub out: PathBuf,
    /// Keep the files' contents too (every allocated byte): only for a volume whose files may
    /// be shared.
    #[arg(long)]
    pub with_data: bool,
    /// When the volume cannot be opened: bytes kept from the start of the volume (or disk), as
    /// well as its last MiB and the places file systems keep copies of their superblocks.
    #[arg(long, value_parser = parse_size, default_value = "16M", value_name = "SIZE")]
    pub fallback_head: u64,
}

/// What a capture keeps, where it reads it.
struct Plan {
    /// `metadata`, `full` (`--with-data`) or `fallback`.
    mode: &'static str,
    /// Offset 0 of the capture in its source, and its length.
    source: fs_inspect::DynSource,
    base: u64,
    len: u64,
    keep: Vec<ByteRange>,
    info: Value,
}

/// `capture`: the volume's metadata (its allocated blocks less its files' contents) into
/// `<out>/capture.fsbs`, in volume coordinates, and `<out>/manifest.json`. A volume that
/// cannot be opened is captured conservatively (`"mode": "fallback"`): the start of its
/// partition (or disk), its end, and where superblock copies are. One JSON summary line.
pub fn capture(a: &CaptureArgs, opts: &OpenOptions) -> anyhow::Result<Option<DiskSet>> {
    std::fs::create_dir_all(&a.out).with_context(|| format!("creating {}", a.out.display()))?;
    let set = open_set(&a.volume.source, opts)?;
    let mut manifest = json!({
        "format": "fs-inspect capture 1",
        "fs_inspect_version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "created_unix": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()),
        // File names only: where the images were is the reporter's own business.
        "images": a.volume.source.images.iter().map(|i| file_name(i)).collect::<Vec<_>>(),
        "disks": disks(&set),
        "volumes": set.volumes(None).map_or_else(
            |e| json!({ "error": e.to_string() }),
            |v| json!(v.iter().map(|e| set_record(e, &set)).collect::<Vec<_>>()),
        ),
    });
    // A volume `--volume` or `--logical` names that is not there is the caller's mistake, not
    // one to capture around (with neither, no volume with a file system is: the fallback).
    let sel = &a.volume.select;
    let opened = match sel.open(&set) {
        Err(e) if e.kind() == fs_inspect::ErrorKind::NotFound && (sel.volume.is_some() || sel.logical.is_some()) => {
            return Err(e.into());
        }
        r => r,
    };
    let plan = match opened.map_err(anyhow::Error::from).and_then(|vol| volume_plan(a, &vol)) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("capturing conservatively: {e:#}");
            let mut p = fallback_plan(a, &set)?;
            p.info["fallback_reason"] = json!(format!("{e:#}"));
            p
        }
    };
    let file = a.out.join("capture.fsbs");
    let written = write_sparse(&file, &*plan.source, plan.base, plan.len, &plan.keep)?;
    manifest["mode"] = json!(plan.mode);
    manifest["volume"] = plan.info;
    manifest["capture"] = json!({
        "file": "capture.fsbs",
        "coordinates": if plan.mode == "fallback" { "region" } else { "volume" },
        "image_bytes": plan.len,
        "kept_bytes": total(&plan.keep),
        "stored_bytes": written.stored,
        "runs": written.runs,
        "file_bytes": written.file_bytes,
        "sha256": written.sha256,
    });
    manifest["diagnostics"] = json!(
        set.diagnostics()
            .iter()
            .map(|d| json!({
                "severity": d.severity.as_str(),
                "code": d.code.as_str(),
                "message": d.message,
                "volume": d.volume.map(|i| i.0),
            }))
            .collect::<Vec<_>>()
    );
    let mpath = a.out.join("manifest.json");
    std::fs::write(&mpath, serde_json::to_string_pretty(&manifest)? + "\n")
        .with_context(|| format!("writing {}", mpath.display()))?;
    println!(
        "{}",
        json!({
            "type": "summary",
            "mode": plan.mode,
            "out": a.out.display().to_string(),
            "image_bytes": plan.len,
            "stored_bytes": written.stored,
            "sha256": written.sha256,
        })
    );
    Ok(Some(set))
}

fn file_name(image: &str) -> String {
    Path::new(image).file_name().map_or_else(|| image.to_string(), |n| n.to_string_lossy().into_owned())
}

fn disks(set: &DiskSet) -> Value {
    json!(
        set.disks()
            .iter()
            .map(|d| match d.device().map(|d| d.info(None)) {
                None => json!({ "absent": true }),
                Some(Ok(i)) => json!({
                    "origin": i.origin.as_str(),
                    "container": i.container.as_str(),
                    "bytes": i.size,
                    "sector_size": i.sector_size,
                    "scheme": i.scheme.as_str(),
                }),
                Some(Err(e)) => json!({ "error": e.to_string() }),
            })
            .collect::<Vec<_>>()
    )
}

/// The plan for an opened volume: its map's data, less its files' contents (unless
/// `--with-data`), each widened to whole allocation units.
fn volume_plan(a: &CaptureArgs, vol: &Volume) -> anyhow::Result<Plan> {
    let i = vol.info();
    anyhow::ensure!(i.fs.kind != fs_inspect::FsKind::Raw, "no file system recognized on the volume");
    let map = vol.map(&VolumeMapOptions::default(), None)?;
    let data = map.ranges(BlockClass::Data);
    let unit = i.fs.unit.max(1);
    let mut info = json!({
        "index": i.index.map(|x| x.0),
        "offset": i.offset,
        "reach": i.reach.length,
        "coverage_bytes": i.coverage_bytes,
        "logical": i.logical.as_ref().map(ToString::to_string),
        "fs": i.fs.kind.as_str(),
        "unit_bytes": i.fs.unit,
        "volume_bytes": i.fs.size,
        "label": i.fs.label,
        "uuid": i.fs.uuid,
        "state": crate::output::state_json(&vol.state(None)?),
        "data_bytes": total(&data),
    });
    let (mode, keep) = if a.with_data {
        ("full", data)
    } else {
        let content = vol.file_content(None)?;
        let widened = sort_coalesce(
            content
                .ranges
                .iter()
                .map(|r| ByteRange::from_bounds(r.offset / unit * unit, r.end().div_ceil(unit) * unit))
                .collect(),
        );
        info["file_content"] = json!({
            "files": content.files,
            "unreadable": content.unreadable,
            "bytes": total(&widened),
        });
        ("metadata", subtract(data.iter().copied(), widened.iter().copied()).collect())
    };
    info["verify"] = match vol.verify(&VerifyOptions::default(), None) {
        Ok(r) => serde_json::to_value(&r)?,
        Err(e) => json!({ "error": e.to_string() }),
    };
    info["diagnostics"] = json!(
        vol.diagnostics()
            .iter()
            .map(|d| format!("{}: [{}] {}", d.severity.as_str(), d.code, d.message))
            .collect::<Vec<_>>()
    );
    let len = i.coverage_bytes.max(map.extent().length);
    Ok(Plan { mode, source: fs_inspect::unstable::volume_source(vol).clone(), base: 0, len, keep, info })
}

/// The plan for a volume that cannot be opened: the region of its partition (`--volume`
/// naming one on a disk) or of the disk (`--disk`), its first `--fallback-head` bytes, its
/// last MiB, and 64 KiB at the places file systems keep superblock copies.
fn fallback_plan(a: &CaptureArgs, set: &DiskSet) -> anyhow::Result<Plan> {
    let sel = &a.volume.select;
    let region = sel.volume.and_then(|v| {
        let vols = set.volumes(None).ok()?;
        let e = vols.iter().find(|e| e.index.0 == v)?;
        match e.location {
            VolumeLocation::Device { device: DeviceRef::Disk(d), range } => Some((d.0, range.offset, range.length)),
            // On a logical volume or a pool: the region is a disk's (--disk).
            VolumeLocation::Device { device: DeviceRef::Logical { .. }, .. } | VolumeLocation::Pool { .. } => None,
            _ => None,
        }
    });
    let (disk, base, len) = match (region, sel.offset) {
        (Some(r), _) => r,
        (None, Some(off)) => {
            let d = set.reader(fs_inspect::DiskIndex(sel.disk), None)?;
            (sel.disk, off, sel.length.unwrap_or(d.size().saturating_sub(off)))
        }
        (None, None) => (sel.disk, 0, set.reader(fs_inspect::DiskIndex(sel.disk), None)?.size()),
    };
    let source = set.reader(fs_inspect::DiskIndex(disk), None)?;
    let len = len.min(source.size().saturating_sub(base));
    const MIB: u64 = 1 << 20;
    let mut keep =
        vec![ByteRange::new(0, a.fallback_head.min(len)), ByteRange::from_bounds(len.saturating_sub(MIB), len)];
    // ext2/3/4 backup superblocks (groups 1, 3^n, 5^n, 7^n) at 1 KiB and 4 KiB blocks, btrfs
    // superblock mirrors, the XFS secondary superblocks of 4 allocation groups.
    let mut groups = vec![1u64];
    for b in [3u64, 5, 7] {
        let mut g = b;
        while g < 1 << 20 {
            groups.push(g);
            g *= b;
        }
    }
    for g in groups {
        keep.push(ByteRange::new(g * 8 * MIB, 64 << 10));
        keep.push(ByteRange::new(g * 128 * MIB, 64 << 10));
    }
    keep.extend([ByteRange::new(64 * MIB, 64 << 10), ByteRange::new(256 << 30, 64 << 10)]);
    keep.extend((1..4).map(|k| ByteRange::new(len / 4 * k / 4096 * 4096, 64 << 10)));
    let keep: Vec<ByteRange> = sort_coalesce(keep)
        .into_iter()
        .filter(|r| r.offset < len)
        .map(|r| ByteRange::from_bounds(r.offset, r.end().min(len)))
        .collect();
    let info = json!({ "disk": disk, "region_offset": base, "region_bytes": len, "fallback_head": a.fallback_head });
    Ok(Plan { mode: "fallback", source, base, len, keep, info })
}

struct Written {
    stored: u64,
    runs: u64,
    file_bytes: u64,
    sha256: String,
}

/// Write the `len`-byte image whose bytes `keep` (sorted, coalesced, within it) are read from
/// `src` at `base +` their offset, the rest zeros, to `path` as a sparse image
/// (`fs_inspect::io::sparse`); blocks of zeros are left out.
fn write_sparse(
    path: &Path,
    src: &dyn BlockSource,
    base: u64,
    len: u64,
    keep: &[ByteRange],
) -> anyhow::Result<Written> {
    let file = std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut w = Writer::new(BufWriter::with_capacity(CHUNK, file), len)?;
    let mut buf = vec![0u8; CHUNK];
    for r in keep {
        let mut at = r.offset;
        while at < r.end() {
            let n = (r.end() - at).min(CHUNK as u64) as usize;
            let b = &mut buf[..n];
            src.read_exact_at(base + at, b).with_context(|| format!("reading {n} bytes at {}", base + at))?;
            w.push_nonzero(at, b)?;
            at += n as u64;
        }
    }
    w.finish()?;
    let back = SparseFile::open(path)?;
    let (mut hash, mut file_bytes) = (Sha256::new(), 0u64);
    let mut f = std::fs::File::open(path)?;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
        file_bytes += n as u64;
    }
    Ok(Written {
        stored: back.stored(),
        runs: back.runs().count() as u64,
        file_bytes,
        sha256: hash.finalize().iter().map(|b| format!("{b:02x}")).collect(),
    })
}

/// Bytes `ranges` cover.
fn total(ranges: &[ByteRange]) -> u64 {
    ranges.iter().map(|r| r.length).sum()
}
