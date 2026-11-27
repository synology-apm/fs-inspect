//! Opening a volume: the boot sector's geometry, the superblock and checkpoint to use, then
//! the tables of that checkpoint.

use super::RefsFs;
use super::tables::{Tables, load_tables};
use crate::format::layout::{BootSector, CONTAINER_BYTES, Checkpoint, MIN_NODE_BYTES, SUPERBLOCK_LCN, Superblock};
use crate::format::tree::PageReader;
use fs_inspect_core::FsInfoExt;
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::range::sort_coalesce;
use fs_inspect_core::{
    ByteRange, DiagCode, Diagnostics, DriverContext, Error, FsInfo, FsKind, Limits, Result, Role, Site,
};
use fs_inspect_io::DynSource;

/// Cluster size, cluster count and volume bytes from the boot sector; versions other than
/// 3.x, clusters other than 4 KiB or 64 KiB and containers other than 64 MiB are unsupported.
fn geometry(b: &BootSector) -> Result<(u32, u64, u64)> {
    if b.major < 3 {
        return Err(Error::unsupported(format!("ReFS {}.{} (only 3.x is supported)", b.major, b.minor)));
    }
    if b.major > 3 {
        return Err(Error::unsupported(format!("ReFS {}.{}", b.major, b.minor)));
    }
    let bps = b.bytes_per_sector;
    if !bps.is_power_of_two() || !(512..=4096).contains(&bps) {
        return Err(Error::corrupt(format!("{bps} bytes per sector")));
    }
    let cluster = bps.checked_mul(b.sectors_per_cluster).unwrap_or(0);
    if cluster != 4096 && cluster != 65536 {
        return Err(Error::unsupported(format!("ReFS clusters of {cluster} bytes")));
    }
    if b.container_bytes != 0 && b.container_bytes != CONTAINER_BYTES {
        return Err(Error::unsupported(format!("ReFS containers of {} bytes", b.container_bytes)));
    }
    let bytes = b.sector_count.checked_mul(u64::from(bps)).ok_or_else(|| Error::corrupt("sector count"))?;
    let clusters = bytes / u64::from(cluster);
    if clusters <= SUPERBLOCK_LCN + 3 {
        return Err(Error::corrupt(format!("volume of {clusters} clusters")));
    }
    Ok((cluster, clusters, bytes))
}

/// The newest valid superblock copy (the primary on a tie).
fn pick_superblock(reader: &PageReader, clusters: u64, diag: &Diagnostics) -> Result<Superblock> {
    let cluster = u64::from(reader.cluster_bytes());
    let mut best: Option<Superblock> = None;
    let mut why = String::new();
    for lcn in [SUPERBLOCK_LCN, clusters - 3, clusters - 2] {
        let sb = reader.read_cluster(lcn).and_then(|b| Superblock::parse(&b, lcn));
        match sb {
            Err(e) if e.scope() != Scope::Unit => return Err(e),
            Err(e) => {
                if why.is_empty() {
                    why = format!("at LCN {lcn:#x}: {e}");
                }
            }
            Ok(sb)
                if !reader.integrity().ok(
                    Role::Select,
                    Site::new(StructureKind::RefsSuperblock).at(lcn * cluster),
                    || sb.verdict,
                ) =>
            {
                if why.is_empty() {
                    why = format!("at LCN {lcn:#x}: checksum mismatch");
                }
            }
            Ok(sb) => {
                if best.as_ref().is_none_or(|b| sb.generation > b.generation) {
                    best = Some(sb);
                }
            }
        }
    }
    let sb = best.ok_or_else(|| Error::corrupt(format!("no valid ReFS superblock ({why})")))?;
    if sb.lcn != SUPERBLOCK_LCN {
        diag.warn(DiagCode::BackupUsed, format!("using the superblock copy at LCN {:#x} ({why})", sb.lcn));
    }
    Ok(sb)
}

impl RefsFs {
    /// Open the volume at offset 0 of `src`; damage worked around goes to `ctx.diagnostics`.
    pub fn open(src: DynSource, ctx: &DriverContext) -> Result<Self> {
        let limits = ctx.limits.clone();
        let diag = ctx.diagnostics.clone();
        let integrity = ctx.integrity();
        let head = src.read_vec(0, 512.min(src.size() as usize))?;
        let boot = BootSector::parse(&head)?;
        let (cluster, clusters, volume_bytes) = geometry(&boot)?;
        if !integrity.ok(Role::Validate, Site::new(StructureKind::RefsBootSector).at(0), || boot.checksum_ok.into()) {
            diag.warn(DiagCode::ChecksumMismatch, "boot sector checksum mismatch");
        }
        if volume_bytes > src.size() {
            diag.warn(
                DiagCode::Inconsistent,
                format!("the volume is {volume_bytes} bytes, the source only {}", src.size()),
            );
        }
        let page_clusters = (MIN_NODE_BYTES / cluster).max(1) as usize;
        // The volume signature is only known after the superblock; the superblock does not
        // need it.
        let boot_reader = PageReader::new(src.clone(), cluster, clusters, page_clusters, 0, integrity.clone());
        let sb = pick_superblock(&boot_reader, clusters, &diag)?;
        let reader = PageReader::new(src, cluster, clusters, page_clusters, sb.volume_signature(), integrity);

        let (cp, tables) = choose_checkpoint(&reader, &sb, clusters, &limits, &diag)?;
        let Tables { reader, map, extra, sub_free } = tables;
        let extra = fixed_metadata(extra, &sb, u64::from(cluster), clusters, volume_bytes);

        Ok(RefsFs {
            info: FsInfo::new(
                FsKind::Refs,
                u64::from(cluster),
                volume_bytes,
                None,
                Some(format!("{:016X}", boot.serial)),
            ),
            boot,
            sb,
            cp,
            reader,
            map,
            clusters,
            extra,
            sub_free,
            limits,
            diag,
            objects: std::sync::OnceLock::new(),
            security: std::sync::OnceLock::new(),
            log: std::sync::OnceLock::new(),
            listed: Default::default(),
        })
    }
}

/// The newest checkpoint whose tables load, with them; the others tried are reported.
fn choose_checkpoint(
    reader: &PageReader,
    sb: &Superblock,
    clusters: u64,
    limits: &Limits,
    diag: &Diagnostics,
) -> Result<(Checkpoint, Tables)> {
    let mut cps: Vec<Checkpoint> = Vec::new();
    let mut why: Vec<String> = Vec::new();
    let mut checksum_bad = false;
    let cluster = u64::from(reader.cluster_bytes());
    for &lcn in &sb.checkpoints {
        let site = Site::new(StructureKind::RefsCheckpoint).at(lcn * cluster);
        match reader.read_cluster(lcn).and_then(|b| Checkpoint::parse(&b, lcn, sb.volume_signature())) {
            Ok(cp) if !reader.integrity().ok(Role::Select, site, || cp.verdict) => {
                checksum_bad = true;
                why.push(format!("at LCN {lcn:#x}: checksum mismatch"));
            }
            Ok(cp) => cps.push(cp),
            Err(e) if e.scope() != Scope::Unit => return Err(e),
            Err(e) => why.push(format!("at LCN {lcn:#x}: {e}")),
        }
    }
    cps.sort_by_key(|c| std::cmp::Reverse(c.clock));
    let mut chosen = None;
    for (n, cp) in cps.into_iter().enumerate() {
        match load_tables(reader, &cp, clusters, limits, diag) {
            Ok(t) => {
                chosen = Some((cp, t, n));
                break;
            }
            Err(e) if e.scope() != Scope::Unit => return Err(e),
            Err(e) => why.push(format!("checkpoint at LCN {:#x} (clock {}): {e}", cp.lcn, cp.clock)),
        }
    }
    let Some((cp, tables, n)) = chosen else {
        return Err(Error::corrupt(format!("no usable ReFS checkpoint ({})", why.join("; "))));
    };
    if n > 0 || !why.is_empty() {
        let code = match (n > 0, checksum_bad) {
            (true, _) => DiagCode::BackupUsed,
            (false, true) => DiagCode::ChecksumMismatch,
            (false, false) => DiagCode::Inconsistent,
        };
        diag.warn(code, format!("using the checkpoint at LCN {:#x} ({})", cp.lcn, why.join("; ")));
    }
    Ok((cp, tables))
}

/// The volume's fixed metadata (bytes): the tables' `extra`, the boot area up to the
/// superblock, the superblock backups, the backup boot sector and whatever follows the last
/// cluster, and the checkpoints.
fn fixed_metadata(
    mut extra: Vec<ByteRange>,
    sb: &Superblock,
    c: u64,
    clusters: u64,
    volume_bytes: u64,
) -> Vec<ByteRange> {
    extra.push(ByteRange::new(0, (SUPERBLOCK_LCN + 1) * c));
    extra.push(ByteRange::new((clusters - 3) * c, volume_bytes - (clusters - 3) * c));
    for &l in &sb.checkpoints {
        if l < clusters {
            extra.push(ByteRange::new(l * c, c));
        }
    }
    sort_coalesce(extra)
}
