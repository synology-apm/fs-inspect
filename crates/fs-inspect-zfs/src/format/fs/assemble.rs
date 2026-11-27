//! Assembling the pool from the leaves at hand: the device's label, the other leaves given with
//! it, the best readable uberblock and its MOS, the pool configuration (topology, members) and
//! the features in use.

use super::ZfsFs;
use crate::format::auxdev;
use crate::format::blkptr::VDEV_DATA_OFFSET;
use crate::format::dnode::ot;
use crate::format::dsl::mos_object;
use crate::format::label::{self, LABEL_SIZE, Leaf, RING_OFFSET, Uberblock};
use crate::format::nvlist::{self, NvList};
use crate::format::objset::{Objset, read_data};
use crate::format::pool::{Geometry, Leaf as Given, VdevMap};
use crate::format::raidz::Raidz;
use crate::format::reader::BlockReader;
use crate::format::zap;
use fs_inspect_core::FsInfoExt;
use fs_inspect_core::Scope;
use fs_inspect_core::{DiagCode, Diagnostics, DriverContext, Error, FsInfo, FsKind, Limits, MemberRole, Result};
use std::collections::BTreeMap;

/// Uberblocks tried, best first, before giving up on the MOS.
const MAX_UBERBLOCKS: usize = 8;

/// Features this driver reads correctly when active (read-incompatible and read-only
/// compatible ones alike: several of the latter change how space is accounted). Any other
/// active feature makes the pool unsupported.
pub const KNOWN_FEATURES: &[&str] = &[
    "com.delphix:async_destroy",
    "com.delphix:empty_bpobj",
    "org.illumos:lz4_compress",
    "com.joyent:multi_vdev_crash_dump",
    "com.delphix:spacemap_histogram",
    "com.delphix:enabled_txg",
    "com.delphix:hole_birth",
    "com.delphix:zpool_checkpoint",
    "com.delphix:spacemap_v2",
    "com.delphix:extensible_dataset",
    "com.delphix:bookmarks",
    "com.joyent:filesystem_limits",
    "com.delphix:embedded_data",
    "org.open-zfs:large_blocks",
    "org.zfsonlinux:large_dnode",
    "org.illumos:sha512",
    "org.illumos:skein",
    "org.illumos:edonr",
    "com.delphix:redaction_bookmarks",
    "com.delphix:redacted_datasets",
    "com.delphix:bookmark_written",
    "com.delphix:log_spacemap",
    "com.delphix:livelist",
    "com.delphix:device_removal",
    "com.delphix:obsolete_counts",
    "org.zfsonlinux:userobj_accounting",
    "com.datto:bookmark_v2",
    "com.datto:encryption",
    "org.zfsonlinux:project_quota",
    "org.zfsonlinux:allocation_classes",
    "com.datto:resilver_defer",
    "org.openzfs:device_rebuild",
    "org.freebsd:zstd_compress",
    "org.openzfs:draid",
    "org.openzfs:zilsaxattr",
    "com.delphix:head_errlog",
    "org.openzfs:blake3",
    "com.fudosecurity:block_cloning",
    "com.klarasystems:vdev_zaps_v2",
    "com.delphix:redaction_list_spill",
    "org.openzfs:raidz_expansion",
    "com.klarasystems:fast_dedup",
    "org.openzfs:longname",
    "com.klarasystems:large_microzap",
    "com.truenas:block_cloning_endian",
    "com.klarasystems:dynamic_gang_header",
    "com.truenas:physical_rewrite",
];

/// The pool and this device's place in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pool {
    pub name: String,
    pub version: u64,
    pub pool_guid: u64,
    /// This device (leaf vdev).
    pub guid: u64,
    /// Its top-level vdev.
    pub top_guid: u64,
    pub top_id: u64,
    /// `disk`, `file`, `mirror` or `raidz`.
    pub top_type: String,
    /// The top-level vdev is a log device (SLOG).
    pub is_log: bool,
    /// Top-level vdevs of the pool (holes left out).
    pub tops: usize,
    pub ashift: u32,
    /// Allocatable bytes of the top-level vdev (from its children's 4 MiB data start).
    pub asize: u64,
    pub ms_shift: u32,
    pub ms_array: u64,
    pub top_zap: u64,
    /// Children of a mirror or raidz vdev (this device among them; 1 for a disk or a file).
    pub width: usize,
    /// The raidz shape of the top-level vdev, if it is one.
    pub raidz: Option<Raidz>,
    /// This device's place among the children.
    pub child: usize,
    /// Why the pool does not use this device (offline, faulted, removed), if it does not.
    pub down: Option<&'static str>,
    /// Every device the pool's configuration names, and whether it is at hand.
    pub members: Vec<Member>,
}

/// A device of the pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub guid: u64,
    /// What it is in the pool: a leaf of a top-level vdev, a cache or a spare.
    pub role: MemberRole,
    /// The path the pool last opened it by.
    pub path: Option<String>,
    /// Given and used for reading.
    pub present: bool,
}

/// The state of a pool's devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolStatus {
    /// Every device given.
    Complete,
    /// Devices missing or down, every top-level vdev readable through redundancy.
    Degraded,
}

/// A top-level vdev's type as `zpool status` names it (`mirror`, `raidz2`, `disk`).
pub(crate) fn vdev_layout(c: &NvList) -> String {
    let ty = c.str("type").unwrap_or_default();
    match c.u64("nparity") {
        Some(p) if ty == "raidz" => format!("raidz{p}"),
        _ => ty.to_string(),
    }
}

impl Pool {
    pub fn status(&self) -> PoolStatus {
        if self.members.iter().filter(|m| !matches!(m.role, MemberRole::Cache | MemberRole::Spare)).all(|m| m.present) {
            PoolStatus::Complete
        } else {
            PoolStatus::Degraded
        }
    }
}

fn nv_err(what: &str) -> Error {
    Error::corrupt(format!("ZFS configuration without {what}"))
}

/// The MOS read from an uberblock: the objset, its object directory and the pool configuration.
struct Mos {
    objset: Objset,
    dir: BTreeMap<String, Vec<u64>>,
    config: NvList,
    /// The pool's spare and cache devices (`spares`, `l2cache`): the configuration does not
    /// hold them, objects of their own in the object directory do.
    aux: Vec<NvList>,
}

/// What the label of the device being opened says of it and its pool, checked.
struct Own {
    version: u64,
    guid: u64,
    top_guid: u64,
    pool_guid: u64,
    /// The pool's name (empty: not in the label).
    name: String,
    /// Top-level vdevs of the pool, when the label says.
    children: Option<u64>,
    top_id: u64,
    ashift: u64,
    /// Allocatable bytes of its top-level vdev, as the label has them.
    asize: u64,
    geometry: Geometry,
    /// Its place among the children of its top-level vdev.
    child: usize,
}

impl Own {
    fn read(own: &Leaf, diag: &Diagnostics) -> Result<Own> {
        let cfg = &own.cfg;
        match own.state() {
            auxdev::STATE_SPARE => return Err(Error::unsupported("ZFS hot spare device (no pool data)")),
            auxdev::STATE_L2CACHE => return Err(Error::unsupported("ZFS cache device (L2ARC, no pool data)")),
            2 => diag.info(DiagCode::Inconsistent, "the pool was destroyed (zpool destroy)"),
            _ => {}
        }
        let version = cfg.u64("version").ok_or_else(|| nv_err("version"))?;
        if version != label::VERSION_FEATURES && !(1..=label::VERSION_MAX_LEGACY).contains(&version) {
            return Err(Error::unsupported(format!("ZFS pool version {version}")));
        }
        let guid = cfg.u64("guid").ok_or_else(|| nv_err("guid"))?;
        let ltop = cfg.list("vdev_tree").ok_or_else(|| nv_err("vdev_tree"))?;
        layout_supported(ltop)?;
        let top_id = ltop.u64("id").ok_or_else(|| nv_err("vdev id"))?;
        let ashift = ltop.u64("ashift").ok_or_else(|| nv_err("ashift"))?;
        if !(9..=16).contains(&ashift) {
            return Err(Error::corrupt(format!("ashift {ashift}")));
        }
        if top_id > 0xff_ffff {
            return Err(Error::corrupt(format!("vdev id {top_id}")));
        }
        Ok(Own {
            version,
            guid,
            top_guid: cfg.u64("top_guid").ok_or_else(|| nv_err("top_guid"))?,
            pool_guid: cfg.u64("pool_guid").ok_or_else(|| nv_err("pool_guid"))?,
            name: cfg.str("name").unwrap_or_default().to_string(),
            children: cfg.u64("vdev_children"),
            top_id,
            ashift,
            asize: ltop.u64("asize").unwrap_or(0),
            geometry: shape(ltop)?,
            child: child_of(ltop, guid).ok_or_else(|| Error::corrupt("the device is not in its label's vdev tree"))?,
        })
    }
}

impl ZfsFs {
    /// Opened up to the topology and features: no metaslabs or intent logs yet.
    pub(super) fn open_pool(own: Leaf, ctx: &DriverContext) -> Result<Self> {
        let limits = ctx.limits.clone();
        let diag = ctx.diagnostics.clone();
        own.warn(&diag);
        let len = own.src.size();
        let o = Own::read(&own, &diag)?;
        let (mut vdevs, leaves) = gather(own, &o, ctx)?;
        let ubs = uberblocks(&leaves)?;
        let integrity = ctx.integrity();
        let reader = BlockReader::new(vdevs.clone(), None, diag.clone(), integrity.clone())
            .with_max_cache_bytes(ctx.max_cache_bytes);
        let (ub, mos) = newest_mos(&reader, &ubs, &limits, &diag)
            .map_err(|e| if e.scope() == Scope::Unit { not_given(&vdevs, &o).unwrap_or(e) } else { e })?;
        if ub.version != o.version
            && !(ub.version <= label::VERSION_MAX_LEGACY || ub.version == label::VERSION_FEATURES)
        {
            return Err(Error::unsupported(format!("ZFS pool version {}", ub.version)));
        }
        let tops = top_level_vdevs(&mos.config, &ub, &diag)?;
        let pool = place(&o, &mos.config, &mos.aux, &tops, &mut vdevs, &diag)?;
        let aligned = label::aligned_size(len);
        let held = match pool.raidz {
            Some(g) => g.child_range(pool.child, 0, pool.asize).map_or(0, |r| r.1),
            None => pool.asize,
        };
        if VDEV_DATA_OFFSET.saturating_add(held).saturating_add(2 * LABEL_SIZE) > aligned {
            diag.warn(
                DiagCode::Inconsistent,
                format!("the vdev holds {held} allocatable bytes of this device, more than the {len}-byte volume"),
            );
        }
        let features = features(&reader, &mos, &tops)?;
        // With dynamic gang headers a gang header takes one sector, up to 8 KiB.
        let gang = features.contains_key("com.klarasystems:dynamic_gang_header").then(|| 1usize << o.ashift.min(13));
        let reader = BlockReader::new(vdevs, gang, diag.clone(), integrity).with_max_cache_bytes(ctx.max_cache_bytes);
        let info = FsInfo::new(
            FsKind::Zfs,
            1 << o.ashift,
            aligned,
            Some(pool.name.clone()).filter(|n| !n.is_empty()),
            Some(format!("{}", o.pool_guid)),
        );
        Ok(ZfsFs {
            info,
            reader,
            ub,
            pool,
            mos: mos.objset,
            dir: mos.dir,
            features,
            metaslabs: Vec::new(),
            zil: Vec::new(),
            zil_pending: Vec::new(),
            zil_datasets: Vec::new(),
            limits,
            diag,
            ns: std::sync::OnceLock::new(),
            overlay: None,
            touched: std::sync::OnceLock::new(),
            scratch: ctx.scratch.clone(),
        })
    }
}

/// The leaves of the pool at hand: the device being opened and, among the volumes given with
/// it, the other leaves of its pool (spare and cache devices hold no pool data), with their
/// ashift.
fn gather(own: Leaf, o: &Own, ctx: &DriverContext) -> Result<(VdevMap, Vec<(Leaf, u64)>)> {
    let mut vdevs = VdevMap::default();
    vdevs.add(o.top_id, o.geometry, o.asize, Given { guid: o.guid, child: o.child, src: own.src.clone() });
    let mut leaves = vec![(own, o.ashift)];
    for p in ctx.peers.as_ref().map(|p| p.volumes(FsKind::Zfs)).unwrap_or_default() {
        let Ok(l) = Leaf::read(p.clone()) else { continue };
        let Some((id, a)) = l.top() else { continue };
        if l.cfg.u64("pool_guid") != Some(o.pool_guid)
            || matches!(l.state(), auxdev::STATE_SPARE | auxdev::STATE_L2CACHE)
            || !(9..=16).contains(&a)
        {
            continue;
        }
        // A dRAID vdev anywhere in the pool: no use reading further.
        let Some(t) = l.cfg.list("vdev_tree") else { continue };
        layout_supported(t)?;
        let Some(g) = l.cfg.u64("guid") else { continue };
        let (Ok(geometry), Some(child)) = (shape(t), child_of(t, g)) else { continue };
        if vdevs.add(id, geometry, t.u64("asize").unwrap_or(0), Given { guid: g, child, src: p }) {
            leaves.push((l, a));
        }
    }
    Ok((vdevs, leaves))
}

/// The uberblocks of every label of every leaf, best first: a transaction group writes its
/// uberblock to some of the leaves only.
fn uberblocks(leaves: &[(Leaf, u64)]) -> Result<Vec<Uberblock>> {
    let mut ubs = Vec::new();
    for (leaf, ashift) in leaves {
        let slot = label::slot_size(*ashift);
        for (l, ring) in leaf.rings.iter().enumerate() {
            if ring.is_empty() {
                continue;
            }
            let ring_off = label::label_offset(leaf.src.size(), l) + RING_OFFSET;
            if label::has_big_endian_uberblock(ring, slot) {
                return Err(Error::unsupported("big-endian ZFS pool"));
            }
            ubs.extend(label::ring_uberblocks(ring, ring_off, slot));
        }
    }
    label::sort_best_first(&mut ubs);
    ubs.dedup_by(|a, b| a.txg == b.txg && a.rootbp == b.rootbp);
    if ubs.is_empty() {
        return Err(Error::corrupt("no valid uberblock"));
    }
    Ok(ubs)
}

/// The MOS of the best uberblock it can be read from (the first [`MAX_UBERBLOCKS`]); damage
/// when none.
fn newest_mos(r: &BlockReader, ubs: &[Uberblock], limits: &Limits, diag: &Diagnostics) -> Result<(Uberblock, Mos)> {
    let mut last = None;
    for (i, ub) in ubs.iter().take(MAX_UBERBLOCKS).enumerate() {
        match read_mos(r, ub, limits) {
            Ok(m) => {
                if i > 0 {
                    diag.warn(
                        DiagCode::BackupUsed,
                        format!("using uberblock txg {} (newer ones lead to unreadable metadata)", ub.txg),
                    );
                }
                return Ok((ub.clone(), m));
            }
            Err(e) if e.scope() == Scope::Unit => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| Error::corrupt("no readable MOS")))
}

/// Why no MOS could be read, when it is devices not given: a raidz vdev with too few children
/// to rebuild its blocks from, or top-level vdevs missing.
fn not_given(vdevs: &VdevMap, o: &Own) -> Option<Error> {
    for (id, top) in vdevs.iter() {
        if let Geometry::Raidz(g) = top.geometry
            && top.leaves.len() < g.width - g.nparity
        {
            return Some(Error::unavailable(format!(
                "ZFS pool {} spans top-level vdevs not given: {id} (raidz{}, {} of {} devices; give every device of the pool)",
                o.name,
                g.nparity,
                top.leaves.len(),
                g.width
            )));
        }
    }
    let children = o.children.unwrap_or(0);
    ((vdevs.tops() as u64) < children).then(|| {
        Error::unavailable(format!(
            "ZFS pool {} spans top-level vdevs not given: it has {children} top-level vdevs, {} given (give every device of the pool)",
            o.name,
            vdevs.tops()
        ))
    })
}

/// The top-level vdevs of the pool configuration in the MOS (the labels hold only their own),
/// by id, holes left out. Every one is a disk, a file or a mirror or raidz vdev of them.
fn top_level_vdevs<'a>(config: &'a NvList, ub: &Uberblock, diag: &Diagnostics) -> Result<BTreeMap<u64, &'a NvList>> {
    let root = config.list("vdev_tree").ok_or_else(|| nv_err("vdev_tree in the MOS"))?;
    let children = root.lists("children").ok_or_else(|| nv_err("top-level vdevs"))?;
    let mut tops = BTreeMap::new();
    for c in children.iter().filter(|c| c.str("type") != Some("hole")) {
        layout_supported(c)?;
        let id = c.u64("id").ok_or_else(|| nv_err("vdev id"))?;
        if tops.insert(id, c).is_some() {
            return Err(Error::corrupt(format!("two top-level vdevs with id {id}")));
        }
    }
    if guid_sum(root, 0) != ub.guid_sum {
        diag.warn(DiagCode::Inconsistent, "the uberblock's guid sum is not the pool configuration's");
    }
    Ok(tops)
}

/// The pool and this device's place in it, as the configuration has them and as the label
/// says; `vdevs` keeps only the leaves the pool uses.
fn place(
    o: &Own,
    config: &NvList,
    aux: &[NvList],
    tops: &BTreeMap<u64, &NvList>,
    vdevs: &mut VdevMap,
    diag: &Diagnostics,
) -> Result<Pool> {
    let not_the_pools = || Error::corrupt("the label's top-level vdev is not the pool's");
    let top = *tops.get(&o.top_id).ok_or_else(not_the_pools)?;
    if top.u64("guid") != Some(o.top_guid) || shape(top)? != o.geometry {
        return Err(not_the_pools());
    }
    let top_type = top.str("type").unwrap_or_default().to_string();
    let width = match top.lists("children") {
        Some(kids) if matches!(top_type.as_str(), "mirror" | "raidz") => {
            if child_of(top, o.guid) != Some(o.child) {
                return Err(Error::corrupt(format!("the device is not where its label puts it in its {top_type}")));
            }
            kids.len()
        }
        _ => {
            if o.top_guid != o.guid {
                return Err(Error::corrupt("a single-device vdev whose guid is not the device's"));
            }
            1
        }
    };
    let pool_name = config.str("name").unwrap_or(&o.name).to_string();
    let down = keep_used(vdevs, tops, top, o.guid, &pool_name, diag);
    let members = members(config, aux, tops, vdevs, &pool_name, diag)?;
    let asize = top.u64("asize").ok_or_else(|| nv_err("asize"))?;
    let ms_shift = top.u64("metaslab_shift").ok_or_else(|| nv_err("metaslab_shift"))?;
    if !(16..=40).contains(&ms_shift) || top.u64("ashift") != Some(o.ashift) {
        return Err(Error::corrupt(format!("metaslab shift {ms_shift}")));
    }
    Ok(Pool {
        name: if o.name.is_empty() { pool_name } else { o.name.clone() },
        version: o.version,
        pool_guid: o.pool_guid,
        guid: o.guid,
        top_guid: o.top_guid,
        top_id: o.top_id,
        top_type,
        is_log: top.u64("is_log") == Some(1),
        tops: tops.len(),
        ashift: o.ashift as u32,
        asize,
        ms_shift: ms_shift as u32,
        ms_array: top.u64("metaslab_array").unwrap_or(0),
        top_zap: top.u64("com.delphix:vdev_zap_top").unwrap_or(0),
        width,
        raidz: match o.geometry {
            Geometry::Raidz(g) => Some(g),
            Geometry::Plain => None,
        },
        child: o.child,
        down,
        members,
    })
}

/// Keep in `vdevs` the leaves given that are where the configuration puts them and that the
/// pool uses (not offline, faulted, removed). Why this device (`guid`, of `top`) is not used,
/// if it is not.
fn keep_used(
    vdevs: &mut VdevMap,
    tops: &BTreeMap<u64, &NvList>,
    top: &NvList,
    guid: u64,
    pool_name: &str,
    diag: &Diagnostics,
) -> Option<&'static str> {
    let given = vdevs.count();
    vdevs.retain(|id, leaf| {
        tops.get(&id).is_some_and(|c| {
            child_of(c, leaf.guid) == Some(leaf.child) && find_guid(c, leaf.guid, 0).is_some_and(|l| down(l).is_none())
        })
    });
    let own_down = find_guid(top, guid, 0).and_then(down);
    if let Some(why) = own_down {
        diag.warn(DiagCode::ContainerDegraded, format!("this device is {why} in pool {pool_name}"));
    }
    if vdevs.count() + usize::from(own_down.is_some()) < given {
        diag.info(
            DiagCode::Inconsistent,
            format!(
                "{} of the devices given are not in pool {pool_name}'s configuration or not in use",
                given - vdevs.count()
            ),
        );
    }
    own_down
}

/// Every device the configuration names and whether it is at hand. Each top-level vdev needs
/// one leaf, a raidz vdev all but its parity count: unsupported when it has fewer; degraded
/// (a warning) when a leaf is missing still.
fn members(
    config: &NvList,
    aux: &[NvList],
    tops: &BTreeMap<u64, &NvList>,
    vdevs: &VdevMap,
    pool_name: &str,
    diag: &Diagnostics,
) -> Result<Vec<Member>> {
    let mut missing = Vec::new();
    let mut members = Vec::new();
    for (id, c) in tops {
        let leaves = leaves_of(c);
        let at_hand = vdevs.leaves(*id).len();
        let need = match shape(c)? {
            Geometry::Raidz(g) => g.width - g.nparity,
            Geometry::Plain => 1,
        };
        if at_hand < need {
            missing.push(format!("{id} ({}, {at_hand} of {} devices)", c.u64("guid").unwrap_or(0), leaves.len()));
        }
        let layout = vdev_layout(c);
        let log = c.u64("is_log") == Some(1);
        for (i, l) in leaves.iter().enumerate() {
            let g = l.u64("guid").unwrap_or(0);
            let child = c.lists("children").map(|_| i as u32);
            let role = MemberRole::Vdev { top: *id, layout: layout.clone(), child, log };
            let present = vdevs.leaves(*id).iter().any(|x| x.guid == g);
            members.push(Member { guid: g, role, path: l.str("path").map(str::to_string), present });
        }
    }
    for (key, role) in [("l2cache", MemberRole::Cache), ("spares", MemberRole::Spare)] {
        let listed = std::iter::once(config).chain(aux).flat_map(|n| n.lists(key).unwrap_or_default());
        for l in listed {
            let g = l.u64("guid").unwrap_or(0);
            // Cache and spare devices open on their own (labels only), never read here.
            let present = false;
            members.push(Member { guid: g, role: role.clone(), path: l.str("path").map(str::to_string), present });
        }
    }
    if !missing.is_empty() {
        return Err(Error::unavailable(format!(
            "ZFS pool {pool_name} spans top-level vdevs not given: {} (give every device of the pool)",
            missing.join(", ")
        )));
    }
    let absent: Vec<String> = members
        .iter()
        .filter(|m| !m.present && !matches!(m.role, MemberRole::Cache | MemberRole::Spare))
        .map(|m| format!("{} ({})", m.guid, m.role))
        .collect();
    if !absent.is_empty() {
        diag.warn(
            DiagCode::ContainerDegraded,
            format!(
                "pool {pool_name} is degraded, read through redundancy: {} not given or not in use",
                absent.join(", ")
            ),
        );
    }
    Ok(members)
}

/// The features in use (a non-zero count in `features_for_read` or `features_for_write`);
/// unsupported when one is not in [`KNOWN_FEATURES`], or when a raidz vdev was expanded (or is
/// expanding: older blocks keep their old width).
fn features(r: &BlockReader, mos: &Mos, tops: &BTreeMap<u64, &NvList>) -> Result<BTreeMap<String, u64>> {
    let mut features = BTreeMap::new();
    for key in ["features_for_read", "features_for_write"] {
        if let Some(obj) = mos.dir.get(key).and_then(|v| v.first().copied()) {
            let z = mos_object(r, &mos.objset, obj)?;
            for e in zap::entries(r, &z, 4096)? {
                if e.first().unwrap_or(0) > 0 {
                    features.insert(e.name_str(), e.first().unwrap_or(0));
                }
            }
        }
    }
    if let Some(f) = features.keys().find(|f| !KNOWN_FEATURES.contains(&f.as_str())) {
        return Err(Error::unsupported(format!("ZFS feature {f}")));
    }
    if features.contains_key("org.openzfs:raidz_expansion") && tops.values().any(|c| c.str("type") == Some("raidz")) {
        return Err(Error::unsupported("expanded ZFS raidz vdev (its blocks have several widths)"));
    }
    Ok(features)
}

/// Refuse a top-level vdev (from a label or the pool configuration) other than a disk, a file,
/// or a mirror or raidz vdev of them: dRAID, indirect (device removal), a raidz vdev that was
/// expanded (its blocks have several widths), a resilver or a spare in use.
fn layout_supported(top: &NvList) -> Result<()> {
    let ty = top.str("type").unwrap_or_default();
    match ty {
        "disk" | "file" | "hole" => Ok(()),
        "mirror" | "raidz" => {
            for k in top.lists("children").ok_or_else(|| nv_err("children"))? {
                let t = k.str("type").unwrap_or_default();
                if !matches!(t, "disk" | "file") {
                    return Err(Error::unsupported(format!("ZFS {ty} with a {t} child (resilver or spare in use)")));
                }
            }
            if ty == "raidz" && top.get("raidz_expand_txgs").is_some() {
                return Err(Error::unsupported("expanded ZFS raidz vdev (its blocks have several widths)"));
            }
            shape(top).map(|_| ())
        }
        t => Err(Error::unsupported(format!("ZFS {t} vdev"))),
    }
}

/// How top-level vdev `top` (a vdev tree) spreads its space over its children.
fn shape(top: &NvList) -> Result<Geometry> {
    if top.str("type") != Some("raidz") {
        return Ok(Geometry::Plain);
    }
    let width = top.lists("children").ok_or_else(|| nv_err("raidz children"))?.len();
    let nparity = top.u64("nparity").ok_or_else(|| nv_err("nparity"))?;
    let ashift = top.u64("ashift").ok_or_else(|| nv_err("ashift"))?;
    if !(1..=3).contains(&nparity) || width <= nparity as usize || width > 255 || !(9..=16).contains(&ashift) {
        return Err(Error::corrupt(format!("raidz{nparity} vdev of {width} children, ashift {ashift}")));
    }
    Ok(Geometry::Raidz(Raidz { nparity: nparity as usize, width, ashift: ashift as u32 }))
}

/// Where leaf `guid` is among the children of top-level vdev `top` (0 for a disk or a file).
fn child_of(top: &NvList, guid: u64) -> Option<usize> {
    match top.lists("children") {
        Some(kids) => kids.iter().position(|k| k.u64("guid") == Some(guid)),
        None => (top.u64("guid") == Some(guid)).then_some(0),
    }
}

/// The leaf vdevs of top-level vdev `top` (itself for a disk or a file).
fn leaves_of(top: &NvList) -> Vec<&NvList> {
    match top.lists("children") {
        Some(kids) => kids.iter().collect(),
        None => vec![top],
    }
}

/// Why the pool does not use leaf `l` (offline, faulted, removed), if it does not.
fn down(l: &NvList) -> Option<&'static str> {
    [("offline", "offline"), ("faulted", "faulted"), ("removed", "removed")]
        .into_iter()
        .find(|(k, _)| l.u64(k).is_some_and(|v| v != 0))
        .map(|(_, why)| why)
}

/// The sum of the guids of `tree` and every vdev under it (what an uberblock's `guid_sum` is
/// for the pool's root vdev).
fn guid_sum(tree: &NvList, depth: usize) -> u64 {
    let kids = if depth > 8 { None } else { tree.lists("children") };
    kids.into_iter().flatten().fold(tree.u64("guid").unwrap_or(0), |s, c| s.wrapping_add(guid_sum(c, depth + 1)))
}

/// The child of `tree` with guid `guid`, searched depth first.
fn find_guid(tree: &NvList, guid: u64, depth: usize) -> Option<&NvList> {
    if tree.u64("guid") == Some(guid) {
        return Some(tree);
    }
    if depth > 8 {
        return None;
    }
    tree.lists("children")?.iter().find_map(|c| find_guid(c, guid, depth + 1))
}

/// The MOS, its object directory and the pool configuration, from uberblock `ub`.
fn read_mos(r: &BlockReader, ub: &Uberblock, limits: &Limits) -> Result<Mos> {
    let mos = Objset::read(r, &ub.rootbp).map_err(|e| e.at("MOS", ub.offset))?;
    if mos.ty != crate::format::objset::ost::META {
        return Err(Error::corrupt(format!("MOS of type {}", mos.ty)));
    }
    let d = mos_object(r, &mos, 1)?;
    if d.ty != ot::OBJECT_DIRECTORY {
        return Err(Error::corrupt(format!("MOS object directory of type {}", d.ty)));
    }
    let mut dir = BTreeMap::new();
    for e in zap::entries(r, &d, limits.max_dir_entries)? {
        dir.insert(e.name_str(), e.values);
    }
    let object = |name: &str| dir.get(name).and_then(|v| v.first().copied());
    let cfg_obj = object("config").ok_or_else(|| nv_err("MOS config"))?;
    let config = packed_nvlist(r, &mos, cfg_obj, limits, "config")?;
    // The spare and cache devices: what the pool lists of them, not needed to read it.
    let aux = ["spares", "l2cache"]
        .into_iter()
        .filter_map(|name| packed_nvlist(r, &mos, object(name)?, limits, name).ok())
        .collect();
    Ok(Mos { objset: mos, dir, config, aux })
}

/// MOS object `obj`, a packed name-value list (`what` names it in errors), decoded.
fn packed_nvlist(r: &BlockReader, mos: &Objset, obj: u64, limits: &Limits, what: &str) -> Result<NvList> {
    let c = mos_object(r, mos, obj)?;
    if c.ty != ot::PACKED_NVLIST {
        return Err(Error::corrupt(format!("MOS {what} object of type {}", c.ty)));
    }
    let size = fs_inspect_core::bytes::u64_at(&c.bonus, 0)?;
    if size > c.data_bytes() || size > limits.max_alloc {
        return Err(Error::corrupt(format!("packed {what} of {size} bytes")));
    }
    nvlist::decode(&read_data(r, &c, 0, size as usize)?)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::format::blkptr::BlkPtr;
    use crate::format::nvlist::Value;
    use crate::format::nvlist::encode::nv;
    use fs_inspect_core::ErrorKind;
    use fs_inspect_io::{DynSource, MemSource};
    use std::sync::Arc;

    fn s(v: &str) -> Value {
        Value::Str(v.into())
    }

    fn leaf(ty: &str, guid: u64) -> NvList {
        nv(vec![("type", s(ty)), ("guid", Value::U64(guid)), ("path", s(&format!("/dev/d{guid}")))])
    }

    fn top(ty: &str, id: u64, guid: u64, kids: Vec<NvList>, extra: Vec<(&str, Value)>) -> NvList {
        let mut p =
            vec![("type", s(ty)), ("id", Value::U64(id)), ("guid", Value::U64(guid)), ("ashift", Value::U64(12))];
        if !kids.is_empty() {
            p.push(("children", Value::Lists(kids)));
        }
        p.extend(extra);
        nv(p)
    }

    fn raidz(nparity: u64, width: u64) -> NvList {
        let kids = (0..width).map(|i| leaf("disk", 100 + i)).collect();
        top("raidz", 0, 10, kids, vec![("nparity", Value::U64(nparity))])
    }

    fn set(l: &mut NvList, name: &str, v: Option<Value>) {
        l.pairs.retain(|p| p.0 != name);
        if let Some(v) = v {
            l.pairs.push((name.to_string(), v));
        }
    }

    fn src() -> DynSource {
        Arc::new(MemSource::new(vec![0u8; 1 << 20]))
    }

    fn given(guid: u64, child: usize) -> Given {
        Given { guid, child, src: src() }
    }

    fn warnings(d: &Diagnostics) -> Vec<String> {
        d.all().into_iter().map(|d| d.message).collect()
    }

    /// Disks, files, holes, and mirrors and raidz vdevs of them are read; everything else is
    /// refused as unsupported, a vdev missing what its type needs as damage.
    #[test]
    fn only_plain_mirror_and_raidz_layouts_are_supported() {
        for t in ["disk", "file", "hole"] {
            assert!(layout_supported(&leaf(t, 1)).is_ok(), "{t}");
        }
        let mirror = |kid: &str| top("mirror", 0, 9, vec![leaf("disk", 1), leaf(kid, 2)], vec![]);
        assert!(layout_supported(&mirror("file")).is_ok());
        assert_eq!(layout_supported(&mirror("spare")).unwrap_err().kind(), ErrorKind::Unsupported);
        assert_eq!(layout_supported(&mirror("replacing")).unwrap_err().kind(), ErrorKind::Unsupported);
        assert_eq!(layout_supported(&top("mirror", 0, 9, vec![], vec![])).unwrap_err().kind(), ErrorKind::Corrupt);
        assert!(layout_supported(&raidz(1, 3)).is_ok());
        let mut expanded = raidz(1, 3);
        set(&mut expanded, "raidz_expand_txgs", Some(Value::Other(0)));
        assert_eq!(layout_supported(&expanded).unwrap_err().kind(), ErrorKind::Unsupported);
        assert_eq!(layout_supported(&raidz(3, 3)).unwrap_err().kind(), ErrorKind::Corrupt);
        for t in ["draid", "indirect", ""] {
            assert_eq!(layout_supported(&leaf(t, 1)).unwrap_err().kind(), ErrorKind::Unsupported, "{t}");
        }
    }

    /// A raidz vdev's shape: parity 1 to 3, more children than parity, at most 255, an ashift
    /// of 9 to 16; anything else, or a field missing, is damage.
    #[test]
    fn raidz_shapes_are_checked() {
        assert_eq!(shape(&leaf("disk", 1)).unwrap(), Geometry::Plain);
        assert_eq!(shape(&raidz(2, 5)).unwrap(), Geometry::Raidz(Raidz { nparity: 2, width: 5, ashift: 12 }));
        for (p, w) in [(0, 3), (4, 6), (2, 2), (1, 256)] {
            assert!(shape(&raidz(p, w)).is_err(), "raidz{p} of {w}");
        }
        for a in [None, Some(8), Some(17)] {
            let mut t = raidz(1, 3);
            set(&mut t, "ashift", a.map(Value::U64));
            assert!(shape(&t).is_err(), "{a:?}");
        }
        let mut no_parity = raidz(1, 3);
        set(&mut no_parity, "nparity", None);
        assert!(shape(&no_parity).is_err());
        assert!(shape(&nv(vec![("type", s("raidz"))])).is_err());
    }

    /// The vdev tree helpers: a device's place, the leaves, why one is down, the guid sum and
    /// the search by guid (bounded in depth), and the layout's name.
    #[test]
    fn vdev_tree_helpers() {
        let m = top("mirror", 0, 9, vec![leaf("disk", 1), leaf("disk", 2)], vec![]);
        assert_eq!((child_of(&m, 2), child_of(&m, 3)), (Some(1), None));
        let d = leaf("disk", 5);
        assert_eq!((child_of(&d, 5), child_of(&d, 6)), (Some(0), None));
        assert_eq!(leaves_of(&m).len(), 2);
        assert_eq!(leaves_of(&d), [&d]);
        assert_eq!(down(&d), None);
        for k in ["offline", "faulted", "removed"] {
            let mut l = leaf("disk", 1);
            set(&mut l, k, Some(Value::U64(0)));
            assert_eq!(down(&l), None);
            set(&mut l, k, Some(Value::U64(1)));
            assert_eq!(down(&l), Some(k));
        }
        assert_eq!(guid_sum(&m, 0), 12);
        assert_eq!(find_guid(&m, 2, 0).and_then(|l| l.u64("guid")), Some(2));
        assert!(find_guid(&m, 7, 0).is_none());
        // Deeper than 8 levels is neither searched nor summed.
        let mut deep = leaf("disk", 77);
        for g in 0..10 {
            deep = top("mirror", 0, 1000 + g, vec![deep], vec![]);
        }
        assert!(find_guid(&deep, 77, 0).is_none());
        assert_eq!(guid_sum(&deep, 0), (1000..1010).sum::<u64>());
        assert_eq!(vdev_layout(&raidz(2, 4)), "raidz2");
        assert_eq!(vdev_layout(&m), "mirror");
        assert_eq!(vdev_layout(&nv(vec![])), "");
    }

    fn ub(guid_sum: u64) -> Uberblock {
        Uberblock {
            version: 5000,
            txg: 10,
            guid_sum,
            timestamp: 0,
            rootbp: BlkPtr::default(),
            checkpoint_txg: 0,
            offset: 0,
        }
    }

    fn config(tops: Vec<NvList>) -> NvList {
        nv(vec![("name", s("tank")), ("vdev_tree", Value::List(top("root", 0, 1, tops, vec![])))])
    }

    /// The configuration's top-level vdevs by id, holes left out; two with one id, one without
    /// an id, or none at all, is damage; a guid sum other than the uberblock's is reported.
    #[test]
    fn top_level_vdevs_of_the_configuration() {
        let diag = Diagnostics::new();
        let mut no_id = leaf("disk", 1);
        assert!(top_level_vdevs(&config(vec![no_id.clone()]), &ub(0), &diag).is_err());
        set(&mut no_id, "id", Some(Value::U64(0)));
        let c = config(vec![no_id, leaf("hole", 0), top("disk", 2, 3, vec![], vec![])]);
        let tops = top_level_vdevs(&c, &ub(1 + 1 + 3), &diag).unwrap();
        assert_eq!(tops.keys().copied().collect::<Vec<_>>(), [0, 2]);
        assert!(diag.is_empty());
        let _ = top_level_vdevs(&c, &ub(99), &diag).unwrap();
        assert_eq!(diag.len(), 1);
        let dup = config(vec![top("disk", 4, 1, vec![], vec![]), top("file", 4, 2, vec![], vec![])]);
        assert!(top_level_vdevs(&dup, &ub(0), &diag).unwrap_err().message().contains("two top-level vdevs"));
        assert!(top_level_vdevs(&nv(vec![]), &ub(0), &diag).is_err());
        let no_kids = nv(vec![("vdev_tree", Value::List(nv(vec![("guid", Value::U64(1))])))]);
        assert!(top_level_vdevs(&no_kids, &ub(0), &diag).is_err());
        let draid = config(vec![top("draid", 0, 1, vec![], vec![])]);
        assert_eq!(top_level_vdevs(&draid, &ub(0), &diag).unwrap_err().kind(), ErrorKind::Unsupported);
    }

    fn pool(members: Vec<Member>) -> Pool {
        Pool {
            name: String::new(),
            version: 5000,
            pool_guid: 0,
            guid: 0,
            top_guid: 0,
            top_id: 0,
            top_type: String::new(),
            is_log: false,
            tops: 0,
            ashift: 12,
            asize: 0,
            ms_shift: 0,
            ms_array: 0,
            top_zap: 0,
            width: 1,
            raidz: None,
            child: 0,
            down: None,
            members,
        }
    }

    /// Members: each leaf of each top-level vdev and whether it is at hand, then the cache and
    /// spare devices (never at hand); a raidz vdev short of more than its parity is not given,
    /// one short of a leaf is degraded.
    #[test]
    fn members_and_what_is_missing() {
        let rz = raidz(1, 3);
        let mirror = top("mirror", 1, 20, vec![leaf("disk", 21), leaf("disk", 22)], vec![("is_log", Value::U64(1))]);
        let tops: BTreeMap<u64, &NvList> = [(0, &rz), (1, &mirror)].into_iter().collect();
        let g = shape(&rz).unwrap();
        let mut vdevs = VdevMap::default();
        vdevs.add(0, g, 0, given(100, 0));
        vdevs.add(0, g, 0, given(101, 1));
        vdevs.add(1, Geometry::Plain, 0, given(21, 0));
        vdevs.add(1, Geometry::Plain, 0, given(22, 1));
        let cfg = nv(vec![("l2cache", Value::Lists(vec![leaf("disk", 30)]))]);
        let aux = [nv(vec![("spares", Value::Lists(vec![leaf("disk", 31)]))])];
        let diag = Diagnostics::new();
        let m = members(&cfg, &aux, &tops, &vdevs, "tank", &diag).unwrap();
        let summary: Vec<_> = m.iter().map(|m| (m.guid, m.present)).collect();
        assert_eq!(summary, [(100, true), (101, true), (102, false), (21, true), (22, true), (30, false), (31, false)]);
        assert!(matches!(m[3].role, MemberRole::Vdev { top: 1, log: true, child: Some(0), .. }));
        assert_eq!((m[5].role.clone(), m[6].role.clone()), (MemberRole::Cache, MemberRole::Spare));
        assert_eq!(m[6].path.as_deref(), Some("/dev/d31"));
        let w = warnings(&diag);
        assert!(w.len() == 1 && w[0].contains("degraded") && w[0].contains("102"), "{w:?}");
        assert_eq!(pool(m.clone()).status(), PoolStatus::Degraded);
        let complete: Vec<_> = m.into_iter().filter(|m| m.guid != 102).collect();
        assert_eq!(pool(complete).status(), PoolStatus::Complete);
        // One raidz leaf of three: the pool spans a vdev not given.
        let mut short = VdevMap::default();
        short.add(0, g, 0, given(100, 0));
        short.add(1, Geometry::Plain, 0, given(21, 0));
        let e = members(&cfg, &aux, &tops, &short, "tank", &Diagnostics::new()).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unavailable);
        assert!(e.message().contains("1 of 3 devices"), "{e}");
    }

    /// The leaves the configuration does not put where they say, or that are down, are
    /// dropped; this device down is reported and returned.
    #[test]
    fn keep_used_drops_leaves_out_of_place_or_down() {
        let mut off = leaf("disk", 2);
        set(&mut off, "offline", Some(Value::U64(1)));
        let m = top("mirror", 0, 9, vec![leaf("disk", 1), off, leaf("disk", 3)], vec![]);
        let tops: BTreeMap<u64, &NvList> = [(0, &m)].into_iter().collect();
        let mut vdevs = VdevMap::default();
        vdevs.add(0, Geometry::Plain, 0, given(1, 0));
        vdevs.add(0, Geometry::Plain, 0, given(2, 1));
        vdevs.add(0, Geometry::Plain, 0, given(3, 0)); // not where its label puts it
        vdevs.add(5, Geometry::Plain, 0, given(4, 0)); // no such top-level vdev
        let diag = Diagnostics::new();
        assert_eq!(keep_used(&mut vdevs, &tops, &m, 2, "tank", &diag), Some("offline"));
        assert_eq!(vdevs.count(), 1);
        let w = warnings(&diag);
        assert!(w.iter().any(|w| w.contains("this device is offline")), "{w:?}");
        assert!(w.iter().any(|w| w.contains("3 of the devices given")), "{w:?}");
        // Everything in place: nothing said.
        let mut vdevs = VdevMap::default();
        vdevs.add(0, Geometry::Plain, 0, given(1, 0));
        let diag = Diagnostics::new();
        assert_eq!(keep_used(&mut vdevs, &tops, &m, 1, "tank", &diag), None);
        assert!(diag.is_empty());
    }

    fn own(top_id: u64, guid: u64, top_guid: u64, geometry: Geometry, child: usize) -> Own {
        Own {
            version: 5000,
            guid,
            top_guid,
            pool_guid: 77,
            name: String::new(),
            children: Some(2),
            top_id,
            ashift: 12,
            asize: 1 << 30,
            geometry,
            child,
        }
    }

    /// The pool and this device's place: the label's top-level vdev must be the
    /// configuration's (guid, shape, place among the children), its metaslab shift in range.
    #[test]
    fn place_checks_the_label_against_the_configuration() {
        let ms = |shift: u64| vec![("asize", Value::U64(1 << 30)), ("metaslab_shift", Value::U64(shift))];
        let m = top("mirror", 0, 9, vec![leaf("disk", 1), leaf("disk", 2)], ms(24));
        let tops: BTreeMap<u64, &NvList> = [(0, &m)].into_iter().collect();
        let cfg = config(vec![]);
        let run = |o: &Own, tops: &BTreeMap<u64, &NvList>| {
            let mut vdevs = VdevMap::default();
            vdevs.add(o.top_id, o.geometry, 0, given(o.guid, o.child));
            place(o, &cfg, &[], tops, &mut vdevs, &Diagnostics::new())
        };
        let p = run(&own(0, 2, 9, Geometry::Plain, 1), &tops).unwrap();
        assert_eq!((p.name.as_str(), p.width, p.top_type.as_str(), p.ms_shift), ("tank", 2, "mirror", 24));
        assert!(!p.is_log && p.raidz.is_none());
        // Not the pool's: another top-level vdev id, guid or shape; another place.
        assert!(run(&own(1, 2, 9, Geometry::Plain, 1), &tops).is_err());
        assert!(run(&own(0, 2, 8, Geometry::Plain, 1), &tops).is_err());
        let rz = Geometry::Raidz(Raidz { nparity: 1, width: 2, ashift: 12 });
        assert!(run(&own(0, 2, 9, rz, 1), &tops).is_err());
        assert!(run(&own(0, 2, 9, Geometry::Plain, 0), &tops).unwrap_err().message().contains("where its label"));
        // A single device whose guid is not the vdev's.
        let d = top("disk", 0, 5, vec![], ms(24));
        let one: BTreeMap<u64, &NvList> = [(0, &d)].into_iter().collect();
        assert!(run(&own(0, 5, 5, Geometry::Plain, 0), &one).is_ok());
        assert!(run(&own(0, 6, 5, Geometry::Plain, 0), &one).is_err());
        // The metaslab shift out of range, or the ashift not the label's.
        for bad in [top("disk", 0, 5, vec![], ms(12)), top("disk", 0, 5, vec![], ms(41))] {
            let t: BTreeMap<u64, &NvList> = [(0, &bad)].into_iter().collect();
            assert!(run(&own(0, 5, 5, Geometry::Plain, 0), &t).unwrap_err().message().contains("metaslab shift"));
        }
        let mut other_ashift = top("disk", 0, 5, vec![], ms(24));
        set(&mut other_ashift, "ashift", Some(Value::U64(9)));
        let t: BTreeMap<u64, &NvList> = [(0, &other_ashift)].into_iter().collect();
        assert!(run(&own(0, 5, 5, Geometry::Plain, 0), &t).is_err());
        for missing in ["asize", "metaslab_shift"] {
            let mut t = top("disk", 0, 5, vec![], ms(24));
            set(&mut t, missing, None);
            let tt: BTreeMap<u64, &NvList> = [(0, &t)].into_iter().collect();
            assert!(run(&own(0, 5, 5, Geometry::Plain, 0), &tt).is_err(), "{missing}");
        }
        // The label's name wins over the configuration's.
        let mut named = own(0, 5, 5, Geometry::Plain, 0);
        named.name = "label-name".into();
        assert_eq!(run(&named, &one).unwrap().name, "label-name");
    }

    /// A pool missing devices: a raidz vdev with fewer children than it needs, or fewer
    /// top-level vdevs than the label counts, is not given (unavailable), else nothing to say.
    #[test]
    fn not_given_names_the_devices_missing() {
        let rz = Raidz { nparity: 1, width: 3, ashift: 12 };
        let mut vdevs = VdevMap::default();
        vdevs.add(0, Geometry::Raidz(rz), 0, given(1, 0));
        let o = own(0, 1, 9, Geometry::Raidz(rz), 0);
        assert!(not_given(&vdevs, &o).unwrap().message().contains("raidz1, 1 of 3"));
        vdevs.add(0, Geometry::Raidz(rz), 0, given(2, 1));
        // Two of three is enough; one top-level vdev of the two the label counts is not.
        assert!(not_given(&vdevs, &o).unwrap().message().contains("2 top-level vdevs, 1 given"));
        vdevs.add(1, Geometry::Plain, 0, given(3, 0));
        assert!(not_given(&vdevs, &o).is_none());
        let unknown = Own { children: None, ..own(0, 1, 9, Geometry::Plain, 0) };
        assert!(not_given(&VdevMap::default(), &unknown).is_none());
    }

    fn label(cfg: NvList) -> Leaf {
        Leaf { src: src(), cfg, rings: Vec::new(), missing: Vec::new() }
    }

    fn label_cfg(extra: Vec<(&str, Value)>, tree: NvList) -> NvList {
        let mut l = nv(vec![
            ("version", Value::U64(5000)),
            ("guid", Value::U64(2)),
            ("top_guid", Value::U64(9)),
            ("pool_guid", Value::U64(77)),
            ("vdev_tree", Value::List(tree)),
        ]);
        for (n, v) in extra {
            set(&mut l, n, Some(v));
        }
        l
    }

    /// What the device's own label must hold: spare and cache devices are refused (no pool
    /// data), a destroyed pool noted; the version, guids, vdev tree, its id and ashift checked.
    #[test]
    fn own_label_is_checked() {
        let tree = top("mirror", 0, 9, vec![leaf("disk", 1), leaf("disk", 2)], vec![]);
        let diag = Diagnostics::new();
        let o = Own::read(&label(label_cfg(vec![("name", s("tank"))], tree.clone())), &diag).unwrap();
        assert_eq!((o.child, o.top_id, o.name.as_str(), o.children), (1, 0, "tank", None));
        assert!(diag.is_empty());
        let read = |extra: Vec<(&str, Value)>, tree: &NvList| Own::read(&label(label_cfg(extra, tree.clone())), &diag);
        assert_eq!(read(vec![("state", Value::U64(3))], &tree).err().unwrap().kind(), ErrorKind::Unsupported);
        assert_eq!(read(vec![("state", Value::U64(4))], &tree).err().unwrap().kind(), ErrorKind::Unsupported);
        assert!(read(vec![("state", Value::U64(2))], &tree).is_ok());
        assert!(warnings(&diag).iter().any(|w| w.contains("destroyed")));
        for v in [0, 29, 4999] {
            assert_eq!(read(vec![("version", Value::U64(v))], &tree).err().unwrap().kind(), ErrorKind::Unsupported);
        }
        assert!(read(vec![("version", Value::U64(28))], &tree).is_ok());
        for a in [8, 17] {
            let mut t = tree.clone();
            set(&mut t, "ashift", Some(Value::U64(a)));
            assert!(read(vec![], &t).err().unwrap().message().contains("ashift"));
        }
        let mut t = tree.clone();
        set(&mut t, "id", Some(Value::U64(1 << 24)));
        assert!(read(vec![], &t).err().unwrap().message().contains("vdev id"));
        for field in ["id", "ashift"] {
            let mut t = tree.clone();
            set(&mut t, field, None);
            assert!(read(vec![], &t).is_err(), "{field}");
        }
        // The device is not in its own tree.
        assert!(read(vec![("guid", Value::U64(3))], &tree).err().unwrap().message().contains("not in its label"));
        for field in ["version", "guid", "top_guid", "pool_guid", "vdev_tree"] {
            let mut c = label_cfg(vec![], tree.clone());
            set(&mut c, field, None);
            assert_eq!(Own::read(&label(c), &diag).err().unwrap().kind(), ErrorKind::Corrupt, "{field}");
        }
        assert_eq!(read(vec![], &leaf("draid", 2)).err().unwrap().kind(), ErrorKind::Unsupported);
    }
}
