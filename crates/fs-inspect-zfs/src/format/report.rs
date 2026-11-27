//! What a disk set reports of ZFS pools, as it does of md arrays: which devices holding ZFS form
//! which pool, each pool's devices (every leaf of every top-level vdev, the cache and spare
//! devices), which of them were given, and whether the pool can be read. Each leaf stays a
//! volume of its own, mapped by the ZFS driver.
//!
//! Errors follow the drivers' rule ([`Scope::Unit`]): damage or a feature not read
//! describes the device or the pool (a label that cannot be used, a pool that cannot be read);
//! a failing source or a cancel is the read's error, never taken for a missing device.

use fs_inspect_core::Scope;
use std::sync::Arc;

use crate::format::auxdev;
use crate::format::fs::{Member, PoolStatus, ZfsFs, vdev_layout};
use crate::format::label::Leaf;
use fs_inspect_core::{Diagnostics, DriverContext, Error, ErrorKind, FsKind, Limits, MemberRole, Peers, Result};
use fs_inspect_io::DynSource;

/// A pool's state as the devices given show it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportStatus {
    /// Every device given.
    Complete,
    /// Devices missing or not in use, every top-level vdev readable through redundancy.
    Degraded,
    /// A top-level vdev cannot be read: not given, or too few of its children
    /// ([`ErrorKind::Unavailable`]).
    Incomplete,
    /// Not readable by this driver: a feature it does not read (dRAID, an expanded raidz
    /// vdev, ...) or damage.
    Unsupported,
}

/// A pool as the devices given show it.
#[derive(Debug, Clone)]
pub struct PoolReport {
    pub name: String,
    pub pool_guid: u64,
    pub status: ReportStatus,
    /// The pool's devices (for a pool that cannot be read: those its given leaves' labels
    /// name).
    pub members: Vec<Member>,
    /// Why the pool cannot be read (`Incomplete`: [`ErrorKind::Unavailable`], naming what is
    /// not given; `Unsupported`: the driver's error).
    pub error: Option<Error>,
}

/// What a device's ZFS labels say it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelRole {
    /// A leaf of a top-level vdev of pool `pool_guid`.
    Leaf { pool_guid: u64 },
    /// A cache device (L2ARC). Its labels name no pool: the pool listing its guid is its pool.
    Cache,
    /// A hot spare. Its labels name no pool (one may serve several): the pools listing its
    /// guid are its pools.
    Spare,
}

/// A device's identity from its ZFS labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Label {
    /// The device's guid.
    pub guid: u64,
    pub role: LabelRole,
}

/// The identity of `src` from its labels. `None`: no usable label (damaged, or a pool this
/// driver does not read); the device then opens as a volume of its own, which reports why.
/// `Err`: reading failed (or was cancelled).
pub fn label(src: &DynSource) -> Result<Option<Label>> {
    let l = match Leaf::read(src.clone()) {
        Ok(l) => l,
        Err(e) if e.scope() == Scope::Unit => return Ok(None),
        Err(e) => return Err(e),
    };
    let Some(guid) = l.cfg.u64("guid") else { return Ok(None) };
    let role = match l.state() {
        auxdev::STATE_SPARE => LabelRole::Spare,
        auxdev::STATE_L2CACHE => LabelRole::Cache,
        _ => match l.cfg.u64("pool_guid") {
            Some(pool_guid) => LabelRole::Leaf { pool_guid },
            None => return Ok(None),
        },
    };
    Ok(Some(Label { guid, role }))
}

/// The report of the pool whose leaf `src` is (its other devices among `ctx.peers`). `Err`:
/// reading failed (or was cancelled), or `src` is no leaf of a pool.
pub fn report(src: DynSource, ctx: &DriverContext) -> Result<PoolReport> {
    let l = Leaf::read(src.clone())?;
    if matches!(l.state(), auxdev::STATE_SPARE | auxdev::STATE_L2CACHE) {
        return Err(Error::invalid_argument("a cache or spare device is no leaf of a pool"));
    }
    let pool_guid = l.cfg.u64("pool_guid").ok_or_else(|| Error::corrupt("ZFS label without pool_guid"))?;
    let name = l.cfg.str("name").unwrap_or_default().to_string();
    let e = match ZfsFs::read_pool(src, ctx) {
        Ok(p) => {
            return Ok(PoolReport {
                name: p.name.clone(),
                pool_guid,
                status: match p.status() {
                    PoolStatus::Complete => ReportStatus::Complete,
                    PoolStatus::Degraded => ReportStatus::Degraded,
                },
                members: p.members,
                error: None,
            });
        }
        Err(e) => e,
    };
    let status = match e.kind() {
        ErrorKind::Unavailable => ReportStatus::Incomplete,
        _ if e.scope() == Scope::Unit => ReportStatus::Unsupported,
        _ => return Err(e),
    };
    Ok(PoolReport { name, pool_guid, status, members: members_from_labels(l, pool_guid, ctx), error: Some(e) })
}

/// The devices the labels of a pool's given leaves name (`first` and the peers of its pool):
/// each its own top-level vdev's. For a pool that cannot be read (its configuration is in the
/// MOS).
fn members_from_labels(first: Leaf, pool_guid: u64, ctx: &DriverContext) -> Vec<Member> {
    let mut labels = vec![first];
    for s in ctx.peers.as_ref().map(|p| p.volumes(FsKind::Zfs)).unwrap_or_default() {
        labels.extend(Leaf::read(s).ok().filter(|x| x.cfg.u64("pool_guid") == Some(pool_guid)));
    }
    let given: Vec<u64> = labels.iter().filter_map(|x| x.cfg.u64("guid")).collect();
    let mut members = Vec::new();
    let mut seen = Vec::new();
    for x in &labels {
        let Some(t) = x.cfg.list("vdev_tree") else { continue };
        let Some(id) = t.u64("id").filter(|id| !seen.contains(id)) else { continue };
        if matches!(x.state(), auxdev::STATE_SPARE | auxdev::STATE_L2CACHE) {
            continue;
        }
        seen.push(id);
        let layout = vdev_layout(t);
        let log = t.u64("is_log") == Some(1);
        let kids: Vec<_> = t.lists("children").map(|k| k.iter().collect()).unwrap_or_else(|| vec![t]);
        for (i, k) in kids.iter().enumerate() {
            let g = k.u64("guid").unwrap_or(0);
            let child = t.lists("children").map(|_| i as u32);
            let role = MemberRole::Vdev { top: id, layout: layout.clone(), child, log };
            let present = given.contains(&g);
            members.push(Member { guid: g, role, path: k.str("path").map(str::to_string), present });
        }
    }
    members
}

/// A pool found among the devices given to [`group`].
#[derive(Debug, Clone)]
pub struct PoolGroup<K> {
    pub report: PoolReport,
    /// The device found for each member of `report.members` (its index there) that was given.
    pub found: Vec<(usize, K)>,
    /// Members given on several devices (a cloned disk): `(member index, devices)`; the first
    /// device is the one in `found`, the others stay devices of their own.
    pub duplicates: Vec<(usize, Vec<K>)>,
}

/// What [`group`] found.
#[derive(Debug, Clone)]
pub struct Grouping<K> {
    pub pools: Vec<PoolGroup<K>>,
    /// Devices that could not be read (the read's error): which pool they belong to, if any,
    /// is not known. A pool missing a member may be missing one of them.
    pub unread: Vec<(K, Error)>,
}

/// A leaf given to [`group`]: the caller's key, its source, its device guid.
struct GivenLeaf<'a, K> {
    key: K,
    src: &'a DynSource,
    guid: u64,
}

/// Group `devices` (each holding ZFS, keyed by the caller) into pools, in the order of their
/// first device: each pool is read from its first leaf that reads (the others among `peers`),
/// its cache and spare devices join it. A device in no pool (no usable label, a cache or spare
/// device no pool lists) is in none. `Err`: cancelled.
pub fn group<K: Copy>(devices: &[(K, DynSource)], peers: &Arc<dyn Peers>, limits: &Limits) -> Result<Grouping<K>> {
    let mut unread: Vec<(K, Error)> = Vec::new();
    // Pool guid -> its leaves, in device order.
    let mut by_pool: Vec<(u64, Vec<GivenLeaf<'_, K>>)> = Vec::new();
    // Cache and spare devices (key, device guid).
    let mut aux: Vec<(K, u64)> = Vec::new();
    for (k, src) in devices {
        match label(src) {
            Ok(Some(Label { guid, role: LabelRole::Leaf { pool_guid } })) => {
                match by_pool.iter_mut().find(|(p, _)| *p == pool_guid) {
                    Some((_, v)) => v.push(GivenLeaf { key: *k, src, guid }),
                    None => by_pool.push((pool_guid, vec![GivenLeaf { key: *k, src, guid }])),
                }
            }
            Ok(Some(Label { guid, role: LabelRole::Cache | LabelRole::Spare })) => aux.push((*k, guid)),
            Ok(None) => {}
            Err(e) if e.is_cancelled() => return Err(e),
            Err(e) => unread.push((*k, e)),
        }
    }
    let mut pools = Vec::new();
    for (_, leaves) in by_pool {
        let mut failed = Vec::new();
        let mut report = None;
        for &GivenLeaf { key: k, src, .. } in &leaves {
            let ctx = DriverContext {
                limits: limits.clone(),
                diagnostics: Diagnostics::new(),
                peers: Some(peers.clone()),
                ..Default::default()
            };
            match self::report(src.clone(), &ctx) {
                Ok(r) => {
                    report = Some(r);
                    break;
                }
                Err(e) if e.is_cancelled() => return Err(e),
                Err(e) => failed.push((k, e)),
            }
        }
        let Some(report) = report else {
            // No leaf reads the pool: each stays a device of its own, with its read's error.
            unread.extend(failed);
            continue;
        };
        let mut given: Vec<(K, u64)> = leaves.iter().map(|l| (l.key, l.guid)).collect();
        // The cache and spare devices the pool lists join it (a spare shared by pools joins the
        // first).
        aux.retain(|&(k, g)| {
            let listed =
                report.members.iter().any(|m| m.guid == g && matches!(m.role, MemberRole::Cache | MemberRole::Spare));
            if listed {
                given.push((k, g));
            }
            !listed
        });
        let mut found = Vec::new();
        let mut duplicates = Vec::new();
        for (mi, m) in report.members.iter().enumerate() {
            let on: Vec<K> = given.iter().filter(|(_, g)| *g == m.guid).map(|&(k, _)| k).collect();
            if let Some(&first) = on.first() {
                found.push((mi, first));
            }
            if on.len() > 1 {
                duplicates.push((mi, on));
            }
        }
        pools.push(PoolGroup { report, found, duplicates });
    }
    Ok(Grouping { pools, unread })
}
