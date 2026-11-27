//! The guest systems on a set's disks and where each mounts the set's volumes, read from the
//! guests' own files ([`DiskSet::guest`]).
//!
//! - **Windows**: an NTFS volume holding `Windows/System32/config/SYSTEM`. Its drive letters
//!   are the `MountedDevices` values of that hive: a GPT partition's (or an LDM volume's) GUID,
//!   or an MBR disk signature and partition offset.
//! - **Linux**: an ext, XFS, btrfs or ZFS root holding `etc/fstab` that is the volume's
//!   default root or the root its fstab mounts at `/`. Each fstab line names a volume by file
//!   system UUID or label, partition UUID or label, LVM or md device, or ZFS dataset; btrfs's
//!   `subvol=` / `subvolid=` pick the root.
//! - **ZFS**: every dataset with a `mountpoint` mounts there, for the Linux system on its pool
//!   (or the only Linux system of the set).
//! - **macOS**: an APFS container with a System volume: it mounts at `/` and the Data volume of
//!   its volume group at `/System/Volumes/Data`.
//!
//! What cannot be read or matched (a damaged hive, a `/dev/sdb1` line, a letter of a disk not
//! in the set) is a `guest_config` diagnostic of the set, never an error.

use crate::CancelToken;
use fs_inspect_core::ByteRange;
use std::sync::OnceLock;

use crate::device::PartitionEntry;
use crate::fs::{FsHandle, Name, NodeId, NodeKind, RootId, RootInfo, RootKind, StreamId};
use crate::set::{
    ContainerInfo, ContainerKind, DeviceRef, DiskSet, LogicalInfo, Readability, VolumeEntry, VolumeIndex,
    VolumeLocation,
};
use fs_inspect_core::{DiagCode, Diagnostics, Error, ErrorKind, FsInfo, FsKind, Result, Scope, Severity, VolumeRole};
use fs_inspect_disk::DiskId;
use fs_inspect_guest::fstab::{self, FstabEntry, Spec};
use fs_inspect_guest::mounted_devices::{self, WinDevice};
use fs_inspect_guest::regf::Hive;

/// The largest SYSTEM hive read (servers' reach a few hundred MiB only with huge driver
/// stores; desktops' are 10 to 30 MiB).
const MAX_HIVE: u64 = 256 << 20;
/// The largest fstab read.
const MAX_FSTAB: u64 = 1 << 20;

/// The operating systems found on a set's disks and their mounts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Guest {
    /// In volume order.
    pub systems: Vec<GuestSystem>,
    /// Each system's in the order its files give them; a mount of no system (a ZFS dataset
    /// of a pool no Linux system of the set is on) last.
    pub mounts: Vec<GuestMount>,
    /// The volumes a system may be on whose file system, or system files, could not be read
    /// for what they hold, and the kind of error (a [`Scope::Unit`] one), in volume order.
    pub(crate) unread: Vec<(VolumeIndex, ErrorKind)>,
}

/// An operating system installed on a volume of the set.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GuestSystem {
    pub os: GuestOs,
    /// The volume and the root ([`RootInfo::root`]) its system files are on.
    pub volume: VolumeIndex,
    pub root: RootId,
}

fs_inspect_core::named_enum! {
    /// A kind of operating system; stable names `windows`, `linux`, `macos`.
    pub enum GuestOs ("guest OS") {
        /// Windows.
        Windows = 1 => "windows",
        /// Linux.
        Linux = 2 => "linux",
        /// macOS.
        MacOs = 3 => "macos",
    }
}

crate::set::index_types! {
    /// System `n` of a guest: [`Guest::systems`]`[n]`.
    GuestSystemIndex,
}

/// Where a system mounts a root of a volume of the set.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GuestMount {
    /// Its system ([`Guest::systems`]); `None` for a ZFS dataset no system of the set
    /// claims.
    pub system: Option<GuestSystemIndex>,
    pub volume: VolumeIndex,
    /// The root mounted ([`RootInfo::root`]).
    pub root: RootId,
    pub at: MountPoint,
}

fs_inspect_io::tagged_enum! {
    /// A mount point.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub enum MountPoint ("mount point") kind MountPointKind {
        /// A Windows drive letter, upper case.
        Letter(char) = 1 => "letter",
        /// An absolute path (Linux, ZFS, macOS).
        Path(String) = 2 => "path",
    }
}

impl std::fmt::Display for MountPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MountPoint::Letter(c) => write!(f, "{c}:"),
            MountPoint::Path(p) => f.write_str(p),
        }
    }
}

/// A volume as the guest search sees it: its file system's facts and browse handle, opened
/// on first use.
struct Opened {
    info: FsInfo,
    fs: Option<FsHandle>,
    roots: Vec<RootInfo>,
}

impl Opened {
    /// The root a mount without options shows.
    fn default_root(&self) -> Option<RootId> {
        self.roots.iter().find(|r| r.default).or_else(|| self.roots.first()).map(|r| r.root)
    }
}

struct Search<'a> {
    set: &'a DiskSet,
    vols: &'a [VolumeEntry],
    opened: Vec<OnceLock<Option<Opened>>>,
    diag: Diagnostics,
    systems: Vec<GuestSystem>,
    mounts: Vec<GuestMount>,
    /// The volumes whose system files could not be read, and why ([`Guest::unread`]).
    unread: std::cell::RefCell<Vec<(VolumeIndex, ErrorKind)>>,
}

impl DiskSet {
    /// The operating systems on the set's disks and where they mount its volumes (see the
    /// [module](crate::guest)). Found once, on first use; what a guest's files say that
    /// cannot be read or matched is in [`diagnostics`](Self::diagnostics) (`guest_config`).
    /// An error when the disks cannot be laid out, the search is cancelled, or the source
    /// fails (I/O that is not damage, permission): what it hides is not known to be absent.
    pub fn guest(&self, cancel: Option<&CancelToken>) -> Result<&Guest> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            if let Some(g) = self.guest_cell().get() {
                return Ok(g);
            }
            let g = tracing::debug_span!("disk.guest").in_scope(|| Search::run(self))?;
            Ok(self.guest_cell().get_or_init(|| g))
        })
    }
}

impl<'a> Search<'a> {
    fn run(set: &'a DiskSet) -> Result<Guest> {
        let vols = set.volumes(None)?;
        let mut s = Search {
            set,
            vols,
            opened: vols.iter().map(|_| OnceLock::new()).collect(),
            diag: set.guest_diag(),
            systems: Vec::new(),
            mounts: Vec::new(),
            unread: std::cell::RefCell::default(),
        };
        let mut windows: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut linux: Vec<(usize, Vec<FstabEntry>)> = Vec::new();
        for v in vols {
            if v.readable == Readability::No {
                continue;
            }
            match v.fs_kind {
                Some(FsKind::Ntfs) => {
                    let Some(root) = s.open(v.index)?.and_then(Opened::default_root) else { continue };
                    if let Some(hive) = s.read(v.index, root, "Windows/System32/config/SYSTEM", MAX_HIVE)? {
                        windows.push((s.systems.len(), hive));
                        s.systems.push(GuestSystem { os: GuestOs::Windows, volume: v.index, root });
                    }
                }
                Some(FsKind::Ext2 | FsKind::Ext3 | FsKind::Ext4 | FsKind::Xfs | FsKind::Btrfs | FsKind::Zfs) => {
                    let roots: Vec<RootInfo> = s.open(v.index)?.map(|o| o.roots.clone()).unwrap_or_default();
                    // A writable snapshot can be the default (openSUSE boots one).
                    for r in
                        roots.iter().filter(|r| (r.kind != RootKind::Snapshot || r.default) && r.access.is_readable())
                    {
                        let Some(text) = s.read(v.index, r.root, "etc/fstab", MAX_FSTAB)? else { continue };
                        let entries = fstab::parse(&String::from_utf8_lossy(&text));
                        let at_root = |s: &Search<'_>| -> Result<bool> {
                            for e in entries.iter().filter(|e| e.at == "/") {
                                if s.resolve(e)?.is_some_and(|(vi, ri)| vi == v.index && ri == r.root) {
                                    return Ok(true);
                                }
                            }
                            Ok(false)
                        };
                        let zfs_root = r.mountpoint.as_deref() == Some("/");
                        if r.default || zfs_root || at_root(&s)? {
                            linux.push((s.systems.len(), entries));
                            s.systems.push(GuestSystem { os: GuestOs::Linux, volume: v.index, root: RootId(r.root.0) });
                        }
                    }
                }
                Some(FsKind::Apfs) => {
                    let roots: Vec<RootInfo> = s.open(v.index)?.map(|o| o.roots.clone()).unwrap_or_default();
                    for sys in roots.iter().filter(|r| r.role == Some(VolumeRole::System)) {
                        let si = s.systems.len();
                        s.systems.push(GuestSystem { os: GuestOs::MacOs, volume: v.index, root: RootId(sys.root.0) });
                        s.add(Some(si), v.index, RootId(sys.root.0), MountPoint::Path("/".into()));
                        let data = roots.iter().find(|r| {
                            r.role == Some(VolumeRole::Data)
                                && r.volume_group.is_some()
                                && r.volume_group == sys.volume_group
                        });
                        if let Some(d) = data {
                            s.add(Some(si), v.index, RootId(d.root.0), MountPoint::Path("/System/Volumes/Data".into()));
                        }
                    }
                }
                _ => {}
            }
        }
        for (si, hive) in windows {
            s.windows_mounts(si, &hive)?;
        }
        for (si, entries) in linux {
            s.linux_mounts(si, &entries)?;
        }
        s.zfs_mounts()?;
        let mut unread = s.unread.into_inner();
        unread.sort_by_key(|(v, _)| *v);
        unread.dedup_by_key(|(v, _)| *v);
        Ok(Guest { systems: s.systems, mounts: s.mounts, unread })
    }

    /// Volume `vi`'s system files cannot be read, by an error of `kind`.
    fn unread(&self, vi: VolumeIndex, kind: ErrorKind) {
        self.unread.borrow_mut().push((vi, kind));
    }

    /// Volume `vi`'s file system, opened once; `None` when it does not open (logged). An
    /// error that is not the volume's (not [`Scope::Unit`]) is returned.
    fn open(&self, vi: VolumeIndex) -> Result<Option<&Opened>> {
        let cell = &self.opened[vi.0 as usize];
        if let Some(o) = cell.get() {
            return Ok(o.as_ref());
        }
        let opened = match self.try_open(vi) {
            Ok(o) => Some(o),
            Err(e) => match e.scope() {
                Scope::Unit => {
                    tracing::debug!(volume = %vi, error = %e, "guest search: the volume does not open");
                    self.unread(vi, e.kind());
                    None
                }
                Scope::Source | Scope::Caller | Scope::Cancelled => {
                    return Err(e.context(format_args!("volume {vi}")));
                }
            },
        };
        Ok(cell.get_or_init(|| opened).as_ref())
    }

    fn try_open(&self, vi: VolumeIndex) -> Result<Opened> {
        let vol = self.set.open_volume(vi, None)?;
        let info = vol.info().fs.clone();
        let fs = match vol.browse(&crate::fs::BrowseOptions::default(), None) {
            Ok(h) => Some(h),
            Err(e) => match e.scope() {
                Scope::Unit => {
                    tracing::debug!(volume = %vi, error = %e, "guest search: the volume does not browse");
                    // A volume with no files of its own (swap, an external log, raw bytes) has
                    // nothing a system could keep there.
                    if info.kind != FsKind::Raw && !info.kind.is_auxiliary() {
                        self.unread(vi, e.kind());
                    }
                    None
                }
                Scope::Source | Scope::Caller | Scope::Cancelled => return Err(e),
            },
        };
        let roots = match &fs {
            Some(h) => h.roots(None)?,
            None => Vec::new(),
        };
        Ok(Opened { info, fs, roots })
    }

    /// File `path` of root `root` of volume `vi`, at most `max` bytes; `None` when it is not
    /// there. A file that is there but cannot be read for what its volume holds ([`Scope::Unit`])
    /// is reported and `None`; any other error stops the search.
    fn read(&self, vi: VolumeIndex, root: RootId, path: &str, max: u64) -> Result<Option<Vec<u8>>> {
        let Some(o) = self.open(vi)? else { return Ok(None) };
        let (Some(h), Some(r)) = (o.fs.as_ref(), o.roots.iter().find(|r| r.root == RootId(root.0))) else {
            return Ok(None);
        };
        match read_file(h, r.node, path, max) {
            Ok(b) => Ok(b),
            Err(e) => match e.scope() {
                Scope::Unit => {
                    self.diag.warn(DiagCode::GuestConfig, format!("volume {vi}: {path} cannot be read: {e}"));
                    self.unread(vi, e.kind());
                    Ok(None)
                }
                Scope::Source | Scope::Caller | Scope::Cancelled => {
                    Err(e.context(format_args!("volume {vi}: reading {path}")))
                }
            },
        }
    }

    /// A mount, once.
    fn add(&mut self, system: Option<usize>, volume: VolumeIndex, root: RootId, at: MountPoint) {
        let m = GuestMount { system: system.map(|s| GuestSystemIndex(s as u32)), volume, root, at };
        if !self.mounts.contains(&m) {
            self.mounts.push(m);
        }
    }

    fn note(&self, message: String) {
        self.diag.report(Severity::Info, DiagCode::GuestConfig, message);
    }

    /// Windows system `si`'s drive letters, from its SYSTEM hive.
    fn windows_mounts(&mut self, si: usize, hive: &[u8]) -> Result<()> {
        let at = self.systems[si].volume;
        let letters = match Hive::open(hive).and_then(|h| mounted_devices::drive_letters(&h)) {
            Ok(l) => l,
            Err(e) => {
                self.diag.warn(DiagCode::GuestConfig, format!("volume {at}: the SYSTEM hive cannot be read: {e}"));
                self.unread(at, e.kind());
                return Ok(());
            }
        };
        for (letter, dev) in letters {
            let found = match &dev {
                WinDevice::Gpt(guid) => self.first(|v, _| {
                    partition_guid(v).is_some_and(|g| g.eq_ignore_ascii_case(guid)) || self.ldm_guid_is(v, guid)
                }),
                WinDevice::Mbr { signature, offset } => self.first(|v, set| {
                    matches!(v.location, VolumeLocation::Device { device: DeviceRef::Disk(d), range: ByteRange { offset: o, .. } }
                        if o == *offset && mbr_signature(set, d.0 as usize) == Some(*signature))
                }),
                _ => continue,
            };
            let root = match found {
                Some(vi) => self.open(vi)?.and_then(Opened::default_root),
                None => None,
            };
            match (found, root) {
                (Some(vi), Some(root)) => self.add(Some(si), vi, root, MountPoint::Letter(letter)),
                (Some(vi), None) => self.note(format!("drive {letter}: is volume {vi}, which does not open")),
                (None, _) => self.note(format!("drive {letter}: of the system on volume {at} is not on these disks")),
            }
        }
        Ok(())
    }

    /// Linux system `si`'s mounts, from its fstab.
    fn linux_mounts(&mut self, si: usize, entries: &[FstabEntry]) -> Result<()> {
        for e in entries.iter().filter(|e| e.is_mountable_fs()) {
            match self.resolve(e)? {
                Some((vi, root)) => self.add(Some(si), vi, root, MountPoint::Path(e.at.clone())),
                None => self.note(format!(
                    "fstab of the system on volume {}: {} (mounted at {}) is not on these disks",
                    self.systems[si].volume,
                    spec_text(&e.spec),
                    e.at
                )),
            }
        }
        Ok(())
    }

    /// Every ZFS dataset with a mount point: of the Linux system on its pool, else of the
    /// set's only Linux system.
    fn zfs_mounts(&mut self) -> Result<()> {
        let linux: Vec<usize> = (0..self.systems.len()).filter(|&i| self.systems[i].os == GuestOs::Linux).collect();
        for v in self.vols.iter().filter(|v| v.fs_kind == Some(FsKind::Zfs) && v.readable != Readability::No) {
            let roots: Vec<RootInfo> = self.open(v.index)?.map(|o| o.roots.clone()).unwrap_or_default();
            let system = linux.iter().copied().find(|&i| self.systems[i].volume == v.index).or(if linux.len() == 1 {
                Some(linux[0])
            } else {
                None
            });
            for r in roots.iter().filter(|r| r.kind != RootKind::Snapshot) {
                if let Some(m) = &r.mountpoint {
                    self.add(system, v.index, RootId(r.root.0), MountPoint::Path(m.clone()));
                }
            }
        }
        Ok(())
    }

    /// The volume and root an fstab line mounts; `None` when it is not on these disks.
    fn resolve(&self, e: &FstabEntry) -> Result<Option<(VolumeIndex, RootId)>> {
        let vi = match &e.spec {
            Spec::Uuid(u) => self.first_fs(|i| i.uuid.as_deref().is_some_and(|x| x.eq_ignore_ascii_case(u)))?,
            Spec::Label(l) => self.first_fs(|i| i.label.as_deref() == Some(l.as_str()))?,
            Spec::PartUuid(p) => self.first(|v, set| part_uuid_is(set, v, p)),
            Spec::PartLabel(l) => self.first(|v, _| partition_name(v) == Some(l.as_str())),
            Spec::Lvm { vg, lv } => self.lv(ContainerKind::Lvm, |c| c.name == *vg, |l| l.name == *lv),
            Spec::LvmUuid { vg, lv } => {
                self.lv(ContainerKind::Lvm, |c| same_lvm_uuid(&c.uuid, vg), |l| same_lvm_uuid(&l.uuid, lv))
            }
            Spec::Md(name) => self.md(name),
            Spec::Zfs(ds) => return self.dataset(ds),
            _ => None,
        };
        let Some(vi) = vi else { return Ok(None) };
        let Some(o) = self.open(vi)? else { return Ok(None) };
        let root = if o.info.kind == FsKind::Btrfs {
            if let Some(id) = e.subvolid() {
                o.roots.iter().find(|r| r.root == RootId(id)).map(|r| r.root)
            } else if let Some(path) = e.subvol() {
                o.roots.iter().find(|r| r.path.trim_start_matches('/') == path).map(|r| r.root)
            } else {
                o.default_root()
            }
        } else {
            o.default_root()
        };
        Ok(root.map(|r| (vi, r)))
    }

    /// The first volume (in set order) that `f` picks.
    fn first(&self, f: impl Fn(&VolumeEntry, &DiskSet) -> bool) -> Option<VolumeIndex> {
        self.vols.iter().find(|v| f(v, self.set)).map(|v| v.index)
    }

    /// The first readable volume whose file system `f` picks.
    fn first_fs(&self, f: impl Fn(&FsInfo) -> bool) -> Result<Option<VolumeIndex>> {
        for v in self.vols.iter().filter(|v| v.readable != Readability::No && v.fs_kind.is_some()) {
            if self.open(v.index)?.is_some_and(|o| f(&o.info)) {
                return Ok(Some(v.index));
            }
        }
        Ok(None)
    }

    /// The volume at the start of logical volume `lv` of a container of `kind` whose name
    /// `name` accepts.
    fn lv(
        &self,
        kind: ContainerKind,
        container: impl Fn(&ContainerInfo) -> bool,
        lv: impl Fn(&LogicalInfo) -> bool,
    ) -> Option<VolumeIndex> {
        let cs = self.set.containers(None).ok()?;
        let (ci, li) = cs
            .iter()
            .enumerate()
            .filter(|(_, c)| c.kind == kind && container(c))
            .find_map(|(ci, c)| c.lvs.iter().position(&lv).map(|li| (ci, li)))?;
        self.first(|v, _| {
            matches!(v.location, VolumeLocation::Device { device: DeviceRef::Logical { container, lv }, range: ByteRange { offset: 0, .. } }
                if container.0 as usize == ci && lv.0 as usize == li)
        })
    }

    /// The volume of md array `name` (`md<N>` or `md/<name>`).
    fn md(&self, name: &str) -> Option<VolumeIndex> {
        let want = name.strip_prefix("md/").unwrap_or(name);
        let accepts = |c: &str| {
            let short = c.rsplit(':').next().unwrap_or(c);
            c == want
                || short == want
                || want
                    .strip_prefix("md")
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && short == n)
        };
        let cs = self.set.containers(None).ok()?;
        let c = cs.iter().find(|c| c.kind == ContainerKind::Md && accepts(&c.name))?;
        let lv = c.lvs.first()?.name.clone();
        self.lv(ContainerKind::Md, |x| x.name == c.name, |l| l.name == lv)
    }

    /// The ZFS volume and root of dataset `ds`.
    fn dataset(&self, ds: &str) -> Result<Option<(VolumeIndex, RootId)>> {
        for v in self.vols.iter().filter(|v| v.fs_kind == Some(FsKind::Zfs) && v.readable != Readability::No) {
            if let Some(r) = self.open(v.index)?.and_then(|o| o.roots.iter().find(|r| r.path == ds)) {
                return Ok(Some((v.index, r.root)));
            }
        }
        Ok(None)
    }

    /// Whether `v` is the volume of an LDM logical volume whose GUID is `guid` (as
    /// `MountedDevices` gives it).
    fn ldm_guid_is(&self, v: &VolumeEntry, guid: &str) -> bool {
        let VolumeLocation::Device { device: DeviceRef::Logical { container, lv }, range: ByteRange { offset: 0, .. } } =
            v.location
        else {
            return false;
        };
        let Ok(cs) = self.set.containers(None) else { return false };
        let Some(c) = cs.get(container.0 as usize).filter(|c| c.kind == ContainerKind::Ldm) else { return false };
        c.lvs.get(lv.0 as usize).is_some_and(|l| same_guid(&l.uuid, guid))
    }
}

/// Regular file `path` (names separated by `/`) under directory `dir`, at most `max` bytes;
/// `None` when no regular file is there.
fn read_file(h: &FsHandle, dir: NodeId, path: &str, max: u64) -> Result<Option<Vec<u8>>> {
    let names: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    let mut node = dir;
    for (i, name) in names.iter().enumerate() {
        let want = if i + 1 == names.len() { NodeKind::File } else { NodeKind::Dir };
        let Some(e) = h.lookup(node, &Name::new(name), None)? else { return Ok(None) };
        if h.stat(e.node, None)?.kind != want {
            return Ok(None);
        }
        node = e.node;
    }
    let f = h.open(node, StreamId::MAIN, None)?;
    if f.size() > max {
        return Err(Error::limit(format!("{path} is {} bytes, more than {max}", f.size())));
    }
    let mut buf = vec![0u8; f.size() as usize];
    let mut at = 0;
    while at < buf.len() {
        let n = f.read_at(at as u64, &mut buf[at..], None)?;
        if n == 0 {
            buf.truncate(at);
            break;
        }
        at += n;
    }
    Ok(Some(buf))
}

fn partition_guid(v: &VolumeEntry) -> Option<&str> {
    match &v.partition.as_ref()?.entry {
        PartitionEntry::Gpt { guid, .. } => Some(guid),
        _ => None,
    }
}

fn partition_name(v: &VolumeEntry) -> Option<&str> {
    match &v.partition.as_ref()?.entry {
        PartitionEntry::Gpt { name, .. } => name.as_deref(),
        _ => None,
    }
}

/// Disk `d`'s MBR signature.
fn mbr_signature(set: &DiskSet, d: usize) -> Option<u32> {
    match set.disks().get(d)?.device()?.info_here().ok()?.disk_id? {
        DiskId::Mbr(sig) => Some(sig),
        _ => None,
    }
}

/// Whether `v` is the partition of `PARTUUID=` `p`: a GPT GUID, or `<MBR signature>-<number>`
/// in hex.
fn part_uuid_is(set: &DiskSet, v: &VolumeEntry, p: &str) -> bool {
    if partition_guid(v).is_some_and(|g| g.eq_ignore_ascii_case(p)) {
        return true;
    }
    let Some((sig, num)) = p.split_once('-') else { return false };
    let (Ok(sig), Ok(num)) = (u32::from_str_radix(sig, 16), u32::from_str_radix(num, 16)) else { return false };
    let VolumeLocation::Device { device: DeviceRef::Disk(d), .. } = v.location else { return false };
    v.partition.as_ref().is_some_and(|pi| pi.number == num && matches!(pi.entry, PartitionEntry::Mbr { .. }))
        && mbr_signature(set, d.0 as usize) == Some(sig)
}

/// Whether two GUIDs written as text are the same, whatever their case and dashes. An LDM
/// volume's GUID (stored big-endian, printed as its bytes) and the `DMIO:ID:` value naming it
/// in `MountedDevices` (a Windows GUID structure, printed as Windows does) give the same text.
fn same_guid(a: &str, b: &str) -> bool {
    let hex = |s: &str| s.chars().filter(char::is_ascii_hexdigit).collect::<String>().to_ascii_lowercase();
    let (a, b) = (hex(a), hex(b));
    a.len() == 32 && a == b
}

/// An fstab spec as the line writes it, for diagnostics.
fn spec_text(s: &Spec) -> String {
    match s {
        Spec::Uuid(u) => format!("UUID={u}"),
        Spec::Label(l) => format!("LABEL={l}"),
        Spec::PartUuid(p) => format!("PARTUUID={p}"),
        Spec::PartLabel(l) => format!("PARTLABEL={l}"),
        Spec::Lvm { vg, lv } => format!("/dev/{vg}/{lv}"),
        Spec::LvmUuid { vg, lv } => format!("/dev/disk/by-id/dm-uuid-LVM-{vg}{lv}"),
        Spec::Md(m) => format!("/dev/{m}"),
        Spec::Zfs(d) => d.clone(),
        Spec::Device(p) | Spec::Other(p) => p.clone(),
    }
}

/// Whether LVM UUID `uuid` (as LVM shows it, with dashes) is `bare` (without them).
fn same_lvm_uuid(uuid: &str, bare: &str) -> bool {
    uuid.chars().filter(|&c| c != '-').eq(bare.chars())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn lvm_uuids_match_without_their_dashes() {
        assert!(same_lvm_uuid("R49Wqm-EZUE-Q4Ug-qdqc-4rZS-ywlg-MogFbL", "R49WqmEZUEQ4Ugqdqc4rZSywlgMogFbL"));
        assert!(!same_lvm_uuid("R49Wqm-EZUE-Q4Ug-qdqc-4rZS-ywlg-MogFbL", "R49WqmEZUEQ4Ugqdqc4rZSywlgMogFbM"));
    }

    #[test]
    fn guids_match_whatever_their_case_and_dashes() {
        assert!(same_guid("01234567-89AB-CDEF-0011-223344556677", "0123456789abcdef0011223344556677"));
        assert!(!same_guid("01234567-89AB-CDEF-0011-223344556678", "01234567-89AB-CDEF-0011-223344556677"));
        assert!(!same_guid("x", "x"));
    }

    /// From a Windows Server 2025 dynamic disk: drive G:'s `MountedDevices` value and the LDM
    /// volume record's GUID (as fs-inspect-volmgr prints its bytes) name the same volume,
    /// `\\?\Volume{266b2805-dfec-11f1-bcd3-00155d0be630}`. The value's bytes in their stored
    /// order are another GUID.
    #[test]
    fn an_ldm_volume_is_named_by_its_mounted_devices_value() {
        let mut value = b"DMIO:ID:".to_vec();
        value.extend([0x05, 0x28, 0x6B, 0x26, 0xEC, 0xDF, 0xF1, 0x11, 0xBC, 0xD3, 0x00, 0x15, 0x5D, 0x0B, 0xE6, 0x30]);
        let WinDevice::Gpt(guid) = WinDevice::decode(&value) else { panic!("{value:x?} is not a GUID") };
        assert!(same_guid("266b2805-dfec-11f1-bcd3-00155d0be630", &guid));
        assert!(!same_guid("05286b26-ecdf-f111-bcd3-00155d0be630", &guid));
    }

    #[test]
    fn specs_and_mount_points_print_as_written() {
        assert_eq!(spec_text(&Spec::Lvm { vg: "vg".into(), lv: "root".into() }), "/dev/vg/root");
        assert_eq!(spec_text(&Spec::Uuid("ab".into())), "UUID=ab");
        assert_eq!(MountPoint::Letter('C').to_string(), "C:");
        assert_eq!(MountPoint::Path("/boot".into()).to_string(), "/boot");
        assert_eq!(GuestOs::MacOs.to_string(), "macos");
    }
}
