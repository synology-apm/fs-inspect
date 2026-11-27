//! `/etc/fstab`: which device a Linux system mounts where.
//!
//! One mount per line: the device (`spec`), the mount point, the file system type, the options
//! (comma-separated), then the dump and pass numbers, which are not kept. Fields are separated by
//! runs of spaces and tabs; `#` starts a comment line. A space, tab, newline or backslash inside
//! the device or the mount point is written as an octal escape (`\040`, `\011`, `\012`, `\134`).
//! A missing type is `auto`, missing options are none.

/// One mount of an fstab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FstabEntry {
    pub spec: Spec,
    /// The mount point, escapes decoded (`none` for swap).
    pub at: String,
    /// The file system type as written (`ext4`, `xfs`, `swap`, `auto`, ...).
    pub fstype: String,
    /// The options as written, in order (`defaults` when the line says so).
    pub options: Vec<String>,
}

/// The device of an fstab line.
///
/// Values are as written (escapes decoded, quotes removed): UUIDs keep their case, so compare
/// them without regard to case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spec {
    /// `UUID=` or `/dev/disk/by-uuid/`: a file system's UUID.
    Uuid(String),
    /// `LABEL=` or `/dev/disk/by-label/`: a file system's label.
    Label(String),
    /// `PARTUUID=` or `/dev/disk/by-partuuid/`: a GPT partition's unique GUID, or an MBR disk
    /// signature and partition number (`1234abcd-02`).
    PartUuid(String),
    /// `PARTLABEL=` or `/dev/disk/by-partlabel/`: a GPT partition's name.
    PartLabel(String),
    /// `/dev/mapper/<vg>-<lv>` or `/dev/disk/by-id/dm-name-<vg>-<lv>` (a `-` inside a name is
    /// doubled), or `/dev/<vg>/<lv>`: an LVM logical volume. A device-mapper name of another
    /// kind with a `-` in it (such as `luks-<uuid>`) reads as one too; the caller checks that
    /// the volume group exists.
    Lvm { vg: String, lv: String },
    /// `/dev/disk/by-id/dm-uuid-LVM-<vg uuid><lv uuid>`: an LVM logical volume by the UUIDs of
    /// its volume group and itself, each 32 characters without the dashes LVM shows them with.
    LvmUuid { vg: String, lv: String },
    /// `/dev/md<N>` or `/dev/md/<name>`: an md array, as `md<N>` or `md/<name>`.
    Md(String),
    /// A ZFS dataset (type `zfs`, a spec not starting with `/`).
    Zfs(String),
    /// Another path under `/dev`.
    Device(String),
    /// Anything else (`tmpfs`, `proc`, `server:/export`, ...).
    Other(String),
}

impl FstabEntry {
    /// The btrfs subvolume of a `subvol=` option, without its leading `/` (`""` is the top
    /// level).
    pub fn subvol(&self) -> Option<&str> {
        self.option("subvol").map(|v| v.trim_start_matches('/'))
    }

    /// The btrfs subvolume id of a `subvolid=` option.
    pub fn subvolid(&self) -> Option<u64> {
        self.option("subvolid")?.parse().ok()
    }

    /// Whether the line mounts a file system kept on a disk: false for swap, pseudo and memory
    /// file systems, network file systems, bind mounts and mount points that are not absolute
    /// paths. `noauto` mounts count.
    pub fn is_mountable_fs(&self) -> bool {
        const PSEUDO: &[&str] = &[
            "swap",
            "none",
            "tmpfs",
            "ramfs",
            "proc",
            "sysfs",
            "devpts",
            "devtmpfs",
            "cgroup",
            "cgroup2",
            "securityfs",
            "debugfs",
            "tracefs",
            "mqueue",
            "hugetlbfs",
            "configfs",
            "pstore",
            "efivarfs",
            "binfmt_misc",
            "fusectl",
            "autofs",
            "rpc_pipefs",
            "nfsd",
            "bpf",
            "overlay",
        ];
        const NETWORK: &[&str] =
            &["nfs", "nfs4", "cifs", "smb3", "smbfs", "sshfs", "fuse", "ceph", "glusterfs", "9p", "davfs", "afs"];
        let t = self.fstype.as_str();
        let bind = self.options.iter().any(|o| o == "bind" || o == "rbind");
        self.at.starts_with('/') && !bind && !PSEUDO.contains(&t) && !NETWORK.contains(&t) && !t.starts_with("fuse.")
    }

    /// The value of option `name=`.
    fn option(&self, name: &str) -> Option<&str> {
        self.options.iter().find_map(|o| o.strip_prefix(name)?.strip_prefix('='))
    }
}

/// The mounts of fstab `text`. Lines that are not mounts (fewer than two fields) are skipped.
pub fn parse(text: &str) -> Vec<FstabEntry> {
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<FstabEntry> {
    let line = line.trim();
    if line.starts_with('#') {
        return None;
    }
    let mut fields = line.split([' ', '\t']).filter(|f| !f.is_empty());
    let spec = fields.next()?;
    let at = unescape_octal(fields.next()?);
    let fstype = fields.next().unwrap_or("auto").to_string();
    let options =
        fields.next().map(|o| o.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect()).unwrap_or_default();
    Some(FstabEntry { spec: parse_spec(&unescape_octal(spec), &fstype), at, fstype, options })
}

/// Kernel directories under `/dev` that hold no volume groups.
const DEV_DIRS: &[&str] = &[
    "disk",
    "mapper",
    "md",
    "block",
    "char",
    "bus",
    "cpu",
    "dri",
    "input",
    "net",
    "pts",
    "shm",
    "snd",
    "usb",
    "vfio",
    "hugepages",
    "mqueue",
    "fd",
    "zvol",
    "loop",
    "bsg",
    "raw",
    "serial",
];

fn parse_spec(spec: &str, fstype: &str) -> Spec {
    for (tag, make) in [
        ("UUID", Spec::Uuid as fn(String) -> Spec),
        ("LABEL", Spec::Label),
        ("PARTUUID", Spec::PartUuid),
        ("PARTLABEL", Spec::PartLabel),
    ] {
        if let Some(v) = strip_prefix_ignore_case(spec, tag).and_then(|r| r.strip_prefix('=')) {
            return make(unquote(v).to_string());
        }
    }
    let Some(dev) = spec.strip_prefix("/dev/") else {
        if fstype == "zfs" && !spec.starts_with('/') && !spec.is_empty() {
            return Spec::Zfs(spec.to_string());
        }
        return Spec::Other(spec.to_string());
    };
    for (dir, make) in [
        ("disk/by-uuid/", Spec::Uuid as fn(String) -> Spec),
        ("disk/by-label/", Spec::Label),
        ("disk/by-partuuid/", Spec::PartUuid),
        ("disk/by-partlabel/", Spec::PartLabel),
    ] {
        if let Some(v) = dev.strip_prefix(dir).filter(|v| !v.is_empty() && !v.contains('/')) {
            return make(unescape_hex(v));
        }
    }
    if let Some(id) = dev.strip_prefix("disk/by-id/dm-uuid-LVM-")
        && id.len() == 64
        && id.is_ascii()
    {
        let (vg, lv) = id.split_at(32);
        return Spec::LvmUuid { vg: vg.to_string(), lv: lv.to_string() };
    }
    if let Some(name) = dev.strip_prefix("mapper/").or_else(|| dev.strip_prefix("disk/by-id/dm-name-"))
        && let Some((vg, lv)) = split_dm_name(name)
    {
        return Spec::Lvm { vg, lv };
    }
    if let Some(n) = dev.strip_prefix("md")
        && !n.is_empty()
        && n.bytes().all(|b| b.is_ascii_digit())
    {
        return Spec::Md(dev.to_string());
    }
    if let Some(n) = dev.strip_prefix("md/")
        && !n.is_empty()
        && !n.contains('/')
    {
        return Spec::Md(dev.to_string());
    }
    let parts: Vec<&str> = dev.split('/').collect();
    if let [vg, lv] = parts[..]
        && !vg.is_empty()
        && !lv.is_empty()
        && !DEV_DIRS.contains(&vg)
    {
        return Spec::Lvm { vg: vg.to_string(), lv: lv.to_string() };
    }
    Spec::Device(spec.to_string())
}

/// `<vg>-<lv>` of a device-mapper name, where `--` stands for a `-` inside a name.
fn split_dm_name(name: &str) -> Option<(String, String)> {
    let mut vg = String::new();
    let mut chars = name.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '-' {
            vg.push(c);
        } else if chars.peek() == Some(&'-') {
            chars.next();
            vg.push('-');
        } else {
            let lv = chars.collect::<String>().replace("--", "-");
            return (!vg.is_empty() && !lv.is_empty()).then_some((vg, lv));
        }
    }
    None
}

fn strip_prefix_ignore_case<'s>(s: &'s str, prefix: &str) -> Option<&'s str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| &s[prefix.len()..])
}

/// A value without its surrounding quotes (`"..."` or `'...'`).
fn unquote(v: &str) -> &str {
    for q in ['"', '\''] {
        if let Some(inner) = v.strip_prefix(q).and_then(|r| r.strip_suffix(q)) {
            return inner;
        }
    }
    v
}

/// Decode `\NNN` (three octal digits, at most 0o377) escapes.
fn unescape_octal(s: &str) -> String {
    unescape(s, |rest| {
        let d = rest.get(..3)?;
        if !d.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            return None;
        }
        Some((u8::try_from(u16::from_str_radix(d, 8).ok()?).ok()?, 3))
    })
}

/// Decode `\xNN` escapes (how udev writes bytes of names in `/dev/disk/by-*` links).
fn unescape_hex(s: &str) -> String {
    unescape(s, |rest| {
        let d = rest.strip_prefix('x')?.get(..2)?;
        if !d.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some((u8::from_str_radix(d, 16).ok()?, 3))
    })
}

/// `s` with each backslash escape `decode` recognizes (given the text after the backslash, the
/// byte and how many characters it used) replaced by its byte; other backslashes are kept.
fn unescape(s: &str, decode: impl Fn(&str) -> Option<(u8, usize)>) -> String {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while let Some(p) = s[i..].find('\\') {
        out.extend_from_slice(&s.as_bytes()[i..i + p]);
        let rest = &s[i + p + 1..];
        match decode(rest) {
            Some((b, used)) => {
                out.push(b);
                i += p + 1 + used;
            }
            None => {
                out.push(b'\\');
                i += p + 1;
            }
        }
    }
    out.extend_from_slice(&s.as_bytes()[i..]);
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
