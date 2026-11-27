//! The disks a command reads and the volume chosen on them.

use crate::args::parse_size;
use anyhow::Context as _;
use clap::Args;
use fs_inspect::Named;
use fs_inspect::{Device, DiskSet, DiskSpec, OpenOptions, Volume};
use std::path::PathBuf;

/// The disks: image files or devices.
#[derive(Args, Debug)]
pub struct SourceArgs {
    /// Disk images: files (raw, `name.001` of a split raw image, VHD, VHDX, a sparse `.fsbs`
    /// capture) or devices. Several disks form one set (disk 0, 1, ... in this order), so
    /// volume managers spanning them are assembled.
    #[arg(required = true, num_args = 1.., value_name = "IMAGE")]
    pub images: Vec<String>,
    /// More segments of a split raw image, in order (normally found from `name.001`); with one
    /// image only. Repeatable.
    #[arg(long = "segment", value_name = "FILE")]
    pub segments: Vec<PathBuf>,
}

/// Which volume of the disks.
#[derive(Args, Debug)]
pub struct SelectArgs {
    /// Volume index (as `list` prints it); default: the only volume with a file system.
    #[arg(long, conflicts_with_all = ["offset", "logical"], value_name = "INDEX")]
    pub volume: Option<u32>,
    /// A volume on a logical volume: its `id` as `list` prints it (`lvm:<vg>/<lv>`,
    /// `md:<name>`, `ldm:<group>/<volume>`), `<vg>/<lv>`, `md:<uuid>`, or the logical volume's
    /// UUID.
    #[arg(long, conflicts_with = "offset", value_name = "ID")]
    pub logical: Option<String>,
    /// The disk `--offset` (and `--whole-disk`) refers to.
    #[arg(long, default_value_t = 0, value_name = "INDEX")]
    pub disk: u32,
    /// Byte offset of the volume on that disk (sizes like 1M accepted).
    #[arg(long, value_parser = parse_size, value_name = "SIZE")]
    pub offset: Option<u64>,
    /// Length of the volume at `--offset` (default: the partition starting there, else to the
    /// end of the image, then not trusted to bound the unused ranges).
    #[arg(long, value_parser = parse_size, requires = "offset", value_name = "SIZE")]
    pub length: Option<u64>,
}

impl SelectArgs {
    /// The volume chosen on `set`: offsets are on `--disk`; the other selections name volumes
    /// of the whole set.
    pub fn open(&self, set: &DiskSet) -> fs_inspect::Result<Volume> {
        match (self.volume, &self.logical, self.offset) {
            (Some(i), _, _) => set.open_volume(fs_inspect::VolumeIndex(i), None),
            (None, Some(sel), _) => set.open_volume(set.find_volume(sel, None)?, None),
            (None, None, Some(offset)) => {
                set.open_volume_at(fs_inspect::DiskIndex(self.disk), offset, self.length, None)
            }
            (None, None, None) => set.open_volume(set.only_volume(None)?, None),
        }
    }

    /// Fails when a volume is chosen: `--whole-disk` takes none.
    pub fn ensure_whole_disk(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.volume.is_none() && self.logical.is_none() && self.offset.is_none(),
            "--whole-disk takes no volume"
        );
        Ok(())
    }
}

/// The disks and one volume on them.
#[derive(Args, Debug)]
pub struct VolumeArgs {
    #[command(flatten)]
    pub source: SourceArgs,
    #[command(flatten)]
    pub select: SelectArgs,
}

impl VolumeArgs {
    /// The disks and the volume chosen on them.
    pub fn open(&self, opts: &OpenOptions) -> anyhow::Result<(DiskSet, Volume)> {
        let set = open_set(&self.source, opts)?;
        let vol = self.select.open(&set)?;
        Ok((set, vol))
    }
}

/// What disk `image` is: a file or device (with `--segment`s).
pub fn disk_spec(image: &str, src: &SourceArgs) -> anyhow::Result<DiskSpec> {
    if let Some(spec) = crate::fault::disk_spec(image, src) {
        return spec;
    }
    if src.segments.is_empty() && crate::sparse::is_sparse(std::path::Path::new(image)) {
        let f = crate::sparse::SparseFile::open(std::path::Path::new(image))?;
        return Ok(DiskSpec::source(std::sync::Arc::new(f)));
    }
    // Without `--segment`, the first segment of a split raw image finds the others.
    let mut paths = vec![PathBuf::from(image)];
    paths.extend(src.segments.iter().cloned());
    Ok(DiskSpec::split(&paths))
}

pub fn open_set(src: &SourceArgs, opts: &OpenOptions) -> anyhow::Result<DiskSet> {
    if src.images.len() > 1 && !src.segments.is_empty() {
        return Err(fs_inspect::Error::invalid_argument("--segment needs a single image").into());
    }
    let specs = src
        .images
        .iter()
        .map(|i| disk_spec(i, src).with_context(|| format!("opening {i}")))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let set = match DiskSet::open(&specs, opts, Some(crate::app::interrupt())) {
        Ok(set) => set,
        Err(e) if src.images.len() == 1 => {
            return Err(anyhow::Error::from(e).context(format!("opening {}", src.images[0])));
        }
        Err(e) => return Err(e.into()),
    };
    // Every image named on the command line is read: one that cannot be (its VHD / VHDX header
    // damaged, a format not supported) fails the command, with what the set says of it.
    for (i, d) in set.disks().iter().enumerate() {
        if let fs_inspect::SetDisk::Unreadable(why) = d {
            let said = set
                .diagnostics()
                .into_iter()
                .find(|x| {
                    x.code == fs_inspect::DiagCode::DiskUnreadable && x.disk == Some(fs_inspect::DiskIndex(i as u32))
                })
                .map_or_else(|| format!("disk {i} cannot be read ({})", why.as_str()), |x| x.message);
            let image = src.images.get(i).map_or("", String::as_str);
            return Err(
                anyhow::Error::from(fs_inspect::Error::new(why.error_kind(), said)).context(format!("opening {image}"))
            );
        }
    }
    Ok(set)
}

pub fn disk_of(set: &DiskSet, disk: u32) -> anyhow::Result<&Device> {
    let d = set.disks().get(disk as usize).and_then(fs_inspect::SetDisk::device);
    Ok(d.ok_or_else(|| fs_inspect::Error::not_found(format!("no disk {disk}")))?)
}
