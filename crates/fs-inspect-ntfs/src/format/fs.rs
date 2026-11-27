//! The NTFS [`Filesystem`](fs_inspect_core::Filesystem): used clusters from `$Bitmap`, streamed
//! a chunk at a time.

use crate::format::Error;
use crate::format::attr::AttrType;
use crate::format::deleted::deleted_clusters;
use crate::format::entry::{Stream, StreamBody};
use crate::format::exclude::clusters_to_ranges;
use crate::format::geometry::Geometry;
use crate::format::volume::{NtfsVolume, map_stream_bytes, system_records};
use crate::format::vss_storage::vss_storage_clusters;
use fs_inspect_core::FsInfoExt;
use fs_inspect_core::{
    ByteRange, Confidence, Consistency, DiagCode, DriverContext, FnCursor, FsInfo, FsKind, RangeCursor, Sniff,
    push_bit_runs, push_range,
};
use fs_inspect_io::DynSource;
use fs_inspect_io::batch::BATCH_BYTES;
use std::sync::Arc;

/// An opened NTFS volume.
#[derive(Debug)]
pub struct NtfsFs {
    vol: NtfsVolume,
    info: FsInfo,
    /// The `$LogFile` restart area, read once.
    consistency: std::sync::OnceLock<Consistency>,
    /// The directories of the `$Extend` tree ([`extend_dirs`](crate::format::files::extend_dirs)),
    /// listed the first time a namespace call needs them.
    pub(crate) extend: std::sync::OnceLock<Option<std::collections::HashSet<crate::format::attr::Frn>>>,
    /// Where `$Secure:$SDS` holds each security id's descriptor, read the first time one is
    /// asked for (again after a [`trim`](fs_inspect_core::Namespace::trim)).
    pub(crate) sds: std::sync::Mutex<Option<std::sync::Arc<crate::format::security::SdsIndex>>>,
    /// Where a verification's findings go.
    integrity: fs_inspect_core::Integrity,
    /// Opened over a replay of the log ([`DriverContext::replayed`]): the log counts as applied.
    recovered: bool,
    /// Where a replay of the log keeps what it holds.
    scratch: fs_inspect_core::store::Scratch,
    /// Most bytes a replay keeps in memory
    /// ([`DriverContext::max_cache_bytes`](fs_inspect_core::DriverContext::max_cache_bytes)).
    cache_bytes: u64,
}

/// `High` for a boot sector that parses, `Medium` for the OEM name alone.
pub fn probe(s: &Sniff<'_>) -> Option<(FsKind, Confidence)> {
    if s.head.len() < 512 || &s.head[3..11] != b"NTFS    " {
        return None;
    }
    let c = if Geometry::parse(&s.head[..512]).is_ok() { Confidence::High } else { Confidence::Medium };
    Some((FsKind::Ntfs, c))
}

/// The volume's length: what the boot sector describes plus the backup boot sector after it,
/// cut at the end of a source that ends past the last whole cluster.
///
/// No cluster lies past the last whole one, only the sectors that do not fill a cluster and
/// the backup boot sector (a copy of `$Boot`'s first sector). A VSS shadow copy device ends
/// right after the last cluster: those bytes are not in the snapshot, and the volume read from
/// it ends there (a restore of it writes the backup boot sector itself, or `chkdsk` does). A
/// source that ends before the last cluster does not open ([`NtfsVolume::open_with`]).
fn volume_bytes(vol: &NtfsVolume) -> u64 {
    let g = vol.geometry();
    let (full, have) = (g.volume_bytes(), vol.source().size());
    if have >= full {
        return full;
    }
    vol.diagnostics().info(
        DiagCode::ShortImage,
        format!(
            "the volume ends at byte {have}, after its last cluster but {} bytes before the end the boot \
             sector gives ({full}, a VSS shadow copy device ends there): its backup boot sector is not in it",
            full - have
        ),
    );
    have
}

/// Open the NTFS volume starting at offset 0 of `src`.
pub fn open(src: DynSource, ctx: &DriverContext) -> fs_inspect_core::Result<Arc<dyn fs_inspect_core::Filesystem>> {
    Ok(Arc::new(NtfsFs::open(src, ctx)?))
}

impl NtfsFs {
    pub fn open(src: DynSource, ctx: &DriverContext) -> crate::format::Result<Self> {
        let vol = NtfsVolume::open_with(src, ctx.limits.clone(), ctx.diagnostics.clone())?;
        let g = *vol.geometry();
        let label = vol
            .entry(system_records::VOLUME)
            .ok()
            .flatten()
            .and_then(|e| match e.stream(AttrType::VOLUME_NAME, &[]).map(|s| &s.body) {
                Some(StreamBody::Resident { data }) => {
                    let units: Vec<u16> = data.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
                    Some(String::from_utf16_lossy(&units))
                }
                _ => None,
            })
            .filter(|l| !l.is_empty());
        let info = FsInfo::new(
            FsKind::Ntfs,
            u64::from(g.cluster_size),
            volume_bytes(&vol),
            label,
            Some(format!("{:016X}", g.serial)),
        );
        Ok(NtfsFs {
            vol,
            info,
            consistency: std::sync::OnceLock::new(),
            extend: std::sync::OnceLock::new(),
            sds: std::sync::Mutex::new(None),
            integrity: ctx.integrity(),
            recovered: ctx.replayed.is_some(),
            scratch: ctx.scratch.clone(),
            cache_bytes: ctx.max_cache_bytes,
        })
    }

    pub fn volume(&self) -> &NtfsVolume {
        &self.vol
    }

    /// Where a verification's findings go.
    pub(crate) fn integrity(&self) -> &fs_inspect_core::Integrity {
        &self.integrity
    }

    /// Warn when `$Bitmap` marks clusters in use past its padding (a shrink may leave a longer
    /// stream): some file then holds clusters outside the volume, which no backup of the volume
    /// covers. `valid`: bytes of the stream that hold real bits. At most [`BATCH_BYTES`] bytes
    /// past the padding are looked at.
    ///
    /// The bits past the last cluster up to the stream's 8-byte rounding are padding, which NTFS
    /// may mark in use: XP marks all of them, newer Windows' format the first (the partial
    /// cluster holding the backup boot sector; its bytes in the volume count as used anyway, see
    /// `allocated`). They are not reported, nor that first bit when there is no padding.
    fn check_past_end(&self, stream: &Stream, valid: u64) -> crate::format::Result<()> {
        let count = self.vol.geometry().cluster_count;
        let first_byte = count.div_ceil(64) * 8;
        let end_byte = valid.min(first_byte + BATCH_BYTES);
        if end_byte <= first_byte {
            return Ok(());
        }
        let mut data = Vec::new();
        self.vol.read_stream_into(stream, first_byte, end_byte - first_byte, &mut data)?;
        if count.is_multiple_of(64)
            && let Some(b) = data.first_mut()
        {
            *b &= !1;
        }
        let (mut n, mut first, mut last) = (0u64, u64::MAX, 0u64);
        for (i, &b) in data.iter().enumerate() {
            let base = (first_byte + i as u64) * 8;
            if b != 0 {
                n += u64::from(b.count_ones());
                first = first.min(base + u64::from(b.trailing_zeros()));
                last = base + 7 - u64::from(b.leading_zeros());
            }
        }
        if n > 0 {
            self.vol.diagnostics().warn(
                DiagCode::Inconsistent,
                format!(
                    "$Bitmap marks {n} clusters past the end of the volume in use (clusters {first}..={last}, \
                 the volume has {count}): files may hold data outside the volume, which is not backed up; \
                 check the volume (chkdsk)"
                ),
            );
        }
        Ok(())
    }

    fn bitmap_stream(&self) -> crate::format::Result<Stream> {
        let e = self.vol.entry(system_records::BITMAP)?.ok_or_else(|| Error::corrupt("$Bitmap record not in use"))?;
        let s = e.unnamed_data().ok_or_else(|| Error::corrupt("$Bitmap has no $DATA"))?.clone();
        if s.runlist_error {
            return Err(Error::corrupt("$Bitmap runlist is damaged"));
        }
        let need = self.vol.geometry().cluster_count.div_ceil(8);
        if let StreamBody::NonResident { runs, .. } = &s.body {
            let mapped = need.min(s.size());
            if map_stream_bytes(runs, self.vol.geometry().cluster_size, 0, mapped).is_none() {
                return Err(Error::corrupt("$Bitmap is not fully mapped"));
            }
        }
        Ok(s)
    }
}

impl fs_inspect_core::sealed::Fs for NtfsFs {}

impl fs_inspect_core::Filesystem for NtfsFs {
    fn default_excludes(&self) -> &'static [fs_inspect_core::DefaultExclude] {
        fs_inspect_core::exclude::WINDOWS_DEFAULTS
    }

    fn info(&self) -> &FsInfo {
        &self.info
    }

    fn allocated(self: Arc<Self>) -> fs_inspect_core::Result<Box<dyn RangeCursor>> {
        let stream = self.bitmap_stream()?;
        let g = *self.vol.geometry();
        let cs = g.cluster_size as u64;
        let need = g.cluster_count.div_ceil(8);
        // Bits the stream can vouch for: up to its initialized size.
        let valid = match &stream.body {
            StreamBody::NonResident { initialized, size, .. } => (*initialized).min(*size),
            StreamBody::Resident { data } => data.len() as u64,
        };
        if valid < need {
            self.vol.diagnostics().warn(
                DiagCode::CountedAsUsed,
                format!("$Bitmap holds {valid} of {need} bytes; the clusters it does not cover count as used"),
            );
        }
        self.check_past_end(&stream, valid)?;
        let tail = ByteRange::from_bounds(g.cluster_count * cs, self.info.size);
        let mut pos = 0u64;
        let mut data = Vec::new();
        let fs = self.clone();
        Ok(Box::new(FnCursor::new(move |out: &mut Vec<ByteRange>| {
            if pos >= need {
                // Sectors past the last whole cluster, and the backup boot sector.
                push_range(out, tail.offset, tail.length);
                return Ok(false);
            }
            let len = BATCH_BYTES.min(need - pos);
            let first_bit = pos * 8;
            let nbits = (len * 8).min(g.cluster_count - first_bit);
            let readable = valid.saturating_sub(pos).min(len);
            if readable > 0 {
                fs.vol.read_stream_into(&stream, pos, readable, &mut data)?;
                push_bit_runs(out, &data, nbits.min(data.len() as u64 * 8), first_bit * cs, cs);
            }
            let vouched = (readable * 8).min(nbits);
            if vouched < nbits {
                push_range(out, (first_bit + vouched) * cs, (nbits - vouched) * cs);
            }
            pos += len;
            Ok(true)
        })))
    }

    fn namespace(self: Arc<Self>) -> Option<Arc<dyn fs_inspect_core::Namespace>> {
        Some(self)
    }

    /// The data of files deleted while open (`$Extend\$Deleted`), when the `$LogFile` is clean.
    fn default_ranges(&self) -> fs_inspect_core::Result<Vec<ByteRange>> {
        if !self.consistency().is_clean() {
            return Ok(Vec::new());
        }
        let cs = self.vol.geometry().cluster_size as u64;
        Ok(clusters_to_ranges(deleted_clusters(&self.vol)?, cs))
    }

    fn implicit_exclusions(&self) -> fs_inspect_core::Result<Vec<ByteRange>> {
        let cs = self.vol.geometry().cluster_size as u64;
        Ok(clusters_to_ranges(vss_storage_clusters(&self.vol)?, cs))
    }

    fn file_map(&self) -> Option<&dyn fs_inspect_core::FileMap> {
        Some(self)
    }

    /// The `$LogFile` restart area's clean flag (a VSS snapshot has it; a raw read of a
    /// mounted volume does not).
    fn verify(&self, scope: &fs_inspect_core::VerifyScope) -> fs_inspect_core::Result<()> {
        crate::format::verify::verify(self, scope)
    }

    /// Redo and undo of `$LogFile` (`lfs::recover`), when it is
    /// not clean.
    fn replay(&self) -> Option<fs_inspect_core::Result<Arc<dyn fs_inspect_core::Replayed>>> {
        if self.recovered || self.consistency().is_clean() {
            return None;
        }
        Some(
            crate::format::lfs::recover::replay(&self.vol, self.cache_bytes, &self.scratch)
                .map(|r| Arc::new(r) as Arc<dyn fs_inspect_core::Replayed>),
        )
    }

    fn consistency(&self) -> Consistency {
        self.consistency
            .get_or_init(|| {
                if self.recovered || crate::format::lfs::restart::clean(&self.vol).unwrap_or(false) {
                    Consistency::Clean
                } else {
                    Consistency::Inconsistent {
                        why: "the $LogFile restart area is not marked clean (or cannot be read)".into(),
                        allocation_covered: false,
                        notes: Vec::new(),
                    }
                }
            })
            .clone()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::synth::{StreamData, SyntheticVolume, VolumeSpec};
    use crate::{Run, format::Result};
    use fs_inspect_core::{CursorIter, ErrorKind, Filesystem};

    /// A volume of `clusters` clusters of 1 KiB whose `$Bitmap` stream is changed by `f`.
    fn with_bitmap(clusters: u64, f: impl FnOnce(&mut StreamData)) -> (Result<Arc<NtfsFs>>, DriverContext) {
        let mut synth = SyntheticVolume::format(VolumeSpec { clusters, cluster_size: 1024, ..Default::default() });
        let s = synth.files.get_mut(&system_records::BITMAP).unwrap().data_mut().unwrap();
        f(&mut s.data);
        synth.materialize();
        let ctx = DriverContext::default();
        (NtfsFs::open(Arc::new(synth.source()), &ctx).map(Arc::new), ctx)
    }

    /// A `$Bitmap` whose initialized size stops short of the volume vouches only for what it
    /// holds: the clusters past it count as used, with a warning saying how much it holds.
    #[test]
    fn the_clusters_a_short_bitmap_does_not_cover_count_as_used() {
        let (fs, ctx) = with_bitmap(8192, |d| {
            let StreamData::NonResident { initialized, .. } = d else { panic!("a non-resident $Bitmap") };
            *initialized = 512;
        });
        let fs = fs.unwrap();
        let used: Vec<ByteRange> = CursorIter::new(fs.clone().allocated().unwrap()).map(|r| r.unwrap()).collect();
        let tail = ByteRange::new(4096 * 1024, 4096 * 1024);
        assert_eq!(fs_inspect_core::range::subtract([tail], used).count(), 0, "clusters 4096.. are used");
        let warned = ctx.diagnostics.all();
        assert!(
            warned.iter().any(|d| d.code == DiagCode::CountedAsUsed && d.message.contains("holds 512 of 1024 bytes")),
            "{warned:?}"
        );
    }

    /// A `$Bitmap` whose runs do not reach the clusters it must describe cannot give the map:
    /// it fails as damage rather than guess.
    #[test]
    fn a_bitmap_its_runs_do_not_map_fails_the_map() {
        let (fs, _) = with_bitmap(16384, |d| {
            let StreamData::NonResident { runs, .. } = d else { panic!("a non-resident $Bitmap") };
            // 2048 bytes: two clusters; keep only the first.
            let [Run::Mapped { vcn, lcn, len: 2 }] = runs[..] else { panic!("{runs:?}") };
            *runs = vec![Run::Mapped { vcn, lcn, len: 1 }];
        });
        let e = match fs {
            Ok(fs) => fs.clone().allocated().err().expect("no map from an unmapped $Bitmap"),
            Err(e) => e,
        };
        assert_eq!(e.kind(), ErrorKind::Corrupt, "{e}");
        assert!(e.to_string().contains("$Bitmap"), "{e}");
    }

    /// The golden line of a file system's [`Consistency`](fs_inspect_core::Consistency).
    fn consistency_line(fs: &dyn fs_inspect_core::Filesystem) -> String {
        match fs.consistency() {
            fs_inspect_core::Consistency::Clean => "  consistency: clean\n".into(),
            fs_inspect_core::Consistency::Inconsistent { why, .. } => format!("  consistency: inconsistent: {why}\n"),
            fs_inspect_core::Consistency::Unknown(why) => format!("  consistency: unknown: {why}\n"),
            other => format!("  consistency: {other:?}\n"),
        }
    }

    /// What the driver reports of synthetic volumes (`fs_inspect_testkit::golden::fs_report`)
    /// and how much it reads opening and mapping them: a plain volume; streams stored every
    /// way (resident, sparse with a hole, compressed, an alternate stream, a hard link); a
    /// fragmented `$MFT` with small clusters; a `$LogFile` not marked clean; a `$Bitmap` shorter
    /// than the volume.
    #[test]
    fn golden_maps() {
        use crate::format::attr::attr_flags;
        use crate::synth::{Placement, ROOT};
        use fs_inspect_testkit::golden::{CountingSource, check, fs_report};

        let mut plain = SyntheticVolume::format(VolumeSpec::default());
        plain.batch(|v| {
            let docs = v.create_dir(ROOT, "docs");
            v.create_file(docs, "a.txt", 100, 1, Placement::FirstFit);
            v.create_file(docs, "b.bin", 3 * 4096 + 17, 2, Placement::FirstFit);
            v.create_file(ROOT, "c.bin", 40_000, 3, Placement::MaxRun(2));
        });

        let mut streams = SyntheticVolume::format(VolumeSpec::default());
        streams.batch(|v| {
            let sparse = v.create_file(ROOT, "sparse.bin", 64 * 4096, 4, Placement::FirstFit);
            v.set_sparse(sparse);
            v.zero_data(sparse, 8 * 4096, 32 * 4096);
            let packed = v.create_file(ROOT, "packed.bin", 32 * 4096, 5, Placement::FirstFit);
            v.files.get_mut(&packed).unwrap().data_mut().unwrap().flags |= attr_flags::COMPRESSED;
            let ads = v.create_file(ROOT, "ads.txt", 10, 6, Placement::FirstFit);
            v.add_ads(ads, "small", 50, 7);
            v.add_ads(ads, "big", 5 * 4096, 8);
            v.add_link(ads, ROOT, "link.txt");
        });

        let mut fragmented = SyntheticVolume::format(VolumeSpec {
            cluster_size: 1024,
            clusters: 16384,
            initial_mft_records: 32,
            mft_grow_records: 16,
            mft_grow_placement: Placement::Scattered,
            ..Default::default()
        });
        fragmented.batch(|v| {
            for i in 0..80 {
                v.create_file(ROOT, &format!("f{i:02}"), 2000 + i * 300, 10 + i, Placement::FirstFit);
            }
        });

        let mut dirty = SyntheticVolume::format(VolumeSpec::default());
        dirty.create_file(ROOT, "open.bin", 9000, 9, Placement::FirstFit);
        dirty.write_restart(false);

        let mut short =
            SyntheticVolume::format(VolumeSpec { clusters: 8192, cluster_size: 1024, ..Default::default() });
        let s = short.files.get_mut(&system_records::BITMAP).unwrap().data_mut().unwrap();
        let StreamData::NonResident { initialized, .. } = &mut s.data else { panic!("a non-resident $Bitmap") };
        *initialized = 512;
        short.materialize();

        let cases = [
            ("plain", plain, &["/docs/a.txt", "/docs/b.bin", "/c.bin"][..]),
            ("streams", streams, &["/sparse.bin", "/packed.bin", "/ads.txt", "/link.txt"][..]),
            ("fragmented-mft", fragmented, &["/f00", "/f79"][..]),
            ("log-not-clean", dirty, &["/open.bin"][..]),
            ("bitmap-short", short, &[][..]),
        ];
        let mut out = String::new();
        let mut reads = String::new();
        for (name, synth, lookups) in cases {
            let counting = CountingSource::new(Arc::new(synth.source()));
            let ctx = DriverContext::default();
            out.push_str(&format!("== {name}\n"));
            match NtfsFs::open(counting.clone(), &ctx) {
                Ok(fs) => {
                    let fs = Arc::new(fs);
                    out.push_str(&fs_report(fs.clone(), &ctx.diagnostics, lookups));
                    out.push_str(&consistency_line(&*fs));
                }
                Err(e) => out.push_str(&format!("open error {:?}: {e}\n", e.kind())),
            }
            reads.push_str(&format!("{name}: {}\n", counting.summary()));
        }
        check(env!("CARGO_MANIFEST_DIR"), "ntfs", &out);
        check(env!("CARGO_MANIFEST_DIR"), "ntfs-reads", &reads);
    }
}
