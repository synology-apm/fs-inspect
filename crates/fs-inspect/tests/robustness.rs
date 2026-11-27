//! Hostile input: mutated images must give errors or ranges, never panics, hangs or huge
//! allocations. Covers the facade, the partition scanner and every driver the registry
//! picks for the mutated bytes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::{BlockClass, ByteRange, DiskSet, DiskSpec, Map, OpenOptions, VolumeMapOptions};
use fs_inspect_io::MemSource;
use fs_inspect_testkit::disk::{self, DiskPart};
use fs_inspect_testkit::{Placement, ROOT, SyntheticVolume, VolumeSpec};
use proptest::prelude::*;
use std::sync::{Arc, OnceLock};

fn seed_images() -> &'static Vec<Vec<u8>> {
    static IMAGES: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    IMAGES.get_or_init(|| {
        let mut v = SyntheticVolume::format(VolumeSpec { clusters: 1024, ..Default::default() });
        v.create_file(ROOT, "pagefile.sys", 64 << 10, 1, Placement::Scattered);
        v.create_file(ROOT, "x.bin", 20_000, 2, Placement::FirstFit);
        let gpt = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&v.image)]).image;
        let mbr = disk::disk_image(disk::TableKind::Mbr, 512, &[DiskPart::logical(&v.image)]).image;
        vec![v.image.clone(), gpt, mbr]
    })
}

/// The used and unused blocks of `map` in blocks of `unit` (0: the map's) are sorted, disjoint
/// and tile it.
fn check(map: &Map, unit: u64) {
    let unit = if unit == 0 { None } else { Some(fs_inspect::range::Granularity::new(unit).unwrap()) };
    let mut all: Vec<ByteRange> = Vec::new();
    for class in [BlockClass::Used, BlockClass::Unused] {
        let Ok(blocks) = map.blocks(class, unit) else { return };
        assert!(blocks.windows(2).all(|w| w[0].end() < w[1].offset), "blocks must stay sorted and disjoint");
        all.extend(blocks.iter().copied());
    }
    all.sort();
    assert_eq!(
        fs_inspect::range::sort_coalesce(all),
        [map.extent()].into_iter().filter(|r| r.length > 0).collect::<Vec<_>>()
    );
}

/// Open everything there is and map it; errors are fine.
fn exercise(bytes: Vec<u8>) {
    let Ok(set) = DiskSet::open(&[DiskSpec::source(Arc::new(MemSource::new(bytes)))], &OpenOptions::default(), None)
    else {
        return;
    };
    if let Ok(m) = set.map(fs_inspect::DiskIndex(0), &fs_inspect::DeviceMapOptions::default(), None) {
        check(&m, 512);
    }
    let Ok(vols) = set.volumes(None) else { return };
    for e in vols {
        let Ok(vol) = set.open_volume(e.index, None) else { continue };
        if let Ok(m) = vol.map(&VolumeMapOptions::default(), None) {
            check(&m, 0);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: fs_inspect_testkit::cases(256), ..ProptestConfig::default() })]

    #[test]
    fn mutated_images_never_panic(
        which in 0usize..3,
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..64),
        hot in proptest::collection::vec((0usize..(64 << 10), any::<u8>()), 0..32),
    ) {
        let mut b = seed_images()[which].clone();
        let len = b.len();
        for (i, v) in edits {
            b[i.index(len)] = v;
        }
        // Concentrate some damage on the metadata near the start (boot sectors, tables, MFT).
        for (i, v) in hot {
            if i < len {
                b[i] = v;
            }
        }
        exercise(b);
    }

    #[test]
    fn random_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..(80 << 10))) {
        exercise(bytes);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: fs_inspect_testkit::cases(128), ..ProptestConfig::default() })]

    /// Containers and partition tables mutated inside their own structures, with the
    /// checksums made valid again, so the damage gets past the checksum checks into the
    /// parsers behind them.
    #[test]
    fn mutated_structures_with_valid_checksums_never_panic(
        which in 0usize..8,
        region in any::<prop::sample::Index>(),
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..16),
    ) {
        let fixtures = disk::mutation_layouts();
        let mut b = fixtures[which % fixtures.len()].1.clone();
        let regions = disk::structure_regions(b.len());
        let (at, n) = regions[region.index(regions.len())];
        for (i, v) in edits {
            b[at + i.index(n)] = v;
        }
        disk::fix_checksums(&mut b);
        exercise(b);
    }
}
