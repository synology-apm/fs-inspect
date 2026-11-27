//! RAID and mirror segments, flattened onto the PVs.

use super::text::{Section, Value};
use super::{Run, SECTOR};
use crate::map::{Area, Layout, ParityAlgo, Segment};
use std::collections::HashMap;

/// The name a RAID or mirror segment type is shown as (`raid5_ls` is a `raid5`).
pub(super) fn raid_name(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "mirror" => "mirror",
        "raid1" => "raid1",
        "raid0" | "raid0_meta" => "raid0",
        "raid10" | "raid10_near" => "raid10",
        "raid4" => "raid4",
        k if k.starts_with("raid5") => "raid5",
        k if k.starts_with("raid6") => "raid6",
        _ => return None,
    })
}

/// A RAID or mirror segment at logical bytes `[start, start + len)`, flattened onto the PVs:
/// its images (the `_rimage_` / `_mimage_` sub-LVs, linear LVs in `runs`) are cut where any of
/// them changes PV run, and each piece is a segment whose areas are on the PVs (the parity
/// rotation goes on across pieces). `next`: where each image's part of the LV's next RAID
/// segment starts. `Err`: why it is not mapped.
pub(super) fn raid_segments(
    kind: &str,
    seg: &Section,
    start: u64,
    len: u64,
    ext: u64,
    runs: &HashMap<&str, Vec<Run>>,
    next: &mut HashMap<String, u64>,
) -> std::result::Result<Vec<Segment>, String> {
    let k = RaidKind::of(kind, seg)?;
    let images = raid_images(kind, seg, ext, next)?;
    let n = images.len() as u64;
    if n == 0 || n as usize > crate::MAX_MEMBERS {
        return Err(format!("{n} images"));
    }
    let chunk = seg.uint("stripe_size").unwrap_or(0).saturating_mul(SECTOR);
    // Logical bytes per image byte, and the span of each image this segment uses.
    let (num, den) = k.ratio(n)?;
    let span = len
        .is_multiple_of(num)
        .then(|| len / num)
        .and_then(|x| x.checked_mul(den))
        .ok_or_else(|| format!("{len} bytes do not divide over {n} images"))?;
    let cuts = image_cuts(&images, span, runs)?;
    if matches!(k, RaidKind::Raid10(_)) && cuts.len() > 2 {
        return Err("a RAID 10 whose images are in several pieces".into());
    }
    let row = !matches!(k, RaidKind::Mirror);
    let mut out = Vec::new();
    for w in cuts.windows(2) {
        let (a, b) = (w[0], w[1]);
        if row && (chunk == 0 || !a.is_multiple_of(chunk)) {
            return Err(format!("image pieces not on {chunk}-byte chunks"));
        }
        let areas = image_areas(&images, runs, a, b)?;
        out.push(Segment { start: start + a * num / den, len: (b - a) * num / den, layout: k.layout(chunk, a, areas) });
    }
    if kind != "mirror" {
        for (name, base) in &images {
            next.insert(name.clone(), base + span);
        }
    }
    Ok(out)
}

/// How a RAID or mirror segment lays its images out.
pub(super) enum RaidKind {
    Mirror,
    Striped,
    /// The parity algorithm, and RAID 6.
    Parity(ParityAlgo, bool),
    /// Near copies.
    Raid10(u64),
}

impl RaidKind {
    fn of(kind: &str, seg: &Section) -> std::result::Result<RaidKind, String> {
        use ParityAlgo::*;
        Ok(match kind {
            "mirror" | "raid1" => RaidKind::Mirror,
            "raid0" | "raid0_meta" => RaidKind::Striped,
            "raid10" | "raid10_near" => RaidKind::Raid10(seg.uint("data_copies").ok().filter(|&c| c >= 2).unwrap_or(2)),
            "raid4" | "raid5_n" => RaidKind::Parity(ParityLast, false),
            "raid5" | "raid5_ls" => RaidKind::Parity(LeftSymmetric, false),
            "raid5_la" => RaidKind::Parity(LeftAsymmetric, false),
            "raid5_ra" => RaidKind::Parity(RightAsymmetric, false),
            "raid5_rs" => RaidKind::Parity(RightSymmetric, false),
            "raid6" | "raid6_zr" => RaidKind::Parity(RotatingZeroRestart, true),
            "raid6_nr" => RaidKind::Parity(RotatingNRestart, true),
            "raid6_nc" => RaidKind::Parity(RotatingNContinue, true),
            "raid6_la_6" => RaidKind::Parity(LeftAsymmetric6, true),
            "raid6_ra_6" => RaidKind::Parity(RightAsymmetric6, true),
            "raid6_ls_6" => RaidKind::Parity(LeftSymmetric6, true),
            "raid6_rs_6" => RaidKind::Parity(RightSymmetric6, true),
            "raid6_n_6" => RaidKind::Parity(ParityLast, true),
            other => return Err(format!("{other} is not mapped")),
        })
    }

    /// Logical bytes per image byte (`num / den`) over `n` images.
    fn ratio(&self, n: u64) -> std::result::Result<(u64, u64), String> {
        Ok(match self {
            RaidKind::Mirror => (1, 1),
            RaidKind::Striped => (n, 1),
            RaidKind::Parity(_, r6) => {
                (n.checked_sub(if *r6 { 2 } else { 1 }).filter(|&d| d > 0).ok_or("too few images")?, 1)
            }
            RaidKind::Raid10(near) => (n, *near),
        })
    }

    /// The layout of the piece starting `a` bytes into each image, on `areas`.
    fn layout(&self, chunk: u64, a: u64, areas: Vec<Area>) -> Layout {
        match self {
            RaidKind::Mirror => Layout::Mirror { legs: areas },
            RaidKind::Striped => Layout::Striped { chunk, areas },
            RaidKind::Parity(algo, raid6) => {
                Layout::Parity { chunk, algo: *algo, raid6: *raid6, first_row: a / chunk, areas }
            }
            RaidKind::Raid10(near) => {
                Layout::Raid10 { chunk, near: *near as u32, far: 1, offset: false, stride: 0, areas }
            }
        }
    }
}

/// A segment's images, and where its part of each starts in it (`next`: where the previous
/// RAID segment's part of each image ended).
pub(super) fn raid_images(
    kind: &str,
    seg: &Section,
    ext: u64,
    next: &HashMap<String, u64>,
) -> std::result::Result<Vec<(String, u64)>, String> {
    let mut images = Vec::new();
    if kind == "mirror" {
        let l = seg.list("mirrors").ok_or("a mirror without its images")?;
        for w in l.chunks(2) {
            match w {
                [Value::Str(n), Value::Int(le)] if *le >= 0 => {
                    images.push((n.clone(), (*le as u64).saturating_mul(ext)))
                }
                _ => return Err("a mirror image list that is not (name, extent) pairs".into()),
            }
        }
        return Ok(images);
    }
    let key = if kind.starts_with("raid0") { "raid0_lvs" } else { "raids" };
    let l = seg.list(key).ok_or("a RAID segment without its images")?;
    // A reshape's spare room before the data (1 means none).
    let off = match seg.uint("data_offset") {
        Ok(0 | 1) | Err(_) => 0,
        Ok(d) => d.saturating_mul(SECTOR),
    };
    for v in l {
        let Value::Str(n) = v else { return Err("a RAID image list with a non-name".into()) };
        if !n.contains("_rmeta_") {
            images.push((n.clone(), next.get(n).copied().unwrap_or(off)));
        }
    }
    Ok(images)
}

/// Where, in `[0, span)` of the images, any image changes PV run (with 0 and `span`).
pub(super) fn image_cuts(
    images: &[(String, u64)],
    span: u64,
    runs: &HashMap<&str, Vec<Run>>,
) -> std::result::Result<Vec<u64>, String> {
    let mut cuts = vec![0, span];
    for (name, base) in images {
        let r = runs.get(name.as_str()).ok_or_else(|| format!("image {name} is not a linear volume"))?;
        for &(off, _, _) in r {
            if off > *base && off < base + span {
                cuts.push(off - base);
            }
        }
    }
    cuts.sort_unstable();
    cuts.dedup();
    Ok(cuts)
}

/// Each image's area for its piece `[a, b)` (one PV run holds it).
pub(super) fn image_areas(
    images: &[(String, u64)],
    runs: &HashMap<&str, Vec<Run>>,
    a: u64,
    b: u64,
) -> std::result::Result<Vec<Area>, String> {
    let mut areas = Vec::with_capacity(images.len());
    for (name, base) in images {
        let off = base + a;
        let r = &runs[name.as_str()];
        let &(ro, rl, ra) =
            r.iter().find(|x| x.0 <= off && off < x.0 + x.1).ok_or_else(|| format!("image {name} is too short"))?;
        if off + (b - a) > ro + rl {
            return Err(format!("image {name} is too short"));
        }
        areas.push(Area { member: ra.member, start: ra.start + (off - ro) });
    }
    Ok(areas)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::text::parse;
    use super::*;

    const K: u64 = 1 << 10;
    const M: u64 = 1 << 20;

    fn sec(t: &str) -> Section {
        parse(t.as_bytes(), 8, 1000).unwrap()
    }

    type Runs = HashMap<&'static str, Vec<Run>>;

    /// A PV run of an image: (image offset, length, PV, PV offset).
    type PvRun = (u64, u64, usize, u64);

    /// Each image's PV runs.
    fn runs(v: &[(&'static str, &[PvRun])]) -> Runs {
        v.iter()
            .map(|(n, r)| (*n, r.iter().map(|&(o, l, m, s)| (o, l, Area { member: m as _, start: s })).collect()))
            .collect()
    }

    fn area(m: usize, start: u64) -> Area {
        Area { member: m as _, start }
    }

    fn areas_of(l: &Layout) -> &[Area] {
        match l {
            Layout::Mirror { legs } => legs,
            Layout::Striped { areas, .. } | Layout::Parity { areas, .. } | Layout::Raid10 { areas, .. } => areas,
            Layout::Linear(_) => panic!("linear"),
        }
    }

    #[test]
    fn segment_type_names() {
        for (k, n) in [
            ("mirror", Some("mirror")),
            ("raid1", Some("raid1")),
            ("raid0_meta", Some("raid0")),
            ("raid10_near", Some("raid10")),
            ("raid4", Some("raid4")),
            ("raid5_n", Some("raid5")),
            ("raid6_nc", Some("raid6")),
            ("striped", None),
            ("thin", None),
        ] {
            assert_eq!(raid_name(k), n, "{k}");
        }
    }

    #[test]
    fn segments_that_are_not_mapped() {
        let two = runs(&[("a", &[(0, M, 0, 0)]), ("b", &[(0, M, 1, 0)])]);
        let split = runs(&[("a", &[(0, 4 * K, 0, 0), (4 * K, M, 0, M)]), ("b", &[(0, 2 * M, 1, 0)])]);
        let cases: &[(&str, &str, u64, &Runs, &str)] = &[
            ("raid7", r#"raids = ["a", "b"]"#, 4 * K, &two, "raid7 is not mapped"),
            ("mirror", "", 4 * K, &two, "a mirror without its images"),
            ("mirror", r#"mirrors = ["a"]"#, 4 * K, &two, "not (name, extent) pairs"),
            ("mirror", r#"mirrors = ["a", -1]"#, 4 * K, &two, "not (name, extent) pairs"),
            ("raid1", "", 4 * K, &two, "a RAID segment without its images"),
            // RAID 0 lists its images under another name.
            ("raid0", r#"raids = ["a", "b"]"#, 4 * K, &two, "a RAID segment without its images"),
            ("raid1", "raids = [1]", 4 * K, &two, "a RAID image list with a non-name"),
            ("raid1", r#"raids = ["a_rmeta_0"]"#, 4 * K, &two, "0 images"),
            ("raid5_ls", r#"raids = ["a"] stripe_size = 16"#, 4 * K, &two, "too few images"),
            ("raid6_zr", r#"raids = ["a", "b"] stripe_size = 16"#, 4 * K, &two, "too few images"),
            ("raid0", r#"raid0_lvs = ["a", "b"] stripe_size = 16"#, 4 * K + 1, &two, "do not divide over 2 images"),
            ("raid1", r#"raids = ["a", "c"]"#, 4 * K, &two, "image c is not a linear volume"),
            ("raid1", r#"raids = ["a", "b"]"#, 2 * M, &two, "image a is too short"),
            ("raid0", r#"raid0_lvs = ["a", "b"]"#, 8 * K, &two, "not on 0-byte chunks"),
            ("raid0", r#"raid0_lvs = ["a", "b"] stripe_size = 128"#, 256 * K, &split, "not on 65536-byte chunks"),
            ("raid10", r#"raids = ["a", "b"] stripe_size = 8"#, 8 * K, &split, "several pieces"),
        ];
        for &(kind, text, len, r, why) in cases {
            let mut next = HashMap::new();
            let e = raid_segments(kind, &sec(text), 0, len, 64 * K, r, &mut next).unwrap_err();
            assert!(e.contains(why), "{kind} {text}: {e}");
            assert!(next.is_empty());
        }
    }

    #[test]
    fn pieces_and_continuation() {
        // RAID 5 over three images; image 0 changes PV run 64 KiB in. The rmeta sub-LVs are
        // not images.
        let r = runs(&[
            ("r_rimage_0", &[(0, 64 * K, 0, M), (64 * K, 128 * K, 0, 3 * M)]),
            ("r_rimage_1", &[(0, 192 * K, 1, M)]),
            ("r_rimage_2", &[(0, 192 * K, 2, M)]),
        ]);
        let s = sec(
            r#"stripe_size = 16 raids = ["r_rmeta_0", "r_rimage_0", "r_rmeta_1", "r_rimage_1", "r_rmeta_2", "r_rimage_2"]"#,
        );
        let mut next = HashMap::new();
        let got = raid_segments("raid5_ls", &s, 10 * M, 256 * K, 64 * K, &r, &mut next).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].start, got[0].len, got[1].start, got[1].len), (10 * M, 128 * K, 10 * M + 128 * K, 128 * K));
        assert_eq!(
            got[0].layout,
            Layout::Parity {
                chunk: 8 * K,
                algo: ParityAlgo::LeftSymmetric,
                raid6: false,
                first_row: 0,
                areas: vec![area(0, M), area(1, M), area(2, M)]
            }
        );
        // The second piece goes on with the parity rotation: 8 rows of 8 KiB in.
        assert_eq!(
            got[1].layout,
            Layout::Parity {
                chunk: 8 * K,
                algo: ParityAlgo::LeftSymmetric,
                raid6: false,
                first_row: 8,
                areas: vec![area(0, 3 * M), area(1, M + 64 * K), area(2, M + 64 * K)]
            }
        );
        assert_eq!(next.len(), 3);
        assert!(next.values().all(|&v| v == 128 * K));
        // The LV's next RAID segment starts where this one ended in each image.
        let got = raid_segments("raid5_ls", &s, 20 * M, 128 * K, 64 * K, &r, &mut next).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(areas_of(&got[0].layout), [area(0, 3 * M + 64 * K), area(1, M + 128 * K), area(2, M + 128 * K)]);
        assert!(next.values().all(|&v| v == 192 * K));
    }

    #[test]
    fn mirror_extents_and_data_offset() {
        let r = runs(&[("m_0", &[(0, 256 * K, 0, M)]), ("m_1", &[(0, 256 * K, 1, M)])]);
        // An old mirror names each image's first extent; it does not move `next`.
        let mut next = HashMap::new();
        let s = sec(r#"mirrors = ["m_0", 0, "m_1", 2]"#);
        let got = raid_segments("mirror", &s, 0, 64 * K, 64 * K, &r, &mut next).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].layout, Layout::Mirror { legs: vec![area(0, M), area(1, M + 128 * K)] });
        assert!(next.is_empty());
        // A RAID 1 with reshape room before its data (in sectors); 1 means none.
        for (off, start) in [(8, 4 * K), (1, 0), (0, 0)] {
            let s = sec(&format!(r#"raids = ["m_0", "m_1"] data_offset = {off}"#));
            let mut next = HashMap::new();
            let got = raid_segments("raid1", &s, 0, 64 * K, 64 * K, &r, &mut next).unwrap();
            assert_eq!(areas_of(&got[0].layout), [area(0, M + start), area(1, M + start)], "data_offset {off}");
            assert_eq!(next["m_0"], start + 64 * K);
        }
    }
}
