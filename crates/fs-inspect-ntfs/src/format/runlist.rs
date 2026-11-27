//! Mapping pairs (runlist) decoding and encoding.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Run {
    Mapped { vcn: u64, lcn: u64, len: u64 },
    Sparse { vcn: u64, len: u64 },
}

impl Run {
    pub fn vcn(&self) -> u64 {
        match *self {
            Run::Mapped { vcn, .. } | Run::Sparse { vcn, .. } => vcn,
        }
    }
    pub fn len(&self) -> u64 {
        match *self {
            Run::Mapped { len, .. } | Run::Sparse { len, .. } => len,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn lcn(&self) -> Option<u64> {
        match *self {
            Run::Mapped { lcn, .. } => Some(lcn),
            Run::Sparse { .. } => None,
        }
    }
    pub fn end_vcn(&self) -> u64 {
        self.vcn() + self.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunlistError {
    #[error("mapping pairs truncated at byte {0}")]
    Truncated(usize),
    #[error("invalid run header {header:#04x} at byte {at}")]
    BadHeader { header: u8, at: usize },
    #[error("zero-length run at byte {0}")]
    ZeroLength(usize),
    #[error("run LCN {lcn}+{len} outside volume ({cluster_count} clusters)")]
    LcnOutOfRange { lcn: i128, len: u64, cluster_count: u64 },
    #[error("runs extend past highest VCN ({end} > {highest}+1)")]
    VcnOverflow { end: u64, highest: i64 },
    #[error("runs end at VCN {end}, expected {expected}")]
    VcnGap { end: u64, expected: u64 },
    #[error("too many runs (limit {0})")]
    TooManyRuns(usize),
}

/// Decode mapping pairs. `lowest_vcn`/`highest_vcn` come from the attribute header;
/// `highest_vcn == -1` denotes an empty attribute. Every mapped run must lie within
/// `cluster_count`; at most `max_runs` runs.
pub fn decode(
    bytes: &[u8],
    lowest_vcn: u64,
    highest_vcn: i64,
    cluster_count: u64,
    max_runs: usize,
) -> Result<Vec<Run>, RunlistError> {
    let mut runs = Vec::new();
    let mut pos = 0usize;
    let mut vcn = lowest_vcn;
    let mut lcn: i128 = 0;
    loop {
        let Some(&header) = bytes.get(pos) else {
            return Err(RunlistError::Truncated(pos));
        };
        if header == 0 {
            break;
        }
        let len_bytes = (header & 0x0F) as usize;
        let off_bytes = (header >> 4) as usize;
        if len_bytes == 0 || len_bytes > 8 || off_bytes > 8 {
            return Err(RunlistError::BadHeader { header, at: pos });
        }
        let start = pos;
        pos += 1;
        let Some(len_field) = bytes.get(pos..pos + len_bytes) else {
            return Err(RunlistError::Truncated(pos));
        };
        let len = read_unsigned(len_field);
        pos += len_bytes;
        if len == 0 {
            return Err(RunlistError::ZeroLength(start));
        }
        if runs.len() >= max_runs {
            return Err(RunlistError::TooManyRuns(max_runs));
        }
        if off_bytes == 0 {
            runs.push(Run::Sparse { vcn, len });
        } else {
            let Some(off_field) = bytes.get(pos..pos + off_bytes) else {
                return Err(RunlistError::Truncated(pos));
            };
            pos += off_bytes;
            lcn += read_signed(off_field) as i128;
            if lcn < 0 || lcn + len as i128 > cluster_count as i128 {
                return Err(RunlistError::LcnOutOfRange { lcn, len, cluster_count });
            }
            runs.push(Run::Mapped { vcn, lcn: lcn as u64, len });
        }
        vcn = vcn.checked_add(len).ok_or(RunlistError::VcnOverflow { end: u64::MAX, highest: highest_vcn })?;
        if highest_vcn >= 0 && vcn > highest_vcn as u64 + 1 {
            return Err(RunlistError::VcnOverflow { end: vcn, highest: highest_vcn });
        }
    }
    if highest_vcn < 0 && !runs.is_empty() {
        return Err(RunlistError::VcnOverflow { end: vcn, highest: highest_vcn });
    }
    Ok(runs)
}

/// Verify that `runs` cover exactly `[lowest, highest + 1)`.
pub fn check_complete(runs: &[Run], lowest: u64, highest: i64) -> Result<(), RunlistError> {
    // Widened: `highest` comes from disk and may be i64::MAX.
    let expected = (highest as i128 + 1).max(lowest as i128) as u64;
    let end = runs.last().map(|r| r.end_vcn()).unwrap_or(lowest);
    if end != expected {
        return Err(RunlistError::VcnGap { end, expected });
    }
    Ok(())
}

fn read_unsigned(b: &[u8]) -> u64 {
    b.iter().rev().fold(0u64, |acc, &x| (acc << 8) | x as u64)
}

fn read_signed(b: &[u8]) -> i64 {
    let v = read_unsigned(b);
    let bits = b.len() * 8;
    if bits == 64 {
        v as i64
    } else if v & (1 << (bits - 1)) != 0 {
        (v | (!0u64 << bits)) as i64
    } else {
        v as i64
    }
}

fn unsigned_bytes(v: u64) -> usize {
    let mut n = 1;
    while n < 8 && (v >> (n * 8)) != 0 {
        n += 1;
    }
    n
}

fn signed_bytes(v: i64) -> usize {
    for n in 1..8 {
        let bits = n * 8;
        let min = -(1i64 << (bits - 1));
        let max = (1i64 << (bits - 1)) - 1;
        if v >= min && v <= max {
            return n;
        }
    }
    8
}

/// Encode runs as mapping pairs (terminated with 0x00).
pub fn encode(runs: &[Run]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prev_lcn: i64 = 0;
    for r in runs {
        let len = r.len();
        let lb = unsigned_bytes(len);
        match *r {
            Run::Sparse { .. } => {
                out.push(lb as u8);
                out.extend_from_slice(&len.to_le_bytes()[..lb]);
            }
            Run::Mapped { lcn, .. } => {
                let delta = lcn as i64 - prev_lcn;
                let ob = signed_bytes(delta);
                out.push(((ob as u8) << 4) | lb as u8);
                out.extend_from_slice(&len.to_le_bytes()[..lb]);
                out.extend_from_slice(&delta.to_le_bytes()[..ob]);
                prev_lcn = lcn as i64;
            }
        }
    }
    out.push(0);
    out
}

/// Merge adjacent runs (same kind, contiguous VCN and LCN).
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn normalize(runs: &[Run]) -> Vec<Run> {
    let mut out: Vec<Run> = Vec::with_capacity(runs.len());
    for &r in runs.iter().filter(|r| !r.is_empty()) {
        if let Some(last) = out.last_mut() {
            match (*last, r) {
                (Run::Mapped { vcn, lcn, len }, Run::Mapped { vcn: v2, lcn: l2, len: n2 })
                    if vcn + len == v2 && lcn + len == l2 =>
                {
                    *last = Run::Mapped { vcn, lcn, len: len + n2 };
                    continue;
                }
                (Run::Sparse { vcn, len }, Run::Sparse { vcn: v2, len: n2 }) if vcn + len == v2 => {
                    *last = Run::Sparse { vcn, len: len + n2 };
                    continue;
                }
                _ => {}
            }
        }
        out.push(r);
    }
    out
}

/// Total mapped clusters.
pub fn mapped_clusters(runs: &[Run]) -> u64 {
    runs.iter().filter_map(|r| r.lcn().map(|_| r.len())).sum()
}

/// Map a VCN range `[vcn, vcn+len)` to LCN extents (sparse parts skipped).
/// `runs` must be sorted by VCN.
pub fn map_vcn_range(runs: &[Run], vcn: u64, len: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    if len == 0 {
        return out;
    }
    let end = vcn.saturating_add(len);
    let start_idx = runs.partition_point(|r| r.end_vcn() <= vcn);
    for r in &runs[start_idx..] {
        if r.vcn() >= end {
            break;
        }
        if let Run::Mapped { vcn: rv, lcn, len: rl } = *r {
            let s = vcn.max(rv);
            let e = end.min(rv + rl);
            if s < e {
                out.push((lcn + (s - rv), e - s));
            }
        }
    }
    out
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn known_vector() {
        // 0x21 0x18 0x34 0x56 : len 0x18, lcn +0x5634
        // 0x21 0x08 0x00 0xF0 : len 8, delta -0x1000
        // 0x01 0x04 : sparse 4
        let b = [0x21, 0x18, 0x34, 0x56, 0x21, 0x08, 0x00, 0xF0, 0x01, 0x04, 0x00];
        let runs = decode(&b, 0, 0x18 + 8 + 4 - 1, 1 << 20, 100).unwrap();
        assert_eq!(
            runs,
            vec![
                Run::Mapped { vcn: 0, lcn: 0x5634, len: 0x18 },
                Run::Mapped { vcn: 0x18, lcn: 0x4634, len: 8 },
                Run::Sparse { vcn: 0x20, len: 4 },
            ]
        );
        assert_eq!(encode(&runs), b.to_vec());
        // A three-byte delta field decodes the same.
        let b3 = [0x21, 0x18, 0x34, 0x56, 0x31, 0x08, 0x00, 0xF0, 0xFF, 0x01, 0x04, 0x00];
        assert_eq!(decode(&b3, 0, 0x18 + 8 + 4 - 1, 1 << 20, 100).unwrap(), runs);
    }

    #[test]
    fn check_complete_max_highest() {
        // highest_vcn = i64::MAX with an empty runlist must not overflow or pass.
        assert!(matches!(check_complete(&[], 0, i64::MAX), Err(RunlistError::VcnGap { .. })));
        assert_eq!(check_complete(&[], 0, -1), Ok(()));
    }

    #[test]
    fn errors() {
        assert_eq!(decode(&[0x11, 0x05], 0, 10, 100, 10), Err(RunlistError::Truncated(2)));
        assert!(matches!(
            decode(&[0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0, 10, 100, 10),
            Err(RunlistError::BadHeader { .. })
        ));
        assert!(matches!(decode(&[0x90, 0], 0, 10, 100, 10), Err(RunlistError::BadHeader { .. })));
        assert_eq!(decode(&[0x11, 0x00, 0x05, 0x00], 0, 10, 100, 10), Err(RunlistError::ZeroLength(0)));
        assert!(matches!(decode(&[0x11, 0x05, 0x62, 0x00], 0, 10, 100, 10), Err(RunlistError::LcnOutOfRange { .. })));
        // negative LCN
        assert!(matches!(decode(&[0x11, 0x05, 0xF0, 0x00], 0, 10, 100, 10), Err(RunlistError::LcnOutOfRange { .. })));
        assert!(matches!(decode(&[0x11, 0x20, 0x05, 0x00], 0, 10, 100, 10), Err(RunlistError::VcnOverflow { .. })));
        assert_eq!(
            decode(&[0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00], 0, 10, 100, 2),
            Err(RunlistError::TooManyRuns(2))
        );
        assert_eq!(decode(&[0x00], 0, -1, 100, 2), Ok(vec![]));
        // eight-byte fields
        let b = [0x88, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(decode(&b, 0, 0, 100, 2).unwrap(), vec![Run::Mapped { vcn: 0, lcn: 2, len: 1 }]);
    }

    #[test]
    fn completeness() {
        let runs = vec![Run::Mapped { vcn: 5, lcn: 1, len: 5 }];
        assert!(check_complete(&runs, 5, 9).is_ok());
        assert!(check_complete(&runs, 5, 10).is_err());
        assert!(check_complete(&[], 0, -1).is_ok());
    }

    #[test]
    fn vcn_mapping() {
        let runs = vec![
            Run::Mapped { vcn: 0, lcn: 100, len: 4 },
            Run::Sparse { vcn: 4, len: 4 },
            Run::Mapped { vcn: 8, lcn: 10, len: 4 },
        ];
        assert_eq!(map_vcn_range(&runs, 2, 8), vec![(102, 2), (10, 2)]);
        assert_eq!(map_vcn_range(&runs, 4, 4), vec![]);
    }

    #[test]
    fn normalization() {
        let runs = vec![
            Run::Mapped { vcn: 0, lcn: 100, len: 4 },
            Run::Mapped { vcn: 4, lcn: 104, len: 4 },
            Run::Sparse { vcn: 8, len: 1 },
            Run::Sparse { vcn: 9, len: 1 },
            Run::Mapped { vcn: 10, lcn: 1, len: 1 },
        ];
        assert_eq!(
            normalize(&runs),
            vec![
                Run::Mapped { vcn: 0, lcn: 100, len: 8 },
                Run::Sparse { vcn: 8, len: 2 },
                Run::Mapped { vcn: 10, lcn: 1, len: 1 }
            ]
        );
    }

    fn arb_runs() -> impl Strategy<Value = Vec<Run>> {
        proptest::collection::vec((any::<bool>(), 1u64..1_000_000, 0u64..(1 << 40)), 0..40).prop_map(|v| {
            let mut vcn = 0;
            v.into_iter()
                .map(|(sparse, len, lcn)| {
                    let r = if sparse { Run::Sparse { vcn, len } } else { Run::Mapped { vcn, lcn, len } };
                    vcn += len;
                    r
                })
                .collect()
        })
    }

    proptest! {
        #[test]
        fn roundtrip(runs in arb_runs()) {
            let enc = encode(&runs);
            let end: u64 = runs.iter().map(|r| r.len()).sum();
            let dec = decode(&enc, 0, end as i64 - 1, 1 << 41, 1000).unwrap();
            prop_assert_eq!(dec, runs);
        }

        #[test]
        fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..200), cc in 1u64..1_000_000) {
            if let Ok(runs) = decode(&bytes, 0, i64::MAX, cc, 1000) {
                for r in runs {
                    if let Run::Mapped { lcn, len, .. } = r {
                        prop_assert!(lcn + len <= cc);
                    }
                }
            }
        }
    }
}
