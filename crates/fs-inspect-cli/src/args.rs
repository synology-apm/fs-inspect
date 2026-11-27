//! The exclusion and range output options of `fs-inspect map`, and the value parsers (sizes,
//! block sizes, numbers) the other commands use too.

use clap::{Args, ValueEnum};
use fs_inspect::range::Granularity;
use fs_inspect::{BlockClass, DeviceMapOptions, ExcludePattern, VolumeMapOptions};
use std::path::PathBuf;

/// Which files to leave out.
#[derive(Args, Debug)]
pub struct ExcludeArgs {
    /// Leave a file out: an absolute path in the volume (with `--whole-disk`, in every volume).
    /// `*` and `?` match within one name (`/*.sig`; not `**`, nor `..`). A missing file is
    /// skipped. Repeatable.
    #[arg(long = "exclude", value_name = "PATH")]
    pub exclude: Vec<ExcludePattern>,
    /// Do not leave out the file systems' default files (paging, swap and spent hibernation
    /// files).
    #[arg(long)]
    pub no_default_excludes: bool,
}

impl ExcludeArgs {
    /// Map options leaving these files out.
    pub fn volume_options(&self) -> VolumeMapOptions {
        VolumeMapOptions::default().with_default_excludes(!self.no_default_excludes).with_excludes(self.exclude.clone())
    }

    pub fn device_options(&self) -> DeviceMapOptions {
        DeviceMapOptions::default().with_map(self.volume_options())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum KindArg {
    /// Blocks to copy.
    Data,
    /// Blocks that read as zeros: write zeros, do not read them.
    Zero,
    /// Blocks not needed (in a comparison: used before, free now).
    Unused,
    /// Data and zero together: everything a restore must get right.
    Used,
    /// Allocated but left out (excluded files, the VSS diff area): part of unused, exact.
    Excluded,
}

impl KindArg {
    pub fn as_str(self) -> &'static str {
        match self {
            KindArg::Data => "data",
            KindArg::Zero => "zero",
            KindArg::Unused => "unused",
            KindArg::Used => "used",
            KindArg::Excluded => "excluded",
        }
    }

    pub fn class(self) -> BlockClass {
        match self {
            KindArg::Data => BlockClass::Data,
            KindArg::Zero => BlockClass::Zero,
            KindArg::Unused => BlockClass::Unused,
            KindArg::Used => BlockClass::Used,
            KindArg::Excluded => BlockClass::Excluded,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CoordsArg {
    /// From the volume's start.
    Volume,
    /// From the start of the disk image.
    Image,
}

/// What a command printing ranges prints.
#[derive(Args, Debug)]
pub struct OutArgs {
    /// Block size of the ranges: `exact` (byte ranges), `unit` (the file system's allocation
    /// unit), or a power of two (sizes like 64K accepted). A whole disk's ranges are at least
    /// its sector.
    #[arg(long, value_parser = parse_block_size, default_value = "exact", value_name = "SIZE")]
    pub block_size: BlockSize,
    /// Offsets relative to the volume or to the image.
    #[arg(long, value_enum, default_value_t = CoordsArg::Volume)]
    pub coords: CoordsArg,
    /// Which ranges to print; repeatable. Default: data, zero, unused and excluded.
    #[arg(long, value_enum)]
    pub kind: Vec<KindArg>,
    /// Output file (written atomically); stdout when omitted.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

impl OutArgs {
    pub fn kinds(&self) -> Vec<KindArg> {
        if self.kind.is_empty() {
            vec![KindArg::Data, KindArg::Zero, KindArg::Unused, KindArg::Excluded]
        } else {
            // Each kind once, in the order first named.
            let mut k: Vec<KindArg> = Vec::with_capacity(self.kind.len());
            for &x in &self.kind {
                if !k.contains(&x) {
                    k.push(x);
                }
            }
            k
        }
    }
}

pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        None => (s, 1u64),
        Some((i, _)) => {
            let m = match s[i..].to_ascii_lowercase().as_str() {
                "k" | "kb" | "kib" => 1 << 10,
                "m" | "mb" | "mib" => 1 << 20,
                "g" | "gb" | "gib" => 1 << 30,
                "t" | "tb" | "tib" => 1 << 40,
                other => return Err(format!("unknown size suffix {other:?}")),
            };
            (&s[..i], m)
        }
    };
    let n: u64 = num.parse().map_err(|_| format!("bad size {s:?}"))?;
    n.checked_mul(mult).ok_or_else(|| format!("size {s:?} overflows"))
}

/// The block size of printed ranges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockSize {
    /// Byte ranges (a whole disk's: sectors).
    Exact,
    /// The file system's allocation unit (a whole disk's: the largest of its volumes').
    Unit,
    /// Blocks of this many bytes.
    Bytes(Granularity),
}

impl BlockSize {
    /// The `unit` of [`Map::blocks`](fs_inspect::Map::blocks).
    pub fn unit(self) -> Option<Granularity> {
        match self {
            BlockSize::Exact => Some(Granularity::BYTE),
            BlockSize::Unit => None,
            BlockSize::Bytes(g) => Some(g),
        }
    }
}

pub fn parse_block_size(s: &str) -> Result<BlockSize, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "exact" => Ok(BlockSize::Exact),
        "unit" => Ok(BlockSize::Unit),
        _ => match parse_size(s)? {
            0 => Err("block size 0: use `exact` or `unit`".into()),
            n => Granularity::new(n).map(BlockSize::Bytes).map_err(|_| format!("block size {n} is not a power of two")),
        },
    }
}

pub fn parse_u64(s: &str) -> Result<u64, String> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16),
        None => s.parse(),
    }
    .map_err(|_| format!("bad number {s:?}"))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn sizes_take_binary_suffixes_in_any_case() {
        assert_eq!(parse_size("4096"), Ok(4096));
        assert_eq!(parse_size(" 64k "), Ok(64 << 10));
        assert_eq!(parse_size("1M"), Ok(1 << 20));
        assert_eq!(parse_size("2MiB"), Ok(2 << 20));
        assert_eq!(parse_size("3gb"), Ok(3 << 30));
        assert_eq!(parse_size("1TiB"), Ok(1 << 40));
    }

    #[test]
    fn a_bad_size_says_why() {
        assert_eq!(parse_size("4x"), Err("unknown size suffix \"x\"".into()));
        assert_eq!(parse_size("k"), Err("bad size \"k\"".into()));
        assert_eq!(parse_size(""), Err("bad size \"\"".into()));
        assert!(parse_size("99999999999999999999").unwrap_err().starts_with("bad size"));
        assert_eq!(parse_size("16777216T"), Err("size \"16777216T\" overflows".into()));
    }

    #[test]
    fn block_sizes_are_exact_unit_or_a_power_of_two() {
        assert_eq!(parse_block_size("EXACT"), Ok(BlockSize::Exact));
        assert_eq!(parse_block_size("unit"), Ok(BlockSize::Unit));
        let b = parse_block_size("64K").unwrap();
        assert_eq!(b.unit(), Some(Granularity::new(64 << 10).unwrap()));
        assert_eq!(BlockSize::Exact.unit(), Some(Granularity::BYTE));
        assert_eq!(BlockSize::Unit.unit(), None);
        assert_eq!(parse_block_size("0"), Err("block size 0: use `exact` or `unit`".into()));
        assert_eq!(parse_block_size("3000"), Err("block size 3000 is not a power of two".into()));
        assert!(parse_block_size("big").is_err());
    }

    #[test]
    fn numbers_are_decimal_or_hex() {
        assert_eq!(parse_u64("4096"), Ok(4096));
        assert_eq!(parse_u64(" 0x1000 "), Ok(4096));
        assert_eq!(parse_u64("0XfF"), Ok(255));
        assert_eq!(parse_u64("0x"), Err("bad number \"0x\"".into()));
        assert_eq!(parse_u64("12k"), Err("bad number \"12k\"".into()));
    }

    /// No `--kind`: every kind but `used`; a kind named twice is printed once, in the order the
    /// kinds were first named.
    #[test]
    fn kinds_default_and_each_once() {
        let out = |kind: Vec<KindArg>| OutArgs {
            block_size: BlockSize::Exact,
            coords: CoordsArg::Volume,
            kind,
            output: None,
        };
        assert_eq!(out(vec![]).kinds(), [KindArg::Data, KindArg::Zero, KindArg::Unused, KindArg::Excluded]);
        let named = vec![KindArg::Used, KindArg::Data, KindArg::Used, KindArg::Data, KindArg::Data];
        assert_eq!(out(named).kinds(), [KindArg::Used, KindArg::Data]);
    }
}
