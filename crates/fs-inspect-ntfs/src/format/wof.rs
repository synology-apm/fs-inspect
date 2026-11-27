//! WOF (`IO_REPARSE_TAG_WOF`): `WOF_EXTERNAL_INFO` (version u32, provider u32: 1 WIM, 2
//! file), then for the file provider `FILE_PROVIDER_EXTERNAL_INFO_V1` (version u32,
//! algorithm u32, flags u32). The data is in the `WofCompressedData` stream.

use fs_inspect_core::Result;
use fs_inspect_core::bytes::u32_at;
use fs_inspect_core::windows::reparse::{Reparse, WOF};

/// The WOF compression of a file-provider WOF reparse point: `Ok(None)` for another tag,
/// an error for the WIM provider (its data is in a WIM file, not on the volume).
pub fn wof(r: &Reparse) -> Result<Option<WofAlgorithm>> {
    if r.tag != WOF {
        return Ok(None);
    }
    let provider = u32_at(&r.data, 4)?;
    if provider != 2 {
        return Err(fs_inspect_core::Error::unsupported(format!(
            "a WOF file of provider {provider} (its data is outside the volume)"
        )));
    }
    Ok(Some(match u32_at(&r.data, 12)? {
        0 => WofAlgorithm::Xpress4K,
        1 => WofAlgorithm::Lzx,
        2 => WofAlgorithm::Xpress8K,
        3 => WofAlgorithm::Xpress16K,
        a => return Err(fs_inspect_core::Error::unsupported(format!("WOF compression algorithm {a}"))),
    }))
}

/// How WOF compressed a file (`FILE_PROVIDER_COMPRESSION_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WofAlgorithm {
    Xpress4K,
    Xpress8K,
    Xpress16K,
    Lzx,
}

impl WofAlgorithm {
    /// Bytes of each chunk.
    pub fn chunk_size(self) -> u64 {
        match self {
            WofAlgorithm::Xpress4K => 4096,
            WofAlgorithm::Xpress8K => 8192,
            WofAlgorithm::Xpress16K => 16384,
            WofAlgorithm::Lzx => 32768,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn wof_info() {
        let mut b = WOF.to_le_bytes().to_vec();
        b.extend_from_slice(&16u16.to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        for v in [1u32, 2, 1, 3] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        assert_eq!(wof(&Reparse::parse(&b).unwrap()).unwrap(), Some(WofAlgorithm::Xpress16K));
        b[12] = 1; // the WIM provider
        assert!(wof(&Reparse::parse(&b).unwrap()).is_err());
    }
}
