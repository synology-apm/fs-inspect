//! The frozen ABI table: each sized struct's least accepted `struct_size` (`elem_size` for the
//! strided entries of the batch calls) on 64-bit targets. A struct only grows at its end, so
//! these never change; a failing assert here is an ABI break, not a value to update.

#![cfg(target_pointer_width = "64")]

use crate::support::{SizedStruct, StridedStruct};

macro_rules! frozen {
    ($trait:ident: $($t:ident = $n:literal),* $(,)?) => {
        $(const _: () = assert!(<crate::$t as $trait>::MIN_SIZE == $n);)*
    };
}

frozen! { SizedStruct:
    FsInspectBitmapShape = 40,
    FsInspectBrowseOptions = 16,
    FsInspectCatalogDisk = 12,
    FsInspectCatalogGroup = 56,
    FsInspectCatalogProblem = 24,
    FsInspectCatalogVolume = 104,
    FsInspectCloudFile = 21,
    FsInspectContainer = 48,
    FsInspectDeviceInfo = 88,
    FsInspectDiagnostic = 48,
    FsInspectDiagnosticsInfo = 16,
    FsInspectDirOptions = 16,
    FsInspectDiskSpec = 40,
    FsInspectErrorLocation = 32,
    FsInspectExportOptions = 48,
    FsInspectExportSummary = 32,
    FsInspectFinding = 96,
    FsInspectGuestMount = 48,
    FsInspectGuestSystem = 24,
    FsInspectIoCounts = 32,
    FsInspectItemError = 48,
    FsInspectLayoutInfo = 40,
    FsInspectLimits = 88,
    FsInspectLinkInfo = 56,
    FsInspectListingInfo = 40,
    FsInspectLogicalVolume = 96,
    FsInspectMapOptions = 48,
    FsInspectMember = 72,
    FsInspectNodeName = 56,
    FsInspectNote = 24,
    FsInspectOpenOptions = 48,
    FsInspectPartition = 168,
    FsInspectPartitionTableInfo = 16,
    FsInspectProgress = 32,
    FsInspectRangesInfo = 48,
    FsInspectReadAheadOptions = 40,
    FsInspectReadAheadStats = 72,
    FsInspectReadEvent = 56,
    FsInspectRootInfo = 128,
    FsInspectSecurityInfo = 80,
    FsInspectSetDisk = 16,
    FsInspectSkipped = 32,
    FsInspectSourceOps = 64,
    FsInspectStat = 192,
    FsInspectStreamInfo = 56,
    FsInspectUsage = 32,
    FsInspectVerifyChecked = 32,
    FsInspectVerifyNotCovered = 32,
    FsInspectVerifyOptions = 24,
    FsInspectVerifySummary = 48,
    FsInspectVolumeEntry = 192,
    FsInspectVolumeInfo = 104,
    FsInspectVolumeStateInfo = 72,
    FsInspectWalkOptions = 24,
    FsInspectWriteOps = 32,
    FsInspectXattr = 57,
}

frozen! { StridedStruct:
    FsInspectDirEntry = 68,
    FsInspectWalkEntry = 80,
}
