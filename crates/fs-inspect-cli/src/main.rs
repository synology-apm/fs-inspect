//! `fs-inspect`: the command line of the fs-inspect SDK. The volumes of disk images (raw,
//! split raw, VHD, VHDX), their maps (data, zero, unused) as JSON Lines, and their file
//! systems' trees: listing, reading and exporting files. Every command is a thin wrapper
//! over [`fs_inspect`].

use clap::{Parser, Subcommand};
use fs_inspect_cli::app::{self, GlobalArgs};
use fs_inspect_cli::browse::{self, CatArgs, ExportArgs, LsArgs, PathArgs, TreeArgs, XattrArgs};
use fs_inspect_cli::capture::{CaptureArgs, capture};
use fs_inspect_cli::list::{info, layout, list};
use fs_inspect_cli::map::{MapArgs, map};
use fs_inspect_cli::source::{SourceArgs, VolumeArgs};
use fs_inspect_cli::verify::{VerifyArgs, verify};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "fs-inspect",
    version,
    about = "The volumes of disk images, their maps and their files",
    long_about = format!(
        "The volumes of disk images (raw, split raw, VHD, VHDX) and their maps: the \
         blocks each volume's file system uses (data, zero) and does not (unused); the files of \
         its file system (list, read, export to a directory, a tar or a zip).\n\n\
         Exit codes: {}, 1 other.",
        app::exit_codes()
    )
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    #[command(flatten)]
    global: GlobalArgs,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// List the volumes of the disks: one JSON object per line. Several disks are read
    /// together: LVM volume groups, md arrays and Windows dynamic disks spanning them are
    /// assembled, and their logical volumes listed after the disks' partitions.
    List(SourceArgs),
    /// What each part of each disk is: partition table, volume manager metadata, a volume
    /// (by its index in `list`), the reserved last MiB, or free. One JSON object per area, in
    /// disk order; the areas of a disk cover it.
    Layout(SourceArgs),
    /// Describe one volume: its file system and geometry.
    Info(VolumeArgs),
    /// The blocks of a volume (or of a whole disk) as JSON Lines, streamed, then a summary
    /// line.
    Map(MapArgs),
    /// The roots of a volume's file system (subvolumes, datasets, APFS volumes, snapshots):
    /// one JSON object per line.
    Roots(VolumeArgs),
    /// A directory's entries: one JSON object per line.
    Ls(LsArgs),
    /// A file's or directory's metadata: stat, names, streams, extended attributes, link
    /// target, security.
    Stat(PathArgs),
    /// A file's content (decoded when compressed), to stdout or a file.
    Cat(CatArgs),
    /// A node's extended attributes (JSON Lines), or one's value (raw bytes).
    Xattr(XattrArgs),
    /// A symbolic link's or junction's target.
    Readlink(PathArgs),
    /// Every entry under a directory, indented (text).
    Tree(TreeArgs),
    /// Files and directories into a directory, a pax tar or a zip archive; then a summary line
    /// (what was left out and why).
    Export(ExportArgs),
    /// Check a volume's file system whole: every checksum it keeps, every copy of a
    /// structure, every node read (with --data, every file's content too). Each finding as a
    /// JSON line, then a summary line. Exit code 15 when something is damaged (no copy of it
    /// is right); a wrong copy beside a right one is reported and passes.
    Verify(VerifyArgs),
    /// Capture a volume's metadata to report a problem with it (docs/reporting.md) or record
    /// it as a test fixture: `<DIR>/capture.fsbs` (sparse, in volume coordinates) and
    /// `<DIR>/manifest.json` (fs-inspect's version, the OS, the disks and volumes, the
    /// volume's info, verification and diagnostics, the capture's SHA-256).
    ///
    /// Privacy: by default the capture keeps the blocks the file system allocates less those
    /// holding files' contents (zeros instead), but metadata still holds file and directory
    /// names, sizes, times, extended attributes, security descriptors, the volume label, and
    /// whatever small files the file system keeps inside its metadata (resident or inline
    /// data, symbolic link targets). Look at what is in it before sharing it. `--with-data`
    /// keeps the contents too. A volume that cannot be opened is captured conservatively
    /// (`"mode": "fallback"` in the manifest): the start and end of its partition or disk and
    /// where superblock copies are, which may hold any data.
    Capture(CaptureArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    app::run(&cli.global, |opts| match &cli.cmd {
        Cmd::List(a) => list(a, opts),
        Cmd::Layout(a) => layout(a, opts),
        Cmd::Info(a) => info(a, opts),
        Cmd::Map(a) => map(a, opts),
        Cmd::Roots(a) => browse::roots(a, opts),
        Cmd::Ls(a) => browse::ls(a, opts),
        Cmd::Stat(a) => browse::stat(a, opts),
        Cmd::Cat(a) => browse::cat(a, opts),
        Cmd::Xattr(a) => browse::xattr(a, opts),
        Cmd::Readlink(a) => browse::readlink(a, opts),
        Cmd::Tree(a) => browse::tree(a, opts),
        Cmd::Export(a) => browse::export(a, opts),
        Cmd::Verify(a) => verify(a, opts),
        Cmd::Capture(a) => capture(a, opts),
    })
}
