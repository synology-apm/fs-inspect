# Reporting a volume fs-inspect reads wrong

When fs-inspect fails to open a volume, or maps, lists or verifies it wrong, a capture of the
volume's metadata shows a developer what fs-inspect saw, and becomes the test that keeps the
fix.

## Capture it

```
fs-inspect list IMAGE...                          # which volume
fs-inspect capture IMAGE... --volume N -o DIR     # DIR/capture.fsbs, DIR/manifest.json
```

`IMAGE` is what fs-inspect reads anyway: a disk image (raw, VHD, VHDX, split raw) or a device
(`\\.\PhysicalDriveN` elevated, `/dev/sdX` as root, `/dev/rdiskN` with sudo).
A volume that is mounted and being written gives a capture that is not consistent: capture a
snapshot (VSS, LVM, `hdiutil`) or an unmounted volume where you can.

- `capture.fsbs` is the volume with the blocks holding files' contents zeroed. Every
  fs-inspect command reads it as an image: `fs-inspect info DIR/capture.fsbs` should show what
  the volume shows.
- `manifest.json` holds fs-inspect's version, the OS, the disks and volumes found, the
  volume's info, its `verify` report and diagnostics, and the capture's SHA-256.

The options and both files' fields are in [cli.md](cli.md#capture).

## What a capture holds

Metadata is not nothing. Before sharing a capture, look at it:

```
fs-inspect tree DIR/capture.fsbs        # every name it holds
```

- `capture.fsbs` holds file and directory names, sizes, times, owners and permissions,
  extended attributes, security descriptors, the volume label and UUID; small files a file
  system keeps inside its metadata (NTFS resident data, ext4 and btrfs inline data, symbolic
  link targets); and journals and logs (NTFS `$LogFile`, the ext journal, the XFS log), which
  can hold pieces of recently written files.
- `manifest.json` names the image files you gave (not their directories) and holds the
  volume's label and UUID, but lists none of the volume's files or directories.
- When the volume cannot be opened (`"mode": "fallback"` in the manifest), the capture is the
  start and the end of the partition or disk and where superblock copies are, whatever they
  hold: **a fallback capture may hold file contents**.
- `--with-data` keeps every file's content as well: only for a volume made for the report.

If the capture cannot be shared, the manifest and the commands' output are often enough to
start with.

## Report it

Open an issue with the **A volume fs-inspect reads wrong** template: the version, the OS
that ran fs-inspect and the one that made the volume, the command and its output, the
manifest, and the capture (zipped, or where to fetch it and its SHA-256).

**Issue attachments are public**: anyone can download them, and there is no private channel
for reports. Attach only a capture you may share; if you may not, say so in the issue and
leave it out.

## From capture to test (developers)

A capture becomes a fixture with `cargo xtask record-fixture`; its golden file records what
fs-inspect reads before the fix, so the fix shows as a diff:
[Recording and re-recording fixtures](contributing/testing.md#recording-and-re-recording-fixtures).
Only commit a capture its owner agreed to publish: the repository is public.
