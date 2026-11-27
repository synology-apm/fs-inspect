# Profiling

For developers who want to find where opening, mapping, browsing or reading spends its time, or
to measure what a change costs.

## Profiling a command

```sh
fs-inspect --profile trace.json map IMAGE > ranges.jsonl
fs-inspect --profile trace.json export IMAGE -p /path --to OUT
```

`--profile FILE` works with every command and records:

- **Every read**, timed at the lowest layer of the read path, the same layer as `--io-stats`
  (the reads of the decoded disk: reads of the file under a VHD or VHDX are not counted
  separately). Each read records its start, duration, offset, length and the innermost span
  it was made in.
- **Every phase**: the debug-level `tracing` spans of the library (below).

When the command ends, FILE is a Chrome trace: open it in Perfetto (<https://ui.perfetto.dev>)
or `chrome://tracing`. Each thread has a phase track and a read track; reads are named after
their phase, and their `args` hold `offset`, `length` and `ok`. Helper threads that read ahead
have read tracks of their own. A one-line summary goes to stderr.

Without `--profile` nothing is recorded. With it, each read costs two clock reads and a lock;
spans are recorded only on entry and exit.

### Spans

| Span | What |
|---|---|
| `disk.table`, `disk.set` | the partition table; assembling a disk set (LVM, md, LDM) |
| `disk.guest` | finding the guest systems of a disk set (drive letters, fstab, ZFS mounts, macOS) |
| `probe`, `fs.open` | detecting the file system; opening it (superblock, start of the MFT, checkpoint, ...) |
| `fs.replay` | replaying a crash-consistent volume's log in memory, the first time a recovered view is read |
| `fs.open.again` | opening the volume again for another view (recovered or on disk) or checksum mode (`Checksums::Trust`); its fields name both |

The change trackers in the file system crates add these spans while a scan runs
(`ScanSession::scan_files`):

| Span | What |
|---|---|
| `ntfs.journal`, `ntfs.walk`, `ntfs.space` | the USN journal range; the MFT and files; space outside files (system streams; inside it `ntfs.indexes` for index blocks, `ntfs.log` for `$LogFile` record pages, `ntfs.extend` for data under `$Extend`) |
| `ext.journal`, `ext.inodes`, `ext.space` | the jbd2 log, inode tables, group metadata |
| `xfs.inodes`, `xfs.space` | inode chunks, AG metadata |
| `btrfs.newext`, `btrfs.files`, `btrfs.space` | new extents in the extent tree, fs trees, tree blocks |
| `refs.walk`, `refs.space` | the directory tree, node pages |
| `apfs.walk`, `apfs.space` | each volume's files, container metadata |
| `zfs.newblk`, `zfs.ddt`, `zfs.files` | blocks born after the previous txg, the dedup table, ZPL files |
| `fat.tree`, `fat.space` | the directory tree, the FAT and directory clusters |

### Summary fields

```json
{"type":"profile","trace":"trace.json","wall_ms":…,"reads":…,"bytes":…,"busy_ms":…,"io_busy":…,
 "gap_ms":…,"after_last_read_ms":…,"outside_spans_ms":…,
 "gaps":[{"under_us":10,"count":…,"ms":…}, …, {"under_us":null,"count":…,"ms":…}],
 "sizes":[{"up_to":4096,"count":…,"bytes":…}, …],
 "phases":[{"name":"fs.open","calls":…,"total_ms":…,"own_ms":…,"reads":…,"bytes":…,"read_ms":…,"gap_ms":…}, …]}
```

| Field | Meaning |
|---|---|
| `wall_ms` | from the start of recording to the end of the command |
| `busy_ms`, `io_busy` | time with at least one read in flight, and its share of the wall time |
| `gap_ms`, `gaps` | time with no read in flight (before the first read too), in classes by length (`under_us` is the bound; `null` is the longest class) |
| `after_last_read_ms` | time after the last read (encoding, comparing, writing output) |
| `outside_spans_ms` | time in no outermost span (argument parsing, writing output files, ...) |
| `sizes` | read sizes in classes (`up_to` is the bound in bytes) |
| `phases` | one entry per span name, by `own_ms` descending: `total_ms` is the span's time, `own_ms` without its child spans; `reads`, `bytes` and `read_ms` are the reads made in it (in no inner span), those of threads reading ahead for it included; `gap_ms` is its time between reads |

With a queue depth above 1, `read_ms` is the sum of the reads' durations and can exceed
`total_ms`.

### Reading a profile

1. **Start with `io_busy`.** High (over 0.9): the device is the bottleneck. Look at `sizes` and
   the trace's read track: many small, scattered reads mean latency (one round trip each);
   large but slow reads mean bandwidth. Low: look for the phases with a large `gap_ms`, the CPU
   work between reads.
2. **Look at the shape of `gaps`.** Many gaps of 10–100 µs are per-item parsing; a few of
   several ms are batch processing or another phase. In the trace, alternating dense reads and
   blank stretches mean a batch is read, then parsed.
3. **Compare latency on a cold source.** A second run on the same image may be served from the
   OS cache (image files on Windows, devices on Linux without `O_DIRECT`).
4. **The number and size of reads do not depend on the queue depth**, only when they are sent.
   More reads is a regression; each file system's golden read counts (`*-reads.txt`) catch it.
