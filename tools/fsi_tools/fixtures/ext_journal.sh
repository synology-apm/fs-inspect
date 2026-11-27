#!/bin/sh
# Make fixtures/ext/journal: an ext4 volume (metadata_csum, so its journal has csum_v3) copied
# while mounted after a sync, so the kernel's log is still to replay (needs_recovery): what the
# journal checksums of a verification are checked against.
# In the virtme-ng VM (the kernel mounts it):
#   tools/docker/kernel_run.sh sh /rw/src/tools/fsi_tools/fixtures/ext_journal.sh
set -eu
out=/rw/src/fixtures/ext/journal
work=${FSI_WORK:-/rw/work}/ext-journal
mkdir -p "$out" "$work/mnt"
live=$work/live.img
img=$work/ext4-jlog.img
rm -f "$live" "$img"
truncate -s 64M "$live"
mkfs.ext4 -q -F -O metadata_csum,64bit "$live"
# A long commit interval: only the sync below commits, and nothing is checkpointed yet.
mount -o loop,commit=600 "$live" "$work/mnt"
i=1
while [ "$i" -le 40 ]; do
    mkdir "$work/mnt/d$i"
    echo "file $i" > "$work/mnt/d$i/f"
    i=$((i + 1))
done
sync
cp --sparse=always "$live" "$img"
umount "$work/mnt"
dumpe2fs -h "$img" 2>/dev/null | grep -E "features|Journal checksum type"
cd /rw/src/tools && python3 -m fsi_tools.check.fsbs pack "$img" "$out/ext4-jlog.fsbs"
sha256sum "$img"
uname -r
rm -rf "$work"
