#!/usr/bin/env bash
# Run a command in a QEMU VM (virtme-ng, Ubuntu kernel with the zfs module) inside the tools
# container, for what the Docker Desktop (WSL2) kernel cannot do (ZFS, XFS v4, btrfs, md linear):
#   tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.zfs_linux
# The command runs as root in the guest with tools/ as the working directory. The guest sees the
# checkout at /rw/src (read-write: fixtures are written there) and the container root
# read-only. /rw/work (FSI_WORK), for pools and scratch images, is a Docker volume
# (KERNEL_RUN_WORK_VOLUME, default fs-inspect-kernel-work) or a host directory
# (KERNEL_RUN_WORK_DIR). (One --rwdir: vng mishandles several.)
# Environment: KERNEL_RUN_MEMORY (4G), KERNEL_RUN_CPUS (4); KERNEL_RUN_KERNEL=hwe boots the HWE
# kernel instead of the GA one (md linear: not in 6.8); KERNEL_RUN_BUILD=1 first builds
# fs-inspect (or the crates of KERNEL_RUN_CRATES, such as "fs-inspect-cli fs-inspect-ffi") for Linux
# in the container and puts them in /rw/work (/rw/work/fs-inspect, ...).
# With FSI_HOST_KERNEL=1 (a Linux host whose kernel has the modules loaded) the command runs in a
# plain container on the host's kernel instead (tools/docker/lib.sh), with the same paths.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
tools_image
kernel_image
crates="${KERNEL_RUN_CRATES:-fs-inspect-cli}"
[ -n "${KERNEL_RUN_BUILD:-}" ] && build_release $crates
work="${KERNEL_RUN_WORK_DIR:-${KERNEL_RUN_WORK_VOLUME:-fs-inspect-kernel-work}}"
kvm=()
[ -e /dev/kvm ] && kvm=(--device /dev/kvm)
# FSI_WORK: /rw/work, or on the host kernel the work volume's (or directory's) own path there too
# (host_path: ZFS opens vdevs in the host's namespace). The host's cgroup namespace too: the swap
# case makes a memory-limited cgroup, which the container's own cgroup root (holding the
# container's processes) cannot have under it.
work_path=/rw/work
work_mount=()
if [ "$host_kernel" = 1 ]; then
  work_path="$(host_path "$work")"
  work_mount=(-v "$work":"$work_path" --cgroupns=host)
fi
mkdir -p "$here/target"
script="target/.zfs-vm-run-$$.sh"  # one per run: runs may overlap
{
  echo "cd /rw/src/tools && export FSI_WORK=$work_path"
  printf 'exec '; printf '%q ' "$@"
  echo
} > "$here/$script"
exec docker run --rm --init --privileged "${kvm[@]}" "${host_mounts[@]}" \
  -v "$here":/rw/src \
  -v "$work":/rw/work "${work_mount[@]}" \
  -v "$target":/target -v fsi-cargo:/root/.cargo/registry \
  -e KERNEL_RUN_BUILD="${KERNEL_RUN_BUILD:-}" -e CRATES="$crates" -e SCRIPT="$script" \
  -e KERNEL_RUN_KERNEL="${KERNEL_RUN_KERNEL:-}" -e KERNEL_RUN_MEMORY="${KERNEL_RUN_MEMORY:-4G}" -e KERNEL_RUN_CPUS="${KERNEL_RUN_CPUS:-4}" -e HOST_KERNEL="$host_kernel" \
  "$vm_image" bash -c '
    set -eo pipefail
    # What the command wrote into the checkout (fixtures, as root) goes back to the checkout
    # owner when it ends, so that the owner can clean or sync the tree (target/ is left alone).
    owner=$(stat -c %u:%g /rw/src)
    own() {
      [ "$owner" = 0:0 ] || find /rw/src -path /rw/src/target -prune -o -user 0 -exec chown -h "$owner" {} + || true
    }
    trap own EXIT
    if [ -n "$KERNEL_RUN_BUILD" ]; then
      for c in $CRATES; do
        cp "/target/release/${c%-cli}" /rw/work/
      done
    fi
    if [ "$HOST_KERNEL" = 1 ]; then bash "/rw/src/$SCRIPT"; exit; fi
    # The GA kernel (the oldest) unless KERNEL_RUN_KERNEL=hwe (the newest).
    pick=head
    [ "$KERNEL_RUN_KERNEL" = hwe ] && pick=tail
    kernel=$(ls /boot/vmlinuz-*-generic | sort -V | $pick -1)
    accel=--disable-kvm
    [ -e /dev/kvm ] && accel=
    cd /tmp
    vng --run "$kernel" $accel --memory "$KERNEL_RUN_MEMORY" --cpus "$KERNEL_RUN_CPUS" \
      --rwdir=/rw --exec "bash /rw/src/$SCRIPT"
  '
