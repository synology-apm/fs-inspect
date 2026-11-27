# Sourced by kernel_run.sh, the runner that uses the tools container: the checkout (`here`), the
# tools images and the release build. A build container sees the checkout read-only at /src; a
# virtme-ng guest sees it at /rw/src, under its one read-write directory (kernel_run.sh).
#
# FSI_HOST_KERNEL=1 (on a Linux host whose kernel has btrfs, XFS v4 and ZFS loaded): the runner
# uses a plain container on the host's kernel, with the tools of the host's Ubuntu release, which
# know its kernel's newest file system features. Otherwise a full kernel is booted with virtme-ng
# under QEMU in the container (Dockerfile.vm; TCG without /dev/kvm).
export MSYS_NO_PATHCONV=1  # Git Bash on Windows: keep container paths as they are
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && (pwd -W 2>/dev/null || pwd))"
host_kernel="${FSI_HOST_KERNEL:-}"

# Build the tools image; set image and target, the Docker volume its builds go to: fsi-tools
# and fsi-target, or on the host kernel fsi-tools:RELEASE and fsi-target-host (another
# glibc).
tools_image() {
  if [ "$host_kernel" = 1 ]; then
    local release
    release="$(. /etc/os-release && echo "$VERSION_ID")"
    image="fsi-tools:$release" target=fsi-target-host
    docker build -q --build-arg UBUNTU="$release" -t "$image" "$here/tools/docker" >/dev/null
  else
    image=fsi-tools target=fsi-target
    docker build -q -t "$image" "$here/tools/docker" >/dev/null
  fi
}

# After tools_image: build the image that runs on a full kernel; set vm_image and host_mounts
# (docker run arguments).
kernel_image() {
  if [ "$host_kernel" = 1 ]; then
    docker build -q --build-arg TOOLS="$image" -t fsi-tools-host \
      -f "$here/tools/docker/Dockerfile.host" "$here/tools/docker" >/dev/null
    vm_image=fsi-tools-host
    # The host's modules, so `modprobe` in the container finds them; the host's /dev, so devices
    # the kernel makes later (zvols' zd*, their partitions) show up (a container's /dev is a copy).
    host_mounts=(-v /lib/modules:/lib/modules:ro -v /dev:/dev)
  else
    docker build -q -t fsi-tools-vm -f "$here/tools/docker/Dockerfile.vm" "$here/tools/docker" >/dev/null
    vm_image=fsi-tools-vm
    host_mounts=()
  fi
}

# After tools_image: build the crates named (default fs-inspect-cli and fs-inspect-ffi) in release
# into the $target volume, each in its own cargo call: built in one, a binary would link with the
# libraries' unified features and differ from a release build of that crate alone.
build_release() {
  local crates="${*:-fs-inspect-cli fs-inspect-ffi}"
  docker run --rm --init -v "$here":/src:ro -v "$target":/target \
    -v fsi-cargo:/root/.cargo/registry -e CRATES="$crates" "$image" bash -c '
      set -eo pipefail
      for c in $CRATES; do
        # From the workspace directory: cargo reads .cargo/config.toml of the workspace from
        # where it runs, not from --manifest-path. A failure shows its errors, a build its last line.
        if ! log=$(cd /src && cargo build --release --locked --target-dir /target -p "$c" 2>&1); then
          echo "$log" | tail -40
          exit 1
        fi
        echo "$log" | tail -1
      done'
}

# ZFS opens a file vdev from its own kernel threads, which resolve the path in the host's mount
# namespace: a pool's files must be at the same path in the container as on the host.
# host_path VOLUME|/DIR prints that path (a volume's mount point on the host; made if missing).
host_path() {
  case "$1" in
    /*) echo "$1" ;;
    *) docker volume create "$1" >/dev/null && docker volume inspect -f '{{.Mountpoint}}' "$1" ;;
  esac
}
