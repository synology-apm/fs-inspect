# Tools to build and verify test images for fs-inspect (run with --privileged for loop mounts).
# UBUNTU: the release (tools/docker/lib.sh builds it on the host's own for Dockerfile.host).
ARG UBUNTU=24.04
FROM ubuntu:${UBUNTU}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      e2fsprogs dosfstools mtools exfatprogs exfat-fuse ntfs-3g xfsprogs btrfs-progs \
      fdisk gdisk util-linux qemu-utils python3 ca-certificates git make gcc libc6-dev \
      kmod fuse3 g++ \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/linux-apfs/apfsprogs.git /opt/apfsprogs \
    && make -C /opt/apfsprogs/mkapfs && make -C /opt/apfsprogs/apfsck \
    && cp /opt/apfsprogs/mkapfs/mkapfs /opt/apfsprogs/apfsck/apfsck /usr/local/bin/
WORKDIR /work
# The work area (fsi_tools.check.images.BASE): a volume mounted here.
ENV FSI_WORK=/work
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/* \
    && curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.99.0
ENV PATH=/root/.cargo/bin:$PATH
# GNU time for peak RSS; fatresize for FAT volume resizing.
RUN apt-get update && apt-get install -y --no-install-recommends time fatresize \
    && rm -rf /var/lib/apt/lists/*
# DRBD metadata after a file system, and md arrays, written by the real tools.
RUN apt-get update && apt-get install -y --no-install-recommends drbd-utils mdadm \
    && rm -rf /var/lib/apt/lists/*
# LVM2 volume groups on device-mapper (md arrays use mdadm above).
RUN apt-get update && apt-get install -y --no-install-recommends lvm2 \
    && rm -rf /var/lib/apt/lists/*
# POSIX ACLs written by setfacl (fsi_tools/fixtures/ext_xfs_btrfs_zfs_browse.py).
RUN apt-get update && apt-get install -y --no-install-recommends acl \
    && rm -rf /var/lib/apt/lists/*
# libfuse3 headers and pkg-config: FUSE programs built on the C API.
RUN apt-get update && apt-get install -y --no-install-recommends libfuse3-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
