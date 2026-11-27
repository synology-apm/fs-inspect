"""An APFS container read without fs-inspect: the space manager of the newest checkpoint
(geometry, counters and the chunk bitmaps), as Apple's APFS reference lays it out, and apfsck
(apfsprogs) on an image. The fixture generators record what it reads next to the images, and
tests/test_apfs_alloc.py checks it on the committed containers."""

import struct

from fsi_tools.core.blockset import bitmap_runs
from fsi_tools.core.system import run


def fletcher64(data):
    m = 0xFFFFFFFF
    s1 = s2 = 0
    for (w,) in struct.iter_unpack("<I", data):
        s1 = (s1 + w) % m
        s2 = (s2 + s1) % m
    c1 = m - ((s1 + s2) % m)
    c2 = m - ((s1 + c1) % m)
    return (c2 << 32) | c1


def valid(obj):
    return struct.unpack_from("<Q", obj)[0] == fletcher64(obj[8:])


def newest_spaceman(f, offset=0):
    """The newest valid checkpoint of the container at `offset` of open file `f`: (block size,
    its xid, the container's block count, the space manager object's bytes, blk(n, count=1)
    reading container blocks)."""

    def blk(n, count=1):
        f.seek(offset + n * bs)
        return f.read(bs * count)

    f.seek(offset)
    b0 = f.read(4096)
    assert b0[32:36] == b"NXSB", "no NXSB"
    bs = struct.unpack_from("<I", b0, 0x24)[0]
    desc_blocks, desc_base = struct.unpack_from("<I", b0, 0x68)[0], struct.unpack_from("<Q", b0, 0x70)[0]
    best = None
    for i in range(desc_blocks):
        b = blk(desc_base + i)
        if b[32:36] == b"NXSB" and struct.unpack_from("<I", b, 0x18)[0] & 0xFFFF == 1 and valid(b):
            xid = struct.unpack_from("<Q", b, 0x10)[0]
            if best is None or xid > best[0]:
                best = (xid, b)
    xid, sb = best
    block_count = struct.unpack_from("<Q", sb, 0x28)[0]
    desc_index, desc_len = struct.unpack_from("<II", sb, 0x88)
    sm_oid = struct.unpack_from("<Q", sb, 0x98)[0]
    (data_blocks,) = struct.unpack_from("<I", sb, 0x6C)
    (data_base,) = struct.unpack_from("<Q", sb, 0x78)
    sm = None
    for k in range(desc_len):
        m = blk(desc_base + (desc_index + k) % desc_blocks)
        if struct.unpack_from("<I", m, 0x18)[0] & 0xFFFF != 0x0C:
            break
        flags, count = struct.unpack_from("<II", m, 0x20)
        for e in range(count):
            _t, _st, size, _pad, _fs, oid, paddr = struct.unpack_from("<IIIIQQQ", m, 0x28 + 40 * e)
            if oid == sm_oid:
                n = size // bs
                sm = b"".join(blk(data_base + (paddr - data_base + j) % data_blocks) for j in range(n))
        if flags & 1:
            break
    assert sm is not None and valid(sm), "space manager not found / bad checksum"
    return bs, xid, block_count, sm, blk


def apfs_meta(path, offset=0):
    """Newest checkpoint's geometry and space manager counters."""
    with open(path, "rb") as f:
        bs, xid, block_count, sm, _ = newest_spaceman(f, offset)
    dev = struct.unpack_from("<QQIIQI", sm, 0x30)
    return {
        "block_size": bs,
        "block_count": block_count,
        "xid": xid,
        "sm_bytes": len(sm),
        "sm_block_count": dev[0],
        "chunks": dev[1],
        "cibs": dev[2],
        "cabs": dev[3],
        "free": dev[4],
        "addr_offset": dev[5],
    }


def apfs_allocation(path, offset=0):
    """The container's allocation as its space manager records it, read from the chunk bitmaps
    of the newest checkpoint (main device; Apple's APFS reference: spaceman_phys_t, cib / cab
    address blocks, chunk_info_t): {"block_size", "block_count", "free" (the space manager's free
    counter), "used" ([(offset, length)] in container bytes, sorted), "bad" (what disagrees
    with itself: a chunk's bitmap with its free count, a checksum, the counters)}. A chunk
    without a bitmap (address 0) is free; blocks no chunk covers count as used (and as bad)."""
    used, bad = [], []
    with open(path, "rb") as f:
        bs, _, block_count, sm, blk = newest_spaceman(f, offset)
        _, chunks, cibs, cabs, free, addr_offset = struct.unpack_from("<QQIIQI", sm, 0x30)
        tops = [struct.unpack_from("<Q", sm, addr_offset + 8 * i)[0] for i in range(cabs or cibs)]
        cib_addrs = []
        for a in tops if cabs else []:
            cab = blk(a)
            if not valid(cab):
                bad.append(f"chunk-info address block at {a}: bad checksum")
                continue
            (n,) = struct.unpack_from("<I", cab, 0x24)
            cib_addrs += [struct.unpack_from("<Q", cab, 0x28 + 8 * i)[0] for i in range(n)]
        if not cabs:
            cib_addrs = tops
        covered, seen, total_free = 0, 0, 0
        for a in cib_addrs:
            cib = blk(a)
            if not valid(cib):
                bad.append(f"chunk-info block at {a}: bad checksum")
                continue
            (n,) = struct.unpack_from("<I", cib, 0x24)
            for i in range(n):
                _xid, addr, count, nfree, bm_addr = struct.unpack_from("<QQIIQ", cib, 0x28 + 32 * i)
                seen += 1
                total_free += nfree
                covered = max(covered, addr + count)
                if bm_addr == 0:
                    if nfree != count:
                        bad.append(f"chunk at block {addr}: no bitmap, {count - nfree} blocks used")
                    continue
                runs = bitmap_runs(blk(bm_addr), count)
                if count - sum(k for _, k in runs) != nfree:
                    bad.append(f"chunk at block {addr}: bitmap and free count {nfree} differ")
                used += [((addr + first) * bs, k * bs) for first, k in runs]
        if seen != chunks:
            bad.append(f"{seen} chunks found, the space manager counts {chunks}")
        if total_free != free:
            bad.append(f"the chunks' free counts sum to {total_free}, the space manager's to {free}")
        if covered < block_count:
            bad.append(f"blocks {covered}.. covered by no chunk")
            used.append((covered * bs, (block_count - covered) * bs))
    return {"block_size": bs, "block_count": block_count, "free": free, "used": sorted(used), "bad": bad}


def apfsck(img, strict=True):
    r = run("apfsck", *(["-cuw"] if strict else []), img, check=False, capture=True)
    return r.returncode, (r.stdout + r.stderr).strip()
