"""Sparse images (`.fsbs`): a raw image stored as its non-zero 4 KiB runs, read back by
fs_inspect_io::sparse (crates/fs-inspect-io/src/sparse.rs documents the format: the data in
64 KiB chunks, each deflated when that is shorter).

    python -m fsi_tools.check.fsbs pack IMAGE OUT.fsbs
    python -m fsi_tools.check.fsbs unpack IN.fsbs IMAGE
"""

import os
import struct
import sys
import zlib

from fsi_tools.oslib.files import data_spans, presize

MAGIC = b"FSBSPRS\x00"
BLOCK = 4096
CHUNK = 64 * 1024
HEAD = 48


def runs(path):
    """Sorted, coalesced (offset, length) of the non-zero BLOCK-sized blocks of `path`."""
    size = os.path.getsize(path)
    zero = bytes(BLOCK)
    out = []
    with open(path, "rb") as f:
        # Read by offset: data_spans moves the descriptor's position (lseek) under any buffered
        # reads, which then return the wrong bytes.
        read = (lambda n, at: os.pread(f.fileno(), n, at)) if hasattr(os, "pread") else None
        for start, end in data_spans(f, size):
            start -= start % BLOCK
            f.seek(start)
            pos = start
            while pos < end:
                n = min(BLOCK * 256, end - pos)
                b = read(n, pos) if read else f.read(n)
                if not b:
                    break
                for k in range(0, len(b), BLOCK):
                    blk = b[k : k + BLOCK]
                    if blk != zero[: len(blk)]:
                        o = pos + k
                        if out and out[-1][0] + out[-1][1] == o:
                            out[-1][1] += len(blk)
                        else:
                            out.append([o, len(blk)])
                pos += len(b)
    return size, [tuple(r) for r in out]


def write(out, size, rs, chunks):
    """Write the sparse image `out`: a `size`-byte image whose runs `rs` hold the data
    `chunks` yields (in order, pieces of any size)."""
    with open(out, "wb") as o:
        o.write(bytes(HEAD))
        ends, pending = [], bytearray()
        stored = total = 0

        def flush():
            nonlocal stored
            z = zlib.compress(bytes(pending), 6)
            body = z if len(z) < len(pending) else bytes(pending)
            o.write(body)
            stored += len(body)
            ends.append(stored)
            pending.clear()

        for b in chunks:
            total += len(b)
            view = memoryview(b)
            while view:
                n = min(CHUNK - len(pending), len(view))
                pending += view[:n]
                view = view[n:]
                if len(pending) == CHUNK:
                    flush()
        if pending:
            flush()
        assert total == sum(ln for _, ln in rs), "data does not match the runs"
        table_at = HEAD + stored
        for off, ln in rs:
            o.write(struct.pack("<QQ", off, ln))
        for e in ends:
            o.write(struct.pack("<Q", e))
        o.seek(0)
        o.write(MAGIC + struct.pack("<QQQIIQ", size, len(rs), total, CHUNK, 0, table_at))


def pack(img, out):
    """Store raw image `img` as the sparse image `out`: (image size, [(offset, length)] runs)."""
    size, rs = runs(img)

    def data():
        with open(img, "rb") as src:
            for off, ln in rs:
                src.seek(off)
                while ln:
                    b = src.read(min(ln, 1 << 20))
                    yield b
                    ln -= len(b)

    write(out, size, rs, data())
    return size, rs


def read(fsbs):
    """(image size, [(offset, length)] runs, the runs' bytes) of the sparse image `fsbs`."""
    with open(fsbs, "rb") as f:
        head = f.read(HEAD)
        assert head[:8] == MAGIC, f"{fsbs}: not a sparse image"
        size, n, total, chunk, _, table_at = struct.unpack("<QQQIIQ", head[8:HEAD])
        body = f.read(table_at - HEAD)
        rs = [struct.unpack("<QQ", f.read(16)) for _ in range(n)]
        m = -(-total // chunk)
        ends = struct.unpack(f"<{m}Q", f.read(8 * m))
    parts, start = [], 0
    for k, e in enumerate(ends):
        b = body[start:e]
        parts.append(b if len(b) == min(chunk, total - k * chunk) else zlib.decompress(b))
        start = e
    data = b"".join(parts)
    assert len(data) == sum(ln for _, ln in rs), f"{fsbs}: data does not match the runs"
    return size, [tuple(r) for r in rs], data


def unpack(fsbs, img):
    """Write the raw image of sparse image `fsbs` to `img` (a sparse file)."""
    size, rs, data = read(fsbs)
    with open(img, "wb") as o:
        presize(o, size)
        at = 0
        for off, ln in rs:
            o.seek(off)
            o.write(data[at : at + ln])
            at += ln


if __name__ == "__main__":
    cmd, a, b = sys.argv[1:4]
    {"pack": pack, "unpack": unpack}[cmd](a, b)
