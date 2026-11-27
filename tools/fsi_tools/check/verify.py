"""Checks of fs-inspect's output, and copies of the used ranges (what a backup restores)."""

import os

from fsi_tools.core.ranges import coalesce, pairs
from fsi_tools.core.units import MiB
from fsi_tools.oslib.files import make_sparse

from .fsinspect import bins, parse_lines


def check_used(img, data, zero, *args):
    """`--kind used` (with the same other arguments) is data and zero together."""
    used = bins.map(img, *args, "--kind", "used")
    assert coalesce(used) == coalesce(list(data) + list(zero)), (
        f"--kind used != data + zero ({len(used)} ranges vs {len(data)} + {len(zero)})"
    )


def table_structures(img, ss=512):
    """(offset, length) of the partition table structures of a disk image, read independently:
    the MBR sector and every EBR, or the protective MBR and both GPT headers and arrays."""
    with open(img, "rb") as f:

        def sector(lba, n=1):
            f.seek(lba * ss)
            return f.read(n * ss)

        mbr = sector(0)
        if mbr[510:512] != b"\x55\xaa":
            return []
        out = [(0, ss)]
        types = [mbr[446 + 16 * i + 4] for i in range(4)]
        if 0xEE in types:
            hdr = sector(1)
            alt, arr = int.from_bytes(hdr[32:40], "little"), int.from_bytes(hdr[72:80], "little")
            n, esz = int.from_bytes(hdr[80:84], "little"), int.from_bytes(hdr[84:88], "little")
            arr_bytes = -(-n * esz // ss) * ss
            out += [(ss, ss), (arr * ss, arr_bytes)]
            b = sector(alt)
            out += [(alt * ss, ss), (int.from_bytes(b[72:80], "little") * ss, arr_bytes)]
            return sorted(out)
        for i in range(4):
            e = mbr[446 + 16 * i : 462 + 16 * i]
            if e[4] in (0x05, 0x0F, 0x85):
                ext = int.from_bytes(e[8:12], "little")
                ebr = ext
                while True:
                    out.append((ebr * ss, ss))
                    nxt = sector(ebr)[446 + 16 : 462 + 16]
                    if nxt[4] not in (0x05, 0x0F, 0x85):
                        break
                    ebr = ext + int.from_bytes(nxt[8:12], "little")
        return sorted(out)


def disk_kept(img, parts):
    """What a whole-disk map keeps used of the space outside `parts` ((start, size), sorted):
    the table structures, everything before the first partition and the last MiB."""
    disk = os.path.getsize(img)
    keep = [*table_structures(img), (0, parts[0][0] if parts else disk), (max(0, disk - MiB), min(MiB, disk))]
    gaps, pos = [], 0
    for start, size in parts:
        if start > pos:
            gaps.append((pos, start))
        pos = max(pos, start + size)
    if pos < disk:
        gaps.append((pos, disk))
    out = []
    for gs, ge in gaps:
        for ks, kl in keep:
            s, e = max(gs, ks), min(ge, ks + kl)
            if s < e:
                out.append((s, e - s))
    return sorted(out)


def check_partition(used, unused, start, length, zero=()):
    """Assert that used, unused and zero are each sorted and coalesced, disjoint, and together
    cover [start, start + length)."""
    allr = sorted(
        [(r["offset"], r["length"], "u") for r in used]
        + [(r["offset"], r["length"], "f") for r in unused]
        + [(r["offset"], r["length"], "z") for r in zero]
    )
    pos = start
    for kind_list in (used, unused, zero):
        prev_end = -1
        for r in kind_list:
            assert r["length"] > 0, f"empty range {r}"
            assert r["offset"] > prev_end, f"not sorted/coalesced at {r}"
            prev_end = r["offset"] + r["length"]
    for off, ln, _ in allr:
        if off < start:
            # a used range may start before the volume when widened to the granularity
            off, ln = start, ln - (start - off)
            if ln <= 0:
                continue
        assert off == pos, f"gap or overlap at {pos:#x} (next range at {off:#x})"
        pos = off + ln
    assert pos >= start + length, f"ranges end at {pos:#x}, volume ends at {start + length:#x}"


# What the bytes outside the used ranges hold in a copy: "random" (default) proves the file
# system never reads them (a real disk restored onto keeps old data there, not zeros);
# "zero" leaves them as holes. Random data goes into the first and last FILL_EDGE bytes of
# every gap (where metadata such as never-used inode-table tails or a journal body starts and
# ends), at most FILL_CAP bytes per copy: the rest stays sparse, so a huge sparse image (the
# 300 GiB btrfs case) does not turn into hundreds of GiB of writes.
COPY_FILL = os.environ.get("FSI_COPY_FILL", "random")
FILL_EDGE = 16 * MiB
FILL_CAP = 1 << 30
_GARBAGE = None


def copy_used(src_img, dst_img, used, base=0, size=None, fill=None, zero=()):
    """Copy only `used` (offset + base) of src_img into a new dst_img of `size` bytes, and
    write zeros over `zero` (what a restore must do for the zero class). `fill` ("random" or
    "zero"; default COPY_FILL): what the bytes outside `used` hold."""
    global _GARBAGE
    size = size if size is not None else os.path.getsize(src_img)
    make_sparse(dst_img, size)
    spans = sorted((o + base, min(o + base + ln, size)) for o, ln in pairs(used))
    with open(src_img, "rb") as s, open(dst_img, "r+b") as d:
        if (fill or COPY_FILL) == "random":
            if _GARBAGE is None:
                _GARBAGE = os.urandom(8 * MiB)
            pos, budget = 0, FILL_CAP
            for a, b in [*spans, (size, size)]:
                if pos < a:
                    edges = [(pos, a)] if a - pos <= 2 * FILL_EDGE else [(pos, pos + FILL_EDGE), (a - FILL_EDGE, a)]
                    for x, y in edges:
                        y = min(y, x + budget)
                        budget -= max(0, y - x)
                        d.seek(x)
                        while x < y:
                            n = min(y - x, len(_GARBAGE))
                            d.write(_GARBAGE[:n])
                            x += n
                pos = max(pos, b)
        for off, end in spans:
            ln = end - off
            s.seek(off)
            d.seek(off)
            while ln > 0:
                n = min(ln, 8 * MiB)
                d.write(s.read(n))
                ln -= n
        zeros = bytes(MiB)
        for o, ln in pairs(zero):
            off, ln = o + base, min(ln, size - o - base)
            d.seek(off)
            while ln > 0:
                n = min(ln, MiB)
                d.write(zeros[:n])
                ln -= n


def verified(img, *args):
    """`fs-inspect verify --data IMG ARGS`, then `verify --disks IMG`, on a volume the system
    just wrote: each run to its end and passed, with no finding but a checksum type not computed
    (`unverified`). What they checked, as a line to report."""
    out = []
    for mode in (["--data", *args], ["--disks"]):
        r = bins.run("verify", img, *mode)
        lines = parse_lines(r.stdout)
        summary = lines[-1] if lines else {}
        found = [f for f in lines[:-1] if f.get("kind") != "unverified"]
        assert r.returncode == 0 and summary.get("passed") and "stopped" not in summary and not found, (
            f"verify {' '.join(mode)}: exit {r.returncode}, {summary}, {found[:5]}\n{r.stderr[-2000:]}"
        )
        checked = {k: v["structures"] for k, v in summary.get("checked", {}).items()}
        out.append(f"{summary.get('fs')}: {checked} not covered {summary.get('not_covered', {})}")
    return "verify " + "; ".join(out)
