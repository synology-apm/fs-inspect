"""Sets of 512-byte units of a volume, held as Python ints (bit i = bytes [512 i, 512 i + 512)).

512 bytes divides every allocation unit of every supported file system, so sets built from
file extents, native allocation bitmaps and fs-inspect output (`--block-size 512`) compare
exactly whatever the cluster size or the alignment of the data area.
"""

import re

UNIT = 512


def from_ranges(ranges):
    """Set covering byte ranges [(offset, length)] (partial units round outwards).

    Many ranges go through a bytearray, converted once: OR-ing each range into the int costs
    the size of the whole set per range (minutes for the clusters of a 50 GiB volume)."""
    spans = [(off // UNIT, -(-(off + ln) // UNIT)) for off, ln in ranges if ln > 0]
    if len(spans) <= 16:
        x = 0
        for s, e in spans:
            x |= ((1 << (e - s)) - 1) << s
        return x
    buf = bytearray((max(e for _, e in spans) + 7) // 8)
    for s, e in spans:
        a, b = -(-s // 8), e // 8  # the whole bytes of [s, e)
        if a >= b:
            for i in range(s, e):
                buf[i >> 3] |= 1 << (i & 7)
            continue
        buf[a:b] = b"\xff" * (b - a)
        for i in (*range(s, a * 8), *range(b * 8, e)):
            buf[i >> 3] |= 1 << (i & 7)
    return int.from_bytes(buf, "little")


def bitmap_runs(bitmap, nbits):
    """Runs (first, count) of the set bits among the first `nbits` of an allocation bitmap
    (least significant bit first)."""
    x = int.from_bytes(bitmap[: (nbits + 7) // 8], "little") & ((1 << nbits) - 1)
    if not x:
        return []
    bits = bin(x)[:1:-1]
    return [(m.start(), m.end() - m.start()) for m in re.finditer("1+", bits)]


def span(off, ln):
    return from_ranges([(off, ln)])


def to_ranges(x):
    """Sorted, coalesced byte ranges [(offset, length)] of a set."""
    if x <= 0:
        return []
    bits = bin(x)[:1:-1]  # LSB first
    return [(m.start() * UNIT, (m.end() - m.start()) * UNIT) for m in re.finditer("1+", bits)]


def count(x):
    return x.bit_count()


def nbytes(x):
    return x.bit_count() * UNIT


def first(x, n=8):
    """The first n ranges of a set, for messages."""
    return [(hex(o), ln) for o, ln in to_ranges(x)[:n]]


def below(nbytes_):
    """All units of [0, nbytes)."""
    return (1 << (nbytes_ // UNIT)) - 1


def shift_range(x, off, ln, to):
    """Units of x within [off, off + ln) moved to start at byte `to` (all multiples of UNIT)."""
    s, n, t = off // UNIT, ln // UNIT, to // UNIT
    return ((x >> s) & ((1 << n) - 1)) << t
