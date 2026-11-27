"""Byte ranges as (offset, length) pairs, and the set operations on them.

Every function takes fs-inspect's JSON ranges (dicts with "offset" and "length") or pairs, in any
order, and gives sorted (offset, length) tuples, overlapping or touching ones merged, none empty.
"""


def pairs(ranges):
    """(offset, length) of each range, as given."""
    return [(r["offset"], r["length"]) if isinstance(r, dict) else (r[0], r[1]) for r in ranges]


def coalesce(ranges):
    """The ranges sorted, overlapping or touching ones merged, empty ones dropped."""
    out = []
    for off, ln in sorted(pairs(ranges)):
        if ln <= 0:
            continue
        if out and off <= out[-1][0] + out[-1][1]:
            end = max(out[-1][0] + out[-1][1], off + ln)
            out[-1] = (out[-1][0], end - out[-1][0])
        else:
            out.append((off, ln))
    return out


def from_bounds(spans):
    """(offset, length) of each [start, end) span."""
    return [(s, e - s) for s, e in spans]


def bounds(ranges):
    """The ranges coalesced, as [start, end) spans."""
    return [(o, o + n) for o, n in coalesce(ranges)]


def coalesce_keyed(items):
    """(key, offset, length) triples (a disk and a range on it) sorted, the overlapping or
    touching ranges of one key merged, empty ones dropped."""
    out = []
    for key, off, ln in sorted(items):
        if ln <= 0:
            continue
        if out and out[-1][0] == key and off <= out[-1][1] + out[-1][2]:
            k, o, n = out[-1]
            out[-1] = (k, o, max(n, off + ln - o))
        else:
            out.append((key, off, ln))
    return out


def subtract(a, b):
    """What `a` covers outside `b`."""
    b = coalesce(b)
    out, j = [], 0
    for off, ln in coalesce(a):
        cur, end = off, off + ln
        while j < len(b) and b[j][0] + b[j][1] <= cur:
            j += 1
        k = j
        while k < len(b) and b[k][0] < end:
            if b[k][0] > cur:
                out.append((cur, b[k][0] - cur))
            cur = max(cur, b[k][0] + b[k][1])
            k += 1
        if cur < end:
            out.append((cur, end - cur))
    return out


def intersect(a, b):
    """What `a` and `b` both cover."""
    a, b = coalesce(a), coalesce(b)
    out, i, j = [], 0, 0
    while i < len(a) and j < len(b):
        lo = max(a[i][0], b[j][0])
        ea, eb = a[i][0] + a[i][1], b[j][0] + b[j][1]
        if lo < min(ea, eb):
            out.append((lo, min(ea, eb) - lo))
        if ea < eb:
            i += 1
        else:
            j += 1
    return out


def total(ranges):
    """Bytes of the ranges, as given (overlaps counted twice)."""
    return sum(ln for _, ln in pairs(ranges))
