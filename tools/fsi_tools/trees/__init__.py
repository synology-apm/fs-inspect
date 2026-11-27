"""The test trees: what the fixture generators (fixtures/) write onto a volume the OS mounts, and
what that OS then reports (each module's manifest)."""

import os
import random


def pattern(seed, n):
    """`n` non-zero bytes, distinct per seed (stored in the fixture; kept small)."""
    rng = random.Random(str(seed))
    return (bytes(rng.randrange(1, 256) for _ in range(4096)) * (n // 4096 + 1))[:n]


def write(path, data):
    """Write `data` to `path`, making its directories."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
