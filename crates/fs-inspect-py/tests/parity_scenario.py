"""The cross-language scenario through the Python binding (`cargo xtask parity-run`): on IMAGE,
the set's disks and volumes, disk 0's layout, the only volume's map, a walk of its main root, a
file read whole, a verification, a tar export to OUT and the set's diagnostics, printed as the
canonical text the Rust facade and the C API print for the same calls
(crates/xtask/src/parity_run.rs has the format).

    python parity_scenario.py IMAGE OUT

A script, not a test module: pytest does not collect it (no ``test_`` prefix).
"""

from __future__ import annotations

import sys

import fs_inspect as fi

WALK_SHOWN = 50
UNIT = 4096
PATH = "/plain.bin"
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
MASK = (1 << 64) - 1


def fnv1a64(h: int, data: bytes | bytearray | memoryview) -> int:
    for b in bytes(data):
        h = ((h ^ b) * FNV_PRIME) & MASK
    return h


def device_text(d: fi.DeviceRef) -> str:
    match d:
        case fi.DeviceRef.Disk(disk):
            return f"disk:{disk}"
        case fi.DeviceRef.Logical(container, lv):
            return f"logical:{container}:{lv}"
    raise AssertionError(d)


def scenario(image: str, tar: str) -> list[str]:
    out: list[str] = []
    # 1. The set: its disks and volumes.
    with fi.DiskSet.open([fi.DiskSpec.path(image)]) as d:
        out.append(f"disks {len(d.disks)}")
        volumes = d.volumes()
        out.append(f"volumes {len(volumes)}")
        for v in volumes:
            fs_kind = v.fs_kind.value if v.fs_kind is not None else "none"
            line = f"volume {v.index} fs={fs_kind} readable={v.readability.value} key={v.key}"
            match v.location:
                case fi.VolumeLocation.Device(device, span):
                    line += (
                        f" location=device device={device_text(device)}"
                        f" offset={span.offset} length={span.length}"
                    )
                case fi.VolumeLocation.Pool(container):
                    line += f" location=pool container={container}"
            out.append(line)

        # 2. Disk 0's layout.
        layout = d.layout(0)
        areas = layout.areas
        out.append(f"layout disk=0 size={layout.size} areas={len(areas)}")
        for i, a in enumerate(areas):
            match a.content:
                case fi.AreaContent.Volume(volume):
                    vol_text = f" volume={volume}"
                case _:
                    vol_text = ""
            out.append(
                f"area {i} kind={a.content.kind.value}{vol_text}"
                f" offset={a.range.offset} length={a.range.length}"
            )

        # 3. The only volume's map.
        vol = d.open_volume(d.only_volume())
        m = vol.map()
        ranges = m.blocks(fi.BlockClass.USED, UNIT)
        out.append(f"map used_bytes={m.bytes(fi.BlockClass.USED)}")
        out.append(
            f"map unit={UNIT} used_ranges={len(ranges)}"
            f" used_range_bytes={sum(r.length for r in ranges)}"
        )

        # 4. A walk of the main root.
        fs = vol.browse()
        root = fs.roots()[0]
        walked = 0
        shown: list[str] = []
        for w in fs.walker(root.node):
            if len(shown) < WALK_SHOWN:
                kind = w.entry.kind.value if w.entry.kind is not None else "unknown"
                shown.append(f"entry {w.path} {kind}")
            walked += 1
        out.append(f"walk entries={walked} shown={len(shown)}")
        out.extend(shown)

        # 5. A file read whole.
        f = fs.open(fs.resolve(root.root, PATH).node)
        buf = bytearray(65536)
        at, h = 0, FNV_OFFSET
        while n := f.read_at(at, buf):
            h = fnv1a64(h, memoryview(buf)[:n])
            at += n
        out.append(f"file {PATH} size={f.size} read={at} fnv1a64={h:016x}")

        # 6. The volume verified.
        r = vol.verify()
        structures = sum(c.structures for c in r.checked.values())
        nbytes = sum(c.bytes for c in r.checked.values())
        out.append(
            f"verify passed={int(r.passed)} complete={int(r.stopped is None)} damaged={r.damaged}"
            f" recovered={r.recovered} findings={len(r.findings)} dropped={r.dropped}"
        )
        out.append(
            f"verify checked_kinds={len(r.checked)} checked_structures={structures}"
            f" checked_bytes={nbytes} not_covered={len(r.not_covered)}"
        )

        # 7. The root exported to a tar archive.
        top = fs.resolve(root.root, "/")
        rep = fs.export([top], fi.TarSink(tar))
        out.append(
            f"export files={rep.files} dirs={rep.dirs} bytes={rep.bytes}"
            f" skipped={len(rep.skipped)} cloud={len(rep.cloud)} notes={len(rep.notes)}"
        )

        # 8. The set's diagnostics.
        out.append(f"diagnostics {len(d.diagnostics)}")
    return out


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("usage: parity_scenario.py IMAGE OUT")
    text = "".join(line + "\n" for line in scenario(sys.argv[1], sys.argv[2]))
    # Bytes as they are: no newline translation on Windows.
    sys.stdout.buffer.write(text.encode())


if __name__ == "__main__":
    main()
