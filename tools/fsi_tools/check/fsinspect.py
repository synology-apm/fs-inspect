"""The command lines of this tree: one place that runs them and parses their JSON lines.

`bins` is the process-wide instance. It runs every command with the fs-inspect binary
(`bins.inspect`, which a caller sets to the binary under test).

The map helpers run `map` with the checks' defaults (one kind, `used`, at the file-system
allocation unit) and hand back its range records ({"offset", "length"}, no summary line).
"""

import json
import os
import tempfile

from fsi_tools.core import system


class CliError(AssertionError):
    """A command exited non-zero (an AssertionError: a check that failed)."""

    def __init__(self, args, returncode, stderr):
        super().__init__(f"{' '.join(map(str, args))}: exit {returncode}: {stderr.strip()[-1500:]}")
        self.returncode = returncode
        self.stderr = stderr


def parse_lines(text):
    """The records of JSON Lines `text`."""
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def has_opt(args, name):
    """Whether option `name` is in `args` (as `NAME VALUE` or `NAME=VALUE`)."""
    return any(a == name or a.startswith(name + "=") for a in args)


def map_args(*args):
    """`map ARGS`, with `--kind used` and `--block-size unit` unless given."""
    args = [str(a) for a in args]
    if not has_opt(args, "--kind"):
        args += ["--kind", "used"]
    if not has_opt(args, "--block-size"):
        args += ["--block-size", "unit"]
    return ["map", *args]


def range_lines(text):
    """The range records of `map` or `scan` output: the summary line dropped, the `type` key
    removed."""
    return [{k: v for k, v in x.items() if k != "type"} for x in parse_lines(text) if x.get("type") != "summary"]


class Binaries:
    """Runs the fs-inspect binary `inspect`."""

    def __init__(self, inspect="fs-inspect"):
        self.inspect = inspect

    def run(self, *args, env=None, check=False, **kw):
        """`args` run by the fs-inspect binary: the finished process (text mode, output
        captured)."""
        r = system.run(self.inspect, *args, check=False, capture=True, env=env, **kw)
        if check and r.returncode != 0:
            raise CliError(args, r.returncode, r.stderr)
        return r

    def map(self, source, *args, env=None):
        """`map` as a list of {"offset", "length"} dicts."""
        return range_lines(self.run(*map_args(source, *args), env=env, check=True).stdout)

    def disk_map(self, source, *args):
        """`map --whole-disk` in 4 KiB blocks with `args`: ({type: [{"offset", "length"}]},
        the summary record)."""
        return self.disk("map", source, *args)

    def disk(self, command, source, *args):
        """`COMMAND SOURCE --whole-disk` in 4 KiB blocks with `args`: as `disk_map`."""
        recs = parse_lines(self.run(command, source, "--whole-disk", "--block-size", "4K", *args, check=True).stdout)
        assert recs and recs[-1]["type"] == "summary", recs[-1:]
        out = {}
        for x in recs[:-1]:
            out.setdefault(x["type"], []).append({"offset": x["offset"], "length": x["length"]})
        return out, recs[-1]

    def spans(self, source, *args):
        """`map` as (offset, length) tuples, and what it wrote on stderr (None if nothing)."""
        r = self.run(*map_args(source, *args), check=True)
        return [(x["offset"], x["length"]) for x in range_lines(r.stdout)], r.stderr.strip() or None

    def log(self, source, *args):
        """What `map` writes on stderr (its warnings)."""
        return self.run(*map_args(source, *args), check=True).stderr.strip()

    def diagnostics(self, source, *args):
        """`map` with `--diagnostics`: (ranges, diagnostic records)."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diag.jsonl")
            out = self.run(*map_args(source, *args, "--diagnostics", path), check=True).stdout
            with open(path) as f:
                return range_lines(out), parse_lines(f.read())

    def info(self, source, *args):
        """`info`: the volume's record (its `state` included)."""
        recs = parse_lines(self.run("info", source, *args, check=True).stdout)
        assert len(recs) == 1, recs
        return recs[0]

    def volumes(self, source, *args, env=None):
        """`list`: one dict per volume."""
        return parse_lines(self.run("list", source, *args, env=env, check=True).stdout)

    def volume(self, source, index=None, offset=None):
        """The `list` entry of a volume: by index, by offset, or the only recognized one."""
        vols = self.volumes(source)
        if index is not None:
            return next(v for v in vols if v["index"] == index)
        if offset is not None:
            return next(v for v in vols if v["offset"] == offset)
        known = [v for v in vols if v["fs"]]
        assert len(known) == 1, vols
        return known[0]


bins = Binaries()
