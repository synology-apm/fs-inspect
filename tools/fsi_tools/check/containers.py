"""Every container a repo's tools start runs with --init: its PID 1 then passes on the SIGTERM
that `docker run` forwards when a job is killed, so the container stops with the job. Without it
the command's own PID 1 ignores the signal and the container outlives the kill."""

import os
import re

# A docker run command (with arguments), not prose naming it.
RUN = re.compile(r"\bdocker run\s+-")
SCRIPTS = (".sh", ".py")


def without_init(root):
    """Where under `root` a script starts a container without --init (path:line). Commands put
    --init on the `docker run` line."""
    found = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x != "__pycache__"]
        for f in files:
            if not f.endswith(SCRIPTS):
                continue
            p = os.path.join(d, f)
            with open(p, encoding="utf-8") as fh:
                for n, line in enumerate(fh, 1):
                    code = line.split("#", 1)[0]
                    if RUN.search(code) and "--init" not in code:
                        found.append(f"{os.path.relpath(p, root)}:{n}")
    return found


def case_dirs_by_hand(root):
    """Where under `root` a directory is made in the scratch area other than through
    images.case_dir (which makes the area first)."""
    found = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x != "__pycache__"]
        for f in files:
            if f.endswith(".py") and f != "images.py":
                with open(os.path.join(d, f), encoding="utf-8") as fh:
                    for n, line in enumerate(fh, 1):
                        if re.search(r"\bdir=WORK\b", line):
                            found.append(f"{os.path.relpath(os.path.join(d, f), root)}:{n}")
    return found
