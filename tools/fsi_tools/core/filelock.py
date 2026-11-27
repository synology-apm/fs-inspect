"""Exclusive locks on files, held by an open file: the system lets go of one when its holder
closes the file or ends, however it ends (killed too), and on one kernel across PID namespaces
(containers sharing a directory), which a PID written to a file cannot tell."""

import os

if os.name == "nt":
    import msvcrt
else:
    import fcntl


def try_lock(path):
    """The file `path` (made if missing) open and locked by this process, or None when another
    open file holds its lock (in this process too). Close it, or unlock(), to let go."""
    f = open(path, "a+b")  # noqa: SIM115  (held: the lock lives as long as the file is open)
    try:
        if os.name == "nt":
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        return None
    return f


def unlock(f):
    """Let go of a lock try_lock() took, and close its file."""
    try:
        if os.name == "nt":
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    finally:
        f.close()
