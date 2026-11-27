"""The exceptions: each kind's class, the built-in exception some also are, pickling."""

from __future__ import annotations

import errno
import pickle

import pytest

import fs_inspect as fi
from fs_inspect import _native

from .conftest import root


def test_some_kinds_are_also_the_builtin_exception_of_the_same_meaning() -> None:
    builtin: list[tuple[type[fi.FsInspectError], type[Exception], int | None]] = [
        (fi.NotFoundError, FileNotFoundError, errno.ENOENT),
        (fi.PermissionDeniedError, PermissionError, errno.EACCES),
        (fi.IsADirectoryError, IsADirectoryError, errno.EISDIR),
        (fi.NoSpaceError, OSError, errno.ENOSPC),
        (fi.IoError, OSError, None),
        (fi.InvalidArgumentError, ValueError, None),
    ]
    for cls, base, code in builtin:
        e = cls("what happened")
        assert isinstance(e, base) and isinstance(e, fi.FsInspectError)
        assert str(e) == f"{cls.kind.summary}: what happened"
        if code is not None:
            assert isinstance(e, OSError) and e.errno == code
    assert not issubclass(fi.CorruptError, OSError)


def test_a_kind_is_its_class(ntfs: fi.Fs) -> None:
    assert fi.CorruptError.kind is fi.ErrorKind.CORRUPT
    assert fi.CorruptError.scope is fi.Scope.UNIT
    assert not hasattr(fi.FsInspectError, "kind"), "the base class is of no kind"
    with pytest.raises(FileNotFoundError) as e:
        ntfs.resolve(root(ntfs).root, "/no/such")
    assert type(e.value) is fi.NotFoundError and e.value.kind is fi.ErrorKind.NOT_FOUND


def test_errors_pickle(ntfs: fi.Fs) -> None:
    with pytest.raises(fi.NotFoundError) as e:
        ntfs.resolve(root(ntfs).root, "/no/such")
    back = pickle.loads(pickle.dumps(e.value))
    assert type(back) is fi.NotFoundError
    assert (str(back), back.message, back.location) == (
        str(e.value),
        e.value.message,
        e.value.location,
    )
    located = fi.CorruptError("bad", location=fi.Location(fi.Space.VOLUME, "superblock", 1024))
    again = pickle.loads(pickle.dumps(located))
    assert type(again) is fi.CorruptError and again.location == located.location
    assert str(again) == str(located) == "corrupt structure: bad (superblock at 0x400)"


def error_and_text(
    kind: str, message: str, space: str | None = None, offset: int = 0
) -> tuple[fi.FsInspectError, str]:
    """The library's error of ``kind`` saying ``message`` (found in ``superblock`` at
    ``offset`` of ``space``), as raised, and its text as the library writes it."""
    got: tuple[fi.FsInspectError, str] = _native._error_and_text(kind, message, space, offset)  # type: ignore[attr-defined]
    return got


def test_str_is_the_errors_whole_text() -> None:
    corrupt = "corrupt structure: bad magic"
    shapes: list[tuple[str, str, str | None, int, str]] = [
        ("corrupt", "bad magic", None, 0, corrupt),
        ("corrupt", "", None, 0, "corrupt structure"),
        ("corrupt", "bad magic", "volume", 0x400, f"{corrupt} (superblock at 0x400)"),
        ("format", "", "device", 0x1BE, "unrecognized format (superblock at device offset 0x1be)"),
        ("not_found", "/no/such", None, 0, "not found: /no/such"),
        ("no_space", "scratch", "volume", 0, "no space left: scratch (superblock at 0x0)"),
        ("cancelled", "", None, 0, "cancelled"),
    ]
    for kind, message, space, offset, text in shapes:
        e, rust = error_and_text(kind, message, space, offset)
        assert (str(e), rust) == (text, text), kind
        assert (e.message, e.args) == (message, (message,)), kind
        if space is None:
            assert e.location is None
        else:
            assert e.location is not None
            assert str(e.location) == text.split(" (")[1].rstrip(")")
        back = pickle.loads(pickle.dumps(e))
        assert type(back) is type(e)
        assert (str(back), back.message, back.location) == (text, message, e.location)
    assert str(fi.CancelledError()) == "cancelled"


def test_an_oserror_ones_text_is_its_whole_text() -> None:
    e, text = error_and_text("not_found", "/no/such", "volume", 0x10)
    assert type(e) is fi.NotFoundError and isinstance(e, FileNotFoundError)
    assert str(e) == text == "not found: /no/such (superblock at 0x10)"
    assert (e.errno, e.strerror, e.filename) == (errno.ENOENT, text, None)
    back = pickle.loads(pickle.dumps(e))
    assert (str(back), back.errno, back.strerror) == (text, errno.ENOENT, text)
    io = fi.IoError("read failed")
    assert (str(io), io.errno, io.strerror) == ("I/O error: read failed", None, str(io))


def test_the_base_class_says_its_message() -> None:
    e = fi.FsInspectError("something", location=fi.Location(fi.Space.VOLUME, "superblock", 0))
    assert str(e) == "something" and e.args == ("something",)
    back = pickle.loads(pickle.dumps(e))
    assert type(back) is fi.FsInspectError and str(back) == "something"
    assert back.location == e.location
    assert str(fi.FsInspectError()) == ""


def test_a_location_says_where() -> None:
    volume = fi.Location(fi.Space.VOLUME, "MFT record", 0xC000)
    device = fi.Location(fi.Space.DEVICE, "GPT header", 0x200)
    assert str(volume) == "MFT record at 0xc000"
    assert str(device) == "GPT header at device offset 0x200"
