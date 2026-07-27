"""Unified read-only view over an uploaded firmware archive, whether it is a
gzip-compressed tarball (.tar.gz / .tgz) or a zip (.zip). The rest of the
firmware analysis (scan_firmware.py, scan_scripts/firmware_check.py) iterates
members through this abstraction instead of calling tarfile/zipfile directly,
so both formats are handled by exactly one code path.

Format is detected by magic bytes, not the filename, because auditor-api
stores every upload under one neutral on-disk name ({device_id}.archive) -
the original .tar.gz/.tgz/.zip name is kept only for display in the devices
table.

Members are always read into memory with a caller-supplied byte cap; nothing
here ever extracts to disk, so a hostile member path (`../`, absolute) cannot
escape anywhere - the API still rejects such archives at upload time as
defense in depth.
"""

import tarfile
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

GZIP_MAGIC = b"\x1f\x8b"
# Local file header, plus the empty-archive and spanned-archive signatures.
ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def detect_format(path: Path) -> str:
    """"targz" or "zip", by magic bytes. Raises ValueError otherwise."""
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head[:2] == GZIP_MAGIC:
        return "targz"
    if head[:4] in ZIP_MAGICS:
        return "zip"
    raise ValueError("unrecognized archive format (expected .tar.gz or .zip)")


@dataclass
class Member:
    """One archive entry, format-agnostic. `mode` is unix permission bits
    (0 when the archive carries none - common for zips created on Windows, so
    never rely on the executable bit alone to identify a file)."""

    name: str
    is_file: bool
    size: int
    mode: int
    _read: Callable[[int], bytes]

    def read(self, cap: int) -> bytes:
        """At most `cap` bytes of this member, decompressed. Reading is always
        bounded so an over-declared size (zip-bomb) can't force unbounded work."""
        return self._read(cap)


class _TarReader:
    def __init__(self, tar: tarfile.TarFile):
        self._tar = tar

    def iter_members(self) -> Iterator[Member]:
        for m in self._tar.getmembers():
            yield Member(
                name=m.name,
                is_file=m.isfile(),
                size=m.size,
                mode=m.mode & 0o7777,
                _read=lambda cap, m=m: self._read(m, cap),
            )

    def _read(self, m: tarfile.TarInfo, cap: int) -> bytes:
        fh = self._tar.extractfile(m)
        return fh.read(cap) if fh is not None else b""


class _ZipReader:
    def __init__(self, zf: zipfile.ZipFile):
        self._zf = zf

    def iter_members(self) -> Iterator[Member]:
        for info in self._zf.infolist():
            yield Member(
                name=info.filename,
                is_file=not info.is_dir(),
                size=info.file_size,
                # Unix mode lives in the high 16 bits of external_attr; 0 if
                # the zip was made by a tool that didn't record it (e.g. the
                # Windows shell's "Send to > Compressed folder").
                mode=(info.external_attr >> 16) & 0o7777,
                _read=lambda cap, info=info: self._read(info, cap),
            )

    def _read(self, info: zipfile.ZipInfo, cap: int) -> bytes:
        with self._zf.open(info) as fh:
            return fh.read(cap)


@contextmanager
def open_archive(path: Path):
    """Context manager yielding a reader with `.iter_members()`, for either a
    .tar.gz or a .zip, detected by content."""
    fmt = detect_format(path)
    if fmt == "targz":
        with tarfile.open(path, "r:gz") as tar:
            yield _TarReader(tar)
    else:
        with zipfile.ZipFile(path, "r") as zf:
            yield _ZipReader(zf)
