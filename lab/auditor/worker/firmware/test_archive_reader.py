import io
import tarfile
import zipfile

import pytest

from lab.auditor.worker.firmware.archive_reader import detect_format, open_archive


def _make_targz(path, files):
    with tarfile.open(path, "w:gz") as tar:
        for name, data, mode in files:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = mode
            tar.addfile(info, io.BytesIO(data))
    return path


def _make_zip(path, files):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in files:
            info = zipfile.ZipInfo(name)
            info.external_attr = (mode & 0o7777) << 16
            zf.writestr(info, data)
    return path


FILES = [("VERSION", b"1.2.3\n", 0o644), ("update.sh", b"#!/bin/sh\n", 0o755)]


def test_detect_format(tmp_path):
    assert detect_format(_make_targz(tmp_path / "a.tar.gz", FILES)) == "targz"
    assert detect_format(_make_zip(tmp_path / "a.zip", FILES)) == "zip"


def test_detect_format_rejects_unknown(tmp_path):
    p = tmp_path / "junk.bin"
    p.write_bytes(b"not an archive")
    with pytest.raises(ValueError):
        detect_format(p)


@pytest.mark.parametrize("maker", [_make_targz, _make_zip])
def test_open_archive_exposes_uniform_members(maker, tmp_path):
    # Members read lazily, so reads must happen while the archive is open.
    path = maker(tmp_path / "fw", FILES)
    with open_archive(path) as archive:
        members = {m.name: m for m in archive.iter_members() if m.is_file}
        assert set(members) == {"VERSION", "update.sh"}
        assert members["VERSION"].read(1024) == b"1.2.3\n"
        assert members["VERSION"].size == len(b"1.2.3\n")
        # The executable bit survives in both formats when recorded.
        assert members["update.sh"].mode & 0o111


@pytest.mark.parametrize("maker", [_make_targz, _make_zip])
def test_read_is_bounded_by_cap(maker, tmp_path):
    payload = b"x" * 10_000
    path = maker(tmp_path / "fw", [("big", payload, 0o644)])
    with open_archive(path) as archive:
        member = next(m for m in archive.iter_members() if m.name == "big")
        assert len(member.read(100)) == 100
