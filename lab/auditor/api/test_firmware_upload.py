import hashlib
import io
import tarfile
import zipfile

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(postgres_url, monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    monkeypatch.setenv("DOCUMENT_STORE_DIR", str(tmp_path))
    from main import app
    return TestClient(app)


def _register_device(client, device_id="device-insecure"):
    response = client.post(
        "/devices",
        json={
            "device_id": device_id, "display_name": device_id,
            "tier": "insecure", "host": device_id,
            "services": [{"service_type": "http", "port": 80}],
        },
    )
    assert response.status_code == 201, response.text


def _make_tar_gz(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _make_zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_upload_firmware_returns_201_with_hash(client):
    _register_device(client)
    data = _make_tar_gz({"VERSION": b"1.0.0-old\n"})
    response = client.post(
        "/devices/device-insecure/firmware",
        files={"firmware": ("camera-fw.tar.gz", data, "application/gzip")},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["firmware_filename"] == "camera-fw.tar.gz"
    assert body["firmware_sha256"] == hashlib.sha256(data).hexdigest()
    assert body["firmware_uploaded_at"] is not None


def test_upload_firmware_404_for_unknown_device(client):
    data = _make_tar_gz({"VERSION": b"1.0.0\n"})
    response = client.post(
        "/devices/does-not-exist/firmware",
        files={"firmware": ("camera-fw.tar.gz", data, "application/gzip")},
    )
    assert response.status_code == 404


def test_upload_zip_firmware_returns_201_with_hash(client):
    _register_device(client)
    data = _make_zip({"VERSION": b"1.0.0-old\n"})
    response = client.post(
        "/devices/device-insecure/firmware",
        files={"firmware": ("camera-fw.zip", data, "application/zip")},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["firmware_filename"] == "camera-fw.zip"
    assert body["firmware_sha256"] == hashlib.sha256(data).hexdigest()


def test_upload_firmware_rejects_wrong_extension(client):
    _register_device(client)
    response = client.post(
        "/devices/device-insecure/firmware",
        files={"firmware": ("camera-fw.rar", b"not-an-archive", "application/octet-stream")},
    )
    assert response.status_code == 400


def test_upload_firmware_rejects_zip_extension_with_non_zip_content(client):
    # .zip is an accepted extension now, but the content must actually be a zip.
    _register_device(client)
    response = client.post(
        "/devices/device-insecure/firmware",
        files={"firmware": ("camera-fw.zip", b"not-a-zip", "application/zip")},
    )
    assert response.status_code == 400


def test_upload_zip_firmware_rejects_path_traversal_member(client):
    _register_device(client)
    data = _make_zip({"../../etc/passwd": b"pwned"})
    response = client.post(
        "/devices/device-insecure/firmware",
        files={"firmware": ("camera-fw.zip", data, "application/zip")},
    )
    assert response.status_code == 400


def test_upload_firmware_rejects_malformed_archive(client):
    _register_device(client)
    response = client.post(
        "/devices/device-insecure/firmware",
        files={"firmware": ("camera-fw.tar.gz", b"not actually gzip", "application/gzip")},
    )
    assert response.status_code == 400


def test_upload_firmware_rejects_path_traversal_member(client):
    _register_device(client)
    data = _make_tar_gz({"../../etc/passwd": b"pwned"})
    response = client.post(
        "/devices/device-insecure/firmware",
        files={"firmware": ("camera-fw.tar.gz", data, "application/gzip")},
    )
    assert response.status_code == 400


def test_upload_firmware_rejects_oversized_upload(client, monkeypatch):
    import main
    monkeypatch.setattr(main, "MAX_FIRMWARE_UPLOAD_BYTES", 10)
    _register_device(client)
    data = _make_tar_gz({"VERSION": b"1.0.0-old\n" * 100})
    response = client.post(
        "/devices/device-insecure/firmware",
        files={"firmware": ("camera-fw.tar.gz", data, "application/gzip")},
    )
    assert response.status_code == 413


def test_delete_firmware_clears_the_fields_and_removes_the_file(client, tmp_path):
    _register_device(client)
    data = _make_tar_gz({"VERSION": b"1.0.0-old\n"})
    client.post(
        "/devices/device-insecure/firmware",
        files={"firmware": ("camera-fw.tar.gz", data, "application/gzip")},
    )
    assert (tmp_path / "firmware" / "device-insecure.archive").exists()

    response = client.delete("/devices/device-insecure/firmware")
    assert response.status_code == 204
    assert not (tmp_path / "firmware" / "device-insecure.archive").exists()

    detail = client.get("/devices/device-insecure").json()
    assert detail["device"]["firmware_sha256"] is None


def test_scan_job_for_firmware_test_requires_firmware_uploaded(client):
    _register_device(client)
    response = client.post(
        "/scan-jobs", json={"device_id": "device-insecure", "test_id": "TEST-FW-SECRETS"}
    )
    assert response.status_code == 400
    assert "firmware" in response.json()["detail"]


def test_scan_job_for_firmware_test_succeeds_once_firmware_is_uploaded(client):
    _register_device(client)
    data = _make_tar_gz({"VERSION": b"1.0.0-old\n"})
    client.post(
        "/devices/device-insecure/firmware",
        files={"firmware": ("camera-fw.tar.gz", data, "application/gzip")},
    )
    response = client.post(
        "/scan-jobs", json={"device_id": "device-insecure", "test_id": "TEST-FW-SECRETS"}
    )
    assert response.status_code == 201
    assert response.json()["status"] == "pending"


def test_scan_job_for_firmware_test_works_even_with_zero_enabled_services(client):
    # The defining reason the firmware branch must run BEFORE the
    # device_services query: a device can have no ENABLED network service at
    # all and still have firmware uploaded (the original query 400s with
    # "no enabled service" before is_applicable is ever consulted).
    response = client.post(
        "/devices",
        json={
            "device_id": "firmware-only-device", "display_name": "firmware-only-device",
            "tier": "unknown", "host": "firmware-only-device",
            "services": [{"service_type": "http", "port": 80, "enabled": False}],
        },
    )
    assert response.status_code == 201, response.text

    data = _make_tar_gz({"VERSION": b"1.0.0\n"})
    client.post(
        "/devices/firmware-only-device/firmware",
        files={"firmware": ("camera-fw.tar.gz", data, "application/gzip")},
    )
    response = client.post(
        "/scan-jobs", json={"device_id": "firmware-only-device", "test_id": "TEST-FW-SECRETS"}
    )
    assert response.status_code == 201, response.text
