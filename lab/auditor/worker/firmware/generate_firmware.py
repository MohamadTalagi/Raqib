import gzip
import io
import json
import subprocess
import tarfile
from pathlib import Path
from typing import Optional

OUTPUT_DIR = Path(__file__).resolve().parent / "output"

VARIANTS = {
    "device-insecure": {
        "version": "1.0.0-old",
        # Intentional training fixture (sandboxed lab, never a live credential).
        "config_ini": (
            "[device]\n"
            "admin_user=admin\n"
            "admin_pass=admin\n"
            "api_key=sk-insecure-hardcoded-key-000111222\n"
        ),
        "manifest": {"packages": [
            {"name": "openssl", "version": "1.0.1e"},
            {"name": "busybox", "version": "1.19.4"},
        ]},
        "update_script": (
            "#!/bin/sh\n"
            "curl -o /tmp/fw.bin http://updates.example.local/latest.bin\n"
            "cp /tmp/fw.bin /firmware/current.bin\n"
        ),
        "signed": False,
    },
    "device-partial": {
        "version": "1.5.0-mid",
        "config_ini": (
            "[device]\n"
            "admin_user=admin\n"
            "admin_pass=Ch4ng3d-Bu7-W3ak\n"
        ),
        "manifest": {"packages": [
            {"name": "openssl", "version": "1.1.1k"},
            {"name": "busybox", "version": "1.34.1"},
        ]},
        "update_script": (
            "#!/bin/sh\n"
            "curl -o /tmp/fw.bin https://updates.example.local/latest.bin\n"
            "cp /tmp/fw.bin /firmware/current.bin\n"
        ),
        "signed": False,
    },
    "device-hardened": {
        "version": "2.0.0-current",
        "config_ini": "[device]\nadmin_user=admin\nadmin_pass=<unique-per-device-set-at-provisioning>\n",
        "manifest": {"packages": [
            {"name": "openssl", "version": "3.0.11"},
            {"name": "busybox", "version": "1.36.1"},
        ]},
        "update_script": (
            "#!/bin/sh\n"
            "curl -o /tmp/fw.bin https://updates.example.local/latest.bin\n"
            "openssl dgst -sha256 -verify /keys/vendor_pub.pem -signature /tmp/fw.sig /tmp/fw.bin || exit 1\n"
            "cp /tmp/fw.bin /firmware/current.bin\n"
        ),
        "signed": True,
    },
}


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = 0
    info.mode = mode
    tar.addfile(info, io.BytesIO(data))


def build_variant(device_id: str, signing_key: Optional[Path] = None, output_dir: Path = OUTPUT_DIR) -> Path:
    spec = VARIANTS[device_id]
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / f"camera-fw-{spec['version']}-{device_id}.tar.gz"

    with gzip.GzipFile(archive_path, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tar:
            _add_bytes(tar, "VERSION", spec["version"].encode() + b"\n")
            _add_bytes(tar, "etc/config.ini", spec["config_ini"].encode())
            _add_bytes(tar, "manifest.json", json.dumps(spec["manifest"], indent=2, sort_keys=True).encode())
            _add_bytes(tar, "update.sh", spec["update_script"].encode(), mode=0o755)

    if spec["signed"] and signing_key is not None:
        sig_path = archive_path.with_suffix(".sig")
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(signing_key), "-out", str(sig_path), str(archive_path)],
            check=True,
        )

    return archive_path


def sha256_of(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    for device_id in VARIANTS:
        path = build_variant(device_id)
        print(f"{device_id}: {path.name} sha256={sha256_of(path)}")


if __name__ == "__main__":
    main()
