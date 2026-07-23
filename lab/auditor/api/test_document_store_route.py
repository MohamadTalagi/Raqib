import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(postgres_url, monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    monkeypatch.setenv("DOCUMENT_STORE_DIR", str(tmp_path))
    from main import app
    return TestClient(app)


def test_serves_a_real_raw_artefact_file(client, tmp_path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    (raw_dir / "EV-TEST-0001.txt").write_text("real raw scan output")

    response = client.get("/document-store/raw/EV-TEST-0001.txt")
    assert response.status_code == 200
    assert response.text == "real raw scan output"


def test_missing_file_is_404(client):
    assert client.get("/document-store/raw/does-not-exist.txt").status_code == 404


def test_path_traversal_is_rejected(client, tmp_path):
    secret = tmp_path.parent / "secret.txt"
    secret.write_text("should never be served")
    try:
        response = client.get("/document-store/../secret.txt")
        assert response.status_code in (400, 404)
    finally:
        secret.unlink(missing_ok=True)
