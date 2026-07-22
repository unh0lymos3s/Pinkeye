"""End-to-end: POST a codebase to the SAST upload endpoint, then confirm the extracted path is
authorized by the scope guard (added to the signed scope) while nothing else in scope changed."""
import io
import types
import zipfile

from fastapi.testclient import TestClient

import app.main as main
from app.models import Intensity
from app.scope import authorize


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_upload_authorizes_extracted_path(tmp_path, monkeypatch):
    # Point the upload root at a writable temp dir (default is the container mount /eye-uploads).
    monkeypatch.setattr(
        main, "settings", types.SimpleNamespace(upload_root=str(tmp_path)), raising=True
    )
    client = TestClient(main.app)

    eng = client.post("/engagements", json={"name": "sast-lab"}).json()
    eid = eng["id"]

    body = _zip({"app/main.py": b"import os\nos.system('id')\n"})
    res = client.post(
        f"/engagements/{eid}/sast/upload?filename=code.zip",
        content=body,
        headers={"content-type": "application/octet-stream"},
    )
    assert res.status_code == 200, res.text
    payload = res.json()
    assert payload["file_count"] == 1
    path = payload["path"]
    assert path.startswith(str(tmp_path))

    # The engagement's scope now authorizes an artifact-surface target under the extracted path...
    updated = main._load_engagement(eid)
    assert path in updated.scope.allowed_artifacts
    d = authorize(updated.scope, path, Intensity.normal, surface="artifact")
    assert d.allowed, d.reason
    d_file = authorize(updated.scope, path + "/app/main.py", Intensity.normal, surface="artifact")
    assert d_file.allowed
    # ...but an unrelated path, and any network target, are still denied.
    assert not authorize(updated.scope, "/etc/shadow", Intensity.normal, surface="artifact").allowed
    assert not authorize(updated.scope, "10.0.0.5", Intensity.normal, surface="network").allowed


def test_upload_rejects_traversal(tmp_path, monkeypatch):
    monkeypatch.setattr(
        main, "settings", types.SimpleNamespace(upload_root=str(tmp_path)), raising=True
    )
    client = TestClient(main.app)
    eid = client.post("/engagements", json={"name": "sast-lab"}).json()["id"]
    body = _zip({"../escape.py": b"pwn"})
    res = client.post(
        f"/engagements/{eid}/sast/upload?filename=evil.zip",
        content=body,
        headers={"content-type": "application/octet-stream"},
    )
    assert res.status_code == 400
