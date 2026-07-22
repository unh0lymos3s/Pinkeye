"""Safe ingestion of uploaded SAST codebases: extraction works, and hostile archives fail closed."""
import io
import tarfile
import zipfile

import pytest

from app.uploads import (
    MAX_FILES,
    UploadError,
    save_and_extract,
)


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _tar_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_extract_zip(tmp_path):
    data = _zip_bytes({"app/main.py": b"print('hi')\n", "app/util.py": b"x = 1\n"})
    result = save_and_extract(str(tmp_path), "eng-1", "code.zip", data)
    assert result.kind == "zip"
    assert result.file_count == 2
    assert (tmp_path / "eng-1").exists()
    # Extracted files land under the returned path.
    import os

    got = sorted(
        os.path.relpath(os.path.join(root, f), result.path)
        for root, _, files in os.walk(result.path)
        for f in files
    )
    assert got == ["app/main.py", "app/util.py"]


def test_extract_tar_gz(tmp_path):
    data = _tar_bytes({"src/a.py": b"a = 1\n"})
    result = save_and_extract(str(tmp_path), "eng-1", "code.tar.gz", data)
    assert result.kind == "tar"
    assert result.file_count == 1


def test_single_file_upload(tmp_path):
    result = save_and_extract(str(tmp_path), "eng-1", "snippet.py", b"import os\n")
    assert result.kind == "file"
    assert result.file_count == 1
    # Kept inside a directory so the analyzers scan a folder, not a bare file.
    import os

    assert os.path.isdir(result.path)


def test_zip_slip_absolute_rejected(tmp_path):
    data = _zip_bytes({"/etc/evil": b"pwn"})
    with pytest.raises(UploadError):
        save_and_extract(str(tmp_path), "eng-1", "evil.zip", data)


def test_zip_slip_traversal_rejected(tmp_path):
    data = _zip_bytes({"../../escape.py": b"pwn"})
    with pytest.raises(UploadError):
        save_and_extract(str(tmp_path), "eng-1", "evil.zip", data)


def test_tar_traversal_rejected(tmp_path):
    data = _tar_bytes({"../escape.py": b"pwn"})
    with pytest.raises(UploadError):
        save_and_extract(str(tmp_path), "eng-1", "evil.tar.gz", data)


def test_tar_symlink_skipped(tmp_path):
    # A symlink member must never be materialized (it could point outside the tree).
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        payload = b"real\n"
        info = tarfile.TarInfo("real.py")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
    result = save_and_extract(str(tmp_path), "eng-1", "code.tar.gz", buf.getvalue())
    import os

    assert not os.path.lexists(os.path.join(result.path, "link"))
    assert os.path.isfile(os.path.join(result.path, "real.py"))


def test_empty_upload_rejected(tmp_path):
    with pytest.raises(UploadError):
        save_and_extract(str(tmp_path), "eng-1", "empty.zip", b"")


def test_zip_bomb_file_count_rejected(tmp_path):
    entries = {f"f{i}.txt": b"x" for i in range(MAX_FILES + 5)}
    data = _zip_bytes(entries)
    with pytest.raises(UploadError):
        save_and_extract(str(tmp_path), "eng-1", "bomb.zip", data)
