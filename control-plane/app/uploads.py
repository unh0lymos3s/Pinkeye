"""Safe ingestion of an uploaded codebase for SAST.

The SAST tools analyze source mounted read-only at /src (sandbox) or handed to an MCP server (Snyk).
Either way the operator uploads an archive (zip / tar / tar.gz) or a single source file; we extract it
into a per-upload directory under `settings.upload_root` and hand the resulting path back so a normal
run can target it (surface="artifact", authorized against the engagement's allowed_artifacts).

Extraction is the security-sensitive part — a hostile archive must never write outside its target dir
or exhaust the host. Defenses here:
  - reject absolute paths and any member that resolves outside the destination (zip-slip / `../`),
  - skip symlinks / hardlinks / device nodes (tar) — no link can point out of the tree,
  - cap the file count and total uncompressed bytes (zip/tar bomb),
so a malicious upload fails closed with a clear error instead of touching the host.

Note the destination is still world-readable code we then run analyzers over; it is mounted read-only
into every tool container, so the analyzers can read but never modify it.
"""
from __future__ import annotations

import io
import os
import re
import tarfile
import uuid
import zipfile
from dataclasses import dataclass

# Bounds. Generous enough for real repos, tight enough that one upload can't fill the disk.
MAX_FILES = 20_000
MAX_TOTAL_BYTES = 500 * 1024 * 1024  # 500 MB uncompressed
MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB on the wire (the archive/file itself)

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class UploadError(ValueError):
    """A rejected upload (too big, malformed, or a path-traversal attempt). Maps to HTTP 400."""


@dataclass
class ExtractResult:
    path: str          # absolute directory the code was extracted into (the run target)
    kind: str          # "zip" | "tar" | "file"
    file_count: int
    total_bytes: int


def _dest_dir(upload_root: str, engagement_id: str) -> str:
    # One directory per upload, namespaced by engagement, so uploads never collide or overwrite.
    safe_eng = _SAFE_NAME.sub("_", engagement_id) or "eng"
    dest = os.path.join(upload_root, safe_eng, uuid.uuid4().hex)
    os.makedirs(dest, exist_ok=False)
    return dest


def _within(base: str, target: str) -> bool:
    """True iff `target` is `base` itself or strictly inside it, after resolving `..`/symlinks."""
    base_real = os.path.realpath(base)
    target_real = os.path.realpath(target)
    return target_real == base_real or target_real.startswith(base_real + os.sep)


def _looks_like_zip(data: bytes, filename: str) -> bool:
    return data[:4] == b"PK\x03\x04" or filename.lower().endswith(".zip")


def _looks_like_tar(filename: str) -> bool:
    name = filename.lower()
    return name.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz"))


def save_and_extract(
    upload_root: str, engagement_id: str, filename: str, data: bytes
) -> ExtractResult:
    """Persist and expand an uploaded codebase, returning where it landed. Raises UploadError on any
    oversize/malformed/traversal condition (fail closed)."""
    if not data:
        raise UploadError("empty upload")
    if len(data) > MAX_UPLOAD_BYTES:
        raise UploadError(f"upload exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit")

    filename = os.path.basename(filename or "upload")
    dest = _dest_dir(upload_root, engagement_id)

    if _looks_like_zip(data, filename):
        count, total = _extract_zip(data, dest)
        return ExtractResult(path=dest, kind="zip", file_count=count, total_bytes=total)
    if _looks_like_tar(filename):
        count, total = _extract_tar(data, dest)
        return ExtractResult(path=dest, kind="tar", file_count=count, total_bytes=total)

    # A single, non-archive source file: keep it under the dest dir so the tools scan a directory.
    safe = _SAFE_NAME.sub("_", filename) or "source"
    out_path = os.path.join(dest, safe)
    with open(out_path, "wb") as fh:
        fh.write(data)
    return ExtractResult(path=dest, kind="file", file_count=1, total_bytes=len(data))


def _extract_zip(data: bytes, dest: str) -> tuple[int, int]:
    count = 0
    total = 0
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise UploadError(f"not a valid zip archive: {exc}") from exc
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename
            if name.startswith("/") or ".." in name.replace("\\", "/").split("/"):
                raise UploadError(f"unsafe path in archive: {name!r}")
            out_path = os.path.join(dest, name)
            if not _within(dest, out_path):
                raise UploadError(f"archive member escapes destination: {name!r}")
            count += 1
            total += info.file_size
            if count > MAX_FILES:
                raise UploadError(f"archive has more than {MAX_FILES} files")
            if total > MAX_TOTAL_BYTES:
                raise UploadError("archive expands beyond the uncompressed size limit")
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with zf.open(info) as src, open(out_path, "wb") as dst:
                dst.write(src.read())
    return count, total


def _extract_tar(data: bytes, dest: str) -> tuple[int, int]:
    count = 0
    total = 0
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError as exc:
        raise UploadError(f"not a valid tar archive: {exc}") from exc
    with tf:
        for member in tf.getmembers():
            if member.isdir():
                out_path = os.path.join(dest, member.name)
                if not _within(dest, out_path):
                    raise UploadError(f"archive member escapes destination: {member.name!r}")
                os.makedirs(out_path, exist_ok=True)
                continue
            # Only extract regular files; a symlink/hardlink/device could point outside the tree.
            if not member.isfile():
                continue
            name = member.name
            if name.startswith("/") or ".." in name.replace("\\", "/").split("/"):
                raise UploadError(f"unsafe path in archive: {name!r}")
            out_path = os.path.join(dest, name)
            if not _within(dest, out_path):
                raise UploadError(f"archive member escapes destination: {name!r}")
            count += 1
            total += member.size
            if count > MAX_FILES:
                raise UploadError(f"archive has more than {MAX_FILES} files")
            if total > MAX_TOTAL_BYTES:
                raise UploadError("archive expands beyond the uncompressed size limit")
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            with extracted as src, open(out_path, "wb") as dst:
                dst.write(src.read())
    return count, total
