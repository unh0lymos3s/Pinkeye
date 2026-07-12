"""Secret loading. Secrets come from mounted files first (e.g. Docker/K8s secrets at /run/secrets),
then environment variables. Values are never logged or written to the audit trail."""
from __future__ import annotations

import os
from pathlib import Path

_SECRETS_DIR = Path(os.getenv("EYE_SECRETS_DIR", "/run/secrets"))


def load_secret(name: str, default: str | None = None) -> str | None:
    """Return the secret `name` from a secrets file or environment variable, or `default`.

    File takes precedence so production can mount secrets without putting them in the process env.
    """
    file_path = _SECRETS_DIR / name
    if file_path.is_file():
        return file_path.read_text().strip()
    return os.getenv(name.upper(), default)
