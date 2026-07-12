"""API-key authentication and role-based access control.

Keys are configured out-of-band as `EYE_API_KEYS="key:tenant:role,..."`. Each key maps to a tenant
and a role (viewer < operator < admin). If no keys are configured the API runs in open dev mode as a
default-tenant admin, so the single-host stack works without setup; production sets keys.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    role: str


def parse_api_keys(spec: str) -> dict[str, Principal]:
    keys: dict[str, Principal] = {}
    for entry in spec.split(","):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split(":")
        if len(parts) != 3:
            continue  # ignore malformed entries rather than granting broad access
        key, tenant, role = parts
        if role not in ROLE_RANK:
            continue
        keys[key] = Principal(tenant_id=tenant, role=role)
    return keys


def has_role(principal: Principal, minimum: str) -> bool:
    return ROLE_RANK[principal.role] >= ROLE_RANK[minimum]


class Authenticator:
    def __init__(self, spec: str | None = None):
        self._keys = parse_api_keys(spec if spec is not None else os.getenv("EYE_API_KEYS", ""))

    @property
    def open_dev_mode(self) -> bool:
        return not self._keys

    def principal_for(self, api_key: str | None) -> Principal | None:
        if self.open_dev_mode:
            return Principal(tenant_id="default", role="admin")
        if not api_key:
            return None
        return self._keys.get(api_key)
