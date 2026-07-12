"""MITRE ATT&CK technique mapping.

Maps a finding's CWE or category to the ATT&CK technique it most closely represents, so findings and
reports can be expressed in the language defenders use. The mapping is intentionally coarse (a
lookup, not inference); an analyst refines it. Returns (technique_id, technique_name) or None.
"""
from __future__ import annotations

# CWE -> ATT&CK technique. Covers the weakness classes this harness's tools actually surface.
_CWE_MAP: dict[str, tuple[str, str]] = {
    "CWE-89": ("T1190", "Exploit Public-Facing Application"),   # SQL injection
    "CWE-79": ("T1059", "Command and Scripting Interpreter"),   # XSS
    "CWE-78": ("T1059", "Command and Scripting Interpreter"),   # OS command injection
    "CWE-502": ("T1190", "Exploit Public-Facing Application"),  # insecure deserialization (e.g. Log4j)
    "CWE-22": ("T1083", "File and Directory Discovery"),        # path traversal
    "CWE-798": ("T1552", "Unsecured Credentials"),              # hardcoded credentials
    "CWE-287": ("T1078", "Valid Accounts"),                     # improper authentication
    "CWE-306": ("T1190", "Exploit Public-Facing Application"),  # missing authentication
    "CWE-434": ("T1105", "Ingress Tool Transfer"),              # unrestricted file upload
}

# Finding category -> ATT&CK technique, used when no CWE is available.
_CATEGORY_MAP: dict[str, tuple[str, str]] = {
    "open-port": ("T1046", "Network Service Discovery"),
    "exposed-endpoint": ("T1595", "Active Scanning"),
    "sast:secret": ("T1552", "Unsecured Credentials"),
    "sast:dependency": ("T1190", "Exploit Public-Facing Application"),
    "credential-attack": ("T1110", "Brute Force"),
    "exploitation": ("T1203", "Exploitation for Client Execution"),
    "post-exploitation": ("T1082", "System Information Discovery"),
    "malware-detection": ("T1204", "User Execution"),
}


def technique_for(cwe: str | None, category: str) -> tuple[str, str] | None:
    if cwe and cwe.upper() in _CWE_MAP:
        return _CWE_MAP[cwe.upper()]
    if category in _CATEGORY_MAP:
        return _CATEGORY_MAP[category]
    # Prefix match for namespaced categories like "nuclei:...".
    prefix = category.split(":", 1)[0]
    for key, value in _CATEGORY_MAP.items():
        if key.split(":", 1)[0] == prefix:
            return value
    return None
