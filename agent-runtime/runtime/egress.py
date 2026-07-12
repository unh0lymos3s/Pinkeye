"""Per-job egress policy derived from the engagement scope.

Defense in depth: the scope guard already blocks out-of-scope *targets*, but a compromised or buggy
tool could try to reach elsewhere. The egress policy is the network-level backstop — the set of
destinations a sandbox is permitted to talk to. Computing it here (pure, testable) is separate from
enforcing it (iptables/nftables on the sandbox's dedicated network, applied by the sandbox layer).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from app.models import Scope


@dataclass
class EgressPolicy:
    cidrs: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)

    @classmethod
    def from_scope(cls, scope: Scope) -> "EgressPolicy":
        return cls(
            cidrs=list(scope.allowed_cidrs),
            domains=[d.lower().lstrip("*.") for d in scope.allowed_domains],
        )

    def allows_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for cidr in self.cidrs:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def allows_host(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return any(host == d or host.endswith("." + d) for d in self.domains)
