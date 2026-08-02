"""Per-job egress policy derived from the engagement scope.

Defense in depth: the scope guard already blocks out-of-scope *targets*, but a compromised or buggy
tool could try to reach elsewhere. The egress policy is the network-level backstop — the set of
destinations a sandbox is permitted to talk to. Computing it here (pure, testable) is separate from
enforcing it (iptables/nftables on the sandbox's dedicated network, applied by the sandbox layer).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.matching import host_in_domains, ip_in_cidrs, normalize_domain
from app.models import Scope


@dataclass
class EgressPolicy:
    """The destinations a sandbox may reach, matched with the *same* primitives the scope guard uses
    (`app.matching`). That sharing is the point: if this layer's notion of "in scope" drifted from the
    guard's, the backstop would silently stop backing up the boundary it exists to reinforce.

    `unrestricted` mirrors the engagement's B3 scope-guard toggle: when the operator has explicitly
    disabled the guard, `scope.authorize()` stops matching the target against `cidrs`/`domains` at
    all (every target is authorized). If this backstop kept matching against the same lists in that
    mode, it would silently re-deny exactly what the guard just allowed — a confusing, undocumented
    partial bypass rather than the loud, all-the-way-through one the operator asked for. `cidrs`/
    `domains` are still populated in that mode (nothing here forgets the original scope), `allows_ip`/
    `allows_host` simply short-circuit to True first.
    """

    cidrs: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    unrestricted: bool = False

    @classmethod
    def from_scope(cls, scope: Scope) -> "EgressPolicy":
        return cls(
            cidrs=list(scope.allowed_cidrs),
            domains=[normalize_domain(d) for d in scope.allowed_domains],
            unrestricted=not scope.scope_guard_enabled,
        )

    def allows_ip(self, ip: str) -> bool:
        if self.unrestricted:
            return True
        return ip_in_cidrs(ip, self.cidrs)

    def allows_host(self, host: str) -> bool:
        if self.unrestricted:
            return True
        return host_in_domains(host, self.domains)
