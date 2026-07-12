"""Per-tenant rate limiting and run budgets.

A token bucket caps how frequently a tenant can launch runs, so one tenant (or a runaway agent loop)
can't monopolize the workers or hammer targets. Time is injectable for deterministic tests.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class _Bucket:
    tokens: float
    last: float


@dataclass
class RateLimiter:
    rate_per_min: float = 30.0
    burst: int = 10
    _clock: "callable" = field(default=time.monotonic)
    _buckets: dict[str, _Bucket] = field(default_factory=dict)

    def allow(self, tenant_id: str) -> bool:
        """Consume one token for `tenant_id`; return False if the bucket is empty."""
        now = self._clock()
        bucket = self._buckets.get(tenant_id)
        if bucket is None:
            self._buckets[tenant_id] = _Bucket(tokens=self.burst - 1, last=now)
            return True
        # Refill based on elapsed time, capped at burst.
        elapsed = now - bucket.last
        bucket.tokens = min(self.burst, bucket.tokens + elapsed * (self.rate_per_min / 60.0))
        bucket.last = now
        if bucket.tokens >= 1:
            bucket.tokens -= 1
            return True
        return False
