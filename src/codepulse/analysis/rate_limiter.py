"""Gemini API Token-Bucket Rate Limiter (§3.4.6, §11).

Enforces an atomic Redis-backed sliding token bucket rate limiter:
- Provisioned Gemini quota: 360 RPM (§11).
- Rate limit: 360 - 10% safety margin = 324 RPM (5.4 req/s) (§3.4.6).
- Burst capacity: 10 tokens (judgment call).
- When tokens are unavailable, returns the exact seconds to wait until 1 token is granted
  so callers can schedule a Celery retry without blocking worker processes.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from codepulse.config import get_settings
from codepulse.persistence.database import get_redis_client

logger = logging.getLogger(__name__)

# Default parameters
DEFAULT_RPM = 324  # 360 RPM - 10% safety margin (§3.4.6)
DEFAULT_BURST = 10  # Burst capacity

TOKEN_BUCKET_LUA = """
local tokens_key = KEYS[1]
local ts_key = KEYS[2]

local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])

local current_tokens = tonumber(redis.call('get', tokens_key))
local last_ts = tonumber(redis.call('get', ts_key))

if current_tokens == nil then
    current_tokens = capacity
    last_ts = now
else
    local elapsed = math.max(0, now - last_ts)
    current_tokens = math.min(capacity, current_tokens + (elapsed * refill_rate))
    last_ts = now
end

if current_tokens >= cost then
    current_tokens = current_tokens - cost
    redis.call('set', tokens_key, tostring(current_tokens), 'EX', 3600)
    redis.call('set', ts_key, tostring(last_ts), 'EX', 3600)
    return {1, 0}
else
    local missing = cost - current_tokens
    local wait_time = missing / refill_rate
    redis.call('set', tokens_key, tostring(current_tokens), 'EX', 3600)
    redis.call('set', ts_key, tostring(last_ts), 'EX', 3600)
    return {0, tostring(wait_time)}
end
"""


class TokenBucketRateLimiter:
    """Redis-backed atomic token bucket rate limiter for external APIs."""

    def __init__(
        self,
        redis_client: Any | None = None,
        *,
        rpm: float | None = None,
        burst: int = DEFAULT_BURST,
        key_prefix: str = "rate_limit:gemini",
    ) -> None:
        self.redis = redis_client or get_redis_client()
        # Allow env override GEMINI_RPM_LIMIT for testing and compose scaling
        if rpm is None:
            env_rpm = os.environ.get("GEMINI_RPM_LIMIT")
            rpm = float(env_rpm) if env_rpm else float(DEFAULT_RPM)
        self.rpm = rpm
        self.refill_rate = self.rpm / 60.0  # tokens per second
        self.burst = burst
        self.tokens_key = f"{key_prefix}:tokens"
        self.ts_key = f"{key_prefix}:ts"
        self._script = self.redis.register_script(TOKEN_BUCKET_LUA)

    def acquire(self, cost: int = 1) -> tuple[bool, float]:
        """Attempt to acquire tokens.

        Returns:
            (True, 0.0) if tokens were acquired.
            (False, wait_seconds) if insufficient tokens; wait_seconds indicates
            time until 1 token will be available.
        """
        now = time.time()
        res = self._script(
            keys=[self.tokens_key, self.ts_key],
            args=[self.burst, self.refill_rate, now, cost],
        )
        allowed = bool(res[0] == 1)
        wait_seconds = float(res[1])
        return allowed, wait_seconds

    def reset(self) -> None:
        """Reset the rate limiter state (useful in tests)."""
        self.redis.delete(self.tokens_key, self.ts_key)
