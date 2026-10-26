"""Distributed Redis Circuit Breaker for External APIs (§6.3, §10.2 Branch D).

Implements the 3-state circuit breaker pattern across distributed Celery workers:
- States: CLOSED (normal), OPEN (tripped), HALF_OPEN (probing recovery).
- Trip threshold: 5 consecutive failures within a 60-second rolling window.
- Recovery timeout: 30 seconds before allowing a probe request in HALF_OPEN.
- Half-open probe: Allows 1 test request. Success closes circuit; failure reopens.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from codepulse.persistence.database import get_redis_client

logger = logging.getLogger(__name__)

DEFAULT_FAILURE_THRESHOLD = 5
DEFAULT_FAILURE_WINDOW = 60.0  # seconds
DEFAULT_RECOVERY_TIMEOUT = 30.0  # seconds

CIRCUIT_CAN_EXECUTE_LUA = """
local state_key = KEYS[1]
local opened_at_key = KEYS[2]
local probe_key = KEYS[3]

local recovery_timeout = tonumber(ARGV[1])
local now = tonumber(ARGV[2])

local state = redis.call('get', state_key)
if state == nil then
    state = 'CLOSED'
    redis.call('set', state_key, 'CLOSED')
end

if state == 'CLOSED' then
    return {1, 'CLOSED'}
elseif state == 'OPEN' then
    local opened_at = tonumber(redis.call('get', opened_at_key) or 0)
    if (now - opened_at) >= recovery_timeout then
        -- Transition to HALF_OPEN and grant the probe slot
        redis.call('set', state_key, 'HALF_OPEN')
        redis.call('set', probe_key, '1', 'EX', 60)
        return {1, 'HALF_OPEN'}
    else
        return {0, 'OPEN'}
    end
elseif state == 'HALF_OPEN' then
    -- Only allow if probe slot has not been claimed
    local claimed = redis.call('set', probe_key, '1', 'NX', 'EX', 60)
    if claimed then
        return {1, 'HALF_OPEN'}
    else
        return {0, 'HALF_OPEN'}
    end
end
return {1, 'CLOSED'}
"""

CIRCUIT_RECORD_FAILURE_LUA = """
local state_key = KEYS[1]
local opened_at_key = KEYS[2]
local failures_key = KEYS[3]
local probe_key = KEYS[4]

local threshold = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local state = redis.call('get', state_key) or 'CLOSED'

if state == 'HALF_OPEN' then
    -- Probe failed: trip back to OPEN
    redis.call('set', state_key, 'OPEN')
    redis.call('set', opened_at_key, tostring(now))
    redis.call('del', probe_key)
    redis.call('del', failures_key)
    return 'OPEN'
else
    local count = redis.call('incr', failures_key)
    if count == 1 then
        redis.call('expire', failures_key, math.ceil(window))
    end
    if count >= threshold then
        redis.call('set', state_key, 'OPEN')
        redis.call('set', opened_at_key, tostring(now))
        redis.call('del', failures_key)
        redis.call('del', probe_key)
        return 'OPEN'
    end
    return state
end
"""

CIRCUIT_RECORD_SUCCESS_LUA = """
local state_key = KEYS[1]
local opened_at_key = KEYS[2]
local failures_key = KEYS[3]
local probe_key = KEYS[4]

local state = redis.call('get', state_key) or 'CLOSED'

if state == 'HALF_OPEN' then
    -- Probe succeeded: close circuit
    redis.call('set', state_key, 'CLOSED')
    redis.call('del', opened_at_key)
    redis.call('del', failures_key)
    redis.call('del', probe_key)
    return 'CLOSED'
else
    redis.call('del', failures_key)
    return 'CLOSED'
end
"""


class CircuitBreaker:
    """Redis-backed distributed circuit breaker conforming to §6.3."""

    def __init__(
        self,
        redis_client: Any | None = None,
        *,
        name: str = "gemini",
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        failure_window: float = DEFAULT_FAILURE_WINDOW,
        recovery_timeout: float = DEFAULT_RECOVERY_TIMEOUT,
    ) -> None:
        self.redis = redis_client or get_redis_client()
        self.name = name
        self.failure_threshold = failure_threshold
        self.failure_window = failure_window
        self.recovery_timeout = recovery_timeout

        self.state_key = f"circuit:{name}:state"
        self.opened_at_key = f"circuit:{name}:opened_at"
        self.failures_key = f"circuit:{name}:failures"
        self.probe_key = f"circuit:{name}:probe"

        self._can_execute_script = self.redis.register_script(CIRCUIT_CAN_EXECUTE_LUA)
        self._record_failure_script = self.redis.register_script(CIRCUIT_RECORD_FAILURE_LUA)
        self._record_success_script = self.redis.register_script(CIRCUIT_RECORD_SUCCESS_LUA)

    def can_execute(self) -> tuple[bool, str]:
        """Check whether request execution is permitted by breaker state.

        Returns:
            (allowed, current_state)
        """
        now = time.time()
        res = self._can_execute_script(
            keys=[self.state_key, self.opened_at_key, self.probe_key],
            args=[self.recovery_timeout, now],
        )
        allowed = bool(res[0] == 1)
        state = str(res[1])
        return allowed, state

    def record_success(self) -> str:
        """Record a successful request execution."""
        state = self._record_success_script(
            keys=[self.state_key, self.opened_at_key, self.failures_key, self.probe_key],
            args=[],
        )
        return str(state)

    def record_failure(self) -> str:
        """Record a failed request execution."""
        now = time.time()
        new_state = self._record_failure_script(
            keys=[self.state_key, self.opened_at_key, self.failures_key, self.probe_key],
            args=[self.failure_threshold, self.failure_window, now],
        )
        if new_state == "OPEN":
            logger.warning("Circuit breaker for %s tripped to OPEN (5 consecutive failures in 60s)", self.name)
        return str(new_state)

    def get_state(self) -> str:
        """Inspect the current breaker state."""
        val = self.redis.get(self.state_key)
        if val is None:
            return "CLOSED"
        return val.decode() if isinstance(val, bytes) else str(val)

    def reset(self) -> None:
        """Reset breaker to CLOSED state (for tests and recovery)."""
        self.redis.delete(self.state_key, self.opened_at_key, self.failures_key, self.probe_key)
