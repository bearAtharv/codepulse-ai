"""Label bounding and cardinality control for Prometheus metrics (§9.2, DEC-016)."""

from __future__ import annotations

import logging
import os
import threading
from typing import Final

logger = logging.getLogger(__name__)

FORBIDDEN_LABEL_KEYS: Final[frozenset[str]] = frozenset({
    "file_path",
    "path",
    "pr_number",
    "pull_request_number",
    "delivery_id",
    "delivery_uuid",
    "sha",
    "head_sha",
    "base_sha",
    "commit_id",
    "user_input",
    "code",
    "source_code",
    "title",
    "rule_title",
    "snippet",
    "patch",
})

DEFAULT_MAX_CARDINALITY: Final[int] = 200
FALLBACK_LABEL_VALUE: Final[str] = "other"


def get_configured_label_cap(default: int = DEFAULT_MAX_CARDINALITY) -> int:
    """Return maximum label cardinality cap from environment or default."""
    env_cap = os.environ.get("METRIC_LABEL_CAP")
    if env_cap:
        try:
            return max(1, int(env_cap))
        except ValueError:
            pass
    return default


class LabelLimiter:
    """Enforces a maximum distinct value cap on a metric label to prevent cardinality explosion."""

    def __init__(
        self,
        max_cardinality: int | None = None,
        fallback: str = FALLBACK_LABEL_VALUE,
    ) -> None:
        self._max_cardinality = max_cardinality
        self.fallback = fallback
        self._seen: set[str] = set()
        self._lock = threading.Lock()

    @property
    def max_cardinality(self) -> int:
        if self._max_cardinality is not None:
            return self._max_cardinality
        return get_configured_label_cap(DEFAULT_MAX_CARDINALITY)

    def bound(self, value: str | None) -> str:
        """Return the label value if under cardinality cap, else return fallback ('other')."""
        if not value:
            return "unknown"
        val_str = str(value).strip()
        if not val_str:
            return "unknown"

        with self._lock:
            if val_str in self._seen:
                return val_str
            if len(self._seen) < self.max_cardinality:
                self._seen.add(val_str)
                return val_str
            return self.fallback

    def reset(self) -> None:
        """Reset seen values (for testing)."""
        with self._lock:
            self._seen.clear()

    @property
    def current_cardinality(self) -> int:
        with self._lock:
            return len(self._seen)


# Global limiter instances for high-cardinality candidate dimensions
_repository_limiter = LabelLimiter()
_endpoint_limiter = LabelLimiter()
_installation_limiter = LabelLimiter()


def bound_repository(repo: str | None) -> str:
    """Bound repository label values to at most 200 distinct repos; overflow to 'other'."""
    return _repository_limiter.bound(repo)


def bound_endpoint(endpoint: str | None) -> str:
    """Bound endpoint label values to at most 200 distinct endpoints; overflow to 'other'."""
    return _endpoint_limiter.bound(endpoint)


def bound_installation(inst_id: Any) -> str:
    """Bound installation_id label values to at most 200 distinct values; overflow to 'other'."""
    return _installation_limiter.bound(str(inst_id) if inst_id is not None else None)


def reset_limiters() -> None:
    """Reset all global limiters (for testing)."""
    _repository_limiter.reset()
    _endpoint_limiter.reset()
    _installation_limiter.reset()
