"""F0.1.7 — Fail-closed decorator.

Core security pattern: every function that makes a security decision MUST fail
conservatively. Unknown = inconclusive, never "approved" or "low risk".
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable, Optional, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

logger = logging.getLogger(__name__)


class FailClosedError(Exception):
    """Raised when a fail-closed function catches an unexpected exception."""


def fail_closed(
    fallback_value: Any = None,
    fallback_message: str = "Operation failed — fallback to safe default",
    log_level: int = logging.ERROR,
    allowed_exceptions: tuple[type[Exception], ...] = (),
) -> Callable[[F], F]:
    """Decorator that enforces fail-closed behavior on security-sensitive functions.

    If the decorated function raises an exception that is NOT in `allowed_exceptions`,
    the decorator:
    1. Logs the error with full traceback
    2. Returns `fallback_value` (should be the most conservative value)
    3. NEVER silently swallows — always logs

    Args:
        fallback_value: Value to return on failure (must be conservative).
        fallback_message: Message to log on failure.
        log_level: Logging level for failures.
        allowed_exceptions: Exception types that should propagate (not caught).

    Example:
        @fail_closed(fallback_value="unclassified", fallback_message="Language detection failed")
        def detect_language(repo_path: str) -> str:
            ...
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if allowed_exceptions and isinstance(e, allowed_exceptions):
                    raise

                logger.log(
                    log_level,
                    "fail_closed_triggered",
                    extra={
                        "function": func.__qualname__,
                        "error": str(e),
                        "fallback_value": fallback_value,
                        "fallback_message": fallback_message,
                    },
                    exc_info=True,
                )
                return fallback_value

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                if allowed_exceptions and isinstance(e, allowed_exceptions):
                    raise

                logger.log(
                    log_level,
                    "fail_closed_triggered",
                    extra={
                        "function": func.__qualname__,
                        "error": str(e),
                        "fallback_value": fallback_value,
                        "fallback_message": fallback_message,
                    },
                    exc_info=True,
                )
                return fallback_value

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper  # type: ignore[return-value]
        return wrapper  # type: ignore[return-value]

    return decorator


class Defaults:
    """Conservative default values for fail-closed operations.

    NEVER use these defaults in production logic — only as fallback.
    """

    UNCLASSIFIED = "unclassified"
    UNKNOWN = "unknown"
    INCONCLUSIVE = "inconclusive"
    CRITICAL = "P0"  # When in doubt, default to critical
    REQUIRES_HUMAN_VALIDATION = "requires_human_validation"
    DENY = "deny"
    NONE = "none"
