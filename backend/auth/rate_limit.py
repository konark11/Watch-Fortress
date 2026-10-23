"""
Minimal in-memory rate limiter - brute-force / credential-stuffing
protection for the login endpoint (OWASP A07:2021 Identification and
Authentication Failures).

Deliberately simple: no new dependency, no external store. State is
tracked per client IP, in-process. Two honest limitations worth naming
to a reviewer: this resets on every backend restart, and it does not
share state across multiple backend processes/instances - a production
deployment behind a load balancer would want a shared store (Redis)
instead of this.
"""
from __future__ import annotations
import time
from collections import defaultdict

MAX_ATTEMPTS = 10
WINDOW_SECONDS = 5 * 60

_attempts: dict[str, list[float]] = defaultdict(list)


def check_and_record(key: str) -> tuple[bool, int]:
    """Returns (allowed, retry_after_seconds). Records this attempt
    whether or not it turns out to succeed - callers should pair this
    with reset() on a successful login."""
    now = time.time()
    window_start = now - WINDOW_SECONDS
    attempts = [t for t in _attempts[key] if t > window_start]
    if len(attempts) >= MAX_ATTEMPTS:
        _attempts[key] = attempts
        retry_after = int(WINDOW_SECONDS - (now - attempts[0]))
        return False, max(retry_after, 1)
    attempts.append(now)
    _attempts[key] = attempts
    return True, 0


def reset(key: str) -> None:
    """Called after a successful login so a legitimate user who mistyped
    a few times isn't left throttled afterward."""
    _attempts.pop(key, None)
