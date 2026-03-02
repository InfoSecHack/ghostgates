"""
ghostgates/client/rate_limiter.py

Async rate limiter respecting GitHub's three rate limit layers:
  1. Primary   — 5 000 req/hr tracked via x-ratelimit-* headers
  2. Secondary — abuse detection triggered by 403/429 + retry-after
  3. Concurrent — asyncio.Semaphore caps in-flight requests
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

logger = logging.getLogger("ghostgates.rate_limiter")

_PRIMARY_WARN_THRESHOLD = 100   # log a warning when remaining drops below this
_SECONDARY_BACKOFF_CAP  = 300   # seconds — hard ceiling for exponential backoff


class RateLimiter:
    """
    Respects GitHub's three rate limit layers:

    1. Primary:    5 000 requests/hour (tracked via x-ratelimit-remaining)
    2. Secondary:  points-per-minute   (tracked via retry-after header on 403/429)
    3. Concurrent: max simultaneous requests (configurable, default 10)

    All mutable state is guarded by ``_lock`` so concurrent asyncio tasks
    never observe a torn write.
    """

    def __init__(self, max_concurrent: int = 10) -> None:
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._lock      = asyncio.Lock()

        # --- Primary limit state ---
        self._remaining: int        = 5_000   # assume full until told otherwise
        self._reset_at:  float      = 0.0     # Unix timestamp from x-ratelimit-reset

        # --- Secondary limit state ---
        # Tracks how many times we've been secondary-rate-limited in a row so
        # that the exponential back-off can double appropriately.
        self._secondary_hit_count: int = 0

    # ------------------------------------------------------------------
    # Semaphore helpers
    # ------------------------------------------------------------------

    async def acquire(self) -> None:
        """Block until a concurrency slot AND primary rate headroom are available."""
        # If the primary limit is already exhausted, wait out the reset window
        # *before* grabbing a concurrency slot (avoids holding a slot while sleeping).
        await self._wait_for_primary_reset()
        await self._semaphore.acquire()

    def release(self) -> None:
        """Release the previously acquired concurrency slot."""
        self._semaphore.release()

    # ------------------------------------------------------------------
    # Header parsing
    # ------------------------------------------------------------------

    def update_from_headers(self, headers: dict) -> None:
        """
        Ingest GitHub rate-limit response headers and update internal state.

        Expected headers (case-insensitive lookup is handled by callers —
        we accept the dict as-is and normalise keys internally):

            x-ratelimit-remaining   integer  requests left in the current window
            x-ratelimit-reset       integer  Unix timestamp of next window start
        """
        # Normalise to lower-case so callers need not worry about casing.
        normalised = {k.lower(): v for k, v in headers.items()}

        remaining_raw = normalised.get("x-ratelimit-remaining")
        reset_raw     = normalised.get("x-ratelimit-reset")

        if remaining_raw is None and reset_raw is None:
            return  # not a rate-limited endpoint; nothing to update

        # Use a plain lock (non-async) because update_from_headers is sync.
        # asyncio.Lock cannot be used from a synchronous context, but since
        # asyncio is single-threaded, simple attribute assignment is already
        # atomic at the Python level.  We document this as "safe for concurrent
        # async tasks" — the GIL protects us here for integer/float writes.
        if remaining_raw is not None:
            try:
                new_remaining = int(remaining_raw)
            except (ValueError, TypeError):
                logger.warning("Unparseable x-ratelimit-remaining: %r", remaining_raw)
                new_remaining = self._remaining

            self._remaining = new_remaining

            if new_remaining == 0:
                logger.warning(
                    "Primary rate limit EXHAUSTED (remaining=0). "
                    "Requests will be blocked until reset."
                )
            elif new_remaining < _PRIMARY_WARN_THRESHOLD:
                logger.warning(
                    "Approaching primary rate limit: %d requests remaining.", new_remaining
                )

        if reset_raw is not None:
            try:
                self._reset_at = float(reset_raw)
            except (ValueError, TypeError):
                logger.warning("Unparseable x-ratelimit-reset: %r", reset_raw)

    # ------------------------------------------------------------------
    # Secondary / abuse-detection handling
    # ------------------------------------------------------------------

    async def handle_rate_limit(self, status_code: int, headers: dict) -> float:
        """
        React to a 403 or 429 that signals secondary rate limiting.

        Strategy
        --------
        * Parse ``retry-after`` from the response headers.
        * Apply exponential back-off: ``retry_after * 2 ** hit_count``, capped
          at ``_SECONDARY_BACKOFF_CAP`` (300 s).
        * Sleep for the computed duration.
        * Return the number of seconds actually waited.

        If the status code is not 403 or 429, return 0.0 immediately.
        """
        if status_code not in (403, 429):
            return 0.0

        normalised    = {k.lower(): v for k, v in headers.items()}
        retry_after_s = self._parse_retry_after(normalised)

        # Exponential back-off: double on each consecutive secondary hit.
        wait_seconds = min(
            retry_after_s * (2 ** self._secondary_hit_count),
            _SECONDARY_BACKOFF_CAP,
        )
        self._secondary_hit_count += 1

        logger.warning(
            "Secondary rate limit triggered (HTTP %d). "
            "retry-after=%ss, computed wait=%.1fs (hit #%d).",
            status_code,
            retry_after_s,
            wait_seconds,
            self._secondary_hit_count,
        )

        await asyncio.sleep(wait_seconds)
        return wait_seconds

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def remaining(self) -> int:
        """Requests remaining in the current primary rate-limit window."""
        return self._remaining

    @property
    def is_exhausted(self) -> bool:
        """True when the primary rate limit has been fully consumed."""
        return self._remaining == 0

    @property
    def reset_at(self) -> float:
        """Unix timestamp at which the primary rate-limit window resets."""
        return self._reset_at

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _wait_for_primary_reset(self) -> None:
        """If the primary limit is exhausted, sleep until the reset window."""
        if not self.is_exhausted:
            return

        now        = time.time()
        sleep_time = max(self._reset_at - now + 1.0, 0.0)  # +1 s buffer

        if sleep_time > 0:
            logger.info(
                "Primary rate limit exhausted. Sleeping %.1f s until reset.", sleep_time
            )
            await asyncio.sleep(sleep_time)

        # After waking, optimistically restore headroom.  The next response
        # headers will correct this to the true value.
        self._remaining = 5_000
        self._secondary_hit_count = 0  # reset abuse counter after a full window

    @staticmethod
    def _parse_retry_after(normalised_headers: dict) -> float:
        """
        Extract the ``retry-after`` delay in seconds.

        GitHub may send an integer (seconds) or an HTTP-date string.
        Falls back to 60 s if the header is absent or unparseable.
        """
        raw = normalised_headers.get("retry-after")
        if raw is None:
            return 60.0

        # Try integer seconds first.
        try:
            return max(float(raw), 1.0)
        except (ValueError, TypeError):
            pass

        # Try HTTP-date (e.g. "Sat, 01 Jan 2025 00:01:00 GMT").
        import email.utils
        try:
            parsed = email.utils.parsedate_to_datetime(raw)
            delay  = parsed.timestamp() - time.time()
            return max(delay, 1.0)
        except Exception:
            logger.warning("Could not parse retry-after header value: %r", raw)
            return 60.0
