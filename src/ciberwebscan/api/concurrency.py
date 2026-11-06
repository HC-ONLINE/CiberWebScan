"""
In-flight admission control for scan endpoints (BUG-013).

Scan operations (analyze, attack, scrape, scrape batch, quick scan) are
long, blocking and non-cancellable once started. Before this module, the
five scan routes were plain ``def`` handlers dispatched by FastAPI onto the
shared AnyIO threadpool (default 40 tokens). A burst larger than the pool
built an unbounded FIFO queue with no signal to the client and no deadline.

This module provides:

- :class:`ScanAdmissionController`: a per-process in-flight counter with
  early rejection (the 429 alternative to an unbounded queue).
- A dedicated AnyIO :class:`~anyio.CapacityLimiter` for scan work (sized
  from ``api.max_concurrent_scans``), so scans stop competing with the
  shared pool's tokens for synchronous dependencies and streaming responses.
- :func:`run_scan`: admission + execution + optional deadline with honest
  cancellation semantics (see below).

Cancellation semantics (verified against the installed AnyIO source and
measured):

Starlette/AnyIO run each request inside a cancel scope. When a route
returns or raises, that scope is torn down and cancels the awaiting path.
``asyncio.shield`` only protects a task from the ``wait_for`` deadline; it
does NOT protect it from request-scope teardown. A naive
``ensure_future`` + ``wait_for(shield(...))`` therefore cancels the scan
work (and releases its slot) as soon as the 504 is delivered, while the
blocking worker thread keeps running: capacity is freed while resources are
still consumed.

To avoid that, the blocking callable runs via
``anyio.to_thread.run_sync(..., abandon_on_cancel=True, limiter=...)``. With
``abandon_on_cancel=True`` AnyIO shields the worker from the request's
cancel scope, so cancelling the *wait* (deadline or client disconnect)
detaches the waiter but leaves the thread running. The in-flight slot is
released via a done callback on the worker future, which fires on the event
loop only when the worker thread has truly finished (and is safely
suppressed if the loop is already closed). Capacity therefore tracks real
resource usage, never the client's willingness to keep waiting.

Note on token ownership: the scan limiter is used *only* as the worker gate
(``run_sync`` acquires and releases its own token). The admission counter is
a separate, module-owned integer so that (a) a task never holds two tokens on
one limiter — AnyIO forbids it — and (b) the slot can outlive the request.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import TypeVar

import anyio.to_thread
from anyio import CapacityLimiter
from fastapi import HTTPException

from ciberwebscan.config.loader import get_config

logger = logging.getLogger(__name__)

T = TypeVar("T")

RETRY_AFTER_SECONDS = 5
"""Seconds advertised in ``Retry-After`` when scan capacity is exhausted."""


class ScanAdmissionController:
    """Bounded in-flight counter for scan operations.

    ``try_acquire`` performs the check and the increment in a single
    synchronous step on the event loop thread (no ``await`` between them),
    so two concurrent requests within one process can never both observe
    free capacity for the same slot. With multiple API worker processes the
    limit is per process, not global.
    """

    def __init__(self, limit: int) -> None:
        """Initialize the controller.

        Args:
            limit: Maximum number of scans allowed in flight.

        Raises:
            ValueError: If limit is below 1.
        """
        if limit < 1:
            raise ValueError("limit must be >= 1")
        self._limit = limit
        self._in_flight = 0

    @property
    def limit(self) -> int:
        """Maximum number of scans allowed in flight."""
        return self._limit

    @property
    def in_flight(self) -> int:
        """Number of scans currently holding a slot."""
        return self._in_flight

    def try_acquire(self) -> bool:
        """Take a slot if one is free.

        Returns:
            True when a slot was acquired, False when the limit is reached.
        """
        if self._in_flight >= self._limit:
            return False
        self._in_flight += 1
        return True

    def release(self) -> None:
        """Return a previously acquired slot.

        Callers must only release a slot they acquired, and only when the
        underlying work has really finished. A release without a matching
        acquisition is logged and ignored rather than corrupting the count.
        """
        if self._in_flight <= 0:
            logger.warning("Scan admission release without a held slot; ignored")
            return
        self._in_flight -= 1


_controller: ScanAdmissionController | None = None
_scan_limiter: CapacityLimiter | None = None


def configure() -> ScanAdmissionController:
    """(Re)build the admission controller and scan limiter from config.

    Called from the application lifespan so the effective limits are fixed
    at startup and logged once. Also usable from tests to apply a modified
    configuration; a reconfigure while scans are in flight discards the old
    accounting, so it must only happen when no scan is running.
    """
    global _controller, _scan_limiter

    limit = get_config().api.max_concurrent_scans
    _controller = ScanAdmissionController(limit)
    _scan_limiter = CapacityLimiter(limit)
    logger.info(
        "Scan concurrency configured: max_concurrent_scans=%d, "
        "scan_timeout_seconds=%s, sync_threadpool_tokens=%d",
        limit,
        get_config().api.scan_timeout_seconds,
        get_config().api.sync_threadpool_tokens,
    )
    return _controller


def reset() -> None:
    """Drop the global controller and limiter (used by tests)."""
    global _controller, _scan_limiter
    _controller = None
    _scan_limiter = None


def get_controller() -> ScanAdmissionController:
    """Return the admission controller, building it from config if needed."""
    if _controller is None:
        return configure()
    return _controller


def get_scan_limiter() -> CapacityLimiter:
    """Return the dedicated AnyIO limiter for scan threads."""
    if _scan_limiter is None:
        configure()
    assert _scan_limiter is not None
    return _scan_limiter


async def run_scan(func: Callable[[], T]) -> T:
    """Run a blocking scan callable with admission control and a deadline.

    The callable executes on a worker thread gated by the dedicated scan
    limiter (not the shared AnyIO threadpool), so scan work cannot crowd out
    synchronous dependencies or streaming responses.

    Saturation behaviour: when ``api.max_concurrent_scans`` scans are
    already in flight, the request is rejected immediately with 429 and a
    ``Retry-After`` header instead of queueing indefinitely.

    Deadline behaviour (``api.scan_timeout_seconds``): the client is
    answered with 504 when the deadline elapses, but the blocking work
    cannot be stopped — it keeps running until it finishes on its own
    (bounded by the per-operation HTTP timeouts), and the in-flight slot is
    held until then (released by the worker's done callback at true thread
    end). With no timeout configured the request waits for the scan to
    complete, as before.

    Args:
        func: Zero-argument callable performing the blocking scan work.

    Returns:
        Whatever the callable returns.

    Raises:
        HTTPException: 429 when at capacity, 504 when the deadline elapses,
            or whatever exception the callable itself raises.
    """
    controller = get_controller()
    if not controller.try_acquire():
        logger.warning(
            "Scan rejected: %d scans already in flight (limit %d)",
            controller.in_flight,
            controller.limit,
        )
        raise HTTPException(
            status_code=429,
            detail=(
                f"Too many concurrent scans ({controller.in_flight} in "
                f"flight, limit {controller.limit}); retry later"
            ),
            headers={"Retry-After": str(RETRY_AFTER_SECONDS)},
        )

    # The slot taken above is released only when the worker thread has truly
    # finished. add_done_callback on the worker future fires on the event
    # loop at thread end (and is suppressed if the loop is already closed),
    # so capacity is never freed while blocking work is still running.
    worker_task: asyncio.Task[T] = asyncio.ensure_future(
        anyio.to_thread.run_sync(
            func,
            abandon_on_cancel=True,
            limiter=get_scan_limiter(),
        )
    )

    def _on_worker_done(finished: asyncio.Future[T]) -> None:
        controller.release()
        if not finished.cancelled():
            # Retrieve the exception (if any) so an abandoned-after-504 scan
            # cannot emit "Task exception was never retrieved".
            finished.exception()

    worker_task.add_done_callback(_on_worker_done)

    timeout = get_config().api.scan_timeout_seconds
    if timeout is None:
        return await worker_task

    try:
        # Shielded: the deadline cancels only our wait, never the worker
        # task that owns the thread and the admission slot.
        return await asyncio.wait_for(asyncio.shield(worker_task), timeout)
    except asyncio.TimeoutError as exc:
        logger.error(
            "Scan exceeded api.scan_timeout_seconds=%.1fs; answering 504 "
            "while the non-cancellable work keeps its admission slot until "
            "it finishes",
            timeout,
        )
        raise HTTPException(
            status_code=504,
            detail=(
                f"Scan exceeded the configured deadline ({timeout:.0f}s). "
                "The request was abandoned; the server-side work may still "
                "be running until it reaches its own bounded end."
            ),
        ) from exc
