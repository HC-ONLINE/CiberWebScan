"""
Async runner utility for bridging sync and async contexts.

Provides a safe way to run async coroutines from both sync and async
callers, handling the event-loop constraints of each.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from collections.abc import Coroutine
from typing import TypeVar

T = TypeVar("T")


def run_async(coro: Coroutine[None, None, T], timeout: float = 30.0) -> T:
    """Run an async coroutine safely from any context.

    When called from a **sync** context (no running event loop) the coroutine
    is executed via :func:`asyncio.run`.

    When called from an **async** context (e.g. inside a FastAPI handler)
    a new thread is spawned with its own event loop so that
    ``asyncio.run`` can execute the coroutine without conflicting with the
    caller's loop.

    Args:
        coro: The coroutine to run.
        timeout: Maximum seconds to wait when running in a thread (default 30).

    Returns:
        The result of the coroutine.

    Raises:
        TimeoutError: If the coroutine does not finish within *timeout* seconds.
        RuntimeError: If no event loop is running and ``asyncio.run`` fails.
        Exception: Any exception raised by the coroutine itself.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # No running loop – safe to use asyncio.run directly.
        return asyncio.run(coro)

    # We are inside a running loop. Run the coroutine in a new thread
    # with its own event loop to avoid "cannot call run_until_complete
    # on a running loop" errors.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(asyncio.run, coro)
        return future.result(timeout=timeout)
