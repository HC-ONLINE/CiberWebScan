"""
Tests for the run_async utility.
"""

from __future__ import annotations

import asyncio
import concurrent.futures

import pytest

from ciberwebscan.utils.async_runner import run_async


async def _async_add(a: int, b: int) -> int:
    return a + b


async def _async_sleep_add(a: int, b: int) -> int:
    await asyncio.sleep(0.01)
    return a + b


async def _async_raises() -> None:
    raise ValueError("test error")


class TestRunAsync:
    """Tests for run_async bridging utility."""

    def test_sync_context(self):
        """run_async works from a sync context (no event loop)."""
        result = run_async(_async_add(2, 3))
        assert result == 5

    def test_sync_context_with_sleep(self):
        """run_async handles coroutines that await."""
        result = run_async(_async_sleep_add(10, 20))
        assert result == 30

    @pytest.mark.asyncio
    async def test_async_context(self):
        """run_async works from an async context (running event loop)."""
        result = run_async(_async_add(4, 5))
        assert result == 9

    @pytest.mark.asyncio
    async def test_async_context_with_sleep(self):
        """run_async handles coroutines that await, from async context."""
        result = run_async(_async_sleep_add(7, 8))
        assert result == 15

    def test_propagates_exception(self):
        """Exceptions from the coroutine are propagated."""
        with pytest.raises(ValueError, match="test error"):
            run_async(_async_raises())

    @pytest.mark.asyncio
    async def test_propagates_exception_async(self):
        """Exceptions propagate even when called from async context."""
        with pytest.raises(ValueError, match="test error"):
            run_async(_async_raises())

    @pytest.mark.asyncio
    async def test_timeout_raises(self):
        """Timeout is respected when called from async context."""

        async def _slow():
            await asyncio.sleep(10)
            return "done"

        with pytest.raises(concurrent.futures.TimeoutError):
            run_async(_slow(), timeout=0.1)
