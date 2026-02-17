"""
User-Agent rotation utilities.

Provides round-robin and random rotation of User-Agent strings,
with support for configuration-based agent lists.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from ciberwebscan.config.models import UserAgentConfig


@dataclass
class UserAgentRotator:
    """
    Round-robin User-Agent rotator.

    Cycles through a list of User-Agent strings, returning a different
    one on each call to next().

    Attributes:
        agents: List of User-Agent strings to rotate through.

    Examples:
        >>> rotator = UserAgentRotator(['Chrome/120', 'Firefox/121'])
        >>> rotator.next()
        'Chrome/120'
        >>> rotator.next()
        'Firefox/121'
        >>> rotator.next()  # Wraps around
        'Chrome/120'
    """

    agents: list[str]
    rotation_interval: int = 1
    _index: int = field(default=0, init=False, repr=False)
    _request_count: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        """Validate agents list and rotation interval."""
        if not self.agents:
            raise ValueError("User-Agent list cannot be empty")
        if self.rotation_interval < 1:
            raise ValueError("rotation_interval must be >= 1")

    def next(self) -> str:
        """
        Get the next User-Agent in rotation.

        The agent only advances after every *rotation_interval* calls,
        keeping the same User-Agent for N consecutive requests.

        Returns:
            Next User-Agent string in the rotation sequence.
        """
        agent = self.agents[self._index]
        self._request_count += 1
        if self._request_count >= self.rotation_interval:
            self._request_count = 0
            self._index = (self._index + 1) % len(self.agents)
        return agent

    def current(self) -> str:
        """
        Get the current User-Agent without advancing.

        Returns:
            Current User-Agent string.
        """
        return self.agents[self._index]

    def reset(self) -> None:
        """Reset rotation to the first User-Agent."""
        self._index = 0
        self._request_count = 0

    def random(self) -> str:
        """
        Get a random User-Agent from the list.

        Returns:
            Random User-Agent string.
        """
        return random.choice(self.agents)

    def __len__(self) -> int:
        """Return the number of User-Agents in rotation."""
        return len(self.agents)

    def __iter__(self):
        """Iterate over all User-Agents."""
        return iter(self.agents)


class UserAgentProvider:
    """
    User-Agent provider with configurable selection mode.

    Supports three modes:
    - static: Always returns the same User-Agent
    - rotate: Round-robin rotation through the list
    - random: Random selection on each call

    This class is designed to work with UserAgentConfig from the
    configuration system.

    Examples:
        >>> # From configuration
        >>> from ciberwebscan.config.models import UserAgentConfig
        >>> config = UserAgentConfig(mode='rotate')
        >>> provider = UserAgentProvider.from_config(config)
        >>> provider.get()
        'Mozilla/5.0 ...'

        >>> # Direct instantiation
        >>> provider = UserAgentProvider(
        ...     mode='static',
        ...     agents=['MyBot/1.0'],
        ... )
        >>> provider.get()
        'MyBot/1.0'
    """

    def __init__(
        self,
        mode: Literal["static", "rotate", "random"] = "rotate",
        agents: list[str] | None = None,
        custom: str | None = None,
        rotation_interval: int = 1,
    ) -> None:
        """
        Initialize the User-Agent provider.

        Args:
            mode: Selection mode ('static', 'rotate', or 'random').
            agents: List of User-Agent strings. Uses defaults if None.
            custom: Custom User-Agent for static mode. If provided and
                mode is 'static', this takes precedence over agents list.
            rotation_interval: Number of consecutive requests that use the
                same User-Agent before rotating. Only applies to 'rotate'
                mode; ignored in 'static' and 'random' modes.

        Raises:
            ValueError: If agents list is empty and no custom is provided.
        """
        self._mode = mode
        self._custom = custom

        # Get default agents if none provided
        if agents is None:
            from ciberwebscan.config.models import DEFAULT_USER_AGENTS

            agents = DEFAULT_USER_AGENTS.copy()

        if not agents and not custom:
            raise ValueError("Must provide agents list or custom User-Agent")

        self._agents = agents
        self._rotator = (
            UserAgentRotator(agents, rotation_interval=rotation_interval)
            if agents
            else None
        )

    @classmethod
    def from_config(cls, config: UserAgentConfig) -> UserAgentProvider:
        """
        Create a UserAgentProvider from configuration.

        Args:
            config: UserAgentConfig instance.

        Returns:
            Configured UserAgentProvider.
        """
        return cls(
            mode=config.mode,
            agents=config.agents,
            custom=config.custom,
            rotation_interval=config.rotate_interval,
        )

    def get(self) -> str:
        """
        Get a User-Agent according to the configured mode.

        Returns:
            User-Agent string based on mode:
            - static: Returns custom or first agent
            - rotate: Returns next agent in rotation
            - random: Returns random agent
        """
        if self._mode == "static":
            if self._custom:
                return self._custom
            return self._agents[0] if self._agents else ""

        if self._mode == "random":
            return random.choice(self._agents)

        # Default: rotate
        if self._rotator:
            return self._rotator.next()
        return self._custom or ""

    def reset(self) -> None:
        """Reset rotation to the beginning (only affects rotate mode)."""
        if self._rotator:
            self._rotator.reset()

    @property
    def mode(self) -> str:
        """Get the current mode."""
        return self._mode

    @property
    def agents(self) -> list[str]:
        """Get the list of User-Agents."""
        return self._agents.copy()

    def __len__(self) -> int:
        """Return the number of available User-Agents."""
        return len(self._agents)


def get_default_user_agents() -> list[str]:
    """
    Get the default list of User-Agents from configuration.

    Returns:
        List of default User-Agent strings.
    """
    from ciberwebscan.config.models import DEFAULT_USER_AGENTS

    return DEFAULT_USER_AGENTS.copy()
