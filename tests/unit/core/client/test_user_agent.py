"""
Unit tests for User-Agent utilities.
"""

import pytest

from ciberwebscan.config.models import DEFAULT_USER_AGENTS, UserAgentConfig
from ciberwebscan.core.client import (
    UserAgentProvider,
    UserAgentRotator,
    get_default_user_agents,
)


class TestUserAgentRotator:
    """Tests for UserAgentRotator class."""

    def test_empty_list_raises(self):
        """Empty user agent list should raise ValueError."""
        with pytest.raises(ValueError) as exc:
            UserAgentRotator([])
        assert "empty" in str(exc.value).lower()

    def test_single_agent_rotation(self):
        """Single agent should always return same value."""
        rotator = UserAgentRotator(["MyBot/1.0"])
        assert rotator.next() == "MyBot/1.0"
        assert rotator.next() == "MyBot/1.0"

    def test_round_robin_rotation(self, sample_user_agents):
        """Agents should rotate in round-robin order."""
        rotator = UserAgentRotator(sample_user_agents)

        assert rotator.next() == sample_user_agents[0]
        assert rotator.next() == sample_user_agents[1]
        assert rotator.next() == sample_user_agents[2]
        # Wrap around
        assert rotator.next() == sample_user_agents[0]

    def test_current_does_not_advance(self, sample_user_agents):
        """current() should not advance the index."""
        rotator = UserAgentRotator(sample_user_agents)

        assert rotator.current() == sample_user_agents[0]
        assert rotator.current() == sample_user_agents[0]
        rotator.next()
        assert rotator.current() == sample_user_agents[1]

    def test_reset(self, sample_user_agents):
        """reset() should return to first agent."""
        rotator = UserAgentRotator(sample_user_agents)

        rotator.next()
        rotator.next()
        rotator.reset()

        assert rotator.current() == sample_user_agents[0]

    def test_random(self, sample_user_agents):
        """random() should return an agent from the list."""
        rotator = UserAgentRotator(sample_user_agents)

        # Call multiple times, all should be from the list
        for _ in range(10):
            agent = rotator.random()
            assert agent in sample_user_agents

    def test_len(self, sample_user_agents):
        """len() should return number of agents."""
        rotator = UserAgentRotator(sample_user_agents)
        assert len(rotator) == len(sample_user_agents)

    def test_iter(self, sample_user_agents):
        """Should be iterable."""
        rotator = UserAgentRotator(sample_user_agents)
        assert list(rotator) == sample_user_agents


class TestUserAgentProvider:
    """Tests for UserAgentProvider class."""

    def test_init_with_defaults(self):
        """Default initialization should use DEFAULT_USER_AGENTS."""
        provider = UserAgentProvider()
        assert len(provider) == len(DEFAULT_USER_AGENTS)

    def test_init_with_custom_agents(self, sample_user_agents):
        """Should accept custom agents list."""
        provider = UserAgentProvider(agents=sample_user_agents)
        assert len(provider) == len(sample_user_agents)

    def test_init_static_mode_with_custom(self):
        """Static mode with custom agent."""
        provider = UserAgentProvider(mode="static", custom="MyBot/1.0")
        assert provider.get() == "MyBot/1.0"
        assert provider.get() == "MyBot/1.0"  # Always same

    def test_init_static_mode_without_custom(self, sample_user_agents):
        """Static mode without custom uses first agent."""
        provider = UserAgentProvider(mode="static", agents=sample_user_agents)
        assert provider.get() == sample_user_agents[0]
        assert provider.get() == sample_user_agents[0]

    def test_rotate_mode(self, sample_user_agents):
        """Rotate mode should cycle through agents."""
        provider = UserAgentProvider(mode="rotate", agents=sample_user_agents)

        assert provider.get() == sample_user_agents[0]
        assert provider.get() == sample_user_agents[1]
        assert provider.get() == sample_user_agents[2]
        assert provider.get() == sample_user_agents[0]  # Wrap around

    def test_random_mode(self, sample_user_agents):
        """Random mode should return agents from list."""
        provider = UserAgentProvider(mode="random", agents=sample_user_agents)

        for _ in range(10):
            agent = provider.get()
            assert agent in sample_user_agents

    def test_reset(self, sample_user_agents):
        """reset() should reset rotation."""
        provider = UserAgentProvider(mode="rotate", agents=sample_user_agents)

        provider.get()
        provider.get()
        provider.reset()

        assert provider.get() == sample_user_agents[0]

    def test_mode_property(self):
        """mode property should return current mode."""
        provider = UserAgentProvider(mode="random")
        assert provider.mode == "random"

    def test_agents_property(self, sample_user_agents):
        """agents property should return copy of agents list."""
        provider = UserAgentProvider(agents=sample_user_agents)
        agents = provider.agents

        # Should be a copy
        assert agents == sample_user_agents
        agents.append("NewAgent")
        assert "NewAgent" not in provider.agents

    def test_from_config_static(self):
        """from_config should work with static mode."""
        config = UserAgentConfig(mode="static", custom="ConfigBot/1.0")
        provider = UserAgentProvider.from_config(config)

        assert provider.mode == "static"
        assert provider.get() == "ConfigBot/1.0"

    def test_from_config_rotate(self):
        """from_config should work with rotate mode."""
        config = UserAgentConfig(mode="rotate")
        provider = UserAgentProvider.from_config(config)

        assert provider.mode == "rotate"
        assert len(provider) == len(DEFAULT_USER_AGENTS)

    def test_from_config_custom_agents(self, sample_user_agents):
        """from_config should use custom agents from config."""
        config = UserAgentConfig(mode="rotate", agents=sample_user_agents)
        provider = UserAgentProvider.from_config(config)

        assert len(provider) == len(sample_user_agents)
        assert provider.get() == sample_user_agents[0]

    def test_empty_agents_and_no_custom_raises(self):
        """Empty agents list without custom should raise."""
        with pytest.raises(ValueError):
            UserAgentProvider(agents=[], custom=None)


class TestGetDefaultUserAgents:
    """Tests for get_default_user_agents function."""

    def test_returns_list(self):
        """Should return a list of strings."""
        agents = get_default_user_agents()
        assert isinstance(agents, list)
        assert all(isinstance(a, str) for a in agents)

    def test_returns_copy(self):
        """Should return a copy, not the original."""
        agents1 = get_default_user_agents()
        agents2 = get_default_user_agents()

        agents1.append("Modified")

        assert "Modified" not in agents2

    def test_matches_default_user_agents(self):
        """Should match DEFAULT_USER_AGENTS from config."""
        agents = get_default_user_agents()
        assert agents == DEFAULT_USER_AGENTS

    def test_agents_look_like_user_agents(self):
        """Agents should look like valid user agent strings."""
        agents = get_default_user_agents()

        for agent in agents:
            assert "Mozilla" in agent or "Bot" in agent.lower()
            assert len(agent) > 20  # Real UAs are fairly long


class TestDefaultUserAgentsConfig:
    """Tests for DEFAULT_USER_AGENTS constant."""

    def test_has_chrome(self):
        """Should include Chrome user agent."""
        assert any("Chrome" in ua for ua in DEFAULT_USER_AGENTS)

    def test_has_firefox(self):
        """Should include Firefox user agent."""
        assert any("Firefox" in ua for ua in DEFAULT_USER_AGENTS)

    def test_has_safari(self):
        """Should include Safari user agent."""
        assert any("Safari" in ua for ua in DEFAULT_USER_AGENTS)

    def test_has_mobile(self):
        """Should include mobile user agents."""
        assert any("Mobile" in ua for ua in DEFAULT_USER_AGENTS)

    def test_has_desktop(self):
        """Should include desktop user agents."""
        assert any("Windows" in ua or "Macintosh" in ua for ua in DEFAULT_USER_AGENTS)

    def test_minimum_count(self):
        """Should have a reasonable number of user agents."""
        assert len(DEFAULT_USER_AGENTS) >= 4


# ── rotation_interval tests ─────────────────────────────────────────


class TestUserAgentRotatorInterval:
    """Tests for UserAgentRotator rotation_interval behaviour."""

    def test_default_interval_is_one(self, sample_user_agents):
        """Default interval=1 rotates on every call (backwards compat)."""
        rotator = UserAgentRotator(sample_user_agents)
        assert rotator.next() == sample_user_agents[0]
        assert rotator.next() == sample_user_agents[1]

    def test_interval_three(self, sample_user_agents):
        """With interval=3, same agent is returned 3 times before rotating."""
        rotator = UserAgentRotator(sample_user_agents, rotation_interval=3)

        for _ in range(3):
            assert rotator.next() == sample_user_agents[0]
        for _ in range(3):
            assert rotator.next() == sample_user_agents[1]
        for _ in range(3):
            assert rotator.next() == sample_user_agents[2]
        # Wraps around
        assert rotator.next() == sample_user_agents[0]

    def test_full_cycle_with_interval(self):
        """Full cycle: 2 agents × interval 2 = 4 calls then back to start."""
        agents = ["A", "B"]
        rotator = UserAgentRotator(agents, rotation_interval=2)

        results = [rotator.next() for _ in range(4)]
        assert results == ["A", "A", "B", "B"]
        # Back to A
        assert rotator.next() == "A"

    def test_reset_clears_request_count(self, sample_user_agents):
        """reset() must also zero the request counter."""
        rotator = UserAgentRotator(sample_user_agents, rotation_interval=3)

        rotator.next()  # count=1
        rotator.next()  # count=2
        rotator.reset()

        # After reset both index and count are 0 → starts fresh
        assert rotator.current() == sample_user_agents[0]
        for _ in range(3):
            assert rotator.next() == sample_user_agents[0]

    def test_invalid_interval_raises(self, sample_user_agents):
        """rotation_interval < 1 should raise ValueError."""
        with pytest.raises(ValueError, match="rotation_interval"):
            UserAgentRotator(sample_user_agents, rotation_interval=0)

    def test_current_unaffected_by_interval(self, sample_user_agents):
        """current() reflects index but doesn't depend on interval logic."""
        rotator = UserAgentRotator(sample_user_agents, rotation_interval=2)

        assert rotator.current() == sample_user_agents[0]
        rotator.next()  # count=1, index still 0
        assert rotator.current() == sample_user_agents[0]
        rotator.next()  # count=2 → rotates, index now 1
        assert rotator.current() == sample_user_agents[1]


class TestUserAgentProviderInterval:
    """Tests for UserAgentProvider rotation_interval wiring."""

    def test_rotate_mode_with_interval(self, sample_user_agents):
        """Provider in rotate mode honours rotation_interval."""
        provider = UserAgentProvider(
            mode="rotate",
            agents=sample_user_agents,
            rotation_interval=2,
        )
        assert provider.get() == sample_user_agents[0]
        assert provider.get() == sample_user_agents[0]
        assert provider.get() == sample_user_agents[1]
        assert provider.get() == sample_user_agents[1]

    def test_random_mode_ignores_interval(self, sample_user_agents):
        """Random mode must ignore rotation_interval entirely."""
        provider = UserAgentProvider(
            mode="random",
            agents=sample_user_agents,
            rotation_interval=100,
        )
        # Just ensure it returns valid agents (can't assert order)
        seen = {provider.get() for _ in range(30)}
        assert seen.issubset(set(sample_user_agents))

    def test_static_mode_ignores_interval(self):
        """Static mode must ignore rotation_interval entirely."""
        provider = UserAgentProvider(
            mode="static",
            custom="StaticBot/1.0",
            rotation_interval=5,
        )
        for _ in range(10):
            assert provider.get() == "StaticBot/1.0"

    def test_from_config_reads_rotate_interval(self, sample_user_agents):
        """from_config must pass rotate_interval to the rotator."""
        config = UserAgentConfig(
            mode="rotate",
            agents=sample_user_agents,
            rotate_interval=3,
        )
        provider = UserAgentProvider.from_config(config)

        # Same agent 3 times, then next
        for _ in range(3):
            assert provider.get() == sample_user_agents[0]
        assert provider.get() == sample_user_agents[1]

    def test_from_config_default_interval(self, sample_user_agents):
        """from_config with default rotate_interval=10 keeps same agent 10 times."""
        config = UserAgentConfig(mode="rotate", agents=sample_user_agents)
        provider = UserAgentProvider.from_config(config)

        # Default is 10 → same agent for 10 calls
        for _ in range(10):
            assert provider.get() == sample_user_agents[0]
        assert provider.get() == sample_user_agents[1]
