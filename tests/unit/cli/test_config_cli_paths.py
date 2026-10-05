"""Path-resolution behavior of the `config` CLI command group.

The CLI must resolve config paths from the user's current working directory
(LOCAL policy): relative paths, ``~`` expansion, and ``--config`` pointers all
act on the caller's CWD, never on the global config base directory.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ciberwebscan.cli.app import app

pytestmark = pytest.mark.unit

runner = CliRunner()

REPO_ROOT = Path(__file__).resolve().parents[3]


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _output(result) -> str:
    """Combined stdout+stderr of a CliRunner invocation."""
    return _strip_ansi(getattr(result, "output", "") or "")


@pytest.fixture
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect HOME/USERPROFILE so the global config base lands in tmp."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    return fake_home


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolated CWD for relative path resolution."""
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    return work


def _write(path: Path, connect: float) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"http:\n  timeout:\n    connect: {connect}\n",
        encoding="utf-8",
    )
    return path


class TestLoadRelativeProfile:
    """Documented flow: `config load examples/profiles/...` from the repo root."""

    def test_load_from_repo_root_exits_zero(
        self, isolated_home: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.chdir(REPO_ROOT)

        result = runner.invoke(
            app, ["config", "load", "examples/profiles/bugbounty.yaml"]
        )

        assert result.exit_code == 0
        assert "Loaded configuration" in _output(result)


class TestExportResolvesFromCwd:
    """Export writes next to the caller, not into the global base."""

    def test_relative_yaml_export_lands_in_cwd(
        self, workdir: Path, isolated_home: Path
    ):
        base = isolated_home / ".ciberwebscan"

        result = runner.invoke(app, ["config", "export", "out.yaml"])

        assert result.exit_code == 0
        assert (workdir / "out.yaml").is_file()
        assert not (base / "out.yaml").exists()

    def test_relative_json_export_lands_in_cwd(
        self, workdir: Path, isolated_home: Path
    ):
        base = isolated_home / ".ciberwebscan"

        result = runner.invoke(app, ["config", "export", "out.json", "-f", "json"])

        assert result.exit_code == 0
        assert (workdir / "out.json").is_file()
        assert not (base / "out.json").exists()


class TestConfigFlagReadWriteSameFile:
    """`--config rel.yaml` reads and writes exactly one file: the CWD's."""

    def test_get_set_reset_roundtrip(self, workdir: Path, isolated_home: Path):
        base = isolated_home / ".ciberwebscan"
        target = _write(workdir / "rel.yaml", 11)

        got = runner.invoke(
            app,
            ["config", "get", "http.timeout.connect", "--config", "rel.yaml"],
        )
        assert got.exit_code == 0
        assert "http.timeout.connect: 11.0" in _output(got)

        set_result = runner.invoke(
            app,
            ["config", "set", "http.timeout.connect", "42.5", "--config", "rel.yaml"],
        )
        assert set_result.exit_code == 0
        assert "42.5" in target.read_text(encoding="utf-8")
        assert not (base / "rel.yaml").exists()

        reset_result = runner.invoke(
            app,
            [
                "config",
                "reset",
                "http.timeout.connect",
                "-y",
                "--config",
                "rel.yaml",
            ],
        )
        assert reset_result.exit_code == 0

        regot = runner.invoke(
            app,
            ["config", "get", "http.timeout.connect", "--config", "rel.yaml"],
        )
        assert regot.exit_code == 0
        assert "http.timeout.connect: 10.0" in _output(regot)
        assert not (base / "rel.yaml").exists()


class TestTildeExpansion:
    """`~` is expanded before validation and lands in the fake home."""

    def test_export_and_load_with_tilde(self, workdir: Path, isolated_home: Path):
        result = runner.invoke(app, ["config", "export", "~/.ciberwebscan/tilde.yaml"])

        assert result.exit_code == 0
        tilde_target = isolated_home / ".ciberwebscan" / "tilde.yaml"
        assert tilde_target.is_file()
        assert not (workdir / "~").exists()

        load_result = runner.invoke(
            app, ["config", "load", "~/.ciberwebscan/tilde.yaml"]
        )
        assert load_result.exit_code == 0


class TestValidationExitCodes:
    """Validator failures exit 2; service failures exit 1."""

    def test_missing_file_exits_two_with_absolute_path(
        self, workdir: Path, isolated_home: Path
    ):
        expected = str(workdir / "missing.yaml")

        result = runner.invoke(app, ["config", "load", "missing.yaml"])

        assert result.exit_code == 2
        assert expected in _output(result)

    def test_directory_exits_one(self, workdir: Path, isolated_home: Path):
        (workdir / "dirfile.yaml").mkdir()

        result = runner.invoke(app, ["config", "load", "dirfile.yaml"])

        assert result.exit_code == 1
        assert "not a file" in _output(result)
