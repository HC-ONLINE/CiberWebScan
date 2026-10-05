"""Path-policy behavior of ConfigService: CONFIG_DIR (sandbox) vs LOCAL (CWD)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from ciberwebscan.services.config_service import ConfigService, PathPolicy

pytestmark = pytest.mark.unit


@pytest.fixture
def config_base(tmp_path: Path):
    """Patch the CONFIG_DIR sandbox base to a temp directory."""
    base = tmp_path / "base"
    base.mkdir()
    with patch(
        "ciberwebscan.services.config_service.get_config_base_dir",
        return_value=base,
    ):
        yield base


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolated CWD for LOCAL path resolution."""
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


# =============================================================================
# Homonym file: same relative name in CWD and in the config base
# =============================================================================


class TestHomonymCwdVsBase:
    """LOCAL resolves from the CWD, CONFIG_DIR resolves from the base."""

    @pytest.fixture
    def homonym(self, tmp_path: Path, config_base: Path, workdir: Path):
        _write(workdir / "hom.yaml", 42)
        _write(config_base / "hom.yaml", 7)
        return workdir / "hom.yaml"

    def test_local_load_uses_cwd(self, homonym: Path):
        service = ConfigService(path_policy=PathPolicy.LOCAL)

        result = service.load("hom.yaml")

        assert result.success
        assert service.config.http.timeout.connect == 42.0

    def test_config_dir_load_uses_base(self, homonym: Path):
        service = ConfigService()  # default CONFIG_DIR

        result = service.load("hom.yaml")

        assert result.success
        assert service.config.http.timeout.connect == 7.0

    def test_local_export_writes_cwd_not_base(self, homonym: Path, config_base: Path):
        service = ConfigService(path_policy=PathPolicy.LOCAL)

        result = service.export_config("out.yaml")

        assert result.success
        assert (homonym.parent / "out.yaml").is_file()
        assert not (config_base / "out.yaml").exists()


# =============================================================================
# save(None) with an explicit config_path
# =============================================================================


class TestSaveNoneExplicitConfigPath:
    """save() without a path must write exactly where the loader reads."""

    def test_destination_identical_to_loader(self, workdir: Path, tmp_path: Path):
        service = ConfigService(config_path="rel.yaml", path_policy=PathPolicy.LOCAL)

        result = service.save()

        assert result.success
        assert result.data == service.loader.config_path
        assert result.data == workdir / "rel.yaml"
        assert (workdir / "rel.yaml").is_file()

    def test_directory_destination_rejected(self, tmp_path: Path):
        directory = tmp_path / "adir"
        directory.mkdir()
        service = ConfigService(config_path=directory, path_policy=PathPolicy.LOCAL)

        result = service.save()

        assert not result.success
        assert result.error_code == "CONFIG_SAVE_ERROR"
        assert "directory" in (result.error or "").lower()

    def test_missing_parents_are_created(self, tmp_path: Path):
        target = tmp_path / "new" / "deep" / "cfg.yaml"
        service = ConfigService(config_path=target, path_policy=PathPolicy.LOCAL)

        result = service.save()

        assert result.success
        assert target.is_file()

    def test_external_path_keeps_legacy_compatibility_under_config_dir(
        self, tmp_path: Path, config_base: Path
    ):
        """An explicit config_path outside the base stays readable/writable.

        The constructor pointer is the caller's own choice (legacy behavior);
        only per-call path arguments are sandboxed under CONFIG_DIR.
        """
        ext_dir = tmp_path / "external"
        ext_dir.mkdir()
        external = _write(ext_dir / "external.yaml", 15.0)

        service = ConfigService(config_path=external)  # CONFIG_DIR default

        assert service.config_path == external
        assert service.loader.config_path == external
        assert service.config.http.timeout.connect == 15.0

        saved = service.save()
        assert saved.success
        assert saved.data == external

        # Per-call path arguments remain contained to the config base.
        blocked = service.save(external)
        assert not blocked.success
        assert blocked.error_code == "PATH_TRAVERSAL_BLOCKED"


# =============================================================================
# LOCAL policy rules (not a sandbox, but not without checks)
# =============================================================================


class TestLocalPolicyRules:
    """Absolute paths, '..' and dirs are allowed; input and type are checked."""

    def test_absolute_path_outside_cwd_allowed(self, workdir: Path, tmp_path: Path):
        target = tmp_path / "elsewhere" / "abs.yaml"
        service = ConfigService(path_policy=PathPolicy.LOCAL)

        result = service.save(str(target))

        assert result.success
        assert target.is_file()
        assert not (workdir / "abs.yaml").exists()

    def test_parent_traversal_allowed(
        self, workdir: Path, monkeypatch: pytest.MonkeyPatch
    ):
        subdir = workdir / "sub"
        subdir.mkdir()
        monkeypatch.chdir(subdir)
        service = ConfigService(path_policy=PathPolicy.LOCAL)

        result = service.export_config("../up.yaml")

        assert result.success
        assert (workdir / "up.yaml").is_file()

    def test_wrong_extension_rejected(self, workdir: Path):
        service = ConfigService(path_policy=PathPolicy.LOCAL)

        result = service.save("evil.txt")

        assert not result.success
        assert result.error_code == "CONFIG_SAVE_ERROR"
        assert "extension" in (result.error or "").lower()

    def test_empty_path_rejected(self, workdir: Path):
        service = ConfigService(path_policy=PathPolicy.LOCAL)

        result = service.save("")

        assert not result.success
        assert result.error_code == "CONFIG_SAVE_ERROR"
        assert "empty" in (result.error or "").lower()

    def test_null_byte_rejected(self, workdir: Path):
        service = ConfigService(path_policy=PathPolicy.LOCAL)

        result = service.load("bad\0name.yaml")

        assert not result.success
        assert result.error_code == "CONFIG_LOAD_ERROR"
        assert "null byte" in (result.error or "").lower()

    def test_missing_file_reports_not_found(self, workdir: Path):
        service = ConfigService(path_policy=PathPolicy.LOCAL)

        result = service.load("nope.yaml")

        assert not result.success
        assert result.error_code == "CONFIG_FILE_NOT_FOUND"

    def test_directory_as_read_target_rejected(self, workdir: Path):
        (workdir / "dir.yaml").mkdir()
        service = ConfigService(path_policy=PathPolicy.LOCAL)

        result = service.load("dir.yaml")

        assert not result.success
        assert result.error_code == "CONFIG_LOAD_ERROR"
        assert "not a file" in (result.error or "").lower()

    def test_directory_as_write_target_rejected(self, workdir: Path):
        (workdir / "dir.yaml").mkdir()
        service = ConfigService(path_policy=PathPolicy.LOCAL)

        result = service.save("dir.yaml")

        assert not result.success
        assert result.error_code == "CONFIG_SAVE_ERROR"
        assert "directory" in (result.error or "").lower()

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only paths")
    def test_drive_relative_path_rejected(self, workdir: Path):
        service = ConfigService(path_policy=PathPolicy.LOCAL)

        result = service.save("C:evil.yaml")

        assert not result.success
        assert result.error_code == "CONFIG_SAVE_ERROR"
        assert "drive-relative" in (result.error or "").lower()


# =============================================================================
# JSON export through _export_result under both policies
# =============================================================================


class TestJsonExport:
    """JSON export keeps the _export_result validation contract."""

    def test_local_json_export_to_new_directory(self, workdir: Path, tmp_path: Path):
        target = tmp_path / "fresh" / "out.json"
        service = ConfigService(path_policy=PathPolicy.LOCAL)

        result = service.export_config(target, format="json")

        assert result.success
        assert result.exported is True
        assert target.is_file()

    def test_config_dir_json_export_stays_in_base(
        self, config_base: Path, workdir: Path
    ):
        service = ConfigService()  # CONFIG_DIR

        result = service.export_config("export.json", format="json")

        assert result.success
        assert (config_base / "export.json").is_file()
        assert not (workdir / "export.json").exists()


# =============================================================================
# path_policy argument normalization (enum, strings, invalid values)
# =============================================================================


class TestPathPolicyNormalization:
    """The constructor must resolve any raw policy value to a PathPolicy member.

    A raw string such as ``"config_dir"`` used to reach the identity check in
    ``_resolve_user_path()`` and silently activate the LOCAL branch, escaping
    the ``~/.ciberwebscan`` sandbox.
    """

    def test_default_is_config_dir(self):
        service = ConfigService()

        assert service._path_policy is PathPolicy.CONFIG_DIR

    def test_explicit_enum_keeps_sandbox(self, config_base: Path, tmp_path: Path):
        service = ConfigService(path_policy=PathPolicy.CONFIG_DIR)
        outside = tmp_path / "outside.yaml"

        assert service._path_policy is PathPolicy.CONFIG_DIR

        result = service.save(str(outside))

        assert not result.success
        assert result.error_code == "PATH_TRAVERSAL_BLOCKED"
        assert not outside.exists()

    def test_string_config_dir_normalized_and_blocks(
        self, config_base: Path, tmp_path: Path
    ):
        service = ConfigService(path_policy="config_dir")
        outside = tmp_path / "outside.yaml"

        assert service._path_policy is PathPolicy.CONFIG_DIR
        assert PathPolicy(service._path_policy) is PathPolicy.CONFIG_DIR

        result = service.save(str(outside))

        assert not result.success
        assert result.error_code == "PATH_TRAVERSAL_BLOCKED"
        assert not outside.exists()

    def test_string_local_normalized_and_allows(self, workdir: Path, tmp_path: Path):
        service = ConfigService(path_policy="local")
        outside = tmp_path / "elsewhere" / "abs.yaml"

        assert service._path_policy is PathPolicy.LOCAL

        result = service.save(str(outside))

        assert result.success
        assert outside.is_file()
        assert not (workdir / "abs.yaml").exists()

    def test_invalid_value_rejected_never_becomes_local(self, config_base: Path):
        with pytest.raises(ValueError, match="not a valid PathPolicy"):
            ConfigService(path_policy="unexpected")

        # The constructor raised, so no service (and no silent LOCAL policy)
        # was ever created; the sandbox base stayed untouched.
        assert list(config_base.iterdir()) == []

    def test_api_construction_pattern_keeps_sandbox(
        self, config_base: Path, tmp_path: Path
    ):
        """API handlers build ``ConfigService()`` bare and stay sandboxed."""
        service = ConfigService()
        outside = tmp_path / "outside.yaml"

        result = service.save(str(outside))

        assert not result.success
        assert result.error_code == "PATH_TRAVERSAL_BLOCKED"
        assert not outside.exists()
