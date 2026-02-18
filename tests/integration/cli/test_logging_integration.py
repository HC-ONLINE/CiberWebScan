"""
Integration tests for logging configuration in CLI.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


class TestLoggingIntegration:
    """Integration tests for logging in CLI context."""

    def test_cli_uses_configured_logging_level(self, tmp_path, monkeypatch):
        """Test that CLI respects logging level from config."""
        # Create a test config file with all required sections
        config_file = tmp_path / "test_config.yaml"
        config_content = """
http:
  timeout:
    connect: 10
    read: 30
    write: 30
    pool: 10
  retry:
    max_attempts: 3
    backoff_factor: 0.5
    retryable_status_codes: [429, 500, 502, 503, 504]
  rate_limit:
    requests_per_second: 5.0
    per_domain: true
  proxy: null
  http2: true
  follow_redirects: true
  max_redirects: 10
  verify_ssl: true
user_agent:
  mode: rotate
  custom: null
  rotate_interval: 10
  agents:
    - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
scraping:
  dynamic:
    enabled: false
    wait_timeout: 10.0
    wait_selector: null
    headless: true
    browser_type: chromium
  pagination:
    enabled: false
    max_pages: 10
    next_selector: null
    page_param: null
  extract_links: true
  extract_images: true
  extract_scripts: true
  extract_forms: true
  max_content_length: 10485760
analysis:
  ssl:
    enabled: true
    check_chain: true
    check_revocation: true
    check_expiry: true
    warning_days: 30
  fingerprint:
    enabled: true
    check_headers: true
    check_html: true
    check_scripts: true
    check_cookies: true
    check_dns: false
  cve:
    enabled: true
    api: all
    nvd_api_key: null
    vulners_api_key: null
    cache_ttl: 86400
  headers:
    enabled: true
    required_headers:
      - Strict-Transport-Security
      - X-Content-Type-Options
      - X-Frame-Options
      - Content-Security-Policy
attack:
  enabled: false
  user_consent: false
  whitelist: ["127.0.0.1", "localhost"]
  xss: true
  sqli: true
  traversal: true
  enumeration: true
  max_payloads: 50
export:
  format: jsonl
  output_dir: exports
  include_raw_html: false
  include_screenshots: false
  streaming: true
  buffer_size: 100
  pretty: true
logging:
  level: DEBUG
  format: "%(levelname)s - %(name)s - %(message)s"
  file: null
  max_size: 10485760
  backup_count: 5
cache:
  enabled: true
  directory: .cache
  ttl: 3600
  max_size_mb: 100
"""
        config_file.write_text(config_content)

        # Copy to default location
        default_config_dir = Path.home() / ".ciberwebscan"
        default_config_dir.mkdir(parents=True, exist_ok=True)
        default_config_file = default_config_dir / "config.yaml"
        import shutil

        shutil.copy(config_file, default_config_file)

        # Run a CLI command that triggers logging
        result = subprocess.run(
            [sys.executable, "-m", "ciberwebscan", "config", "show"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent.parent,
        )

        # Check that DEBUG logs appear in stderr
        assert "DEBUG" in result.stderr
        assert "ciberwebscan.config.loader" in result.stderr

    def test_cli_logs_to_file_when_configured(self, tmp_path, monkeypatch):
        """Test that CLI logs to file when configured."""
        log_file = tmp_path / "cli.log"
        config_file = tmp_path / "test_config.yaml"
        config_content = f"""
http:
  timeout:
    connect: 10
    read: 30
    write: 30
    pool: 10
  retry:
    max_attempts: 3
    backoff_factor: 0.5
    retryable_status_codes: [429, 500, 502, 503, 504]
  rate_limit:
    requests_per_second: 5.0
    per_domain: true
  proxy: null
  http2: true
  follow_redirects: true
  max_redirects: 10
  verify_ssl: true
user_agent:
  mode: rotate
  custom: null
  rotate_interval: 10
  agents:
    - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
scraping:
  dynamic:
    enabled: false
    wait_timeout: 10.0
    wait_selector: null
    headless: true
    browser_type: chromium
  pagination:
    enabled: false
    max_pages: 10
    next_selector: null
    page_param: null
  extract_links: true
  extract_images: true
  extract_scripts: true
  extract_forms: true
  max_content_length: 10485760
analysis:
  ssl:
    enabled: true
    check_chain: true
    check_revocation: true
    check_expiry: true
    warning_days: 30
  fingerprint:
    enabled: true
    check_headers: true
    check_html: true
    check_scripts: true
    check_cookies: true
    check_dns: false
  cve:
    enabled: true
    api: all
    nvd_api_key: null
    vulners_api_key: null
    cache_ttl: 86400
  headers:
    enabled: true
    required_headers:
      - Strict-Transport-Security
      - X-Content-Type-Options
      - X-Frame-Options
      - Content-Security-Policy
attack:
  enabled: false
  user_consent: false
  whitelist: ["127.0.0.1", "localhost"]
  xss: true
  sqli: true
  traversal: true
  enumeration: true
  max_payloads: 50
export:
  format: jsonl
  output_dir: exports
  include_raw_html: false
  include_screenshots: false
  streaming: true
  buffer_size: 100
  pretty: true
logging:
  level: DEBUG
  format: "%(asctime)s - %(levelname)s - %(message)s"
  file: {log_file}
  max_size: 10485760
  backup_count: 5
cache:
  enabled: true
  directory: .cache
  ttl: 3600
  max_size_mb: 100
"""
        config_file.write_text(config_content)

        # Copy to default location
        default_config_dir = Path.home() / ".ciberwebscan"
        default_config_dir.mkdir(parents=True, exist_ok=True)
        default_config_file = default_config_dir / "config.yaml"
        import shutil

        shutil.copy(config_file, default_config_file)

        # Run CLI command
        subprocess.run(
            [sys.executable, "-m", "ciberwebscan", "config", "show"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent.parent,
        )

        # Check that log file was created and contains logs
        assert log_file.exists()
        log_content = log_file.read_text()
        assert "INFO" in log_content or "DEBUG" in log_content

    def test_cli_respects_log_level_filtering(self, tmp_path, monkeypatch):
        """Test that CLI filters logs based on level."""
        # Test with WARNING level - should not show DEBUG logs
        config_file = tmp_path / "test_config.yaml"
        config_content = """
http:
  timeout:
    connect: 10
    read: 30
    write: 30
    pool: 10
  retry:
    max_attempts: 3
    backoff_factor: 0.5
    retryable_status_codes: [429, 500, 502, 503, 504]
  rate_limit:
    requests_per_second: 5.0
    per_domain: true
  proxy: null
  http2: true
  follow_redirects: true
  max_redirects: 10
  verify_ssl: true
user_agent:
  mode: rotate
  custom: null
  rotate_interval: 10
  agents:
    - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
scraping:
  dynamic:
    enabled: false
    wait_timeout: 10.0
    wait_selector: null
    headless: true
    browser_type: chromium
  pagination:
    enabled: false
    max_pages: 10
    next_selector: null
    page_param: null
  extract_links: true
  extract_images: true
  extract_scripts: true
  extract_forms: true
  max_content_length: 10485760
analysis:
  ssl:
    enabled: true
    check_chain: true
    check_revocation: true
    check_expiry: true
    warning_days: 30
  fingerprint:
    enabled: true
    check_headers: true
    check_html: true
    check_scripts: true
    check_cookies: true
    check_dns: false
  cve:
    enabled: true
    api: all
    nvd_api_key: null
    vulners_api_key: null
    cache_ttl: 86400
  headers:
    enabled: true
    required_headers:
      - Strict-Transport-Security
      - X-Content-Type-Options
      - X-Frame-Options
      - Content-Security-Policy
attack:
  enabled: false
  user_consent: false
  whitelist: ["127.0.0.1", "localhost"]
  xss: true
  sqli: true
  traversal: true
  enumeration: true
  max_payloads: 50
export:
  format: jsonl
  output_dir: exports
  include_raw_html: false
  include_screenshots: false
  streaming: true
  buffer_size: 100
  pretty: true
logging:
  level: WARNING
  format: "%(levelname)s - %(message)s"
  file: null
  max_size: 10485760
  backup_count: 5
cache:
  enabled: true
  directory: .cache
  ttl: 3600
  max_size_mb: 100
"""
        config_file.write_text(config_content)

        # Copy to default location
        default_config_dir = Path.home() / ".ciberwebscan"
        default_config_dir.mkdir(parents=True, exist_ok=True)
        default_config_file = default_config_dir / "config.yaml"
        import shutil

        shutil.copy(config_file, default_config_file)

        result = subprocess.run(
            [sys.executable, "-m", "ciberwebscan", "config", "show"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent.parent,
        )

        # Should not contain DEBUG logs
        assert "DEBUG" not in result.stderr

        # Test with DEBUG level - should show DEBUG logs
        config_content_debug = """
http:
  timeout:
    connect: 10
    read: 30
    write: 30
    pool: 10
  retry:
    max_attempts: 3
    backoff_factor: 0.5
    retryable_status_codes: [429, 500, 502, 503, 504]
  rate_limit:
    requests_per_second: 5.0
    per_domain: true
  proxy: null
  http2: true
  follow_redirects: true
  max_redirects: 10
  verify_ssl: true
user_agent:
  mode: rotate
  custom: null
  rotate_interval: 10
  agents:
    - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
scraping:
  dynamic:
    enabled: false
    wait_timeout: 10.0
    wait_selector: null
    headless: true
    browser_type: chromium
  pagination:
    enabled: false
    max_pages: 10
    next_selector: null
    page_param: null
  extract_links: true
  extract_images: true
  extract_scripts: true
  extract_forms: true
  max_content_length: 10485760
analysis:
  ssl:
    enabled: true
    check_chain: true
    check_revocation: true
    check_expiry: true
    warning_days: 30
  fingerprint:
    enabled: true
    check_headers: true
    check_html: true
    check_scripts: true
    check_cookies: true
    check_dns: false
  cve:
    enabled: true
    api: all
    nvd_api_key: null
    vulners_api_key: null
    cache_ttl: 86400
  headers:
    enabled: true
    required_headers:
      - Strict-Transport-Security
      - X-Content-Type-Options
      - X-Frame-Options
      - Content-Security-Policy
attack:
  enabled: false
  user_consent: false
  whitelist: ["127.0.0.1", "localhost"]
  xss: true
  sqli: true
  traversal: true
  enumeration: true
  max_payloads: 50
export:
  format: jsonl
  output_dir: exports
  include_raw_html: false
  include_screenshots: false
  streaming: true
  buffer_size: 100
  pretty: true
logging:
  level: DEBUG
  format: "%(levelname)s - %(message)s"
  file: null
  max_size: 10485760
  backup_count: 5
cache:
  enabled: true
  directory: .cache
  ttl: 3600
  max_size_mb: 100
"""
        config_file.write_text(config_content_debug)
        shutil.copy(config_file, default_config_file)

        result_debug = subprocess.run(
            [sys.executable, "-m", "ciberwebscan", "config", "show"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent.parent,
        )

        # Should contain DEBUG logs
        assert "DEBUG" in result_debug.stderr
