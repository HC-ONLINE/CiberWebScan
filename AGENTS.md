# CiberWebScan - AI Agent Instructions

## Project Overview

CiberWebScan is a hybrid web security scanner combining passive reconnaissance, attack surface analysis, structured extraction, and security assessment of web applications. Version **2.4.0** (beta), licensed under Apache 2.0.

- **Python**: >= 3.10 (supports 3.10, 3.11, 3.12)
- **Package**: `ciberwebscan` (src layout: `src/ciberwebscan/`)
- **Entry point**: `ciberwebscan` CLI → `ciberwebscan.cli.app:main`
- **License**: Apache 2.0

## Architecture Overview

CiberWebScan uses a **layered architecture** with clear separation of concerns:

```
CLI (Typer) / API (FastAPI)
        ↓
    Services (BaseService, ServiceResult[T])
        ↓
    Core Modules
    ├── analyzers/  (ssl, fingerprint, headers, cve)
    ├── attacks/    (xss, sqli, traversal, enumeration)
    ├── client/     (HTTPClient with retry/rate-limit, proxy, user-agent)
    └── scraping/   (static BeautifulSoup, dynamic Playwright)
        ↓
    Export (JSON, JSONL, CSV, HTML)
        ↓
    External Targets
```

- **CLI** (`cli/`): Typer-based commands in `cli/commands/` — each file is a command group
- **API** (`api/`): FastAPI app with factory `create_app()` in `api/app.py`, routes in `api/routes/`, models in `api/models/`
- **Services** (`services/`): Business logic layer, all inherit from `BaseService` and return `ServiceResult[T]`
- **Core** (`core/`): Low-level modules — `analyzers/`, `attacks/`, `scraping/`, `client/`
- **Export** (`export/`): Streaming/batch exporters for JSON, JSONL, CSV, HTML via `BaseExporter` hierarchy
- **Config** (`config/`): Pydantic v2 models in `models.py`, loaded via `ConfigLoader` with `get_config()` singleton
- **Utils** (`utils/`): Logging setup and URL validators

## Key Patterns

### Service Pattern

All services extend `BaseService` and return `ServiceResult[T]`:

```python
from ciberwebscan.services.base import BaseService, ServiceResult


class MyService(BaseService):
    def do_work(self, options: MyOptions) -> ServiceResult[MyData]:
        # Use factory methods for convenience:
        return ServiceResult.ok(data)  # Success
        return ServiceResult.fail("msg")  # Failure
        # Or construct manually:
        result = ServiceResult[MyData](success=True, data=data)
        return result.finalize()  # Always call finalize() to set timing
```

Key `ServiceResult` fields: `success`, `data`, `error`, `error_code`, `started_at`, `finished_at`, `duration_seconds`, `exported`, `export_path`, `warnings`.

### Error Handling

Services use a typed exception hierarchy for structured errors:

```python
from ciberwebscan.services.base import (
    ServiceError,      # Base exception
    ValidationError,   # Input validation failed (code="VALIDATION_ERROR")
    ExecutionError,    # Error during execution (code="EXECUTION_ERROR")
)

# Catch specific errors:
try:
    service.do_work(url)
except ValidationError as e:
    # e.message, e.code, e.details
except ExecutionError as e:
    # e.message, e.code, e.details
except ServiceError as e:
    # Catch-all for service errors
```

### HTTP Client Usage

Use `HTTPClient` as a context manager (wraps httpx with retry, rate-limiting, and adaptive AIMD):

```python
from ciberwebscan.core.client.http_client import HTTPClient

with HTTPClient(timeout=30) as client:
    response = client.get(url)  # Automatic retry with jittered exponential backoff
    response = client.post(url, json=data)  # Also supports HTTP/2
```

### Configuration Access

```python
from ciberwebscan.config.loader import get_config, load_config, reset_config, get_loader

# Singleton access (loads from ~/.ciberwebscan/config.yaml + env vars)
config = get_config()  # Returns AppConfig (Pydantic model)
timeout = config.http.timeout.connect

# Load from specific file
config = load_config("my_config.yaml")

# Reset to defaults
reset_config()

# Get the loader instance (for saving/reloading)
loader = get_loader()
loader.save("exported_config.yaml")
loader.reload()
```

Environment variable overrides use prefix `CIBERWEBSCAN_` with dot-notation mapping:

- `CIBERWEBSCAN_HTTP_TIMEOUT_CONNECT=5` → `config.http.timeout.connect = 5`
- `CIBERWEBSCAN_LOGGING_LEVEL=DEBUG` → `config.logging.level = "DEBUG"`
- Booleans: `true/false/yes/no/1/0`, Lists: comma-separated

### Export Handling

Exporters stream or batch-write data to files. Use the service helper or call exporters directly:

```python
from ciberwebscan.export import JSONExporter, JSONLExporter, CSVExporter, HTMLExporter

# Via service helper (recommended)
service = MyService()
success, path = service._export_result(data, "output.json", format="json")

# Direct exporter usage
with JSONExporter(output_path="output.json", indent=2) as exporter:
    exporter.write_item(item)
```

Formats: `json` (pretty/batch), `jsonl` (streaming), `csv` (streaming), `html` (streaming).

### Logging

Centralized logging via `setup_logging()` in `utils/logging.py`:

```python
from ciberwebscan.utils.logging import setup_logging
from ciberwebscan.config.models import LoggingConfig

setup_logging(LoggingConfig(level="INFO", format="%(asctime)s %(name)s %(message)s"))
```

Supports console output + optional rotating file handler (configurable via `logging.file`, `logging.max_size`, `logging.backup_count`).

## CLI Commands

All commands run via `ciberwebscan <command>` or `python -m ciberwebscan`:

| Command      | Subcommands                                             | Description                                                |
| ------------ | ------------------------------------------------------- | ---------------------------------------------------------- |
| `analyze`    | `url`, `ssl`, `fingerprint`, `cves`                     | Security analysis (headers, SSL, fingerprints, CVE lookup) |
| `attack`     | `test`, `xss`, `sqli`                                   | Attack surface testing                                     |
| `scrape`     | `url`, `batch`                                          | Web scraping (static or dynamic)                           |
| `quick`      | `scan`                                                  | Fast combined scan                                         |
| `config`     | `show`, `get`, `set`, `reset`, `keys`, `export`, `load` | Configuration management                                   |
| `api`        | `run`                                                   | Start REST API server                                      |
| `completion` | `install`, `show`, `uninstall`                          | Shell completion management                                |
| `version`    | (none)                                                  | Show version info                                          |

```bash
# Examples
ciberwebscan analyze url https://example.com
ciberwebscan attack xss https://example.com/search
ciberwebscan scrape url https://example.com --dynamic
ciberwebscan quick scan https://example.com
ciberwebscan config set logging.level DEBUG
ciberwebscan api run --host 0.0.0.0 --port 8000
ciberwebscan completion install --shell zsh
```

## API Reference

### Authentication

All `/api/*` routes require an API key via header:

```
X-API-Key: <your-api-key>
```

### Endpoints

| Method   | Path                       | Description                      |
| -------- | -------------------------- | -------------------------------- |
| GET      | `/health`, `/health/ready` | Health checks (no `/api` prefix) |
| POST     | `/api/auth/...`            | API key management               |
| GET/POST | `/api/config/...`          | Read/update configuration        |
| POST     | `/api/scrape/...`          | Submit scraping tasks            |
| POST     | `/api/analyze/...`         | Submit analysis tasks            |
| POST     | `/api/attack/...`          | Submit attack tests              |
| POST     | `/api/quick/...`           | Quick combined scan              |
| GET      | `/api/download/...`        | Download results by token        |

### Middleware

- **RequestLoggingMiddleware**: Logs method, path, status, duration for every request
- **RateLimitingMiddleware**: In-memory sliding window per IP, returns 429 with `Retry-After` header

### Models

- Requests: `api/models/requests.py`
- Responses: `api/models/responses.py`
- All endpoints use Pydantic v2 validation

## Scraping Modes

| Mode                                | Engine                | When to use                           |
| ----------------------------------- | --------------------- | ------------------------------------- |
| **Static** (`scraping/static.py`)   | BeautifulSoup + lxml  | Fast, no JS rendering needed          |
| **Dynamic** (`scraping/dynamic.py`) | Playwright (Chromium) | JS-heavy sites, SPAs, dynamic content |

```bash
ciberwebscan scrape url https://example.com              # Static (default)
ciberwebscan scrape url https://example.com --dynamic     # Dynamic (Playwright)
```

Dynamic mode requires: `playwright install` (first time)

## Attack Modules

| Module      | File                          | Description                    |
| ----------- | ----------------------------- | ------------------------------ |
| XSS         | `core/attacks/xss.py`         | Cross-site scripting detection |
| SQLi        | `core/attacks/sqli.py`        | SQL injection detection        |
| Traversal   | `core/attacks/traversal.py`   | Path traversal detection       |
| Enumeration | `core/attacks/enumeration.py` | Resource enumeration           |

Base class in `core/attacks/base.py`, payloads in `core/attacks/attack_payloads.json` and `core/attacks/payloads.py`.

## Export System

Four export formats in `src/ciberwebscan/export/`:

| Format | Class           | Streaming                     | Notes                        |
| ------ | --------------- | ----------------------------- | ---------------------------- |
| JSON   | `JSONExporter`  | Optional (batch or streaming) | Pretty-print with `indent=2` |
| JSONL  | `JSONLExporter` | Always                        | One JSON object per line     |
| CSV    | `CSVExporter`   | Always                        | Flat data only               |
| HTML   | `HTMLExporter`  | Always                        | Rendered HTML table          |

Base class: `export/base.py` → `BaseExporter`. Config controls: `export.pretty`, `export.include_raw_html`, `export.buffer_size`, `export.streaming`, `export.output_dir`.

## Configuration Details

### Config File Locations

- **Default**: `~/.ciberwebscan/config.yaml` (auto-created on first load)
- **Custom**: Pass path to `load_config("path/to/config.yaml")`
- **Formats**: YAML (preferred) or JSON

### Environment Variables

Prefix: `CIBERWEBSCAN_` with `_` → `.` mapping:

```bash
# HTTP settings
CIBERWEBSCAN_HTTP_TIMEOUT_CONNECT=5
CIBERWEBSCAN_HTTP_TIMEOUT_READ=30
CIBERWEBSCAN_HTTP_PROXY=http://proxy:8080

# Logging
CIBERWEBSCAN_LOGGING_LEVEL=DEBUG
CIBERWEBSCAN_LOGGING_FILE=logs/app.log

# Scraping
CIBERWEBSCAN_SCRAPING_DYNAMIC_ENABLED=false

# Attacks
CIBERWEBSCAN_ATTACKS_XSS_ENABLED=true
```

See `.env.example` for full list.

### Example Profiles

Pre-built config profiles in `examples/profiles/`:

| Profile          | Rate Limit | Attacks        | Scraping         | Logging |
| ---------------- | ---------- | -------------- | ---------------- | ------- |
| `bugbounty.yaml` | 2 req/s    | XSS, SQLi, CVE | Static           | INFO    |
| `pentest.yaml`   | 5 req/s    | All enabled    | Dynamic          | DEBUG   |
| `recon.yaml`     | —          | None           | Static           | INFO    |
| `stealth.yaml`   | 0.5 req/s  | Minimal        | Static (minimal) | WARNING |

```bash
ciberwebscan config load examples/profiles/bugbounty.yaml
```

## Development Commands

```bash
# Setup
pip install -e ".[dev]"          # CLI + dev dependencies
pip install -e ".[api,dev]"      # Include API dependencies
pip install -e ".[api]"          # API only (no dev tools)
playwright install                # Required for dynamic scraping

# Running
ciberwebscan                      # CLI entry point
python -m ciberwebscan            # Alternative CLI entry
python -m ciberwebscan.api.app    # Direct API server start
ciberwebscan api run              # API via CLI

# Testing
pytest                                          # All tests with coverage
pytest tests/unit/                              # Unit tests only
pytest tests/integration/                       # Integration tests only
pytest tests/unit/core/analyzers/test_ssl.py   # Specific file
pytest -k "test_name"                           # By name pattern
pytest -m "not slow"                            # Exclude slow tests
pytest -m integration                           # Only integration tests

# Code Quality
ruff check .                    # Lint
ruff check . --fix              # Lint + auto-fix
ruff format .                   # Format
pyright                         # Type check
pre-commit run --all-files      # All checks (ruff, prettier, trailing-whitespace, etc.)
pre-commit run pytest --hook-stage pre-push  # Run tests on push
```

## Testing Conventions

- **Structure**: `tests/unit/` mirrors `src/ciberwebscan/` (e.g., `tests/unit/api/routes/test_health.py`)
- **Integration**: `tests/integration/api/` and `tests/integration/cli/`
- **Naming**: Files `test_*.py`, classes `Test*`, functions `test_*`
- **Async**: `asyncio_mode = "auto"` — no need for explicit `@pytest.mark.asyncio`
- **Markers**: `@pytest.mark.slow`, `@pytest.mark.integration`, `@pytest.mark.unit`
- **Coverage**: HTML, terminal, and XML reports; source is `src/ciberwebscan`

### HTTPClient Mocking

Patch at the import path and set `__enter__.return_value`:

```python
from unittest.mock import Mock, patch


@patch("ciberwebscan.core.client.http_client.HTTPClient")
def test_with_mock(mock_http):
    mock_client = Mock()
    mock_http.return_value.__enter__.return_value = mock_client
    mock_client.get.return_value = Mock(text="<html>", headers={})
```

### Service Mocking

Services can be mocked by patching their class or providing mock dependencies:

```python
@patch("ciberwebscan.services.analyze_service.AnalyzeService")
def test_analyze_route(mock_service_class):
    mock_svc = Mock()
    mock_service_class.return_value = mock_svc
    mock_svc.analyze.return_value = ServiceResult.ok(data={})
```

## File Locations

| Purpose             | Location                                                                                 |
| ------------------- | ---------------------------------------------------------------------------------------- |
| CLI entry point     | `src/ciberwebscan/cli/app.py`                                                            |
| CLI commands        | `src/ciberwebscan/cli/commands/`                                                         |
| CLI output helpers  | `src/ciberwebscan/cli/output.py`                                                         |
| CLI validators      | `src/ciberwebscan/cli/validators.py`                                                     |
| API app factory     | `src/ciberwebscan/api/app.py`                                                            |
| API routes          | `src/ciberwebscan/api/routes/`                                                           |
| API models          | `src/ciberwebscan/api/models/requests.py`, `responses.py`                                |
| API auth            | `src/ciberwebscan/api/auth.py`                                                           |
| API middleware      | `src/ciberwebscan/api/middleware.py`                                                     |
| API download helper | `src/ciberwebscan/api/helpers/download_helper.py`                                        |
| Pydantic config     | `src/ciberwebscan/config/models.py`                                                      |
| Config loader       | `src/ciberwebscan/config/loader.py`                                                      |
| Service base        | `src/ciberwebscan/services/base.py`                                                      |
| Services            | `src/ciberwebscan/services/` (analyze, attack, scrape, config, quick, download, cleanup) |
| SSL analyzer        | `src/ciberwebscan/core/analyzers/ssl/`                                                   |
| Fingerprint         | `src/ciberwebscan/core/analyzers/fingerprint/` (includes `signatures.json`)              |
| Security headers    | `src/ciberwebscan/core/analyzers/headers/`                                               |
| CVE lookup          | `src/ciberwebscan/core/analyzers/cve/` (nvd, vulners, circl, aggregator)                 |
| Attack modules      | `src/ciberwebscan/core/attacks/` (base, xss, sqli, traversal, enumeration)               |
| Attack payloads     | `src/ciberwebscan/core/attacks/attack_payloads.json`, `payloads.py`                      |
| HTTP client         | `src/ciberwebscan/core/client/http_client.py`                                            |
| Proxy support       | `src/ciberwebscan/core/client/proxy.py`                                                  |
| User agent          | `src/ciberwebscan/core/client/user_agent.py`                                             |
| Static scraping     | `src/ciberwebscan/core/scraping/static.py`                                               |
| Dynamic scraping    | `src/ciberwebscan/core/scraping/dynamic.py`                                              |
| Export base         | `src/ciberwebscan/export/base.py`                                                        |
| Export formats      | `src/ciberwebscan/export/` (json, jsonl, csv, html)                                      |
| Export models       | `src/ciberwebscan/export/models.py`                                                      |
| Logging setup       | `src/ciberwebscan/utils/logging.py`                                                      |
| URL validators      | `src/ciberwebscan/utils/validators.py`                                                   |
| Cleanup scheduler   | `src/ciberwebscan/services/cleanup_scheduler.py`                                         |
| Example profiles    | `examples/profiles/` (bugbounty, pentest, recon, stealth)                                |
| Manual API tests    | `scripts/apiManualTest/`                                                                 |
| Unit tests          | `tests/unit/`                                                                            |
| Integration tests   | `tests/integration/`                                                                     |
| Shared fixtures     | `tests/conftest.py`                                                                      |
| GitHub Actions      | `.github/workflows/ci.yml`, `docker.yml`                                                 |
| Pre-commit config   | `.pre-commit-config.yaml`                                                                |
| Dockerfile          | `Dockerfile`                                                                             |
| Docs                | `docs/` (API.md, CLI.md, CONFIGURATION.md, CONTRIBUTING.md, etc.)                        |

## Docker & CI/CD

### Docker

Multi-stage build (builder + runtime), non-root user `ciberwebscan`, Playwright Chromium installed:

```bash
docker build -t ciberwebscan .
docker run -p 8000:8000 ciberwebscan  # Starts API on port 8000
```

### GitHub Actions

- **ci.yml**: Runs on push/PR to `main` and `CI-testing` — lint, type check, test (Python 3.10, 3.11, 3.12 matrix)
- **docker.yml**: Builds and pushes to GHCR (`ghcr.io`) on push to `main`

## Pre-commit Hooks

Configured in `.pre-commit-config.yaml` with `fail_fast: true`:

| Hook                       | Stage      | Description                    |
| -------------------------- | ---------- | ------------------------------ |
| `ruff --fix`               | pre-commit | Lint + auto-fix                |
| `ruff-format`              | pre-commit | Format code                    |
| `trailing-whitespace`      | pre-commit | Remove trailing spaces         |
| `end-of-file-fixer`        | pre-commit | Ensure newline at EOF          |
| `check-added-large-files`  | pre-commit | Block files > 500KB            |
| `check-yaml`, `check-toml` | pre-commit | Validate config files          |
| `check-merge-conflict`     | pre-commit | Detect merge conflict markers  |
| `prettier`                 | pre-commit | Format .md, .json, .yaml files |
| `pytest`                   | pre-push   | Run full test suite            |
| `pyright`                  | pre-push   | Type check                     |

## Code Style

- Python 3.10+ features allowed (type unions `X | Y`, pattern matching)
- **Every file** must start with `from __future__ import annotations`
- Double quotes for strings, 88 char line limit (Ruff)
- Pydantic v2 for all data models
- Type hints required on all public functions
- Ruff rules: E, W, F, I, N, UP, B, C4, SIM (ignores E501)
- Pyright mode: `basic` (not strict)
- Target Python version: 3.10
