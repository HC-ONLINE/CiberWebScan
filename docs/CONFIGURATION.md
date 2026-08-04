# Configuration Guide

CiberWebScan uses a flexible configuration system that allows customization of various aspects of the application behavior.

## Table of Contents

1. [Configuration Sources](#configuration-sources)
   - [Environment Variable Limitations](#environment-variable-limitations)
2. [Configuration File](#configuration-file)
3. [Configuration Sections](#configuration-sections)
   - [HTTP Client](#http-client)
   - [User Agent](#user-agent)
   - [Scraping](#scraping)
   - [Analysis](#analysis)
   - [Attack](#attack)
   - [Export](#export)
   - [Cache](#cache)
   - [API](#api)
   - [Logging](#logging)
4. [CLI Commands](#cli-configuration-commands)
5. [Validation & Troubleshooting](#validation)
6. [Development Roadmap](#development-notes)

## Configuration Sources

Configuration values are loaded from multiple sources in order of precedence:

1. **Environment variables**
2. **User configuration file** (`~/.ciberwebscan/config.yaml`)
3. **Default values** (lowest priority)

Environment variable overrides (prefix & mapping)

- Environment overrides use the prefix `CIBERWEBSCAN_` by default (see `ConfigLoader.env_prefix`).
- After the prefix the name is lowercased and underscores are converted to dots to form the config key. Example:
  - `CIBERWEBSCAN_HTTP_TIMEOUT_CONNECT` -> `http.timeout.connect`
- Parsing rules used by `ConfigLoader._load_env` (`src/ciberwebscan/config/loader.py`):
  - Booleans: `true|yes|1` → true, `false|no|0` → false
  - Numbers: values containing `.` → float, otherwise int
  - Lists: comma-separated strings → parsed as arrays
- Examples:
  - `CIBERWEBSCAN_HTTP_TIMEOUT_CONNECT=15` → `http.timeout.connect: 15`
  - `CIBERWEBSCAN_SCRAPING_DYNAMIC_HEADLESS=false` → `scraping.dynamic.headless: false`
  - `CIBERWEBSCAN_USER_AGENT_AGENTS="a,b"` → `user_agent.agents: ["a","b"]`

See implementation: `ConfigLoader._load_env` (`src/ciberwebscan/config/loader.py`).

### Environment Variable Limitations

Our current `ConfigLoader` maps every underscore (`_`) in the environment variable name to a dot (`.`) when building the config path. That works for many simple keys (for example `CIBERWEBSCAN_HTTP_TIMEOUT_CONNECT` → `http.timeout.connect`), but it prevents overriding model fields that themselves contain underscores (for example `user_agent`, `rate_limit`, `include_screenshots`).

What this means in practice:

- Supported via `CIBERWEBSCAN_` envs (examples):

  - `CIBERWEBSCAN_HTTP_TIMEOUT_CONNECT` → `http.timeout.connect`
  - `CIBERWEBSCAN_HTTP_TIMEOUT_READ` → `http.timeout.read`
  - `CIBERWEBSCAN_HTTP_PROXY_ROTATE` → `http.proxy.rotate`
  - `CIBERWEBSCAN_SCRAPING_DYNAMIC_ENABLED` → `scraping.dynamic.enabled`
  - `CIBERWEBSCAN_SCRAPING_DYNAMIC_HEADLESS` → `scraping.dynamic.headless`
  - `CIBERWEBSCAN_ATTACK_ENABLED` → `attack.enabled`
  - `CIBERWEBSCAN_ATTACK_XSS` → `attack.xss`
  - `CIBERWEBSCAN_CACHE_ENABLED` → `cache.enabled`
  - `NVD_API_KEY`, `VULNERS_API_KEY` (read directly by CVE clients)

- NOT supported via `CIBERWEBSCAN_` envs (must use `config.yaml` or change loader):
  - `CIBERWEBSCAN_USER_AGENT_AGENTS` / `CIBERWEBSCAN_USER_AGENT_MODE` → `user_agent.*`
  - `CIBERWEBSCAN_HTTP_RATE_LIMIT_REQUESTS_PER_SECOND` → `http.rate_limit.requests_per_second`
  - `CIBERWEBSCAN_EXPORT_INCLUDE_SCREENSHOTS` → `export.include_screenshots`
  - `CIBERWEBSCAN_ANALYSIS_CVE_NVD_API_KEY` → `analysis.cve.nvd_api_key`
  - `CIBERWEBSCAN_ATTACK_USER_CONSENT` → `attack.user_consent`

Recommendation: for complex/underscore-containing fields, set them in `~/.ciberwebscan/config.yaml`. If you prefer env-based overrides for those fields, we can update `ConfigLoader` to support a double-underscore convention (e.g. `CIBERWEBSCAN_HTTP__RATE_LIMIT__REQUESTS_PER_SECOND`) — tell us if you want that behavior added.

**Note**: Command-line options are specific to individual commands and do not override global configuration. They are used to customize behavior for that particular command execution.

## Configuration File

The configuration file is automatically created in your user directory when you first run CiberWebScan. You can also create it manually.

### Location

- **Linux/macOS**: `~/.ciberwebscan/config.yaml`
- **Windows**: `%USERPROFILE%\.ciberwebscan\config.yaml`

### Format

Configuration files can be in JSON or YAML format.

**JSON Example:**

```json
{
  "http": {
    "timeout": {
      "connect": 15.0,
      "read": 45.0
    },
    "rate_limit": {
      "requests_per_second": 3.0
    }
  },
  "scraping": {
    "dynamic": {
      "enabled": true,
      "headless": false
    }
  }
}
```

**YAML Example:**

```yaml
http:
  timeout:
    connect: 15.0
    read: 45.0
  rate_limit:
    requests_per_second: 3.0

scraping:
  dynamic:
    headless: false
```

## Configuration Sections

### HTTP Client

Configure HTTP request behavior.

```json
{
  "http": {
    "timeout": {
      "connect": 10.0,
      "read": 30.0,
      "write": 30.0,
      "pool": 10.0
    },
    "retry": {
      "max_attempts": 3,
      "backoff_factor": 0.5,
      "retryable_status_codes": [429, 500, 502, 503, 504]
    },
    "rate_limit": {
      "requests_per_second": 5.0,
      "per_domain": true,
      "adaptive": true,
      "min_rate": 0.5,
      "increase_factor": 0.5,
      "decrease_factor": 0.5,
      "latency_spike_factor": 1.5,
      "latency_window": 10
    },
    "proxy": {
      "http": null,
      "https": null,
      "socks5": null,
      "rotate": false,
      "rotation_interval": 10,
      "proxy_list": null
    },
    "http2": true,
    "follow_redirects": true,
    "max_redirects": 10,
    "verify_ssl": true
  }
}
```

### Default values (quick reference)

| Key                                    | Default | Description                                   |
| -------------------------------------- | ------: | --------------------------------------------- |
| `http.timeout.connect`                 |  `10.0` | Connection timeout (seconds)                  |
| `http.timeout.read`                    |  `30.0` | Read timeout (seconds)                        |
| `http.timeout.write`                   |  `30.0` | Write timeout (seconds)                       |
| `http.timeout.pool`                    |  `10.0` | Connection pool timeout (seconds)             |
| `http.retry.max_attempts`              |     `3` | Retry attempts                                |
| `http.retry.backoff_factor`            |   `0.5` | Exponential backoff factor (with ±20% jitter) |
| `http.rate_limit.requests_per_second`  |   `5.0` | Requests per second                           |
| `http.rate_limit.per_domain`           |  `true` | Rate limit per domain                         |
| `http.rate_limit.adaptive`             |  `true` | Enable AIMD adaptive rate control             |
| `http.rate_limit.min_rate`             |   `0.5` | Minimum allowed rate (req/s)                  |
| `http.rate_limit.increase_factor`      |   `0.5` | Additive increase on 2xx responses            |
| `http.rate_limit.decrease_factor`      |   `0.5` | Multiplicative decrease on 429 (×0.5)         |
| `http.rate_limit.latency_spike_factor` |   `1.5` | Latency spike threshold (× median)            |
| `http.rate_limit.latency_window`       |    `10` | Sliding window size for latency measurements  |
| `http.proxy.rotate`                    | `false` | Proxy rotation disabled by default            |
| `http.proxy.rotation_interval`         |    `10` | Requests per proxy when rotating              |
| `http.http2`                           |  `true` | Enable HTTP/2 by default                      |
| `http.follow_redirects`                |  `true` | Follow redirects                              |
| `http.max_redirects`                   |    `10` | Max redirects to follow                       |
| `http.verify_ssl`                      |  `true` | Verify TLS certificates                       |

#### Proxy Rotation

When `rotate` is `true`, CiberWebScan cycles through available proxies
using a round-robin strategy. The proxy changes every `rotation_interval`
requests. Proxies can be supplied through `proxy_list` (recommended) or
will be collected from the individual `http`, `https`, and `socks5` fields.

`proxy_list` accepts either:

- A JSON array of proxy URLs: `["http://p1:8080", "http://p2:8080"]`
- A comma/newline-separated string: `"http://p1:8080, http://p2:8080"`

| Field               | Type             | Default | Description                               |
| ------------------- | ---------------- | ------- | ----------------------------------------- |
| `http`              | string \| null   | null    | Single HTTP proxy URL                     |
| `https`             | string \| null   | null    | Single HTTPS proxy URL                    |
| `socks5`            | string \| null   | null    | Single SOCKS5 proxy URL                   |
| `rotate`            | bool             | false   | Enable proxy rotation                     |
| `rotation_interval` | int (≥ 1)        | 10      | Number of requests before switching proxy |
| `proxy_list`        | list/string/null | null    | List of proxy URLs for rotation           |

Example with rotation enabled:

```json
{
  "http": {
    "proxy": {
      "rotate": true,
      "rotation_interval": 5,
      "proxy_list": [
        "http://proxy1.example.com:8080",
        "http://proxy2.example.com:8080",
        "socks5://proxy3.example.com:1080"
      ]
    }
  }
}
```

### User Agent

Configure user agent rotation.

```json
{
  "user_agent": {
    "mode": "rotate",
    "custom": null,
    "rotate_interval": 10,
    "agents": [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
    ]
  }
}
```

### Default values (quick reference)

| Key                          |                   Default | Description                       |
| ---------------------------- | ------------------------: | --------------------------------- |
| `user_agent.mode`            |                  `rotate` | Default rotation mode             |
| `user_agent.custom`          |                    `null` | No custom UA by default           |
| `user_agent.rotate_interval` |                      `10` | Requests before rotating UA       |
| `user_agent.agents`          | `default list (6 agents)` | Default UA list used for rotation |

### Scraping

Configure web scraping behavior.

```json
{
  "scraping": {
    "dynamic": {
      "wait_timeout": 10.0,
      "wait_selector": null,
      "headless": true,
      "browser_type": "chromium"
    },
    "pagination": {
      "max_pages": 10,
      "next_selector": null,
      "page_param": null
    },
    "extract_links": true,
    "extract_images": true,
    "extract_scripts": true,
    "extract_forms": false,
    "max_content_length": 10485760
  }
}
```

### Default values (quick reference)

| Key                             |            Default | Description                                           |
| ------------------------------- | -----------------: | ----------------------------------------------------- |
| `scraping.dynamic.enabled`      |            `false` | Dynamic (browser) scraping disabled by default        |
| `scraping.dynamic.wait_timeout` |             `10.0` | Wait timeout for dynamic scraping (s)                 |
| `scraping.dynamic.headless`     |             `true` | Playwright runs headless by default                   |
| `scraping.dynamic.browser_type` |         `chromium` | Default browser engine                                |
| `scraping.pagination.max_pages` |               `10` | Max pages to follow in pagination                     |
| `scraping.extract_links`        |             `true` | Extract links by default                              |
| `scraping.extract_images`       |             `true` | Extract images by default                             |
| `scraping.extract_scripts`      |             `true` | Extract scripts by default                            |
| `scraping.extract_forms`        |            `false` | Extract forms by default (opt-in via CLI/API)         |
| `scraping.max_content_length`   | `10485760 (10 MB)` | Max response size handled by scrapers (model default) |

> Implementation status — scraping options
>
> - `scraping.max_content_length`: present in the config model but **not enforced consistently** across all scrapers (see `src/ciberwebscan/core/scraping/static.py` and `src/ciberwebscan/core/scraping/dynamic.py`).
> - `scraping.extract_forms`: now fully wired — controlled by `--forms/--no-forms` CLI flag (default: disabled) and `extract_forms` API parameter (default: `false`). The config value `scraping.extract_forms` is no longer the source of truth; the CLI/API default is `false`.
> - `scraping.extract_*` flags (`extract_links`, `extract_images`, `extract_scripts`): exist in the model but are **only partially applied** by some scrapers.
>
> See the **Development Notes** section for recommended fixes and test coverage.

### Analysis

Configure security analysis settings.

```json
{
  "analysis": {
    "ssl": {
      "enabled": true,
      "check_expiry": true,
      "check_chain": true,
      "check_revocation": true,
      "warning_days": 30
    },
    "fingerprint": {
      "enabled": true,
      "check_headers": true,
      "check_cookies": true,
      "check_html": true,
      "check_scripts": true,
      "check_dns": false
    },
    "cve": {
      "enabled": true,
      "api": "all",
      "nvd_api_key": null,
      "vulners_api_key": null,
      "cache_ttl": 86400
    },
    "headers": {
      "enabled": true,
      "required_headers": [
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy"
      ]
    }
  }
}
```

### Default values (quick reference)

| Key                                 |      Default | Description                         |
| ----------------------------------- | -----------: | ----------------------------------- |
| `analysis.ssl.enabled`              |       `true` | SSL/TLS analysis enabled            |
| `analysis.ssl.warning_days`         |         `30` | Days before expiry to warn          |
| `analysis.fingerprint.enabled`      |       `true` | Technology fingerprinting enabled   |
| `analysis.fingerprint.check_dns`    |      `false` | DNS checks disabled by default      |
| `analysis.cve.api`                  |        `all` | CVE data sources used by default    |
| `analysis.cve.cache_ttl`            |      `86400` | CVE cache TTL (seconds)             |
| `analysis.headers.required_headers` | default list | Security headers checked by default |

> Implementation status — `analysis.fingerprint.deep_scan`
>
> - `analysis.fingerprint.deep_scan` is **proposed but not available** in the persistent configuration model (`FingerprintConfig`).
> - A runtime option `deep_scan` exists on `AnalyzeOptions` (see `src/ciberwebscan/services/analyze_service.py`) and can be passed via CLI, but there is no `analysis.fingerprint.deep_scan` field to persist that behavior in the config file.

### Attack

Configure attack simulation settings.

```json
{
  "attack": {
    "enabled": false,
    "user_consent": false,
    "whitelist": ["127.0.0.1", "localhost"],
    "xss": true,
    "sqli": true,
    "traversal": true,
    "enumeration": true,
    "csrf": true,
    "subdomain": true,
    "max_payloads": 50
  }
}
```

### Default values (quick reference)

| Key                   |                     Default | Description                                |
| --------------------- | --------------------------: | ------------------------------------------ |
| `attack.enabled`      |                     `false` | Attack simulation disabled by default      |
| `attack.user_consent` |                     `false` | User consent required to run attacks       |
| `attack.whitelist`    | `["127.0.0.1","localhost"]` | Default allowed targets for attack testing |
| `attack.xss`          |                      `true` | Run XSS checks by default                  |
| `attack.sqli`         |                      `true` | Run SQLi checks by default                 |
| `attack.traversal`    |                      `true` | Run path traversal checks by default       |
| `attack.enumeration`  |                      `true` | Run enumeration by default                 |
| `attack.csrf`         |                      `true` | Run CSRF checks by default                 |
| `attack.subdomain`    |                      `true` | Enumerate subdomains by default            |
| `attack.max_payloads` |                        `50` | Default max payloads per target            |

### Export

Configure export behavior.

```json
{
  "export": {
    "format": "jsonl",
    "output_dir": "exports",
    "include_raw_html": false,
    "include_screenshots": false,
    "streaming": true,
    "buffer_size": 100,
    "pretty": true
  }
}
```

### Default values (quick reference)

| Key                          |   Default | Description                                           |
| ---------------------------- | --------: | ----------------------------------------------------- |
| `export.format`              |   `jsonl` | Default export format                                 |
| `export.output_dir`          | `exports` | Default export directory                              |
| `export.include_raw_html`    |   `false` | Do not include raw HTML by default                    |
| `export.include_screenshots` |   `false` | Screenshots not included by default (not implemented) |
| `export.streaming`           |    `true` | Use streaming exporter by default                     |
| `export.buffer_size`         |     `100` | Export buffer size                                    |
| `export.pretty`              |    `true` | Pretty-print JSON by default                          |

> Implementation status — `include_screenshots`
>
> - `include_screenshots` is defined in `ExportConfig` (`src/ciberwebscan/config/models.py`) and exposed in API models, but it is **not implemented** by the export pipeline (unused by `BaseService._export_result` and exporter classes).

### Cache

Configure caching behavior.

```json
{
  "cache": {
    "enabled": true,
    "directory": ".cache",
    "ttl": 3600,
    "max_size_mb": 100
  }
}
```

### Default values (quick reference)

| Key                 |  Default | Description                |
| ------------------- | -------: | -------------------------- |
| `cache.enabled`     |   `true` | Caching enabled by default |
| `cache.directory`   | `.cache` | Default cache directory    |
| `cache.ttl`         |   `3600` | Cache TTL (seconds)        |
| `cache.max_size_mb` |    `100` | Max cache size (MB)        |

### API

Configure the FastAPI server and authentication settings.

```json
{
  "api": {
    "host": "0.0.0.0",
    "port": 8000,
    "auth": {
      "api_keys": ["your-api-key-1", "your-api-key-2"]
    },
    "rate_limit": {
      "enabled": true,
      "requests_per_minute": 60
    },
    "cors_origins": ["*"]
  }
}
```

#### Default values (quick reference)

| Key                                  |   Default | Description                               |
| ------------------------------------ | --------: | ----------------------------------------- |
| `api.host`                           | `0.0.0.0` | API server bind address                   |
| `api.port`                           |    `8000` | API server port (1-65535)                 |
| `api.auth.api_keys`                  |      `[]` | List of valid API keys for authentication |
| `api.rate_limit.enabled`             |    `true` | Rate limiting enabled by default          |
| `api.rate_limit.requests_per_minute` |      `60` | Max requests per minute (1-10000)         |
| `api.cors_origins`                   |   `["*"]` | CORS allowed origins                      |

> Note: Use specific domains in cors_origins for production environments to improve security.

### Logging

Configure logging behavior.

```json
{
  "logging": {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "file": null,
    "max_size": 10485760,
    "backup_count": 5
  }
}
```

### Default values (quick reference)

| Key                    |                                                Default | Description                           |
| ---------------------- | -----------------------------------------------------: | ------------------------------------- |
| `logging.level`        |                                                 `INFO` | Default log level                     |
| `logging.format`       | `%(asctime)s - %(name)s - %(levelname)s - %(message)s` | Default log format                    |
| `logging.file`         |                                                 `null` | No log file by default                |
| `logging.max_size`     |                                             `10485760` | Max size for rotated log file (bytes) |
| `logging.backup_count` |                                                    `5` | Number of rotated log files to keep   |

## CLI Configuration Commands

### View Current Configuration

```bash
ciberwebscan config show
```

### View Specific Section

```bash
ciberwebscan config show http
```

### Set Configuration Value

```bash
ciberwebscan config set http.timeout.connect 15.0
```

### Reset Configuration

```bash
ciberwebscan config reset
ciberwebscan config reset http
```

### Get Configuration Value

```bash
ciberwebscan config get http.timeout.connect
```

### List Configuration Keys

```bash
ciberwebscan config keys
ciberwebscan config keys --section http
```

### Export Configuration

```bash
ciberwebscan config export config.yaml  # Exports to YAML (default format)
ciberwebscan config export config.json --format json
```

### Load Configuration

```bash
ciberwebscan config load config.yaml
```

## Configuration Profiles

Profiles are pre-configured configuration files optimized for specific use cases. You can load a profile to quickly switch between different scanning configurations.

### Using Profiles

```bash
# Load a profile
ciberwebscan config load examples/profiles/bugbounty.yaml

# Run your scan
ciberwebscan scrape url https://target.com

# Switch to another profile
ciberwebscan config load examples/profiles/pentest.yaml

# Reset to default configuration
ciberwebscan config reset -y
```

### Included Profiles

| Profile          | Description                         | Use Case                                                                               |
| ---------------- | ----------------------------------- | -------------------------------------------------------------------------------------- |
| `bugbounty.yaml` | Balanced for bug bounty programs    | CVE enabled, moderate rate limit, XSS/SQLi attacks, no traversal/enumeration           |
| `pentest.yaml`   | Full-authorized penetration testing | All attacks enabled, dynamic scraping, DEBUG logging, requires explicit consent        |
| `recon.yaml`     | Passive reconnaissance only         | SSL + fingerprint + headers, no CVE, no attacks                                        |
| `stealth.yaml`   | Low-profile scanning                | Very low rate limit (0.5 req/s), static user-agent, minimal fingerprinting, no attacks |

### Profile Comparison

| Feature          | bugbounty | pentest   | recon     | stealth   |
| ---------------- | --------- | --------- | --------- | --------- |
| Rate Limit       | 2.0 req/s | 5.0 req/s | 3.0 req/s | 0.5 req/s |
| Adaptive AIMD    | Yes       | Yes       | Yes       | Yes       |
| CVE Lookup       | Yes       | Yes       | No        | No        |
| XSS/SQLi         | Yes       | Yes       | No        | No        |
| CSRF             | Yes       | Yes       | No        | No        |
| Traversal        | No        | Yes       | No        | No        |
| Enumeration      | No        | Yes       | No        | No        |
| Dynamic Scraping | No        | Yes       | No        | No        |
| DNS Fingerprint  | No        | Yes       | No        | No        |
| Log Level        | INFO      | DEBUG     | INFO      | WARNING   |

### Creating Custom Profiles

There are two ways to create your own profiles:

#### Method 1: Export and Modify

```bash
# Export current configuration
ciberwebscan config export my-profile.yaml

# Edit the file with your preferred settings
# Then load it when needed
ciberwebscan config load my-profile.yaml
```

#### Method 2: Create from Scratch

Create a YAML file with only the settings you want to override:

```yaml
# my-custom-profile.yaml
http:
  timeout:
    connect: 5.0
    read: 15.0
  rate_limit:
    requests_per_second: 1.0
    adaptive: true
    min_rate: 0.3
    decrease_factor: 0.4

analysis:
  cve:
    enabled: true
    api: nvd

attack:
  enabled: true
  xss: true
  sqli: true
  traversal: false
  enumeration: false
  csrf: true
  max_payloads: 50

logging:
  level: DEBUG
```

Then load it:

```bash
ciberwebscan config load my-custom-profile.yaml
```

### Profile Storage Recommendations

- Store profiles in a dedicated directory (e.g., `~/.ciberwebscan/profiles/` or project-specific)
- Use descriptive names that indicate the use case
- Keep profiles under version control for team environments
- Document any custom profiles with comments in the YAML file

### Persistent configuration vs CLI / runtime options

- Persistent configuration (`config.*`) is stored in the user config file (`~/.ciberwebscan/config.yaml`) and loaded by `ConfigLoader` at startup (or via `get_config()`). Environment variables with the `CIBERWEBSCAN_` prefix and the config file are merged; environment variables have higher precedence.
- CLI/runtime options (for example `AttackOptions`, `AnalyzeOptions`) are dataclasses used only for the current execution. CLI flags are converted into these option objects and **override behavior for that run** but do **not** modify the persistent configuration file.
- When an options field is omitted (or set to `None`), the service may fall back to the value from `get_config()` — see `AttackOptions.__post_init__` (`src/ciberwebscan/services/attack_service.py`) and `AnalyzeOptions` handling (`src/ciberwebscan/services/analyze_service.py`).

## Programmatic Access

You can access configuration in your code:

```python
from ciberwebscan.config.loader import get_config

config = get_config()
timeout = config.http.timeout.connect
```

## Validation

Configuration values are validated by Pydantic when loaded by the `ConfigLoader`.

- Invalid values in the user configuration file are reported as a Pydantic `ValidationError`. When this happens, `ConfigLoader` logs the validation error and falls back to the default configuration — the process continues running with defaults (the invalid file is not applied).

- CLI configuration commands surface user-friendly error messages and will exit with a non-zero status when an operation fails (for example, `ciberwebscan config load` will print the validation error and return a non-zero exit code).

Example (logged Pydantic validation error):

> ERROR ciberwebscan.config.loader: Invalid configuration: 1 validation error for AppConfig
> http -> timeout -> connect
> ensure this value is greater than or equal to 0.1 (type=value_error.number.not_ge; limit_value=0.1)

Example (CLI):

```bash
$ ciberwebscan config load bad-config.yaml
Error: Invalid configuration: 1 validation error for AppConfig
http -> timeout -> connect
  ensure this value is greater than or equal to 0.1 (type=value_error.number.not_ge; limit_value=0.1)
```

Troubleshooting tips:

- Run `ciberwebscan config show --config <path>` to inspect the file the CLI is loading.
- Set `LOG_LEVEL=DEBUG` (or check application logs) to see the full validation details and stack trace.
- The Pydantic error includes the dotted path to the offending field and a short explanation — fix that field in your `config.yaml` and retry.

## Migration

When upgrading CiberWebScan, your existing configuration will be preserved. New default values will be used for any missing settings.

## Development Notes

- [PROPOSED · NOT IMPLEMENTED] `analysis.fingerprint.deep_scan`: Runtime option `deep_scan` exists on `AnalyzeOptions` but there is **no persistent** `analysis.fingerprint.deep_scan` field in the config model. If required, add the field to `FingerprintConfig` and wire it into the fingerprinter initialization in `AnalyzeService`.
- [PARTIAL] `scraping.max_content_length`: Present in `ScrapingConfig` but **not enforced consistently** across scrapers. Suggested action: enforce/max-truncate responses in `src/ciberwebscan/core/scraping/static.py` and `src/ciberwebscan/core/scraping/dynamic.py`, add unit + integration tests and document whether responses are rejected or truncated.
- [DONE] `scraping.extract_forms`: Now fully wired through CLI (`--forms/--no-forms`, default: disabled), API (`extract_forms` field, default: `false`), and core config. Forms are only extracted when explicitly requested.
- [PARTIAL] `scraping.extract_*` (`extract_links`, `extract_images`, `extract_scripts`): Flags exist in the config model but are **only partially applied** by some scrapers; implement conditional extraction where applicable and add tests.
- [NOT IMPLEMENTED] `include_screenshots`: Defined in `ExportConfig` and API models but **not implemented** by the export pipeline (`BaseService._export_result` / exporter classes). Implement screenshot capture/storage and wire into exporters if this feature is desired.
- [PROPOSED] `cache`: `CacheConfig` exists but its practical usage (e.g., CVE caching) is limited in places; add integration points and tests where caching is expected.
