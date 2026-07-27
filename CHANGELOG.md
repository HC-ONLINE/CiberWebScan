# Changelog

## [2.5.0](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.4.1...v2.5.0) (2026-07-27)

### Features

- add adaptive AIMD rate control parameters to RateLimitConfig ([9b1fdc0](https://github.com/HC-ONLINE/CiberWebScan/commit/9b1fdc0e6588d629e7ce4d843354252caed90f18))
- add adaptive AIMD rate limiting configuration to profiles and documentation ([bcea793](https://github.com/HC-ONLINE/CiberWebScan/commit/bcea79370611f80f6283f0542d0bf6da9cd03824))
- add unit tests for adaptive rate limiting in RateLimiter class ([f61b6f5](https://github.com/HC-ONLINE/CiberWebScan/commit/f61b6f59efa7a0cd7c616f61f0bcd500158f8838))
- allow backoff_factor to be zero in RetryConfig and update related tests ([e597330](https://github.com/HC-ONLINE/CiberWebScan/commit/e597330ade57b025dfa922e2e41d977b3de071e1))
- implement AIMD adaptive rate limiting in RateLimiter class ([4874828](https://github.com/HC-ONLINE/CiberWebScan/commit/4874828520e704607947f284039319d57ba51697))

### Bug Fixes

- enforce minimum backoff factor of 0.1 in HTTPClient ([2dde9e0](https://github.com/HC-ONLINE/CiberWebScan/commit/2dde9e07e98ac6e0e8095cf2a1a6a7ef00f934cf))

## [2.4.1](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.4.0...v2.4.1) (2026-07-26)

### features

- Shell completion command (`ciberwebscan completion`) for bash, zsh, and fish
  - `completion install` - Install completion scripts with auto-detected or explicit shell
  - `completion show` - Display generated completion script for manual inspection
  - `completion uninstall` - Remove installed completion scripts
- Uses Click's internal `shell_completion` module for dynamic script generation (stays synced with Click/Typer updates)
- Portable `~` paths in post-install instructions for dotfiles compatibility
- 31 unit tests for completion module

### Bug Fixes

- update CLI completion tests to use Typer's CliRunner ([6ffa074](https://github.com/HC-ONLINE/CiberWebScan/commit/6ffa074ce71499fae1e910aece0772913338e293))
- update CLI completion tests to use Typer's CliRunner ([8afebab](https://github.com/HC-ONLINE/CiberWebScan/commit/8afebab5e2adf97a00424ed2104dc29f7854ab8a))

## 2.4.0 - 2026-07-25

### Added

- Configuration profiles system with pre-configured YAML files for different use cases
- 4 built-in profiles in `examples/profiles/`:
  - `bugbounty.yaml` - Optimized for bug bounty programs (CVE enabled, moderate rate limit, XSS/SQLi attacks)
  - `pentest.yaml` - Full penetration testing configuration (all attacks, dynamic scraping, DEBUG logging)
  - `recon.yaml` - Passive reconnaissance only (SSL + fingerprint + headers, no CVE or attacks)
  - `stealth.yaml` - Low-profile scanning (0.5 req/s, static user-agent, minimal fingerprinting)
- Documentation for configuration profiles in `CONFIGURATION.md`
- Guide for creating custom profiles

## 2.3.0 - 2026-07-25

### Added

- HTML export format for visual security reports with embedded CSS (dark theme)
- `HTMLExporter` class with professional report layout:
  - Risk score cards with color-coded severity
  - SSL/TLS analysis section with grade badge
  - Technology fingerprint grid
  - Security headers table with score
  - CVE findings table with CVSS scores
  - Attack simulation results with evidence and remediation
  - Scraping results (links, forms, scripts)
- CLI support: `--format html` on all export-capable commands
- API support: `export_format: "html"` on analyze, scrape, attack, and quick endpoints
- Auto-detection of `.html` extension in export path
- `export_to_html()` convenience function
- 49 unit tests for HTML exporter

## 2.2.0 - 2026-07-23

### Added

- Quick scan service (`QuickService`) for combined analysis + attacks + scraping
- Preset-based scanning with three levels:
  - `low` - SSL, fingerprint, headers (no attacks, no CVEs)
  - `medium` - Analysis + moderate attacks (XSS, SQLi) - requires consent
  - `high` - Full analysis + all attacks + CVEs - requires consent
- CLI command `ciberwebscan quick scan <URL>` with preset support
- API endpoint `POST /api/quick/scan` for combined scans via REST
- API endpoint `GET /api/quick/presets` to list available presets
- Scraping integration in quick scan via `--selector` / `--dynamic` options

## 2.1.0 - 2026-04-29

### Added

- Complete REST API implementation with FastAPI framework (now in Beta)
- Authentication module with API key-based security and management endpoints
- Full API endpoint suite:
  - `/api/analyze` - Security analysis with detailed options
  - `/api/attack` - URL attack testing with configurable payloads
  - `/api/scrape` - Single and batch URL scraping endpoints
  - `/api/download` - Token-based file download system with automatic cleanup
  - `/api/config` - Configuration management endpoints
  - `/health` and `/health/ready` - Health check endpoints
- Request logging and rate limiting middleware
- Download token generation and validation system with configurable expiration
- Enhanced request/response models with export options and validation
- DownloadCleanupScheduler for managing expired download tokens
- Comprehensive API endpoint unit tests and integration tests
- API command in CLI for server management
- Enhanced documentation with API usage guides and beta status indicators
- FastAPI and python-multipart dependencies for API functionality
- Improved CI/CD workflow for full test coverage with both dev and api dependencies

### Changed

- Updated APIResponse model with download token and URL fields
- Improved error handling across API endpoints
- Enhanced request models with new validation fields
- Updated health check endpoints to use HealthCheckResponse model
- Refactored configuration system to support API settings
- Optimized pre-commit configuration to include FastAPI checks

### Fixed

- Fixed timestamp field to use timezone-aware datetime in API responses
- Improved async/sync context handling in services
- Better input validation across API endpoints

### Known Issues

- REST API is in Beta - expect potential breaking changes
- Some advanced API features may still be under development
- Download tokens are stored in memory (production should use persistent storage)

## 2.0.0 - 2026-02-12

### Added

- Complete refactor of the codebase for improved architecture
- Enhanced CLI with comprehensive commands for analysis, scraping, and attacks
- Core security analysis modules (SSL, fingerprinting, headers, CVE lookup)
- Web scraping capabilities (static and dynamic)
- Ethical penetration testing framework (XSS, SQLi, path traversal, enumeration)
- Flexible export system (JSON, CSV, JSONL)
- Centralized configuration management
- REST API foundation (health endpoints, analysis, scraping) in development
- Comprehensive test suite
- Professional documentation structure

### Changed

- Major version bump from 0.5 to 2.0.0 due to complete rewrite
- Improved error handling and logging
- Enhanced user experience with better CLI output
- Updated dependencies to latest versions

### Fixed

- Resolved numerous issues from previous version
- Improved stability and performance
- Better input validation and security

### Known Issues

- REST API is in development and not publicly available
- Some advanced features are still under development
- Beta status: expect some instability

## 0.5.0 - 2025-09-20 previus version

Initial release with basic functionality. This version had significant issues that led to the complete rewrite in v2.0.0.
