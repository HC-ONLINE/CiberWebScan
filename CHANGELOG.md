# Changelog

## [2.7.4](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.7.3...v2.7.4) (2026-07-31)


### Bug Fixes

* use detected version for CVE lookup filtering ([81505b8](https://github.com/HC-ONLINE/CiberWebScan/commit/81505b826c6d4b69fcbbbedd71ea24cfd4e5cdfd))
* use detected version for CVE lookup filtering ([1b6756f](https://github.com/HC-ONLINE/CiberWebScan/commit/1b6756fbc23b7042dc4d5f960ad786b849c46ed2))

## [2.7.3](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.7.2...v2.7.3) (2026-07-30)


### Bug Fixes

* add network options to scrape command and service ([0a0ea27](https://github.com/HC-ONLINE/CiberWebScan/commit/0a0ea27eee0411ded8319c0a714d4f5d0031225d))

## [2.7.2](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.7.1...v2.7.2) (2026-07-29)


### Bug Fixes

* exclude integration tests from pytest run in CI workflow ([703c1c0](https://github.com/HC-ONLINE/CiberWebScan/commit/703c1c0ace2dd993ac63209948fcbd8b16e890aa))

## [2.7.1](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.7.0...v2.7.1) (2026-07-29)


### Bug Fixes

* enhance mock result in dynamic scraping tests to include title, links, images, forms, and scripts ([9f0deec](https://github.com/HC-ONLINE/CiberWebScan/commit/9f0deec02574887be2461300a3822409e8d04e05))

## [2.7.0](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.6.3...v2.7.0) (2026-07-29)


### Features

* add form and script extraction functions to the scraper ([b0f0632](https://github.com/HC-ONLINE/CiberWebScan/commit/b0f0632e2e190021c1b5e18d769b9c4682162825))


### Bug Fixes

* add extraction of metadata, links, images, forms, and scripts in dynamic and static scrapers ([8a27596](https://github.com/HC-ONLINE/CiberWebScan/commit/8a27596bb4e6f0c015aefcaa55fa50fadbf7fa2d))
* enhance ScrapeResult to include detailed extraction of links, images, forms, and scripts ([1d217a8](https://github.com/HC-ONLINE/CiberWebScan/commit/1d217a831abbf239b24ed9ba3281d8fc1ac6274f))
* update changelog link in README ([2de61c0](https://github.com/HC-ONLINE/CiberWebScan/commit/2de61c07f671670a342fe88d8ec20a149843dc4c))

## [2.6.3](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.6.2...v2.6.3) (2026-07-29)


### Bug Fixes

* add missing attack fields to CSV and HTML exports ([85125e3](https://github.com/HC-ONLINE/CiberWebScan/commit/85125e3c515d5cca1bf1a6625e6789caa2486989))
* add missing attack fields to CSV and HTML exports ([47c9ef8](https://github.com/HC-ONLINE/CiberWebScan/commit/47c9ef8ba95b58ba385a457ee8293be64ae53367))

## [2.6.2](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.6.1...v2.6.2) (2026-07-29)


### Bug Fixes

* update severity indicators in attack results for better clarity ([80d2fd9](https://github.com/HC-ONLINE/CiberWebScan/commit/80d2fd9e4965cf4e27a104adaac8b9f02fe76e26))
* update severity indicators in attack results for better clarity ([ac53c70](https://github.com/HC-ONLINE/CiberWebScan/commit/ac53c70cd3806fc2b8b08ea4907e91c7c0eddc59))

## [2.6.1](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.6.0...v2.6.1) (2026-07-29)


### Bug Fixes

* ensure URL compatibility with urlparse in attack modules and tests ([5ce7fd2](https://github.com/HC-ONLINE/CiberWebScan/commit/5ce7fd219505643b0d9a569351c9a8f2f925d5b5))
* ensure URL compatibility with urlparse in attack modules and tests ([2f18447](https://github.com/HC-ONLINE/CiberWebScan/commit/2f18447532d085b8e1aa533685264e1ecbafecf5))

## [2.6.0](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.5.0...v2.6.0) (2026-07-28)


### Features

* add CSRF attack payloads for low, medium, and high severity levels ([982c55d](https://github.com/HC-ONLINE/CiberWebScan/commit/982c55dbf6005371bc083a09555c5b40cd5b4766))
* add CSRF detection configuration and model support ([1d949ca](https://github.com/HC-ONLINE/CiberWebScan/commit/1d949cac57e66bd3aaa87487606e41f8ac83be84))
* add CSRF detection module to core attack simulation ([aa479fb](https://github.com/HC-ONLINE/CiberWebScan/commit/aa479fbfa9d6c7b8fb9be02a6ef2b589a88081b6))
* add CSRF detection support to API, CLI, and configuration files ([ffaff77](https://github.com/HC-ONLINE/CiberWebScan/commit/ffaff77941a224833c34c9a6c613a43a93a851b6))
* add CSRF option to attack command and update attack target logic ([d19b8b5](https://github.com/HC-ONLINE/CiberWebScan/commit/d19b8b583db51ed0547321ae6cb37bc6892203d5))
* add tokenless CSRF detection support to attack service ([bf7a569](https://github.com/HC-ONLINE/CiberWebScan/commit/bf7a569ddb254736dc58962e68222a369590f169))
* disable CSRF attack option in CLI command environment variables ([1d46e4b](https://github.com/HC-ONLINE/CiberWebScan/commit/1d46e4b25ac97b04a40e172d587fc291e44ca5e1))
* implement CSRF vulnerability detection and testing framework ([303c9b7](https://github.com/HC-ONLINE/CiberWebScan/commit/303c9b7dd14988605ccea46ea83e8da3c4ca2f52))

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
