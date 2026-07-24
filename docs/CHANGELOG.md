# Changelog

All notable changes to CiberWebScan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
