# Changelog

## [2.16.0](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.15.2...v2.16.0) (2026-09-06)


### Features

* add configurable CORS settings to APIConfig ([0494e7e](https://github.com/HC-ONLINE/CiberWebScan/commit/0494e7ea2e5d96ad8672d8562a5c03f7586c680e))
* enhance CORS configuration with customizable options ([2313848](https://github.com/HC-ONLINE/CiberWebScan/commit/2313848cd24bdd30e40771afe8a21d8cac5b39b3))
* enhance CORS configuration with detailed setup instructions and examples ([521da13](https://github.com/HC-ONLINE/CiberWebScan/commit/521da13ac7e5a00292555e6098dfa0fa73610d73))

## [2.15.2](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.15.1...v2.15.2) (2026-09-04)


### Bug Fixes

* prevent potential UnboundLocalError in _export_attack_result ([caebd97](https://github.com/HC-ONLINE/CiberWebScan/commit/caebd97f2049d9fa5ccfe131682b545a586b7230))

## [2.15.1](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.15.0...v2.15.1) (2026-09-03)


### Bug Fixes

* add http_request parameter to enrich_response_with_token in analyze, attack, and scrape endpoints ([fed166f](https://github.com/HC-ONLINE/CiberWebScan/commit/fed166f5c4a64d55fe20af706b5d21b3b82fb4bf))
* correct download URL generation to use actual registered route ([edc5a3a](https://github.com/HC-ONLINE/CiberWebScan/commit/edc5a3af4f77fe11218d7f26bfce4c97037a100b))
* remove incorrect download_url field from DownloadTokenResponse model ([91f0f5a](https://github.com/HC-ONLINE/CiberWebScan/commit/91f0f5a34916fabce2139cfb0aa9da0386ade261))
* update DownloadTokenResponse to remove download_url and clarify expiration ([a0e2a38](https://github.com/HC-ONLINE/CiberWebScan/commit/a0e2a38306fc1f5a523b1d7a95cfabdcd9c1567e))
* update enrich_response_with_token to include download_url generation ([48a8e60](https://github.com/HC-ONLINE/CiberWebScan/commit/48a8e6002774057dc2281776f64ffc84e8694cc7))

## [2.15.0](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.14.0...v2.15.0) (2026-08-31)


### Features

* add click dependency for improved CLI functionality ([b2b745d](https://github.com/HC-ONLINE/CiberWebScan/commit/b2b745d331b0c7cef9bd773466bce6753204843a))
* add PowerShell support for shell completion ([4c97cb8](https://github.com/HC-ONLINE/CiberWebScan/commit/4c97cb8ddcec0fe35b0917f2a8bfca5a4bb6ec99))
* update documentation to include PowerShell support for shell completion ([ef29f29](https://github.com/HC-ONLINE/CiberWebScan/commit/ef29f29d105dc6393d268b186a1321f638d2ba23))


### Bug Fixes

* add validation for supported shells in completion script generation ([1a3fad7](https://github.com/HC-ONLINE/CiberWebScan/commit/1a3fad7a4bc4613acf1f4214c0bb360d72f8f263))

## [2.14.0](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.13.3...v2.14.0) (2026-08-31)


### Features

* add async runner utility for bridging sync and async contexts ([aa25bb3](https://github.com/HC-ONLINE/CiberWebScan/commit/aa25bb30373fbae83a0b0fd6e64aec91289fbe48))


### Bug Fixes

* replace direct asyncio calls with run_async utility in ScrapeService ([10104ec](https://github.com/HC-ONLINE/CiberWebScan/commit/10104ec6e459d12ed2a096251578c729a808fb4a))

## [2.13.3](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.13.2...v2.13.3) (2026-08-14)


### Bug Fixes

* change attack_target to synchronous and add app config usage ([2dc041b](https://github.com/HC-ONLINE/CiberWebScan/commit/2dc041bd1911e99ecd5fcbc9bff5675c02fe6dae))

## [2.13.2](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.13.1...v2.13.2) (2026-08-11)


### Bug Fixes

* resolve env var overrides against the config schema ([20c1660](https://github.com/HC-ONLINE/CiberWebScan/commit/20c16606bc4db37f58252de2b3677b3d223b79da))
* unwrap PEP 604 unions and reject whole-section env keys ([9d9856f](https://github.com/HC-ONLINE/CiberWebScan/commit/9d9856ff70fe78a171eb1ce7d865e800be233803))


### Documentation

* document env var mapping, unmappable vars and validation errors ([90959a0](https://github.com/HC-ONLINE/CiberWebScan/commit/90959a0e9a7e0200731cdc51db1e0f09105fcd29))

## [2.13.1](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.13.0...v2.13.1) (2026-08-11)


### Bug Fixes

* add cookies support to ScrapeService and AnalyzeService ([4a489ef](https://github.com/HC-ONLINE/CiberWebScan/commit/4a489ef10b6507b647b8269c1f66bd6c6eaaa93d))

## [2.13.0](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.12.0...v2.13.0) (2026-08-11)


### Features

* add command injection option to CLI and API attack commands ([0c8c407](https://github.com/HC-ONLINE/CiberWebScan/commit/0c8c407eab7181ec2842b307ead4c82b97df4b0c))
* add command injection payloads to attack models ([8d33942](https://github.com/HC-ONLINE/CiberWebScan/commit/8d33942547a9de5699fa8acb3b84375720b689d7))
* add command injection support to attack models and reports ([b09e19f](https://github.com/HC-ONLINE/CiberWebScan/commit/b09e19f85d97dfc33db847172addc301c9d73141))
* add command injection support to attack options and execution ([650a6e9](https://github.com/HC-ONLINE/CiberWebScan/commit/650a6e92e28124230d18c71f545b22afabc7cf9e))
* implement OS command injection detection and testing framework ([35e07e1](https://github.com/HC-ONLINE/CiberWebScan/commit/35e07e1986b2100a681215aaeb93662ee3384c19))


### Bug Fixes

* enhance command injection testing by preserving query parameters and building form data ([a766e27](https://github.com/HC-ONLINE/CiberWebScan/commit/a766e27a596ab4f34a85b833c273aac3f7f9c61a))
* enhance SQLi detection by adding MySQL error patterns and preserving query parameters ([b2c9566](https://github.com/HC-ONLINE/CiberWebScan/commit/b2c95668dff7dbcfc44bb8df0c0743b81fed7939))
* ensure URL-parameter requests carry original static params with one mutated parameter ([380e6e2](https://github.com/HC-ONLINE/CiberWebScan/commit/380e6e26981ec2ab6f8cac7727d7159319da2ae2))
* remove unnecessary default value for params in HTTP requests ([d6fdee6](https://github.com/HC-ONLINE/CiberWebScan/commit/d6fdee628f17303f8781d9eb6b0053413f969d90))


### Documentation

* docs: update documentation with OS command injection detection details ([c1bcafd](https://github.com/HC-ONLINE/CiberWebScan/commit/c1bcafd12fbdde6b85b602ec6f32e0d11a07d680))

## [2.12.0](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.11.2...v2.12.0) (2026-08-05)


### Features

* **tests:** add auth headers to analyze, attack, and scrape endpoint tests ([ad346e7](https://github.com/HC-ONLINE/CiberWebScan/commit/ad346e71f72fb59179670549c950f727b6e44059))
* **tests:** add integration tests for analyze, attack, export, and scrape endpoints ([05e4a76](https://github.com/HC-ONLINE/CiberWebScan/commit/05e4a765696e523b493dad8ed1215da77d401dcf))
* **tests:** add integration tests for API health and robustness ([9a02607](https://github.com/HC-ONLINE/CiberWebScan/commit/9a026073236ae9a0aa58886c57c20d0cd7ae342e))
* **tests:** add integration tests for auth and config endpoints, remove download endpoint tests ([14903a5](https://github.com/HC-ONLINE/CiberWebScan/commit/14903a50d8afbce58de1c8e99dafbc45f6434de9))

## [2.11.2](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.11.1...v2.11.2) (2026-08-04)


### Bug Fixes

* export missing api and quick commands from cli/commands/__init__.py ([edd6036](https://github.com/HC-ONLINE/CiberWebScan/commit/edd60367014059924946887d90b6ab945f931432))
* export missing api and quick commands from cli/commands/__init__.py ([6884590](https://github.com/HC-ONLINE/CiberWebScan/commit/6884590003134c35631e540fac74c5cd31be4298))

## [2.11.1](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.11.0...v2.11.1) (2026-08-04)


### Bug Fixes

* add missing rom __future__ import annotations to all __init__.p… ([298c347](https://github.com/HC-ONLINE/CiberWebScan/commit/298c347d0db9ca549f465610953af93f4fb2f3de))
* add missing rom __future__ import annotations to all __init__.py, http_client.py, and conftest files ([209890a](https://github.com/HC-ONLINE/CiberWebScan/commit/209890ace878fa593caaa51f213ca8a776f2d0fa))

## [2.11.0](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.10.0...v2.11.0) (2026-08-04)


### Features

* **forms:** enhance form extraction with additional attributes and n… ([0a2e830](https://github.com/HC-ONLINE/CiberWebScan/commit/0a2e83087904c6c371fa87a5454fd032bc31736e))
* **forms:** enhance form extraction with additional attributes and normalization ([4ceb660](https://github.com/HC-ONLINE/CiberWebScan/commit/4ceb660c9a1ba4f1538e5d328b27646d33bc3397))

## [2.10.0](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.9.0...v2.10.0) (2026-08-04)


### Features

* **scraping:** add option to extract HTML forms and their fields ([3f595f9](https://github.com/HC-ONLINE/CiberWebScan/commit/3f595f96b8cce29e579d725b4f038b524f7b3bc3))
* **scraping:** add option to extract HTML forms and their fields ([2ca65b3](https://github.com/HC-ONLINE/CiberWebScan/commit/2ca65b367a3b4f60771e0c4d351896538349572c))

## [2.9.0](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.8.0...v2.9.0) (2026-08-04)


### Features

* **analyzer:** add CDN/PaaS detection to HTML content analysis ([0b6215a](https://github.com/HC-ONLINE/CiberWebScan/commit/0b6215a01194c65b67f7806770004b324a957f7d))
* **analyzer:** add CDN/PaaS signatures handling in technology fingerprinting ([b03d376](https://github.com/HC-ONLINE/CiberWebScan/commit/b03d376d3d9b4fb7cf4eb00022f0f4945b356040))
* **analyzer:** detect backend languages from HTTP headers ([87faa1d](https://github.com/HC-ONLINE/CiberWebScan/commit/87faa1d545cc13340a4be90a5127717874e9464a))
* **analyzer:** load CDN/PaaS signatures from technology signatures file ([215fe8c](https://github.com/HC-ONLINE/CiberWebScan/commit/215fe8c598f443c640bbfea6387c8130dd0c2abe))

## [2.8.0](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.7.5...v2.8.0) (2026-08-04)


### Features

* add subdomain enumeration support to attack service and quick service ([f074a71](https://github.com/HC-ONLINE/CiberWebScan/commit/f074a71b80d9913fa34e00aca9017faf1423db48))
* add subdomain enumeration support to configuration, CLI, API, and documentation ([60c1972](https://github.com/HC-ONLINE/CiberWebScan/commit/60c1972c234402ffe63e1b200de2553a8c47abe9))
* add subdomain findings to CSV and HTML export reports ([c6def40](https://github.com/HC-ONLINE/CiberWebScan/commit/c6def4016f5f9d7243a25e3e7c6b94975f1d3832))
* add subdomain option to attack command and API endpoint ([311bc4f](https://github.com/HC-ONLINE/CiberWebScan/commit/311bc4fd01fc89c97d9b518b710c263a53927326))
* add subdomain options to AttackRequest and AttackConfig models ([9f4d9bd](https://github.com/HC-ONLINE/CiberWebScan/commit/9f4d9bdbe076050faf33a7c212d20325abb7b220))
* add subdomain payloads for enumeration tests ([2b2dc89](https://github.com/HC-ONLINE/CiberWebScan/commit/2b2dc8920f05c63baa743ae15d9a7e0b7f10b35d))
* add subdomain payloads to attack configurations ([5fdf9db](https://github.com/HC-ONLINE/CiberWebScan/commit/5fdf9dbf4c64aeae4455f0085f0b7134681e2acb))
* implement subdomain enumeration engine with DNS brute force ([d7b3d62](https://github.com/HC-ONLINE/CiberWebScan/commit/d7b3d62354c20899f8026b9d9c24fe35540e4945))


### Bug Fixes

* validate at least one attack type is specified before applying config defaults ([913696e](https://github.com/HC-ONLINE/CiberWebScan/commit/913696ebad59fe6299b892e71d502569d5668eb5))

## [2.7.5](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.7.4...v2.7.5) (2026-07-31)


### Bug Fixes

* improve CDN URL normalization and version extraction ([3ad02bb](https://github.com/HC-ONLINE/CiberWebScan/commit/3ad02bb8ec4dd1f583e7e9ca6246f4aeb47d0a19))
* improve CDN URL normalization and version extraction ([7d02e0d](https://github.com/HC-ONLINE/CiberWebScan/commit/7d02e0d51ab264431e73e576797dde1cd3a46e0c))

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
