# Changelog

## [2.5.0](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.4.1...v2.5.0) (2026-07-27)


### Features

* add adaptive AIMD rate control parameters to RateLimitConfig ([9b1fdc0](https://github.com/HC-ONLINE/CiberWebScan/commit/9b1fdc0e6588d629e7ce4d843354252caed90f18))
* add adaptive AIMD rate limiting configuration to profiles and documentation ([bcea793](https://github.com/HC-ONLINE/CiberWebScan/commit/bcea79370611f80f6283f0542d0bf6da9cd03824))
* add unit tests for adaptive rate limiting in RateLimiter class ([f61b6f5](https://github.com/HC-ONLINE/CiberWebScan/commit/f61b6f59efa7a0cd7c616f61f0bcd500158f8838))
* allow backoff_factor to be zero in RetryConfig and update related tests ([e597330](https://github.com/HC-ONLINE/CiberWebScan/commit/e597330ade57b025dfa922e2e41d977b3de071e1))
* implement AIMD adaptive rate limiting in RateLimiter class ([4874828](https://github.com/HC-ONLINE/CiberWebScan/commit/4874828520e704607947f284039319d57ba51697))


### Bug Fixes

* enforce minimum backoff factor of 0.1 in HTTPClient ([2dde9e0](https://github.com/HC-ONLINE/CiberWebScan/commit/2dde9e07e98ac6e0e8095cf2a1a6a7ef00f934cf))

## [2.4.1](https://github.com/HC-ONLINE/CiberWebScan/compare/v2.4.0...v2.4.1) (2026-07-26)


### Bug Fixes

* update CLI completion tests to use Typer's CliRunner ([6ffa074](https://github.com/HC-ONLINE/CiberWebScan/commit/6ffa074ce71499fae1e910aece0772913338e293))
* update CLI completion tests to use Typer's CliRunner ([8afebab](https://github.com/HC-ONLINE/CiberWebScan/commit/8afebab5e2adf97a00424ed2104dc29f7854ab8a))
