# API Documentation

Complete REST API reference for CiberWebScan (Beta).

## Quick Start

### Starting the API

```bash
ciberwebscan api
# Server runs on http://localhost:8000
# API docs: http://localhost:8000/docs
# ReDoc docs: http://localhost:8000/redoc
```

### Authentication

The API requires an API key via the `X-API-Key` header:

```bash
curl -X POST "http://localhost:8000/api/analyze" \
  -H "X-API-Key: your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Response Format

All responses follow a consistent structure:

```json
{
  "success": true,
  "data": { ... },
  "error": null,
  "timestamp": "2026-01-01T00:00:00Z",
  "download_token": "token-uuid",
  "download_url": "/api/download/token-uuid"
}
```

## Endpoints

### Health & Status

#### GET /health

Basic health check endpoint (no authentication required).

**Response:**

```json
{
  "status": "healthy",
  "version": "2.4.0",
  "message": "CiberWebScan API is running",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

#### GET /health/ready

Readiness check for container orchestration (no authentication required).

**Response:**

```json
{
  "status": "ready",
  "version": "2.4.0",
  "message": "CiberWebScan API is ready to accept requests",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

### Security Analysis

#### POST /api/analyze

Perform comprehensive security analysis on a URL.

**Includes:**

- SSL/TLS certificate analysis
- Technology fingerprinting
- Security headers evaluation
- CVE lookup and vulnerability intelligence

**Request:**

```json
{
  "url": "https://example.com",
  "ssl": true,
  "fingerprint": true,
  "analyze_headers": true,
  "cve": true,
  "ssl_verify": true,
  "timeout": 30.0,
  "ssl_timeout": 10.0,
  "deep_scan": false,
  "cve_sources": ["nvd"],
  "cve_limit": 100,
  "cve_severity": null,
  "headers": {},
  "cookies": {}
}
```

**Parameters:**

| Parameter         | Type    | Default  | Description                                           |
| ----------------- | ------- | -------- | ----------------------------------------------------- |
| `url`             | string  | required | Target URL                                            |
| `ssl`             | boolean | true     | Perform SSL/TLS analysis                              |
| `fingerprint`     | boolean | true     | Detect technologies                                   |
| `analyze_headers` | boolean | true     | Analyze security headers                              |
| `cve`             | boolean | true     | Lookup CVEs                                           |
| `ssl_verify`      | boolean | true     | Verify SSL certificates                               |
| `timeout`         | float   | 30.0     | Request timeout (1.0-300.0)                           |
| `ssl_timeout`     | float   | 10.0     | SSL analysis timeout (1.0-120.0)                      |
| `deep_scan`       | boolean | false    | Deeper fingerprinting                                 |
| `cve_sources`     | array   | []       | CVE sources: nvd, vulners, circl                      |
| `cve_limit`       | integer | 100      | Max CVEs to retrieve (1-1000)                         |
| `cve_severity`    | string  | null     | Filter by severity: critical, high, medium, low, info |
| `headers`         | object  | {}       | Custom HTTP headers                                   |
| `cookies`         | object  | {}       | Cookies                                               |
| `proxy`           | string  | null     | HTTP proxy URL                                        |
| `user_agent`      | string  | null     | Custom User-Agent                                     |
| `check_robots`    | boolean | false    | Respect robots.txt                                    |
| `enrich_exploits` | boolean | false    | Enrich CVEs with exploit info                         |
| `export`          | string  | null     | Export file path                                      |
| `export_format`   | string  | json     | json, jsonl, csv, or html                             |

**Response:**

```json
{
  "success": true,
  "data": {
    "url": "https://example.com",
    "timestamp": "2026-01-01T00:00:00Z",
    "ssl_analysis": {
      "protocol_version": "TLSv1.3",
      "certificate": {
        "subject": "CN=example.com",
        "issuer": "...",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-01-01T00:00:00Z"
      },
      "ciphers": [...],
      "vulnerabilities": []
    },
    "fingerprint": {
      "technologies": [
        {
          "name": "nginx",
          "version": "1.24.0",
          "category": "Web Servers"
        }
      ]
    },
    "headers_analysis": {
      "headers": {...},
      "security_issues": [...]
    },
    "cve_results": [
      {
        "id": "CVE-2026-1234",
        "severity": "HIGH",
        "description": "...",
        "cvss_score": 7.5
      }
    ]
  },
  "download_token": "uuid-token",
  "download_url": "/api/download/uuid-token",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

### Scraping

#### POST /api/scrape

Scrape a single URL with flexible extraction options.

**Supports:**

- Static scraping (BeautifulSoup)
- Dynamic scraping (Playwright for JavaScript-rendered content)
- CSS selector extraction
- Structured data extraction with schemas
- Pagination

**Request:**

```json
{
  "url": "https://example.com",
  "dynamic": false,
  "wait_for": null,
  "selector": ".product",
  "attributes": ["id", "title", "price"],
  "extraction_schema": null,
  "timeout": 30.0,
  "headers": {},
  "cookies": {}
}
```

**Parameters:**

| Parameter             | Type    | Default  | Description                                 |
| --------------------- | ------- | -------- | ------------------------------------------- |
| `url`                 | string  | required | Target URL                                  |
| `dynamic`             | boolean | false    | Use Playwright for JS rendering             |
| `wait_for`            | string  | null     | CSS selector to wait for (dynamic mode)     |
| `selector`            | string  | null     | CSS selector for focused extraction         |
| `attributes`          | array   | []       | Attributes to extract from matched elements |
| `extraction_schema`   | object  | null     | Structured extraction schema                |
| `pagination_selector` | string  | null     | Selector for pagination links               |
| `pagination_limit`    | integer | 1        | Max pages to traverse (1-1000)              |
| `timeout`             | float   | 30.0     | Request timeout in seconds (1.0-120.0)      |
| `headers`             | object  | {}       | Custom HTTP headers                         |
| `cookies`             | object  | {}       | Cookies to include                          |
| `proxy`               | string  | null     | HTTP/HTTPS proxy URL                        |
| `user_agent`          | string  | null     | Custom User-Agent                           |
| `check_robots`        | boolean | true     | Respect robots.txt                          |
| `extract_forms`       | boolean | false    | Extract HTML forms and their fields         |
| `export`              | string  | null     | Export file path                            |
| `export_format`       | string  | json     | json, jsonl, csv, or html                   |

**Response:**

```json
{
  "success": true,
  "data": {
    "url": "https://example.com",
    "timestamp": "2026-01-01T00:00:00Z",
    "title": "Page Title",
    "links": [...],
    "images": [...],
    "forms": [...],
    "scripts": [...],
    "extracted_data": [...]
  },
  "download_token": "uuid-token",
  "download_url": "/api/download/uuid-token",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

#### POST /api/scrape/batch

Scrape multiple URLs in batch.

**Request:**

```json
{
  "urls": ["https://example.com/page1", "https://example.com/page2"],
  "dynamic": false,
  "selector": ".item",
  "timeout": 30.0,
  "headers": {},
  "cookies": {}
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "job_id": "uuid-string",
    "results": [
      {
        "url": "https://example.com/page1",
        "success": true,
        "extracted_data": [...]
      }
    ],
    "failed_urls": [
      {
        "url": "https://example.com/page3",
        "error": "Timeout"
      }
    ],
    "total_success": 2,
    "total_failed": 1
  },
  "timestamp": "2026-01-01T00:00:00Z"
}
```

### Attack Simulation

#### POST /api/attack

Perform controlled security attack simulations.

**IMPORTANT**: Only test systems you own or have explicit written authorization to test. Unauthorized security testing is illegal.

**Supports:**

- XSS (Cross-Site Scripting) detection
- SQL Injection testing
- Path Traversal vulnerability testing
- Directory Enumeration
- CSRF (Cross-Site Request Forgery) detection
- Subdomain enumeration (DNS brute force)
- Custom payloads and wordlists

**Request:**

```json
{
  "url": "https://testsite.example.com",
  "xss": true,
  "sqli": true,
  "traversal": true,
  "enumeration": true,
  "csrf": true,
  "subdomain": true,
  "all_attacks": false,
  "intensity": "medium",
  "max_payloads": 50,
  "timeout": 10.0,
  "delay_between_requests": 0.1,
  "concurrent_requests": 1,
  "skip_dangerous_payloads": true,
  "user_consent": true
}
```

**Parameters:**

| Parameter                 | Type        | Default      | Description                      |
| ------------------------- | ----------- | ------------ | -------------------------------- |
| `url`                     | string      | required     | Target URL                       |
| `xss`                     | boolean     | null         | Test XSS vulnerabilities         |
| `sqli`                    | boolean     | null         | Test SQL injection               |
| `traversal`               | boolean     | null         | Test path traversal              |
| `enumeration`             | boolean     | null         | Directory enumeration            |
| `csrf`                    | boolean     | null         | Test CSRF vulnerabilities        |
| `subdomain`               | boolean     | null         | Enumerate active subdomains      |
| `all_attacks`             | boolean     | false        | Enable all attack types          |
| `intensity`               | string      | medium       | low, medium, or high             |
| `max_payloads`            | integer     | null         | Max payloads per attack (1-1000) |
| `custom_payloads_file`    | string      | null         | Path to custom payloads          |
| `custom_wordlist`         | string      | null         | Custom wordlist for enumeration  |
| `timeout`                 | float       | 10.0         | Request timeout (1.0-300.0)      |
| `delay_between_requests`  | float       | 0.1          | Delay between requests (seconds) |
| `concurrent_requests`     | integer     | 1            | Concurrent requests (1-10)       |
| `skip_dangerous_payloads` | boolean     | true         | Skip dangerous payloads          |
| `scope_urls`              | array       | []           | URLs to scope attack to          |
| `export`                  | string      | null         | Export file path                 |
| `export_format`           | string      | json         | json, jsonl, csv, or html        |
| `headers`                 | object      | {}           | Custom HTTP headers              |
| `cookies`                 | object      | {}           | Cookies                          |
| `proxy`                   | string      | null         | HTTP proxy URL                   |
| `user_agent`              | string      | null         | Custom User-Agent                |
| `verbose`                 | boolean     | false        | Verbose output                   |
| **`user_consent`**        | **boolean** | **required** | **Must be true to proceed**      |

**Response:**

```json
{
  "success": true,
  "data": {
    "url": "https://testsite.example.com",
    "timestamp": "2026-01-01T00:00:00Z",
    "attack_results": {
      "xss": {
        "vulnerabilities_found": 2,
        "payloads_tested": 50,
        "results": [
          {
            "type": "XSS",
            "parameter": "search",
            "payload": "<script>alert(1)</script>",
            "status": "vulnerable",
            "severity": "HIGH"
          }
        ]
      },
      "sqli": {
        "vulnerabilities_found": 0,
        "payloads_tested": 50,
        "results": []
      },
      "traversal": {
        "vulnerabilities_found": 1,
        "payloads_tested": 30,
        "results": [...]
      },
      "enumeration": {
        "paths_found": 15,
        "common_paths_tested": 1000,
        "results": [...]
      }
    },
    "total_vulnerabilities": 3,
    "risk_score": 72
  },
  "download_token": "uuid-token",
  "download_url": "/api/download/uuid-token",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

**Error Response (Missing Consent):**

```json
{
  "success": false,
  "error": "Attack simulation requires user_consent=true. Only test systems you own or have explicit permission to test.",
  "error_code": "VALIDATION_ERROR",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

### Quick Scan

#### POST /api/quick/scan

Perform a combined scan using presets: analysis + attacks + scraping in a single request.

**Presets:**

| Preset   | Analysis                     | Attacks                      | Consent Required |
| -------- | ---------------------------- | ---------------------------- | ---------------- |
| `low`    | SSL, fingerprint, headers    | None                         | No               |
| `medium` | + CVE lookup                 | XSS, SQLi (medium intensity) | Yes              |
| `high`   | + exploit enrichment, deeper | All types (high intensity)   | Yes              |

**Request:**

```json
{
  "url": "https://example.com",
  "preset": "low",
  "user_consent": false,
  "timeout": 30.0,
  "selector": null,
  "dynamic": false,
  "headers": {},
  "cookies": {},
  "proxy": null,
  "user_agent": null,
  "output_format": "json"
}
```

**Parameters:**

| Parameter       | Type    | Default  | Description                                           |
| --------------- | ------- | -------- | ----------------------------------------------------- |
| `url`           | string  | required | Target URL                                            |
| `preset`        | string  | low      | Scan preset: low, medium, high                        |
| `user_consent`  | boolean | false    | Must be true for medium/high presets                  |
| `timeout`       | float   | null     | Request timeout in seconds (overrides preset default) |
| `selector`      | string  | null     | CSS selector to extract (enables scraping)            |
| `dynamic`       | boolean | false    | Use Playwright for JS rendering                       |
| `headers`       | object  | {}       | Custom HTTP headers                                   |
| `cookies`       | object  | {}       | Cookies                                               |
| `proxy`         | string  | null     | HTTP/HTTPS proxy URL                                  |
| `user_agent`    | string  | null     | Custom User-Agent                                     |
| `output_format` | string  | json     | Export format: json, jsonl, csv, html                 |

**Response:**

```json
{
  "success": true,
  "data": {
    "url": "https://example.com",
    "timestamp": "2026-01-01T00:00:00Z",
    "ssl_analysis": { ... },
    "fingerprint": { ... },
    "headers_analysis": { ... },
    "cve_results": [ ... ],
    "attack_results": { ... },
    "scrape_result": { ... },
    "risk_score": 40,
    "summary": {
      "critical": 0,
      "high": 0,
      "medium": 4,
      "low": 0
    }
  },
  "preset": "low",
  "duration_seconds": 5.89,
  "warnings": [],
  "download_token": "uuid-token",
  "download_url": "/api/download/uuid-token",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

**Error Response (Missing Consent):**

```json
{
  "success": false,
  "error": "User consent is required for 'medium' preset. Set user_consent=true to confirm you have permission to test this system.",
  "error_code": "CONSENT_REQUIRED",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

#### GET /api/quick/presets

List available scan presets and their configurations (no authentication required).

**Response:**

```json
{
  "presets": {
    "low": {
      "analyze": {
        "ssl": true,
        "fingerprint": true,
        "cve": false,
        "analyze_headers": true
      },
      "has_attacks": false,
      "attack_types": [],
      "intensity": null,
      "scrape_dynamic": false
    },
    "medium": {
      "analyze": {
        "ssl": true,
        "fingerprint": true,
        "cve": true,
        "analyze_headers": true
      },
      "has_attacks": true,
      "attack_types": ["xss", "sqli"],
      "intensity": "medium",
      "scrape_dynamic": false
    },
    "high": {
      "analyze": {
        "ssl": true,
        "fingerprint": true,
        "cve": true,
        "analyze_headers": true,
        "enrich_exploits": true
      },
      "has_attacks": true,
      "attack_types": ["xss", "sqli", "traversal", "enumeration", "csrf"],
      "intensity": "high",
      "scrape_dynamic": true
    }
  }
}
```

### Downloads

#### GET /api/download/{token}

Download previously exported results using a time-limited token.

**URL Parameters:**

| Parameter | Type   | Description                         |
| --------- | ------ | ----------------------------------- |
| `token`   | string | Download token from a POST response |

**Headers:**

```
X-API-Key: your-api-key-here
```

**Response:** File stream (application/octet-stream)

**Status Codes:**

| Code | Description                                           |
| ---- | ----------------------------------------------------- |
| 200  | File downloaded successfully                          |
| 400  | Invalid token                                         |
| 401  | Unauthorized (different user or max retries exceeded) |
| 404  | Token not found                                       |
| 410  | Token expired                                         |
| 429  | Too many retry attempts                               |
| 503  | Download service unavailable                          |

**Example:**

```bash
curl -H "X-API-Key: your-key" \
  "http://localhost:8000/api/download/uuid-token" \
  -o results.json
```

### Authentication

#### GET /api/auth/me

Get information about the current authenticated user.

**Response:**

```json
{
  "identifier": "user-id",
  "auth_method": "api_key",
  "scopes": ["full_access"],
  "authenticated": true
}
```

#### POST /api/auth/generate-key

Generate a new API key (requires admin/full_access scope).

**Response:**

```json
{
  "api_key": "new-key-uuid",
  "message": "Store this key securely. It cannot be retrieved again."
}
```

### Configuration

#### GET /api/config

Retrieve all configuration settings.

**Response:**

```json
{
  "success": true,
  "data": {
    "api": {...},
    "scraping": {...},
    "analysis": {...},
    "attacks": {...}
  },
  "timestamp": "2026-01-01T00:00:00Z"
}
```

#### GET /api/config/sections/{section}

Retrieve a specific configuration section.

**URL Parameters:**

| Parameter | Type   | Description                                     |
| --------- | ------ | ----------------------------------------------- |
| `section` | string | Section name (api, scraping, analysis, attacks) |

**Response:**

```json
{
  "success": true,
  "data": {
    "key1": "value1",
    "key2": "value2"
  },
  "timestamp": "2026-01-01T00:00:00Z"
}
```

#### PUT /api/config

Update configuration settings.

**Request:**

```json
{
  "updates": {
    "scraping.timeout": 45.0,
    "analysis.cve_limit": 150
  }
}
```

#### POST /api/config/export

Export configuration to file.

**Request:**

```json
{
  "format": "yaml"
}
```

#### POST /api/config/load

Load configuration from file.

**Request:**

```json
{
  "file_path": "/path/to/config.yaml"
}
```

#### POST /api/config/reset

Reset to default configuration.

**Request:**

```json
{
  "section": "scraping"
}
```

#### POST /api/config/save

Save configuration to file.

**Request:**

```json
{
  "file_path": "/path/to/config.yaml",
  "format": "yaml"
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "file_path": "/path/to/config.yaml",
    "format": "yaml",
    "message": "Configuration saved successfully"
  },
  "timestamp": "2026-01-01T00:00:00Z"
}
```

## Error Handling

All error responses include standardized error information:

### Validation Error

```json
{
  "success": false,
  "error": "Validation error",
  "error_code": "VALIDATION_ERROR",
  "details": [
    {
      "field": "url",
      "message": "Invalid URL format",
      "value": "not-a-url"
    }
  ],
  "timestamp": "2026-01-01T00:00:00Z"
}
```

### General Error

```json
{
  "success": false,
  "error": "Internal server error",
  "error_code": "INTERNAL_ERROR",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

### Common HTTP Status Codes

| Status | Meaning                                |
| ------ | -------------------------------------- |
| 200    | Success                                |
| 400    | Bad request (validation error)         |
| 401    | Unauthorized (missing/invalid API key) |
| 403    | Forbidden (insufficient permissions)   |
| 404    | Not found                              |
| 429    | Too many requests (rate limited)       |
| 500    | Internal server error                  |
| 503    | Service unavailable                    |

## Configuration

### Environment Variables

Configure the API via environment variables:

```bash
# Server
CIBERWEBSCAN_API_HOST=0.0.0.0
CIBERWEBSCAN_API_PORT=8000

# Authentication
CIBERWEBSCAN_API_AUTH_API_KEYS="key1,key2,key3"

# Rate Limiting
CIBERWEBSCAN_API_RATE_LIMIT_ENABLED=true
CIBERWEBSCAN_API_RATE_LIMIT_REQUESTS_PER_MINUTE=60

# CORS
CIBERWEBSCAN_API_CORS_ORIGINS="http://localhost:3000,https://example.com"

# Downloads
CIBERWEBSCAN_DOWNLOAD_ENABLED=true
CIBERWEBSCAN_DOWNLOAD_TOKEN_EXPIRY_MINUTES=60
CIBERWEBSCAN_DOWNLOAD_MAX_RETRY_ATTEMPTS=3
```

### Rate Limiting

The API includes rate limiting to prevent abuse:

- **Default**: 60 requests per minute
- **Configurable** via `CIBERWEBSCAN_API_RATE_LIMIT_REQUESTS_PER_MINUTE`
- **429 status code** returned when exceeded
- **Retry-After header** included in rate limit responses

### CORS

Cross-Origin Resource Sharing is configured for:

- Origins: Configurable via environment variable
- Credentials: Enabled
- Methods: All (GET, POST, PUT, DELETE, etc.)
- Headers: All

## API Documentation

### Interactive API Docs

Once the API server is running, visit:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

### Example cURL Requests

**Health Check:**

```bash
curl http://localhost:8000/health
```

**Analyze URL:**

```bash
curl -X POST "http://localhost:8000/api/analyze" \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "ssl": true,
    "fingerprint": true,
    "analyze_headers": true
  }'
```

**Scrape URL:**

```bash
curl -X POST "http://localhost:8000/api/scrape" \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "selector": ".product"
  }'
```

**Attack Test:**

```bash
curl -X POST "http://localhost:8000/api/attack" \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://testsite.example.com",
    "xss": true,
    "user_consent": true
  }'
```

**Quick Scan:**

```bash
curl -X POST "http://localhost:8000/api/quick/scan" \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "preset": "low"
  }'
```

**List Quick Scan Presets:**

```bash
curl "http://localhost:8000/api/quick/presets"
```

## Best Practices

### Security

- **Never commit API keys** to version control
- **Store keys securely** using environment variables or secrets manager
- **Rotate keys regularly** for accounts with multiple keys
- **Use HTTPS only** in production
- **Use IP whitelisting** if behind a firewall

### Performance

- **Use timeouts** appropriately (30-60 seconds for most operations)
- **Implement exponential backoff** for retries
- **Respect rate limits** and implement queuing on your side
- **Use batch endpoints** for multiple URLs when available
- **Cache results** when appropriate

### Error Handling

- **Check HTTP status codes** before parsing response
- **Log all errors** for debugging
- **Implement retry logic** with exponential backoff
- **Handle timeouts gracefully**
- **Validate all responses** before processing

### Compliance

- **Only test authorized targets** - obtain written permission
- **Follow responsible disclosure** for vulnerabilities
- **Comply with local laws** regarding security testing
- **Use appropriate delays** between requests
- **Respect robots.txt** when configured

## Support & Troubleshooting

### Common Issues

**401 Unauthorized**: Verify your API key is correct and included in `X-API-Key` header

**429 Too Many Requests**: Rate limit exceeded. Implement exponential backoff

**503 Service Unavailable**: Download service disabled. Check configuration

**Connection Refused**: Ensure API server is running on the correct host/port

### Getting Help

- Check [API Documentation](docs/API.md)
- Review [Configuration Guide](docs/CONFIGURATION.md)
- See [CLI Reference](docs/CLI.md)
- Report issues on GitHub
