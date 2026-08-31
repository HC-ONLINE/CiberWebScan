# Command Line Interface

CiberWebScan provides a comprehensive command-line interface for security analysis, web scraping, and ethical penetration testing.

## Getting Help

```bash
ciberwebscan --help
```

## Commands

### Global Commands

- `version`: Show version information

### Global Options

- `--help`: Show help message

### Analyze Command

Perform security analysis on web applications.

```bash
ciberwebscan analyze <URL> [OPTIONS]
```

Activate specific analyses with flags. At least one of `--ssl`, `--fingerprint`, `--cve`, or `--analyze-headers` must be enabled.

**Options:**

- `--ssl/--no-ssl`: Perform SSL/TLS analysis (default: disabled)
- `--fingerprint/--no-fingerprint, -fp`: Perform technology fingerprinting (default: disabled)
- `--cve/--no-cve`: Look up CVEs for detected technologies (default: disabled)
- `--analyze-headers/--no-analyze-headers`: Analyze HTTP security headers (default: disabled)
- `--deep`: Enable deep scanning
- `--timeout, -t <SECONDS>`: Request timeout (default: 30.0)
- `--ssl-timeout <SECONDS>`: SSL/TLS handshake timeout (default: 10.0)
- `--cve-sources <SOURCES>`: CVE sources (comma-separated: nvd,circl,vulners)
- `--cve-limit <NUMBER>`: Maximum CVEs to retrieve (default: 100)
- `--enrich-exploits, -ee`: Enrich CVEs with exploit info from Vulners
- `--output, -o <FILE>`: Output file path
- `--format, -f <FORMAT>`: Export format: json, jsonl, csv, html (default: json)
- `--json`: Output raw JSON
- `--quiet, -q`: Minimal output
- `--user-agent, -ua <AGENT>`: Custom user agent
- `--headers, -H <HEADERS>`: Custom headers (format: 'Key: Value, Key2: Value2')
- `--proxy <PROXY>`: Proxy server
- `--cookies <COOKIES>`: Cookies (format: 'name1=value1; name2=value2')

**Examples:**

```bash
# SSL + fingerprinting
ciberwebscan analyze https://example.com --ssl --fingerprint

# Full analysis
ciberwebscan analyze https://example.com --ssl --fingerprint --cve --analyze-headers

# SSL only with custom timeout
ciberwebscan analyze https://example.com --ssl --ssl-timeout 15

# Export report
ciberwebscan analyze https://example.com --ssl --fingerprint -o report.json
```

### Scrape Command

Extract data from web pages.

#### scrape url

Scrape a single URL.

```bash
ciberwebscan scrape url <URL> [OPTIONS]
```

**Options:**

- `--dynamic, -d`: Use browser-based scraping for JavaScript content
- `--wait-for, -w <SELECTOR>`: CSS selector to wait for (dynamic mode)
- `--selector, -s <SELECTOR>`: CSS selector for data extraction
- `--attributes, -a <ATTRS>`: Attributes to extract (comma-separated)
- `--pagination, -p <SELECTOR>`: Pagination selector
- `--max-pages <NUMBER>`: Maximum pages to scrape (default: 1)
- `--extract-schema, -es <SCHEMA>`: JSON extraction schema (string or file path)
- `--check-robots/--no-check-robots, -cr`: Respect robots.txt (default: enabled)
- `--forms/--no-forms`: Extract HTML forms and their fields (default: disabled)
- `--timeout, -t <SECONDS>`: Request timeout (default: 30.0)
- `--output, -o <FILE>`: Output file path
- `--format, -f <FORMAT>`: Export format: json, jsonl, csv, html (default: json)
- `--json`: Output raw JSON
- `--quiet, -q`: Minimal output
- `--user-agent, -ua <AGENT>`: Custom user agent
- `--headers, -H <HEADERS>`: Custom headers (format: 'Key: Value, Key2: Value2')
- `--proxy <PROXY>`: Proxy server
- `--cookies <COOKIES>`: Cookies (format: 'name1=value1; name2=value2')

**Examples:**

```bash
# Basic scraping
ciberwebscan scrape url https://example.com

# Dynamic content scraping
ciberwebscan scrape url https://spa.example.com --dynamic --wait-for ".loaded"

# Extract specific data
ciberwebscan scrape url https://example.com --selector ".product" --attributes "href,title"

# Extract forms
ciberwebscan scrape url https://example.com --forms

# Export results
ciberwebscan scrape url https://example.com --selector "a" -o links.json
```

#### scrape batch

Scrape multiple URLs.

```bash
ciberwebscan scrape batch <URLS> [OPTIONS]
```

**Options:**

- `--selector, -s <SELECTOR>`: CSS selector to extract
- `--dynamic, -d`: Use browser-based scraping
- `--timeout, -t <SECONDS>`: Request timeout (default: 30.0)
- `--user-agent, -ua <AGENT>`: Custom user agent
- `--headers, -H <HEADERS>`: Custom headers (format: 'Key: Value, Key2: Value2')
- `--proxy <PROXY>`: Proxy server
- `--cookies <COOKIES>`: Cookies (format: 'name1=value1; name2=value2')
- `--check-robots/--no-check-robots, -cr`: Respect robots.txt (default: enabled)
- `--forms/--no-forms`: Extract HTML forms and their fields (default: disabled)
- `--output, -o <FILE>`: Output file path
- `--format, -f <FORMAT>`: Export format (default: jsonl)
- `--json`: Output raw JSON
- `--quiet, -q`: Minimal output

**Examples:**

```bash
# Scrape multiple URLs
ciberwebscan scrape batch https://example.com https://example.org

# With selector and export
ciberwebscan scrape batch url1 url2 url3 -s "h1" -o results.jsonl

# With proxy and custom headers
ciberwebscan scrape batch url1 url2 --proxy http://proxy:8080 -H "Authorization: Bearer xxx"

# Dynamic scraping with proxy
ciberwebscan scrape batch url1 url2 -d --proxy http://proxy:8080
```

### Attack Command

Perform ethical penetration testing (requires explicit consent).

```bash
ciberwebscan attack <URL> --consent [OPTIONS]
```

**Critical:** The `--consent` flag is required and confirms you have permission to test the target system.

**Options:**

- `--xss`: Test for Cross-Site Scripting vulnerabilities
- `--sqli`: Test for SQL Injection vulnerabilities
- `--traversal`: Test for Path Traversal vulnerabilities
- `--enumeration`: Test for Directory/File enumeration
- `--csrf`: Test for CSRF (Cross-Site Request Forgery) vulnerabilities
- `--subdomain`: Enumerate active subdomains via DNS brute force
- `--command-injection`: Test for OS Command Injection vulnerabilities
- `--json-body <JSON>`: JSON body template for POST/JSON testing (e.g. `'{"cmd": "id"}'`)
- `--all`: Run all attack types
- `--intensity, -i <LEVEL>`: Attack intensity: low, medium, high (default: medium)
- `--max-payloads <NUMBER>`: Maximum payloads per attack (default: 50)
- `--payloads, -p <FILE>`: Custom payloads file (JSON)
- `--wordlist, -w <FILE>`: Custom wordlist for enumeration
- `--timeout, -t <SECONDS>`: Request timeout (default: 10.0)
- `--output, -o <FILE>`: Output file path
- `--format, -f <FORMAT>`: Export format: json, jsonl, csv, html (default: json)
- `--json`: Output raw JSON
- `--quiet, -q`: Minimal output
- `--verbose, -v`: Verbose output
- `--user-agent, -ua <AGENT>`: Custom user agent
- `--proxy <PROXY>`: Proxy server
- `--headers, -H <HEADERS>`: Custom headers (format: 'Key: Value, Key2: Value2')
- `--cookies <COOKIES>`: Cookies (format: 'name1=value1; name2=value2')

**Examples:**

```bash
# XSS testing with consent
ciberwebscan attack https://example.com --consent --xss

# Multiple attack types
ciberwebscan attack https://example.com --consent --xss --sqli

# CSRF testing
ciberwebscan attack https://example.com --consent --csrf

# Subdomain enumeration (DNS brute force)
ciberwebscan attack https://example.com --consent --subdomain

# OS Command Injection over a JSON API endpoint
ciberwebscan attack https://example.com/api/run --consent --command-injection --json-body '{"cmd": "id"}'

# All attacks with low intensity
ciberwebscan attack https://example.com --consent --all --intensity low

# Custom payloads
ciberwebscan attack https://example.com --consent --xss --payloads my_payloads.json
```

### Quick Scan Command

Combined scan using presets: analysis + attacks + scraping in one command.

```bash
ciberwebscan quick <URL> [OPTIONS]
```

**Options:**

- `--preset, -p <PRESET>`: Scan preset: low, medium, high (default: low)
- `--consent`: Confirm you have permission to test (REQUIRED for medium/high)
- `--selector, -s <SELECTOR>`: CSS selector to extract (enables scraping)
- `--dynamic, -d`: Use browser-based scraping (Playwright) - preset high only
- `--timeout, -t <SECONDS>`: Request timeout (overrides preset)
- `--proxy <PROXY>`: HTTP/HTTPS proxy URL
- `--user-agent, -ua <AGENT>`: Custom User-Agent string
- `--headers, -H <HEADERS>`: Custom headers (format: 'Key: Value, Key2: Value2')
- `--cookies, -c <COOKIES>`: Cookies (format: 'name1=value1; name2=value2')
- `--output, -o <FILE>`: Output file path
- `--format, -f <FORMAT>`: Export format: json, jsonl, csv, html (default: json)
- `--json`: Output raw JSON
- `--quiet, -q`: Minimal output
- `--verbose, -v`: Verbose output

**Presets:**

| Preset   | Analysis                     | Attacks                      | Consent Required |
| -------- | ---------------------------- | ---------------------------- | ---------------- |
| `low`    | SSL, fingerprint, headers    | None                         | No               |
| `medium` | + CVE lookup                 | XSS, SQLi (medium intensity) | Yes              |
| `high`   | + exploit enrichment, deeper | All types (high intensity)   | Yes              |

**Examples:**

```bash
# Basic analysis (preset low)
ciberwebscan quick https://example.com

# Analysis with scraping
ciberwebscan quick https://example.com -s ".content"

# Medium scan with attacks (requires consent)
ciberwebscan quick https://example.com --preset medium --consent

# Full scan with dynamic scraping
ciberwebscan quick https://example.com --preset high --consent -d

# Export combined report
ciberwebscan quick https://example.com --preset high --consent -o report.json

# JSON output for automation
ciberwebscan quick https://example.com --json --quiet
```

### API Command

Manage and run the CiberWebScan REST API server.

```bash
ciberwebscan api [OPTIONS]
```

**Options:**

- `--host <TEXT>`: Bind socket to this host (default: 0.0.0.0)
- `--port <INTEGER>`: Bind socket to this port (default: 8000)
- `--reload`: Enable auto-reload (development mode)

**Examples:**

```bash
# Start the API server on default port 8000
ciberwebscan api

# Start on a custom port and host
ciberwebscan api --host 127.0.0.1 --port 9000

# Run in development mode with auto-reload
ciberwebscan api --reload
```

### Completion Command

Manage shell completion for bash, zsh, fish, and powershell.

#### completion install

Install shell completion scripts.

```bash
ciberwebscan completion install [OPTIONS]
```

**Options:**

- `--shell, -s <SHELL>`: Shell to install completion for (auto-detected if not specified). Options: bash, zsh, fish, powershell

**Examples:**

```bash
# Auto-detect shell and install
ciberwebscan completion install

# Install for specific shell
ciberwebscan completion install --shell zsh
ciberwebscan completion install --shell bash
ciberwebscan completion install --shell fish
ciberwebscan completion install --shell powershell
```

#### completion show

Display the generated completion script for manual installation or inspection.

```bash
ciberwebscan completion show [OPTIONS]
```

**Options:**

- `--shell, -s <SHELL>`: Shell to show completion for (auto-detected if not specified). Options: bash, zsh, fish, powershell

**Examples:**

```bash
# Show completion for detected shell
ciberwebscan completion show

# Show completion for specific shell
ciberwebscan completion show --shell bash
```

#### completion uninstall

Remove installed shell completion scripts.

```bash
ciberwebscan completion uninstall [OPTIONS]
```

**Options:**

- `--shell, -s <SHELL>`: Shell to uninstall completion for (auto-detected if not specified). Options: bash, zsh, fish, powershell

**Examples:**

```bash
# Uninstall completion for detected shell
ciberwebscan completion uninstall

# Uninstall for specific shell
ciberwebscan completion uninstall --shell zsh
```

### Config Command

Manage application configuration.

#### config show

Display current configuration.

```bash
ciberwebscan config show [SECTION] [OPTIONS]
```

**Options:**

- `--json`: Output raw JSON
- `--config <FILE>`: Config file path (default: ~/.ciberwebscan/config.yaml)

**Examples:**

```bash
# Show all config
ciberwebscan config show

# Show specific section
ciberwebscan config show scraping

# Show from custom config file
ciberwebscan config show --config my_config.yaml
```

#### config get

Get a specific configuration value.

```bash
ciberwebscan config get <KEY> [OPTIONS]
```

**Options:**

- `--json`: Output raw JSON
- `--config <FILE>`: Config file path (default: ~/.ciberwebscan/config.yaml)

**Examples:**

```bash
ciberwebscan config get scraping.timeout
ciberwebscan config get http.retry.max_attempts --config custom_config.yaml
```

#### config set

Set a configuration value.

```bash
ciberwebscan config set <KEY> <VALUE> [OPTIONS]
```

**Options:**

- `--save/--no-save`: Save changes to config file (default: --save)
- `--config <FILE>`: Config file path (default: ~/.ciberwebscan/config.yaml)

**Examples:**

```bash
ciberwebscan config set scraping.timeout 60
ciberwebscan config set http.retry.max_attempts 5 --save
ciberwebscan config set export.output_dir results --no-save
```

#### config reset

Reset configuration to defaults.

```bash
ciberwebscan config reset [KEY] [OPTIONS]
```

**Options:**

- `--yes, -y`: Skip confirmation
- `--save/--no-save`: Save changes to config file (default: --save)
- `--config <FILE>`: Config file path (default: ~/.ciberwebscan/config.yaml)

**Examples:**

```bash
# Reset specific key
ciberwebscan config reset scraping.timeout

# Reset all (with confirmation)
ciberwebscan config reset

# Reset all (skip confirmation)
ciberwebscan config reset -y
```

#### config keys

List all configuration keys.

```bash
ciberwebscan config keys [OPTIONS]
```

**Options:**

- `--section, -s <SECTION>`: Filter by section

**Examples:**

```bash
# List all keys
ciberwebscan config keys

# List keys in section
ciberwebscan config keys -s scraping
```

#### config export

Export configuration to file.

```bash
ciberwebscan config export <PATH> [OPTIONS]
```

**Options:**

- `--format, -f <FORMAT>`: Export format: yaml, json (default: yaml)

**Examples:**

```bash
ciberwebscan config export config.yaml
ciberwebscan config export config.json -f json
```

#### config load

Load configuration from file.

```bash
ciberwebscan config load <PATH>
```

**Examples:**

```bash
ciberwebscan config load config.yaml
ciberwebscan config load config.json
```

## Configuration

CiberWebScan uses a configuration system that can be customized:

- Default configuration in code
- User configuration file (created automatically)
- Environment variables
- Command-line options

Configuration is stored in `~/.ciberwebscan/config.yaml` by default.

## Error Handling

The CLI provides clear error messages and exit codes:

- `0`: Success
- `1`: General error
- `2`: Validation error or missing consent

## Examples

### Complete Security Assessment

```bash
ciberwebscan analyze https://target.com \
  --ssl \
  --fingerprint \
  --headers \
  --cve \
  --output assessment.json
```

### Web Scraping with Export

```bash
ciberwebscan scrape url https://news.com \
  --dynamic \
  --wait-for ".article" \
  --selector ".article" \
  --attributes "href,title" \
  --output articles.json
```

### Ethical Testing

```bash
ciberwebscan attack https://testsite.com \
  --consent \
  --xss \
  --sqli \
  --command-injection \
  --intensity low \
  --output vulnerabilities.json
```

### Quick Scan

```bash
# Basic analysis
ciberwebscan quick https://example.com

# With scraping and export
ciberwebscan quick https://example.com -s ".data" -o quick_report.json

# Full scan with attacks
ciberwebscan quick https://example.com --preset high --consent -o report.json
```
