# Command Line Interface

CiberWebScan provides a comprehensive command-line interface for security analysis, web scraping, and ethical penetration testing.

## Getting Help

```bash
ciberwebscan --help
```

## Commands

### Global Commands

- `version`: Show version information
- `quick`: Quick scan - scrape and analyze in one command

### Global Options

- `--help`: Show help message

### Analyze Command

Perform security analysis on web applications.

#### analyze url

Analyze a single URL for security issues.

```bash
ciberwebscan analyze url <URL> [OPTIONS]
```

**Options:**

- `--ssl/--no-ssl`: Perform SSL/TLS analysis (default: enabled)
- `--fingerprint/--no-fingerprint, -fp`: Perform technology fingerprinting (default: enabled)
- `--cve/--no-cve`: Look up CVEs for detected technologies (default: enabled)
- `--analyze-headers/--no-analyze-headers`: Analyze HTTP security headers (default: enabled)
- `--deep`: Enable deep scanning
- `--timeout, -t <SECONDS>`: Request timeout (default: 30.0)
- `--cve-sources <SOURCES>`: CVE sources (comma-separated: nvd,circl,vulners)
- `--cve-limit <NUMBER>`: Maximum CVEs to retrieve (default: 100)
- `--enrich-exploits, -ee`: Enrich CVEs with exploit info from Vulners
- `--output, -o <FILE>`: Output file path
- `--format, -f <FORMAT>`: Export format: json, jsonl, csv (default: json)
- `--json`: Output raw JSON
- `--quiet, -q`: Minimal output
- `--user-agent, -ua <AGENT>`: Custom user agent
- `--headers, -H <HEADERS>`: Custom headers (format: 'Key: Value, Key2: Value2')
- `--proxy <PROXY>`: Proxy server
- `--cookies <COOKIES>`: Cookies (format: 'name1=value1; name2=value2')

**Examples:**

```bash
# Full security analysis
ciberwebscan analyze url https://example.com

# SSL only
ciberwebscan analyze url https://example.com --no-fingerprint --no-cve

# Fingerprint and CVEs only
ciberwebscan analyze url https://example.com --no-ssl

# Export report
ciberwebscan analyze url https://example.com -o report.json
```

#### analyze ssl

Perform SSL/TLS analysis only.

```bash
ciberwebscan analyze ssl <URL> [OPTIONS]
```

**Options:**

- `--timeout, -t <SECONDS>`: Request timeout (default: 10.0)
- `--json`: Output raw JSON

**Examples:**

```bash
ciberwebscan analyze ssl https://example.com
```

#### analyze fingerprint

Perform technology fingerprinting only.

```bash
ciberwebscan analyze fingerprint <URL> [OPTIONS]
```

**Options:**

- `--deep`: Enable deep scanning
- `--json`: Output raw JSON

**Examples:**

```bash
ciberwebscan analyze fingerprint https://example.com
ciberwebscan analyze fingerprint https://example.com --deep
```

#### analyze cves

Look up CVEs for specific technologies.

```bash
ciberwebscan analyze cves <TECHNOLOGY> [OPTIONS]
```

**Options:**

- `--sources, -s <SOURCES>`: CVE sources: nvd,circl,vulners
- `--limit, -l <NUMBER>`: Maximum CVEs per technology (default: 50)
- `--json`: Output raw JSON

**Examples:**

```bash
# Single technology
ciberwebscan analyze cves nginx:1.20

# Multiple technologies
ciberwebscan analyze cves wordpress:5.8 php:8.1

# With specific sources
ciberwebscan analyze cves apache --sources nvd,circl
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
- `--timeout, -t <SECONDS>`: Request timeout (default: 30.0)
- `--output, -o <FILE>`: Output file path
- `--format, -f <FORMAT>`: Export format: json, jsonl, csv (default: json)
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
- `--output, -o <FILE>`: Output file path
- `--format, -f <FORMAT>`: Export format (default: jsonl)
- `--json`: Output raw JSON

**Examples:**

```bash
# Scrape multiple URLs
ciberwebscan scrape batch https://example.com https://example.org

# With selector and export
ciberwebscan scrape batch url1 url2 url3 -s "h1" -o results.jsonl
```

### Attack Command

Perform ethical penetration testing (requires explicit consent).

#### attack test

Test for common web vulnerabilities.

```bash
ciberwebscan attack test <URL> --consent [OPTIONS]
```

**Critical:** The `--consent` flag is required and confirms you have permission to test the target system.

**Options:**

- `--xss`: Test for Cross-Site Scripting vulnerabilities
- `--sqli`: Test for SQL Injection vulnerabilities
- `--traversal`: Test for Path Traversal vulnerabilities
- `--enumeration`: Test for Directory/File enumeration
- `--all`: Run all attack types
- `--intensity, -i <LEVEL>`: Attack intensity: low, medium, high (default: medium)
- `--max-payloads <NUMBER>`: Maximum payloads per attack (default: 50)
- `--payloads, -p <FILE>`: Custom payloads file (JSON)
- `--wordlist, -w <FILE>`: Custom wordlist for enumeration
- `--timeout, -t <SECONDS>`: Request timeout (default: 10.0)
- `--output, -o <FILE>`: Output file path
- `--format, -f <FORMAT>`: Export format: json, jsonl, csv (default: json)
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
ciberwebscan attack test https://example.com --consent --xss

# Multiple attack types
ciberwebscan attack test https://example.com --consent --xss --sqli

# All attacks with low intensity
ciberwebscan attack test https://example.com --consent --all --intensity low

# Custom payloads
ciberwebscan attack test https://example.com --consent --xss --payloads my_payloads.json
```

#### attack xss

Test only for XSS vulnerabilities.

```bash
ciberwebscan attack xss <URL> --consent [OPTIONS]
```

**Options:**

- `--intensity, -i <LEVEL>`: Attack intensity: low, medium, high (default: medium)
- `--json`: Output raw JSON

**Examples:**

```bash
ciberwebscan attack xss https://example.com --consent
```

#### attack sqli

Test only for SQL injection vulnerabilities.

```bash
ciberwebscan attack sqli <URL> --consent [OPTIONS]
```

**Options:**

- `--intensity, -i <LEVEL>`: Attack intensity: low, medium, high (default: medium)
- `--json`: Output raw JSON

**Examples:**

```bash
ciberwebscan attack sqli https://example.com/product?id=1 --consent
```

### API Command

Manage and run the CiberWebScan REST API server.

#### api run

Start the REST API server using Uvicorn.

```bash
ciberwebscan api run [OPTIONS]
```

**Options:**

- --host <TEXT>: Bind socket to this host (default: 0.0.0.0)

- --port <INTEGER>: Bind socket to this port (default: 8000)

- --reload: Enable auto-reload (development mode)

**Examples:**

```bash
# Start the API server on default port 8000
ciberwebscan api run

# Start on a custom port and host
ciberwebscan api run --host 127.0.0.1 --port 9000

# Run in development mode with auto-reload
ciberwebscan api run --reload
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
ciberwebscan config get http.max_retries --config custom_config.yaml
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
ciberwebscan config set http.max_retries 5 --save
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
ciberwebscan analyze url https://target.com \
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
ciberwebscan attack test https://testsite.com \
  --consent \
  --xss \
  --sqli \
  --intensity low \
  --output vulnerabilities.json
```

### Quick Scan

```bash
ciberwebscan quick https://example.com -o quick_report.json
```
