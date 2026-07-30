# CiberWebScan

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Version 2.4.0](https://img.shields.io/badge/version-2.4.0-blue.svg)](https://github.com/HC-ONLINE/CiberWebScan)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Beta](https://img.shields.io/badge/status-beta-orange.svg)](https://github.com/HC-ONLINE/CiberWebScan)

## **The complete solution for web application security assessment and passive reconnaissance**

CiberWebScan is a modern, powerful toolkit that combines intelligent web scraping, comprehensive security analysis, and ethical penetration testing capabilities in one unified platform. Whether you're a cybersecurity professional, penetration tester, or security researcher, CiberWebScan provides the tools you need to thoroughly assess web applications and identify potential vulnerabilities.

> **Note**: This is version 2.4.0, a complete refactor of the previous version that addressed numerous issues. Currently in beta, with some features still under development.

## Why Choose CiberWebScan?

**All-in-One Security Platform**
Stop juggling multiple tools. CiberWebScan combines web scraping, vulnerability scanning, technology fingerprinting, and attack simulation in a single, coherent solution.

**Enterprise-Ready Architecture**
Built with modern Python standards, featuring both REST API and CLI interfaces, comprehensive configuration management, and robust error handling for production environments.

**Intelligent Analysis Engine**
Our advanced analyzers automatically identify technologies, assess SSL/TLS configurations, evaluate security headers, and cross-reference known vulnerabilities against CVE databases.

**Ethical Security Testing**
Includes safe, controlled penetration testing capabilities for XSS detection, SQL injection testing, directory enumeration, and path traversal analysis - all designed for authorized testing environments.

---

## Core Capabilities

### Web Intelligence & Data Extraction

- **Advanced Web Scraping**: Combine static parsing with dynamic JavaScript rendering using Beautiful Soup and Playwright
- **Structured Data Extraction**: Transform unstructured web content into actionable, structured datasets
- **Session Management**: Handle complex authentication, cookies, and stateful interactions seamlessly

### Security Assessment Suite

- **Technology Fingerprinting**: Automatically identify web frameworks, CMS platforms, server technologies, and versions
- **SSL/TLS Analysis**: Comprehensive certificate validation, cipher suite evaluation, and protocol security assessment
- **Security Headers Evaluation**: Analyze CSP, HSTS, X-Frame-Options, and other critical security headers
- **Vulnerability Intelligence**: Cross-reference discovered technologies with CVE databases for known security issues

### Controlled Penetration Testing

- **XSS Detection**: Identify potential Cross-Site Scripting vulnerabilities through safe, controlled testing
- **SQL Injection Analysis**: Test for database vulnerabilities using proven penetration testing methodologies
- **Directory Enumeration**: Discover hidden paths, backup files, and sensitive directories
- **Path Traversal Testing**: Identify file system access vulnerabilities through controlled probes

### Professional Integration

- **REST API (Beta)**: A powerful REST interface for seamless integration with existing security workflows. Built with FastAPI, it includes interactive documentation and allows for remote orchestration of scans.
- **Command Line Interface**: Powerful CLI with rich formatting and automation support for security professionals
- **Quick Scan**: Combined analysis + attacks + scraping with presets (`low`/`medium`/`high`) for streamlined assessments
- **Flexible Export Options**: Generate comprehensive reports in JSON, CSV, JSONL, and HTML
- **Configuration Management**: Centralized, persistent configuration system for enterprise deployment

---

## Perfect For

**Cybersecurity Professionals**
Streamline your security assessments with comprehensive analysis tools that deliver actionable intelligence about web application security posture.

**Penetration Testers**
Accelerate your reconnaissance phase with automated technology discovery, vulnerability identification, and controlled security testing capabilities.

**Security Researchers**
Gather detailed technical intelligence about web applications, including technology stacks, security implementations, and potential attack vectors.

**DevSecOps Teams**
Integrate security testing into your development pipeline with API-driven automation and comprehensive reporting capabilities.

**Bug Bounty Hunters**
Enhance your methodology with systematic reconnaissance tools that uncover hidden assets and potential security weaknesses.

---

## Quick Start

### Installation

```bash
# 1. clone the repository and install the package
git clone https://github.com/HC-ONLINE/CiberWebScan.git
cd CiberWebScan

# 2. create a virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. install the package and dependencies

# CLI only
pip install -e .

# CLI + API
pip install -e "[api]"

# Full Developer Setup
# if you are running the developer tests you will also want the dev dependencies, which include testing frameworks and tools
pip install -e "[api,dev]"

# verify that the tool is available
ciberwebscan --help
```

### Basic Usage

#### Comprehensive Security Analysis

```bash
# Full security assessment
ciberwebscan analyze --url https://target.example.com --all-checks

# Technology fingerprinting
ciberwebscan analyze --url https://target.example.com --fingerprint
```

#### Intelligent Web Scraping

```bash
# Extract structured data
ciberwebscan scrape --url https://target.example.com --selector ".product" --export json

# Dynamic content scraping
ciberwebscan scrape --url https://spa.example.com --dynamic --wait-selector ".loaded"
```

#### Controlled Security Testing

```bash
# XSS vulnerability testing (authorized environments only)
ciberwebscan attack --url https://testsite.example.com --xss

# Directory enumeration
ciberwebscan attack --url https://testsite.example.com --enumeration
```

#### Quick Scan (Combined)

```bash
# Basic analysis
ciberwebscan quick scan https://example.com

# Analysis + scraping
ciberwebscan quick scan https://example.com -s ".content"

# Full scan with attacks (requires consent)
ciberwebscan quick scan https://example.com --preset high --consent
```

### REST API Integration

> **API Preview**: The REST interface is functional but considered "unstable." Endpoint signatures and JSON schemas may change as we refine the 2.4.0 specification.

To start the server:

```bash
ciberwebscan api
```

### Interactive Documentation

Once the server is running, you can explore and test all available endpoints through the built-in interactive UI:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Programmatic Access Example

You can also integrate CiberWebScan into your own scripts using the requests library:

```python
import requests

# Security analysis via REST API
response = requests.post(
    "http://localhost:8000/api/analyze", json={"url": "https://target.example.com"}
)

results = response.json()
# Returns: {"success": true, "data": {"technologies": [...], "vulnerabilities": [...]}, ...}
```

---

## Advanced Features

**Multi-Protocol Support**: HTTP/HTTPS with HTTP/2 support for modern web applications

**Proxy Integration**: Route traffic through corporate proxies or security tools like Burp Suite

**Rate Limiting**: Built-in throttling to ensure responsible testing that doesn't impact target systems

**Error Recovery**: Robust error handling with automatic retries and graceful degradation

**Extensive Logging**: Detailed audit trails for compliance and debugging requirements

**Modular Architecture**: Extensible design allows custom analyzers and attack modules

---

## Enterprise Support

CiberWebScan is designed for professional use with enterprise-grade features:

- Comprehensive test coverage with automated quality assurance
- Professional documentation and best practices guides (in development)
- Active development and security updates
- Apache 2.0 licensing for commercial use
- Clean, maintainable codebase following Python standards

> **Beta Status**: As a beta release, some advanced features are still under development. Please report any issues or suggestions.

---

## Responsible Use

CiberWebScan is developed for authorized security testing, research, and educational purposes. Users must ensure they have proper authorization before testing any systems and must comply with applicable laws and regulations.

**Always obtain explicit permission before testing systems you don't own.**

---

## Community & Support

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

- **Found a bug?** Open an [Issue](https://github.com/HC-ONLINE/CiberWebScan/issues) describing the problem.
- **Want a new feature?** Feel free to submit a [Pull Request](https://github.com/HC-ONLINE/CiberWebScan/pulls) with your proposal.
- **Enjoying the tool?** Give us a ⭐ on GitHub to show your support!

## Before contributing, please read our [Contributing Guide](docs/CONTRIBUTING.md) to maintain code quality and consistency.

---

## Documentation

- **[Installation Guide](docs/INSTALLATION.md)** - Complete setup and installation instructions
- **[CLI Reference](docs/CLI.md)** - Detailed command-line interface documentation
- **[API Documentation](docs/API.md)** - REST API endpoints and usage (in development)
- **[Configuration Guide](docs/CONFIGURATION.md)** - Configuration options and customization
- **[Development Guide](docs/DEVELOPMENT.md)** - Contributing, testing, and development setup
- **[Contributing](docs/CONTRIBUTING.md)** - How to contribute to the project
- **[Changelog](CHANGELOG.md)** - Version history and changes

---

## Developed with ❤️ by HC-ONLINE

_Transform your approach to web application security assessment with CiberWebScan's comprehensive, professional-grade toolkit._
