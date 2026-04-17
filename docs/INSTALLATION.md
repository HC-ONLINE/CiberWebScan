# Installation Guide

This guide covers the installation and setup of CiberWebScan.

## Prerequisites

- Python 3.10 or higher
- pip (Python package installer)
- Git (for cloning the repository)

## Installation from Source

1. Clone the repository:

   ```bash
   git clone https://github.com/HC-ONLINE/CiberWebScan.git
   cd CiberWebScan
   ```

2. It's recommended to use a virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install in development mode:

   ```bash
   pip install -e .
   ```

4. (Optional) API Setup:

   ```bash
   pip install -e ".[api]"
   ```

5. (Optional) Install development dependencies:

   ```bash
   pip install -e ".[dev]"
   ```

## Additional Setup

### Playwright Browser Installation

For dynamic web scraping functionality, install Playwright browsers:

```bash
playwright install
```

### Verify Installation

Check that CiberWebScan is properly installed:

```bash
ciberwebscan --help
```

You should see the main help output with available commands.

## Troubleshooting

### Common Issues

1. **ImportError**: Ensure you're using Python 3.10+ and have installed the package correctly.

2. **Playwright errors**: Make sure to run `playwright install` after installation.

3. **Permission errors**: Try installing with `pip install --user` or use a virtual environment.
