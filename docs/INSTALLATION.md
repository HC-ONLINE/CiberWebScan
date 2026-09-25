# Installation Guide

This guide covers the installation and setup of CiberWebScan.

## Prerequisites

- Python 3.10 or higher
- [uv](https://docs.astral.sh/uv/getting-started/installation/) (Python package and environment manager)
- Git (for cloning the repository)

## Installation from Source

1. Clone the repository:

   ```bash
   git clone https://github.com/HC-ONLINE/CiberWebScan.git
   cd CiberWebScan
   ```

2. Install in development mode (`uv` creates and manages `.venv` automatically):

   ```bash
   uv sync
   ```

3. (Optional) API Setup:

   ```bash
   uv sync --extra api
   ```

4. (Optional) Install development dependencies:

   ```bash
   uv sync --extra api --extra dev
   ```

## Additional Setup

### Playwright Browser Installation

For dynamic web scraping functionality, install Playwright browsers:

```bash
uv run playwright install
```

### Verify Installation

Check that CiberWebScan is properly installed:

```bash
uv run ciberwebscan --help
```

You should see the main help output with available commands.

### Shell Completion

CiberWebScan supports shell completion for bash, zsh, fish, and powershell. After installation, enable it with:

```bash
# Auto-detect your shell and install completion
uv run ciberwebscan completion install

# Or specify a shell explicitly
uv run ciberwebscan completion install --shell zsh
uv run ciberwebscan completion install --shell bash
uv run ciberwebscan completion install --shell fish
uv run ciberwebscan completion install --shell powershell
```

The command will print post-installation instructions specific to your shell. See `ciberwebscan completion --help` for more options.

## Troubleshooting

### Common Issues

1. **ImportError**: Ensure you're using Python 3.10+ and have installed the package correctly.

2. **Playwright errors**: Make sure to run `uv run playwright install` after installation.

3. **Permission errors**: Run `uv sync` inside the project so dependencies land in the project-local `.venv` instead of your system Python.
