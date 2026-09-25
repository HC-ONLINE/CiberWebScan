# =============================================================================
# Stage 1: Builder — install dependencies and Playwright browsers
# =============================================================================
FROM python:3.12-slim AS builder

# uv replaces pip for dependency installation (same tool as local dev and CI)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# System deps required by Playwright Chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    xdg-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer caching)
# README.md and LICENSE are required by pyproject.toml metadata
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN UV_PYTHON_DOWNLOADS=never uv sync --locked --no-install-project --extra api

# Install the application source and its Playwright browsers
COPY src/ src/
RUN UV_PYTHON_DOWNLOADS=never uv sync --locked --extra api \
    && uv run playwright install --with-deps chromium

# =============================================================================
# Stage 2: Runtime — minimal image with only what's needed
# =============================================================================
FROM python:3.12-slim AS runtime

WORKDIR /app

# Copy the virtualenv; it is built at /app/.venv in the builder so the
# absolute paths recorded inside it stay valid
COPY --from=builder /app/.venv /app/.venv

# Copy application source (installed in editable mode, needed for package data)
COPY src/ /app/src/

# Non-root user for security
RUN groupadd -r ciberwebscan && useradd -r -g ciberwebscan ciberwebscan \
    && chown -R ciberwebscan:ciberwebscan /app

# Copy Playwright browsers and set ownership
COPY --from=builder --chown=ciberwebscan:ciberwebscan /root/.cache/ms-playwright /home/ciberwebscan/.cache/ms-playwright
USER ciberwebscan

# Playwright env vars
ENV PATH="/app/.venv/bin:$PATH"
ENV PLAYWRIGHT_BROWSERS_PATH=/home/ciberwebscan/.cache/ms-playwright
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

ENTRYPOINT ["ciberwebscan"]
CMD ["api", "--host", "0.0.0.0", "--port", "8000"]
