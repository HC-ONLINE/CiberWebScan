# =============================================================================
# Stage 1: Builder — install dependencies and Playwright browsers
# =============================================================================
FROM python:3.12-slim AS builder

WORKDIR /build

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
COPY pyproject.toml ./
COPY src/ src/

RUN pip install --no-cache-dir --prefix=/install ".[api]"

# Install Playwright and its browsers
RUN pip install --no-cache-dir playwright \
    && playwright install --with-deps chromium

# =============================================================================
# Stage 2: Runtime — minimal image with only what's needed
# =============================================================================
FROM python:3.12-slim AS runtime

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application source (already installed via pip, but needed for package data)
COPY src/ /app/src/
WORKDIR /app

# Non-root user for security
RUN groupadd -r ciberwebscan && useradd -r -g ciberwebscan ciberwebscan \
    && chown -R ciberwebscan:ciberwebscan /app

# Copy Playwright browsers and set ownership
COPY --from=builder --chown=ciberwebscan:ciberwebscan /root/.cache/ms-playwright /home/ciberwebscan/.cache/ms-playwright
USER ciberwebscan

# Playwright env vars
ENV PLAYWRIGHT_BROWSERS_PATH=/home/ciberwebscan/.cache/ms-playwright
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

ENTRYPOINT ["ciberwebscan"]
CMD ["api", "--host", "0.0.0.0", "--port", "8000"]
