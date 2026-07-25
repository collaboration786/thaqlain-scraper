# Thaqlain Calendar Scraper — lightweight Python (no browser needed!)
#
# SG-Captcha is a pure JavaScript proof-of-work puzzle (SHA1), not a behavioral/
# TLS fingerprint system. We solve it with plain HTTP requests — no Playwright,
# no Chromium, no Xvfb. Solves in ~200ms.
#
# Container size: ~150MB (vs ~1.5GB for the Playwright image).

FROM python:3.12-slim

WORKDIR /app

# Install dependencies.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the scraper.
COPY scrape_and_push.py ./

# Env vars (override in docker-compose / Portainer).
ENV WORKER_URL=""
ENV WORKER_INGEST_SECRET=""
ENV SCRAPE_INTERVAL_HOURS="24"

# Run in loop mode (scrape → wait → repeat).
CMD ["python3", "scrape_and_push.py", "--loop"]
