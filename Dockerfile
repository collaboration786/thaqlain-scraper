# Thaqlain Calendar Scraper — lightweight Python (no browser needed).
# Only scrapes the calendar and pushes events to D1. Does NOT handle push
# notifications — the Worker does that natively via the `web-push` library.

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY scrape_and_push.py ./

ENV WORKER_URL=""
ENV WORKER_INGEST_SECRET=""
ENV SCRAPE_INTERVAL_HOURS="24"

CMD ["python3", "scrape_and_push.py", "--loop"]
