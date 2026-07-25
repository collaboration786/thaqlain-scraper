#!/usr/bin/env python3
"""
Thaqlain Calendar Scraper — lightweight Python (no browser needed).

SG-Captcha is a pure JavaScript proof-of-work puzzle (SHA1), not a behavioral/
TLS fingerprint system. This means we can solve it with plain HTTP requests —
no Playwright, no Chromium, no Xvfb. Solves in ~50-200ms.

Architecture:
  1. GET the calendar page → get HTTP 202 + captcha redirect
  2. GET the captcha challenge page → extract sgchallenge, sgsubmit_url
  3. Solve the SHA1 proof-of-work (brute-force nonce)
  4. GET the submit URL with the solution → server sets _I_ cookie
  5. Reuse the session cookie for all 13 month requests (real HTML)
  6. Parse events from the HTML (The Events Calendar / WordPress structure)
  7. POST events to the Cloudflare Worker's /api/import-events endpoint

Usage:
  pip install requests beautifulsoup4
  python3 scrape-and-push.py

Env vars:
  WORKER_URL              — your Cloudflare Worker URL
  WORKER_INGEST_SECRET    — shared secret for the import endpoint
  SCRAPE_INTERVAL_HOURS   — hours between scrapes (loop mode)
"""

import hashlib
import base64
import re
import time
import os
import sys
import json
import requests
from bs4 import BeautifulSoup

# ── Config ───────────────────────────────────────────────────────────────────
BASE_URL = "https://calendar.thaqlain.org"
WORKER_URL = os.environ.get("WORKER_URL", "https://thaqlain-pwa-worker.amalmoh24proton-me.workers.dev")
WORKER_INGEST_SECRET = os.environ.get("WORKER_INGEST_SECRET", "")
SCRAPE_INTERVAL_HOURS = float(os.environ.get("SCRAPE_INTERVAL_HOURS", "24"))
LOOP_MODE = "--loop" in sys.argv
MONTHS_TO_SCRAPE = 13

# ── SG-Captcha Solver ────────────────────────────────────────────────────────

def solve_pow(challenge_str, complexity, max_attempts=10_000_000):
    """
    Solve the SG-Captcha proof-of-work.
    Find a nonce so that SHA1(challenge + str(nonce)) has `complexity` leading
    zero bits (checked as: first 4 bytes as big-endian int, right-shifted by
    32-complexity, equals 0).
    """
    challenge_bytes = challenge_str.encode("utf-8")
    mask = 0xFFFFFFFF >> (32 - complexity)  # alternative check
    target_prefix_bits = 32 - complexity

    for nonce in range(max_attempts):
        candidate = challenge_bytes + str(nonce).encode("utf-8")
        h = hashlib.sha1(candidate).digest()
        first_word = int.from_bytes(h[:4], byteorder="big")
        # Check leading zero bits: shift right so the top `complexity` bits
        # become 0 if they were all zero.
        if (first_word >> target_prefix_bits) == 0:
            solution = base64.b64encode(candidate).decode("utf-8")
            return solution, nonce
    return None, None


def solve_captcha(session):
    """
    Detect and solve the SG-Captcha challenge. Sets the _I_ session cookie.
    Returns True if solved (or no captcha present), False on failure.
    """
    # Step 1: fetch the base URL to trigger the captcha.
    resp = session.get(BASE_URL, allow_redirects=False, timeout=15)

    if resp.status_code != 202 or resp.headers.get("sg-captcha") != "challenge":
        # No captcha — already authorized (cookie cached).
        return True

    # Extract the redirect URL from the meta refresh.
    redirect_match = re.search(r'content="0;([^"]+)"', resp.text)
    if not redirect_match:
        print("  Could not find captcha redirect URL")
        return False
    redirect_url = redirect_match.group(1)

    # Step 2: fetch the challenge page.
    challenge_resp = session.get(BASE_URL + redirect_url, timeout=15)
    if challenge_resp.status_code != 200:
        print(f"  Challenge page returned HTTP {challenge_resp.status_code}")
        return False

    # Extract the three JS constants.
    challenge_match = re.search(r'sgchallenge\s*=\s*"([^"]+)"', challenge_resp.text)
    submit_match = re.search(r'sgsubmit_url\s*=\s*"([^"]+)"', challenge_resp.text)
    if not challenge_match or not submit_match:
        print("  Could not extract sgchallenge/sgsubmit_url from challenge page")
        return False

    challenge_str = challenge_match.group(1)
    submit_url = submit_match.group(1)

    # Parse complexity (first field of the challenge, before the first colon).
    parts = challenge_str.split(":")
    complexity = int(parts[0])
    print(f"  SG-Captcha: complexity={complexity}, solving SHA1 PoW...")

    # Step 3: solve the proof-of-work.
    start = time.time()
    solution, nonce = solve_pow(challenge_str, complexity)
    elapsed = time.time() - start
    if not solution:
        print(f"  Failed to solve PoW after {nonce} attempts")
        return False
    print(f"  Solved in {elapsed:.2f}s (nonce={nonce})")

    # Step 4: submit the solution. The server sets the _I_ cookie.
    sol_param = solution  # base64, may need URL-encoding
    submit_full = BASE_URL + submit_url + f"&sol={sol_param}&s=100:{nonce}"
    # Use a proper User-Agent for the submission.
    submit_resp = session.get(submit_full, timeout=15, allow_redirects=True)
    print(f"  Submit returned HTTP {submit_resp.status_code}")

    # Verify the cookie was set.
    if "_I_" in session.cookies.get_dict():
        print("  ✓ _I_ cookie acquired — session authorized")
        return True
    else:
        print("  ⚠ _I_ cookie not found in response — may still work")
        return True  # try anyway


# ── Calendar Parser ──────────────────────────────────────────────────────────

TEC_CATEGORY_MAP = {
    "rememberance": "mourning",
    "martyrdom-of-ahlulbayt": "mourning",
    "birth-of-ahlulbayt": "celebration",
    "nights-of-worship": "important",
    "historical-events": "important",
    "un-unesco-observances": "regular",
}
CATEGORY_COLOR = {
    "mourning": "#dc2626",
    "celebration": "#16a34a",
    "important": "#d97706",
    "regular": "#64748b",
}


def parse_calendar_html(html, year):
    """Parse The Events Calendar HTML and return a list of event dicts."""
    soup = BeautifulSoup(html, "html.parser")
    events = []
    seen = set()

    articles = soup.select(
        "article.tribe-events-calendar-month__multiday-event, "
        "article.tribe-events-calendar-month__calendar-event, "
        "article[class*='tribe_events_cat-']"
    )

    for el in articles:
        # Title
        title = ""
        for selector in [
            ".tribe-events-calendar-month__multiday-event-bar-title",
            ".tribe-events-calendar-month__multiday-event-hidden-title",
            ".tribe-events-calendar-month__calendar-event-tooltip-title a",
            ".tribe-events-calendar-month__calendar-event-tooltip-title",
            "a[title]",
        ]:
            found = el.select_one(selector)
            if found:
                title = found.get("title", "") or found.get_text(strip=True)
                if title:
                    break
        if not title:
            continue

        # Date
        date_str = ""
        time_el = el.find("time", attrs={"datetime": True})
        if time_el:
            dt = time_el["datetime"]
            if re.match(r"^\d{4}-\d{2}-\d{2}$", dt):
                date_str = dt
        if not date_str:
            date_text_el = el.select_one(".tribe-event-date-start")
            if date_text_el:
                date_text = date_text_el.get_text(strip=True)
                try:
                    parsed = time.strptime(f"{date_text} {year}", "%B %d %Y")
                    date_str = time.strftime("%Y-%m-%d", parsed)
                except ValueError:
                    pass
        if not date_str:
            continue

        # Category
        class_attr = " ".join(el.get("class", []))
        category = "regular"
        cat_match = re.search(r"tribe_events_cat-([a-z-]+)", class_attr)
        if cat_match:
            category = TEC_CATEGORY_MAP.get(cat_match.group(1), "regular")

        # Keyword fallback
        if category == "regular":
            t = title.lower()
            if re.search(r"martyrdom|wafat|demise|ashura|arbaeen|mourning", t):
                category = "mourning"
            elif re.search(r"wiladat|birth|eid|mawlid|nowruz|celebration", t):
                category = "celebration"
            elif re.search(r"laylat|qadr|raghaib|mab|ghadir", t):
                category = "important"

        key = f"{title.lower()}|{date_str}"
        if key in seen:
            continue
        seen.add(key)

        events.append({
            "title": title,
            "event_date": date_str,
            "category": category,
            "color": CATEGORY_COLOR.get(category),
            "source_url": BASE_URL,
        })

    return events


# ── Main scrape logic ────────────────────────────────────────────────────────

def scrape_all_months(session):
    """Scrape all 13 months and return deduplicated events."""
    now = time.gmtime()
    months = []
    for i in range(MONTHS_TO_SCRAPE):
        y = now.tm_year + ((now.tm_mon - 1 + i) // 12)
        m = ((now.tm_mon - 1 + i) % 12) + 1
        months.append((y, m))

    all_events = []
    for year, month in months:
        url = f"{BASE_URL}/?tribe_events_month={month}&tribe_events_year={year}"
        print(f"\n  Scraping {year}-{month:02d}...")

        try:
            resp = session.get(url, timeout=20)
            if resp.status_code == 202:
                print(f"    Captcha re-triggered — re-solving...")
                if not solve_captcha(session):
                    print(f"    Failed to re-solve captcha, skipping")
                    continue
                resp = session.get(url, timeout=20)

            if resp.status_code != 200:
                print(f"    HTTP {resp.status_code}, skipping")
                continue

            events = parse_calendar_html(resp.text, year)
            print(f"    Found {len(events)} events")
            all_events.extend(events)
        except Exception as e:
            print(f"    Error: {e}")

        # Be polite.
        time.sleep(1)

    # Dedup across months.
    seen = set()
    deduped = []
    for e in all_events:
        k = f"{e['title'].lower()}|{e['event_date']}"
        if k not in seen:
            seen.add(k)
            deduped.append(e)

    return deduped


def push_to_worker(events):
    """POST the scraped events to the Worker's /api/import-events endpoint."""
    if not events:
        print("No events to push")
        return

    url = f"{WORKER_URL}/api/import-events"
    print(f"\nPushing {len(events)} events to {url}...")
    headers = {"Content-Type": "application/json"}
    if WORKER_INGEST_SECRET:
        headers["X-Ingest-Secret"] = WORKER_INGEST_SECRET

    try:
        resp = requests.post(url, json={"events": events, "source": "python-scraper"}, headers=headers, timeout=30)
        data = resp.json()
        if resp.status_code == 200:
            print(f"  ✓ Import result: {json.dumps(data, indent=2)}")
        else:
            print(f"  ✗ Import failed: HTTP {resp.status_code}: {json.dumps(data)}")
    except Exception as e:
        print(f"  ✗ Push failed: {e}")
        # Save locally as fallback.
        with open("scraped-events.json", "w") as f:
            json.dump(events, f, indent=2)
        print(f"  Events saved to scraped-events.json")


def run_once():
    """Run one complete scrape cycle."""
    print(f"\n{'='*60}")
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}] Starting scrape cycle")
    print(f"{'='*60}")

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })

    print("\nStep 1: Solving SG-Captcha...")
    if not solve_captcha(session):
        print("Failed to solve captcha — aborting")
        return False

    print("\nStep 2: Scraping 13 months...")
    events = scrape_all_months(session)
    print(f"\nTotal unique events: {len(events)}")

    print("\nStep 3: Pushing to Worker...")
    push_to_worker(events)

    return True


def run_loop():
    """Run continuously, scraping every SCRAPE_INTERVAL_HOURS."""
    print(f"=== Loop mode — scraping every {SCRAPE_INTERVAL_HOURS}h ===")
    while True:
        start = time.time()
        try:
            run_once()
        except Exception as e:
            print(f"Scrape cycle failed: {e}")
        elapsed = time.time() - start
        wait_s = SCRAPE_INTERVAL_HOURS * 3600 - elapsed
        if wait_s > 0:
            print(f"\nNext scrape in {wait_s/60:.0f} minutes...")
            time.sleep(wait_s)


if __name__ == "__main__":
    if LOOP_MODE:
        run_loop()
    else:
        success = run_once()
        sys.exit(0 if success else 1)
