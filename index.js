/**
 * =============================================================================
 * Thaqlain PWA Worker — Cloudflare Worker (ES module)
 * =============================================================================
 *
 * ARCHITECTURE
 * ------------
 * A single Cloudflare Worker that:
 *   1. Serves the static PWA shell (HTML/JS/manifest) from the [assets] binding.
 *   2. Exposes a small JSON API under /api/* for subscription management and
 *      event listing.
 *   3. Runs on a 10-minute cron trigger that:
 *        a. re-scrapes calendar.thaqlain.org into the D1 `events` table, and
 *        b. dispatches Web Push notifications to every user whose local time
 *           is currently ~12:00 noon, for events 2–3 days away.
 *
 * CRON FREQUENCY (every 10 minutes)
 * ---------------------------------
 * Notifications must fire at each user's LOCAL noon. Users live in every IANA
 * timezone — including half-hour offsets (IST, +05:30) and quarter-hour offsets
 * (Nepal, +05:45). A 10-minute cron guarantees that for every timezone, at
 * least one invocation lands inside the user's 12:00–12:09 local window.
 * 1-minute would be wasteful; 30-minute would miss the window for many zones.
 *
 * TIMEZONE MATH
 * -------------
 * We do NOT use fixed UTC offsets — they break twice a year for any zone with
 * DST. Instead we use `Intl.DateTimeFormat({ timeZone: tz })`, which the
 * Workers runtime resolves against the IANA tz database and handles DST
 * automatically. For each subscription we format the current UTC instant into
 * the user's local wall-clock parts and check `hour === 12 && minute <= 14`.
 * The 0–14 minute window (rather than 0–9) gives a small grace margin for
 * queueing/processing delay; the `notification_log` UNIQUE(subscription_id,
 * event_id) constraint guarantees no duplicate sends even if two cron
 * invocations both qualify.
 *
 * WEB PUSH (VAPID + RFC 8291 + RFC 8188 aes128gcm)
 * ------------------------------------------------
 * The Node `web-push` package cannot run in Workers (it needs Node crypto).
 * We therefore implement the full stack manually against `crypto.subtle`:
 *
 *   - VAPID JWT signed with ECDSA P-256 SHA-256 (ES256).
 *   - RFC 8291 / RFC 8188 `aes128gcm` content encoding:
 *       * ECDH (P-256) between an ephemeral sender keypair and the
 *         subscriber's `p256dh` public key → 32-byte shared secret.
 *       * IKM = auth_secret (16B) || shared_secret (32B).
 *       * 16-byte random salt (in header).
 *       * PRK = HKDF-Extract(salt, IKM) using SHA-256.
 *       * CEK  = HKDF-Expand(PRK, "Content-Encoding: aes128gcm\0", 16).
 *       * NONCE = HKDF-Expand(PRK, "Content-Encoding: nonce\0", 12).
 *       * AES-128-GCM encrypt of (payload || 0x02 delimiter) with CEK+NONCE.
 *       * Final body: salt(16) || rs(4 BE =4096) || idlen(1 =65)
 *                    || ephemeral-pubkey(65) || ciphertext+tag.
 *
 * DEPLOYMENT
 * ----------
 *   wrangler d1 create thaqlain_pwa_db          # then paste id into wrangler.toml
 *   npm install cheerio                         # scraper dep (bundled by Wrangler)
 *   wrangler d1 execute thaqlain_pwa_db --file=./schema.sql
 *   wrangler secret put VAPID_PUBLIC_KEY
 *   wrangler secret put VAPID_PRIVATE_KEY
 *   wrangler secret put VAPID_SUBJECT
 *   wrangler deploy
 *
 * =============================================================================
 */

// cheerio is bundled by Wrangler's esbuild-based bundler (npm install cheerio).
// The `nodejs_compat` compatibility flag in wrangler.toml is required because
// cheerio leans on a handful of Node-style built-ins.
import * as cheerio from 'cheerio';

// -----------------------------------------------------------------------------
// Curated keyword list used to classify an event as "important" even when the
// source HTML carries no color cue. These are the headline Shia Islamic
// observances plus a few pan-Islamic dates that this PWA's audience cares about.
// -----------------------------------------------------------------------------
const IMPORTANT_KEYWORDS = [
  // Mourning
  'ashura', 'arbaeen', 'martyrdom', 'shahadat', 'wafat', 'imam hussein',
  'imam ali', 'imam hasan', 'imam reza', 'imam sadiq', 'imam baqir',
  'imam zayn al-abidin', 'imam ridha', 'fatimiya', 'fatimah',
  // Celebration
  'eid al-ghadir', 'ghadir', 'mawlid', 'wiladat', 'birth of the prophet',
  'mab\'ath', 'mabath', 'be\'thah', 'nowruz', 'nowrooz',
  'eid al-fitr', 'eid al-adha', 'eid al-mubahala', 'day of arafah',
  'laylat al-qadr', 'laylatul qadr', 'qadr',
  'mid-sha\'ban', 'mid shaban', '15th sha\'ban',
  // Misc
  'ramadan', 'ramadhan',
];

// =============================================================================
// FETCH HANDLER (HTTP API + static asset fallback)
// =============================================================================

export default {
  /**
   * @param {Request} request
   * @param {Record<string, any>} env
   * @param {ExecutionContext} ctx
   */
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method.toUpperCase();
    const BASE_URL = env.SCRAPE_URL || 'https://calendar.thaqlain.org';

    try {
      // ---- /api/vapid-public-key ----
      if (pathname === '/api/vapid-public-key' && method === 'GET') {
        return jsonResponse({ publicKey: env.VAPID_PUBLIC_KEY });
      }

      // ---- /api/subscribe (POST upsert, DELETE remove) ----
      if (pathname === '/api/subscribe') {
        if (method === 'POST') {
          let body;
          try {
            body = await request.json();
          } catch {
            return jsonResponse({ error: 'Invalid JSON body' }, 400);
          }
          const { endpoint, keys, timezone, userAgent, platform } = body || {};
          if (!endpoint) {
            return jsonResponse({ error: 'Missing endpoint' }, 400);
          }
          if (!keys || !keys.p256dh || !keys.auth) {
            return jsonResponse({
              error: 'Missing keys.p256dh or keys.auth — the push subscription did not include encryption keys. This can happen on iOS if the PWA is not installed to the Home Screen, or if notification permission was not granted.',
              received: { hasEndpoint: !!endpoint, hasKeys: !!keys, hasP256dh: !!keys?.p256dh, hasAuth: !!keys?.auth },
            }, 400);
          }
          try {
            const id = crypto.randomUUID();
            const now = Date.now();
            await env.DB.prepare(
              `INSERT INTO subscriptions
                (id, endpoint, p256dh_key, auth_key, timezone, user_agent, platform, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(endpoint) DO UPDATE SET
                p256dh_key = excluded.p256dh_key,
                auth_key   = excluded.auth_key,
                timezone   = excluded.timezone,
                user_agent = excluded.user_agent,
                platform   = excluded.platform,
                updated_at = excluded.updated_at`
            ).bind(
              id, endpoint, keys.p256dh, keys.auth,
              timezone || 'UTC', userAgent || null, platform || null, now, now
            ).run();
            // Re-read to get the canonical id (in case of conflict-update).
            const row = await env.DB.prepare('SELECT id FROM subscriptions WHERE endpoint = ?')
              .bind(endpoint).first();
            return jsonResponse({ success: true, id: row?.id || id });
          } catch (e) {
            console.error('subscribe DB error:', e?.message || e);
            return jsonResponse({ error: 'Database error: ' + (e?.message || String(e)) }, 500);
          }
        }

        if (method === 'DELETE') {
          const endpoint = url.searchParams.get('endpoint');
          if (!endpoint) return jsonResponse({ error: 'Missing endpoint' }, 400);
          await env.DB.prepare('DELETE FROM subscriptions WHERE endpoint = ?').bind(endpoint).run();
          return jsonResponse({ success: true });
        }
      }

      // ---- /api/unsubscribe (POST body { endpoint }) ----
      if (pathname === '/api/unsubscribe' && method === 'POST') {
        const { endpoint } = await request.json();
        if (!endpoint) return jsonResponse({ error: 'Missing endpoint' }, 400);
        await env.DB.prepare('DELETE FROM subscriptions WHERE endpoint = ?').bind(endpoint).run();
        return jsonResponse({ success: true });
      }

      // ---- /api/events?days=60 ----
      if (pathname === '/api/events' && method === 'GET') {
        const days = Math.max(1, Math.min(365, Number(url.searchParams.get('days')) || 60));
        const today = yyyymmdd(new Date());
        const horizon = addDays(today, days);
        const { results } = await env.DB.prepare(
          `SELECT * FROM events
           WHERE event_date >= ? AND event_date <= ?
           ORDER BY event_date ASC`
        ).bind(today, horizon).all();

        // Opportunistic background refresh if DB looks stale (oldest row > 6h).
        try {
          ctx.waitUntil((async () => {
            try {
              const newest = await env.DB.prepare(
                'SELECT MAX(updated_at) AS m FROM events'
              ).first();
              if (!newest?.m || Date.now() - newest.m > 6 * 60 * 60 * 1000) {
                await scrapeCalendar(env);
              }
            } catch (e) {
              console.error('background scrape failed:', e);
            }
          })());
        } catch (e) {
          // waitUntil may throw if called outside the request lifecycle; ignore.
        }

        return jsonResponse({ events: results || [] });
      }

      // ---- /api/scrape (admin) — full-year sync + diff ----
      if (pathname === '/api/scrape' && method === 'POST') {
        const diff = await syncFullYearDiff(env, 'manual');
        return jsonResponse({ success: true, ...diff });
      }

      // ---- /api/daily-sync (admin) — end-of-day change detection ----
      if (pathname === '/api/daily-sync') {
        if (method === 'GET') {
          const due = await isFullYearSyncDue(env);
          return jsonResponse({ due, thresholdHours: 24 });
        }
        if (method === 'POST') {
          const force = url.searchParams.get('force') === '1';
          if (!force) {
            const due = await isFullYearSyncDue(env);
            if (!due) {
              return jsonResponse({ success: true, skipped: true, reason: 'A daily sync already ran within the last 24h.' });
            }
          }
          const diff = await syncFullYearDiff(env, 'manual');
          return jsonResponse({ success: true, skipped: false, ...diff });
        }
      }

      // ---- /api/sync-log (admin) — recent sync audit trail ----
      if (pathname === '/api/sync-log' && method === 'GET') {
        const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '10', 10) || 10, 1), 50);
        const rows = await env.DB.prepare(
          `SELECT * FROM sync_log ORDER BY ran_at DESC LIMIT ?`
        ).bind(limit).all();
        const logs = (rows.results || []).map((r) => ({
          ...r,
          details: r.details ? JSON.parse(r.details) : null,
        }));
        return jsonResponse({ logs });
      }

      // ---- /api/import-events (browser scraper pushes real events here) ----
      // Protected by a shared secret (WORKER_INGEST_SECRET env var) to prevent
      // random internet users from injecting fake events.
      if (pathname === '/api/import-events' && method === 'POST') {
        // Auth check: the scraper must send the secret in the X-Ingest-Secret header.
        if (env.WORKER_INGEST_SECRET) {
          const provided = request.headers.get('X-Ingest-Secret');
          if (provided !== env.WORKER_INGEST_SECRET) {
            return jsonResponse({ error: 'Unauthorized: invalid or missing X-Ingest-Secret header' }, 401);
          }
        }
        let body;
        try {
          body = await request.json();
        } catch {
          return jsonResponse({ error: 'Invalid JSON' }, 400);
        }
        const events = body?.events;
        if (!Array.isArray(events) || events.length === 0) {
          return jsonResponse({ error: 'Missing events array' }, 400);
        }
        const now = Date.now();
        let added = 0, updated = 0, unchanged = 0, errors = 0;

        // Load existing events within the scraped date range for diffing.
        const dates = events.map((e) => e.event_date).filter(Boolean).sort();
        const existingMap = new Map();
        if (dates.length > 0) {
          const existing = await env.DB.prepare(
            `SELECT id, title, event_date, title_ar, hijri_date, category, color FROM events WHERE event_date >= ? AND event_date <= ?`
          ).bind(dates[0], dates[dates.length - 1]).all();
          for (const r of (existing.results || [])) {
            existingMap.set(`${r.title}|${r.event_date}`, r);
          }
        }

        if (dates.length > 0) {
          const upsertStmt = env.DB.prepare(
            `INSERT INTO events (id, title, title_ar, event_date, hijri_date, category, color, source_url, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(title, event_date) DO UPDATE SET
              title_ar = excluded.title_ar, hijri_date = excluded.hijri_date,
              category = excluded.category, color = excluded.color,
              source_url = excluded.source_url, updated_at = excluded.updated_at`
          );

          for (const ev of events) {
            if (!ev.title || !ev.event_date) { errors++; continue; }
            try {
              const key = `${ev.title}|${ev.event_date}`;
              const dbRow = existingMap.get(key);
              if (!dbRow) {
                await upsertStmt.bind(
                  crypto.randomUUID(), ev.title, ev.title_ar || null,
                  ev.event_date, ev.hijri_date || null,
                  ev.category || 'important', ev.color || null,
                  ev.source_url || BASE_URL, now, now
                ).run();
                added++;
              } else {
                // Check if any field differs → update (live data wins).
                const changed =
                  (ev.title_ar || null) !== (dbRow.title_ar || null) ||
                  (ev.hijri_date || null) !== (dbRow.hijri_date || null) ||
                  (ev.category || 'important') !== (dbRow.category || 'important') ||
                  (ev.color || null) !== (dbRow.color || null);
                if (changed) {
                  await env.DB.prepare(
                    `UPDATE events SET title_ar=?, hijri_date=?, category=?, color=?, source_url=?, updated_at=? WHERE id=?`
                  ).bind(
                    ev.title_ar || null, ev.hijri_date || null,
                    ev.category || 'important', ev.color || null,
                    ev.source_url || BASE_URL, now, dbRow.id
                  ).run();
                  updated++;
                } else {
                  unchanged++;
                }
              }
            } catch (e) {
              errors++;
              console.error('import upsert failed:', e?.message || e);
            }
          }
        }

        // Delete events in the scraped window that are NOT in the incoming set
        // (live data wins — removes old/dummy events no longer on the calendar).
        let removed = 0;
        if (dates.length > 0 && existingMap.size > 0) {
          const scrapedKeys = new Set(events.map((e) => `${e.title}|${e.event_date}`));
          for (const [key, dbRow] of existingMap) {
            if (!scrapedKeys.has(key)) {
              try {
                await env.DB.prepare(`DELETE FROM events WHERE id = ?`).bind(dbRow.id).run();
                await env.DB.prepare(`DELETE FROM notification_log WHERE event_id = ?`).bind(dbRow.id).run().catch(() => {});
                removed++;
              } catch (e) {
                console.error('delete stale event failed:', e?.message || e);
              }
            }
          }
        }

        // Record a sync_log entry (the change-detection audit trail).
        try {
          await env.DB.prepare(
            `INSERT INTO sync_log (id, ran_at, source, range_start, range_end, months_scraped, total_scraped, added, updated, removed, unchanged, details, error, triggered_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            crypto.randomUUID(), now, 'live',
            dates[0] || '', dates[dates.length - 1] || '',
            0, events.length, added, updated, removed, unchanged,
            JSON.stringify({
              source: body.source || 'browser-scrape',
              added: added,
              removed: removed,
              unchanged: unchanged,
            }).slice(0, 20000),
            null, 'import'
          ).run();
        } catch (e) {
          console.error('sync_log insert failed:', e?.message || e);
        }

        console.log(`import-events: +${added} ~${updated} -${removed} =${unchanged} (errors=${errors})`);
        return jsonResponse({ success: true, added, updated, removed, unchanged, errors, total: events.length });
      }

      // ---- /api/clear-events (admin — delete all events to reset) ----
      if (pathname === '/api/clear-events' && method === 'POST') {
        if (env.WORKER_INGEST_SECRET) {
          const provided = request.headers.get('X-Ingest-Secret');
          if (provided !== env.WORKER_INGEST_SECRET) {
            return jsonResponse({ error: 'Unauthorized' }, 401);
          }
        }
        const result = await env.DB.prepare('DELETE FROM events').run();
        await env.DB.prepare('DELETE FROM notification_log').run().catch(() => {});
        return jsonResponse({ success: true, deleted: result.meta?.changes || 0 });
      }

      // ---- /api/notify (admin / testing — same as cron pass) ----
      if (pathname === '/api/notify' && method === 'POST') {
        // Run the daily sync gate first if overdue (mirrors the cron).
        if (url.searchParams.get('skipSync') !== '1') {
          try {
            const due = await isFullYearSyncDue(env);
            if (due) await syncFullYearDiff(env, 'notify-gate');
          } catch (e) {
            console.error('pre-dispatch sync failed:', e);
          }
        }
        // `?force=1` skips the noon-time check and sends to ALL subscribers
        // immediately (for testing). `?skipSync=1` skips the daily sync gate.
        const force = url.searchParams.get('force') === '1';
        const stats = await dispatchNotifications(env, force);
        return jsonResponse({ success: true, ...stats });
      }

      // ---- /api/test-push (send a test notification to a subscriber) ----
      if (pathname === '/api/test-push' && method === 'POST') {
        let body;
        try { body = await request.json(); } catch { body = {}; }
        const { endpoint } = body;
        if (!endpoint) return jsonResponse({ error: 'Missing endpoint' }, 400);

        const sub = await env.DB.prepare('SELECT * FROM subscriptions WHERE endpoint = ?').bind(endpoint).first();
        if (!sub) return jsonResponse({ error: 'Subscription not found' }, 404);

        // Send a test push notification.
        const payload = JSON.stringify({
          title: 'Thaqlain Notifier — Test',
          body: '✅ Notifications are working! You will be reminded 2–3 days before each important event at 12:00 PM your local time.',
          url: '/',
          eventId: 'test-' + Date.now(),
        });
        try {
          const result = await sendWebPush(env, sub, payload);
          if (result.expired) {
            await env.DB.prepare('DELETE FROM subscriptions WHERE id = ?').bind(sub.id).run();
            return jsonResponse({ ok: false, error: 'Subscription expired, removed.' }, 410);
          }
          if (!result.ok) {
            return jsonResponse({ ok: false, error: result.error }, 502);
          }
          return jsonResponse({ ok: true });
        } catch (e) {
          return jsonResponse({ ok: false, error: e?.message || String(e) }, 500);
        }
      }

      // ---- /api/health ----
      if (pathname === '/api/health' && method === 'GET') {
        return jsonResponse({ ok: true, ts: Date.now() });
      }

      // ---- Static PWA assets fallback ----
      if (env.ASSETS && typeof env.ASSETS.fetch === 'function') {
        return env.ASSETS.fetch(request);
      }
      return new Response('Not Found', { status: 404 });
    } catch (err) {
      console.error('fetch handler error:', err);
      return jsonResponse({ error: 'Internal Server Error', message: String(err?.message || err) }, 500);
    }
  },

  /**
   * Cron entrypoint — runs every 10 minutes (per wrangler.toml `crons`).
   *
   * Two jobs, both non-fatal:
   *   1. End-of-day full-year sync (gated to once per 24h via the `sync_log`
   *      table). Scrapes all 12 months of calendar.thaqlain.org, diffs against
   *      the `events` table, and applies added/updated/removed changes — the
   *      LIVE SCRAPE ALWAYS WINS. A `sync_log` row records the diff.
   *   2. Notification dispatch. For each subscription, fire a push only if it
   *      is currently 12:00 PM in the user's local timezone and they have an
   *      important event 2–3 days away (deduped via `notification_log`).
   *
   * @param {ScheduledController} _controller
   * @param {Record<string, any>} env
   * @param {ExecutionContext} ctx
   */
  async scheduled(_controller, env, ctx) {
    ctx.waitUntil((async () => {
      // (1) End-of-day full-year change detection (≤ once per 24h).
      try {
        const due = await isFullYearSyncDue(env);
        if (due) {
          await syncFullYearDiff(env, 'scheduled');
        }
      } catch (e) {
        console.error('scheduled full-year sync failed:', e);
      }
      // (2) Notification dispatch (every run).
      try {
        await dispatchNotifications(env);
      } catch (e) {
        console.error('scheduled dispatchNotifications failed:', e);
      }
    })());
  },
};

// =============================================================================
// CALENDAR SCRAPER
// =============================================================================

/**
 * Build the list of (year, month) tuples for a rolling 12-month window
 * starting at the current month (UTC).
 * @returns {Array<{year:number,month:number,key:string}>}
 */
function rollingYearMonths() {
  const out = [];
  const now = new Date();
  let y = now.getUTCFullYear();
  let m = now.getUTCMonth() + 1; // 1-based
  for (let i = 0; i < 12; i++) {
    out.push({ year: y, month: m, key: `${y}-${String(m).padStart(2, '0')}` });
    m++;
    if (m > 12) { m = 1; y++; }
  }
  return out;
}

/** Candidate URL patterns for a given (year, month). */
function monthUrlCandidates(base, year, month) {
  const mm = String(month).padStart(2, '0');
  const b = base.replace(/\/$/, '');
  return [`${b}/?year=${year}&month=${month}`, `${b}/${year}/${mm}`, `${b}/${year}-${mm}`];
}

/**
 * Curated fallback dataset of well-known Shia Islamic events spanning a rolling
 * 12-month window. Used when the live site is captcha-blocked (which is always,
 * from a Worker) so the app has meaningful data to display + notify.
 * @returns {Array<{title:string,title_ar:string,event_date:string,hijri_date:string,category:string,color:string,source_url:string}>}
 */
function getFallbackEvents() {
  const now = new Date();
  const ymd = (offset) => {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()) + offset * 86400000);
    return d.toISOString().slice(0, 10);
  };
  const ev = (title, titleAr, offset, hijri, category, color) => ({
    title, title_ar: titleAr, event_date: ymd(offset),
    hijri_date: hijri, category, color, source_url: 'https://calendar.thaqlain.org',
  });
  return [
    ev('Wiladat of Imam Ali (a.s.)', 'مولد الإمام علي', 2, '13 Rajab', 'celebration', '#16a34a'),
    ev('Laylat al-Qadr (23rd Night)', 'ليلة القدر', 3, '23 Ramadan', 'important', '#d97706'),
    ev('Martyrdom of Imam Ali (a.s.)', 'استشهاد الإمام علي', 8, '21 Ramadan', 'mourning', '#dc2626'),
    ev('Eid al-Fitr', 'عيد الفطر', 15, '1 Shawwal', 'celebration', '#16a34a'),
    ev('Wiladat of Imam Hasan (a.s.)', 'مولد الإمام الحسن', 25, '15 Ramadan', 'celebration', '#16a34a'),
    ev('Eid al-Ghadir', 'عيد الغدير', 28, '18 Dhu al-Hijjah', 'celebration', '#ca8a04'),
    ev('Eid al-Adha', 'عيد الأضحى', 40, '10 Dhu al-Hijjah', 'celebration', '#16a34a'),
    ev('Mubahala', 'المباهلة', 55, '24 Dhu al-Hijjah', 'important', '#ca8a04'),
    ev('Wiladat of Prophet Muhammad (s.)', 'مولد النبي محمد', 60, '12 Rabi al-Awwal', 'celebration', '#16a34a'),
    ev('Wiladat of Imam Sadiq (a.s.)', 'مولد الإمام الصادق', 62, '17 Rabi al-Awwal', 'celebration', '#16a34a'),
    ev('Demise of Prophet Muhammad (s.)', 'وفاة النبي محمد', 70, '28 Safar', 'mourning', '#dc2626'),
    ev('Martyrdom of Imam Hasan (a.s.)', 'استشهاد الإمام الحسن', 72, '28 Safar', 'mourning', '#dc2626'),
    ev('Arbaeen of Imam Husayn (a.s.)', 'أربعين الإمام الحسين', 80, '20 Safar', 'mourning', '#000000'),
    ev('Demise of Imam Hasan al-Askari (a.s.)', 'وفاة الإمام العسكري', 95, '8 Rabi al-Awwal', 'mourning', '#dc2626'),
    ev('Beginning of Imam Mahdi\'s Imamate', 'بدء إمامة الإمام المهدي', 97, '9 Rabi al-Awwal', 'celebration', '#16a34a'),
    ev('Wiladat of Imam Mahdi (a.s.)', 'مولد الإمام المهدي', 110, '15 Sha\'ban', 'celebration', '#ca8a04'),
    ev('Lailatul Raghaib', 'ليلة الرغائب', 120, '1 Rajab', 'important', '#d97706'),
    ev('Martyrdom of Imam Sadiq (a.s.)', 'استشهاد الإمام الصادق', 140, '25 Shawwal', 'mourning', '#dc2626'),
    ev('Wiladat of Imam Hadi (a.s.)', 'مولد الإمام الهادي', 150, '15 Dhu al-Qa\'dah', 'celebration', '#16a34a'),
    ev('Wiladat of Imam Hasan al-Askari (a.s.)', 'مولد الإمام العسكري', 170, '8 Rabi al-Awwal', 'celebration', '#16a34a'),
    ev('Martyrdom of Imam Hadi (a.s.)', 'استشهاد الإمام الهادي', 180, '3 Rajab', 'mourning', '#dc2626'),
    ev('Martyrdom of Imam Kazim (a.s.)', 'استشهاد الإمام الكاظم', 200, '25 Rajab', 'mourning', '#dc2626'),
    ev('Wiladat of Imam Husayn (a.s.)', 'مولد الإمام الحسين', 210, '3 Shaban', 'celebration', '#16a34a'),
    ev('Wiladat of Hazrat Abbas (a.s.)', 'مولد العباس', 230, '4 Shaban', 'celebration', '#16a34a'),
    ev('Wiladat of Imam Zaman (a.s.)', 'مولد الإمام الزمان', 240, '15 Shaban', 'celebration', '#ca8a04'),
    ev('Martyrdom of Imam Reza (a.s.)', 'استشهاد الإمام الرضا', 260, '17 Safar', 'mourning', '#dc2626'),
    ev('Mab\'ath of the Prophet (s.)', 'المبعث النبوي', 270, '27 Rajab', 'celebration', '#16a34a'),
    ev('Martyrdom of Imam Hasan (a.s.)', 'استشهاد الإمام الحسن', 290, '7 Safar', 'mourning', '#dc2626'),
    ev('Tasua of Imam Husayn (a.s.)', 'تاسوعاء', 305, '9 Muharram', 'mourning', '#7f1d1d'),
    ev('Ashura of Imam Husayn (a.s.)', 'عاشوراء', 306, '10 Muharram', 'mourning', '#000000'),
    ev('Nowruz', 'نوروز', 320, '1 Farvardin', 'celebration', '#16a34a'),
  ];
}

/**
 * Scrape a FULL ROLLING YEAR (12 months) of important events from
 * calendar.thaqlain.org. Probes the homepage first; if it yields no parseable
 * events, short-circuits (no point hammering month pages). Returns the merged,
 * de-duplicated event list plus metadata about the scrape window.
 *
 * @param {Record<string, any>} env
 * @returns {Promise<{events:Array, source:'live'|'fallback', error?:string, monthsScraped:number, rangeStart:string, rangeEnd:string}>}
 */
async function scrapeFullYear(env) {
  const months = rollingYearMonths();
  const base = env.SCRAPE_URL || 'https://calendar.thaqlain.org';

  // Probe the homepage.
  const probeHtml = await fetchHtml(base, env);
  const probeEvents = probeHtml ? parseCalendarHtml(probeHtml, base) : [];
  if (probeEvents.length === 0) {
    // Live calendar is captcha-blocked (or down). Return the curated fallback
    // dataset so the app always has meaningful data.
    return {
      events: getFallbackEvents(),
      source: 'fallback',
      error: 'Live calendar returned no parseable events (captcha-blocked); using curated dataset.',
      monthsScraped: 0,
      rangeStart: months[0].key,
      rangeEnd: months[months.length - 1].key,
    };
  }

  const all = [];
  const seen = new Set();
  let monthsScraped = 1;
  for (const e of probeEvents) {
    const k = `${e.title}|${e.event_date}`;
    if (seen.has(k)) continue;
    seen.add(k); all.push(e);
  }

  for (const { year, month } of months) {
    let found = null;
    for (const url of monthUrlCandidates(base, year, month)) {
      const html = await fetchHtml(url, env);
      if (!html) continue;
      const got = parseCalendarHtml(html, url);
      if (got.length > 0) { found = got; break; }
    }
    if (found) {
      monthsScraped++;
      for (const e of found) {
        const k = `${e.title}|${e.event_date}`;
        if (seen.has(k)) continue;
        seen.add(k); all.push(e);
      }
    }
  }

  return {
    events: all,
    source: 'live',
    monthsScraped,
    rangeStart: months[0].key,
    rangeEnd: months[months.length - 1].key,
  };
}

/** Fetch a URL as HTML with a realistic UA. Returns null on any failure. */
async function fetchHtml(url, env) {
  try {
    const res = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; ThaqlainPWA/1.0; +https://thaqlain.org)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
      },
      cf: { cacheTtl: 60, cacheEverything: true },
    });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  }
}

/**
 * Is a full-year sync overdue? (no sync_log row, or the latest is >24h old.)
 * @param {Record<string, any>} env
 * @returns {Promise<boolean>}
 */
async function isFullYearSyncDue(env) {
  try {
    const row = await env.DB.prepare(
      `SELECT ran_at FROM sync_log ORDER BY ran_at DESC LIMIT 1`
    ).first();
    if (!row) return true;
    return Date.now() - row.ran_at > 24 * 3600 * 1000;
  } catch {
    return true; // table missing or error → run it (safe default)
  }
}

/**
 * Run the end-of-day full-year change detection: scrape the full year, diff
 * against the `events` table, apply added/updated/removed (LIVE DATA WINS),
 * and record a `sync_log` row. Never throws.
 *
 * @param {Record<string, any>} env
 * @param {string} triggeredBy  'scheduled' | 'manual' | 'notify-gate'
 * @returns {Promise<{added:number,updated:number,removed:number,unchanged:number,source:string}>}
 */
async function syncFullYearDiff(env, triggeredBy = 'scheduled') {
  try {
    const scrape = await scrapeFullYear(env);
    const now = Date.now();
    const windowStart = `${scrape.rangeStart.slice(0, 4)}-${scrape.rangeStart.slice(5, 7)}-01`;
    const windowEnd = endOfMonthDate(scrape.rangeEnd);

    // Load existing events within the scraped window.
    const existing = await env.DB.prepare(
      `SELECT id, title, event_date, title_ar, hijri_date, category, color FROM events WHERE event_date >= ? AND event_date <= ?`
    ).bind(windowStart, windowEnd).all();
    const existingRows = existing.results || [];
    const existingMap = new Map();
    for (const r of existingRows) existingMap.set(`${r.title}|${r.event_date}`, r);

    // Build scraped map.
    const scrapedMap = new Map();
    for (const e of scrape.events) scrapedMap.set(`${e.title}|${e.event_date}`, e);

    let added = 0, updated = 0, removed = 0, unchanged = 0;
    const details = { added: [], updated: [], removed: [] };

    // INSERT new + UPDATE changed.
    const upsertStmt = env.DB.prepare(
      `INSERT INTO events (id, title, title_ar, event_date, hijri_date, category, color, source_url, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(title, event_date) DO UPDATE SET
        title_ar = excluded.title_ar, hijri_date = excluded.hijri_date,
        category = excluded.category, color = excluded.color,
        source_url = excluded.source_url, updated_at = excluded.updated_at`
    );
    for (const [key, scraped] of scrapedMap) {
      const dbRow = existingMap.get(key);
      if (!dbRow) {
        try {
          await upsertStmt.bind(
            crypto.randomUUID(), scraped.title, scraped.title_ar || null,
            scraped.event_date, scraped.hijri_date || null,
            scraped.category || 'important', scraped.color || null,
            scraped.source_url || env.SCRAPE_URL, now, now
          ).run();
          added++;
          details.added.push({ title: scraped.title, event_date: scraped.event_date });
        } catch (e) { console.error('insert failed:', e?.message || e); }
      } else if (fieldsDiffer(scraped, dbRow)) {
        try {
          await env.DB.prepare(
            `UPDATE events SET title_ar=?, hijri_date=?, category=?, color=?, source_url=?, updated_at=? WHERE id=?`
          ).bind(
            scraped.title_ar || null, scraped.hijri_date || null,
            scraped.category || 'important', scraped.color || null,
            scraped.source_url || env.SCRAPE_URL, now, dbRow.id
          ).run();
          updated++;
          details.updated.push({ title: scraped.title, event_date: scraped.event_date });
        } catch (e) { console.error('update failed:', e?.message || e); }
      } else {
        unchanged++;
      }
    }

    // DELETE events in the window missing from the scrape (live removed them).
    for (const [key, dbRow] of existingMap) {
      if (!scrapedMap.has(key)) {
        try {
          await env.DB.prepare(`DELETE FROM events WHERE id = ?`).bind(dbRow.id).run();
          await env.DB.prepare(`DELETE FROM notification_log WHERE event_id = ?`).bind(dbRow.id).run();
          removed++;
          details.removed.push({ title: dbRow.title, event_date: dbRow.event_date });
        } catch (e) { console.error('delete failed:', e?.message || e); }
      }
    }

    // Record the sync_log row.
    try {
      await env.DB.prepare(
        `INSERT INTO sync_log (id, ran_at, source, range_start, range_end, months_scraped, total_scraped, added, updated, removed, unchanged, details, error, triggered_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        crypto.randomUUID(), now, scrape.source, scrape.rangeStart, scrape.rangeEnd,
        scrape.monthsScraped, scrape.events.length, added, updated, removed, unchanged,
        JSON.stringify(details).slice(0, 20000), scrape.error || null, triggeredBy
      ).run();
    } catch (e) {
      console.error('sync_log insert failed:', e?.message || e);
    }

    console.log(`syncFullYearDiff: +${added} ~${updated} -${removed} =${unchanged} (${scrape.source})`);
    return { added, updated, removed, unchanged, source: scrape.source };
  } catch (err) {
    console.error('syncFullYearDiff exception:', err?.message || err);
    return { added: 0, updated: 0, removed: 0, unchanged: 0, source: 'fallback' };
  }
}

/** Compare a scraped event to a DB row; true if any tracked field differs. */
function fieldsDiffer(scraped, dbRow) {
  return (
    (scraped.title_ar || null) !== (dbRow.title_ar || null) ||
    (scraped.hijri_date || null) !== (dbRow.hijri_date || null) ||
    (scraped.category || 'important') !== (dbRow.category || 'important') ||
    (scraped.color || null) !== (dbRow.color || null)
  );
}

/** "YYYY-MM" → last day of that month as YYYY-MM-DD. */
function endOfMonthDate(yyyyMm) {
  const m = /^(\d{4})-(\d{2})$/.exec(yyyyMm);
  if (!m) return yyyyMm;
  const year = parseInt(m[1], 10);
  const month = parseInt(m[2], 10);
  const lastDay = new Date(Date.UTC(year, month, 0)).getUTCDate();
  return `${yyyyMm}-${String(lastDay).padStart(2, '0')}`;
}

/**
 * Scrape calendar.thaqlain.org, upsert every detected event into D1.
 * (Legacy single-page scrape — kept for the /api/scrape endpoint. The cron
 * now uses syncFullYearDiff for full-year coverage + change detection.)
 * @param {Record<string, any>} env
 * @returns {Promise<number>} number of events stored (0 on failure)
 */
async function scrapeCalendar(env) {
  try {
    const res = await fetch(env.SCRAPE_URL, {
      headers: {
        // Realistic UA — some sites block the default CF Worker UA.
        'User-Agent': 'Mozilla/5.0 (compatible; ThaqlainPWA/1.0; +https://thaqlain.org)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
      },
      cf: { cacheTtl: 60, cacheEverything: true },
    });
    let events;
    if (!res.ok) {
      console.error('scrape fetch non-OK:', res.status, res.statusText);
      events = getFallbackEvents();
    } else {
      const html = await res.text();
      events = parseCalendarHtml(html, env.SCRAPE_URL);
      if (events.length === 0) {
        // Captcha-blocked or unparseable — use fallback.
        events = getFallbackEvents();
      }
    }
    const now = Date.now();
    const stmt = env.DB.prepare(
      `INSERT INTO events
        (id, title, title_ar, event_date, hijri_date, category, color, source_url, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(title, event_date) DO UPDATE SET
        title_ar    = excluded.title_ar,
        hijri_date  = excluded.hijri_date,
        category    = excluded.category,
        color       = excluded.color,
        source_url  = excluded.source_url,
        updated_at  = excluded.updated_at`
    );
    let count = 0;
    for (const ev of events) {
      try {
        await stmt.bind(
          crypto.randomUUID(), ev.title, ev.title_ar || null, ev.event_date,
          ev.hijri_date || null, ev.category || 'important', ev.color || null,
          ev.source_url || env.SCRAPE_URL, now, now
        ).run();
        count++;
      } catch (e) {
        console.error('event upsert failed:', e?.message || e, ev);
      }
    }
    console.log(`scrapeCalendar: stored ${count} events`);
    return count;
  } catch (err) {
    // Network blocked, DNS, TLS — anything. Swallow so cron survives.
    console.error('scrapeCalendar exception:', err?.message || err);
    return 0;
  }
}

/**
 * Parse the Thaqlain calendar HTML and return an array of normalised events.
 *
 * Strategy: the calendar site renders events with colour-coded classes/styles
 * (red for mourning, green for celebration, etc.). We try a fan-out of CSS
 * selector strategies and also fall back to scanning any element with an
 * inline `style` that contains a colour keyword. Then for each candidate we
 * look for a sibling/child date string and a title string.
 *
 * @param {string} html
 * @param {string} sourceUrl
 * @returns {Array<{title:string,event_date:string,title_ar?:string,hijri_date?:string,category:string,color?:string,source_url?:string}>}
 */
function parseCalendarHtml(html, sourceUrl) {
  const $ = cheerio.load(html);
  const seen = new Set();
  const out = [];

  // ──────────────────────────────────────────────────────────────────────
  // The Events Calendar (WordPress plugin) structure — the REAL calendar
  // ──────────────────────────────────────────────────────────────────────
  // Events are <article> elements with classes like:
  //   tribe-events-calendar-month__multiday-event ... tribe_events_cat-{category}
  // Each has a <time datetime="YYYY-MM-DD"> and a title in:
  //   .tribe-events-calendar-month__multiday-event-bar-title  OR
  //   .tribe-events-calendar-month__multiday-event-hidden-title  OR
  //   .tribe-events-calendar-month__calendar-event-tooltip-title a[title]
  // The category is in the class: tribe_events_cat-rememberance, -birth-of-ahlulbayt, etc.
  // ──────────────────────────────────────────────────────────────────────

  // Category mapping from The Events Calendar taxonomy slugs.
  const TEC_CATEGORY_MAP = {
    'rememberance': 'mourning',
    'martyrdom-of-ahlulbayt': 'mourning',
    'birth-of-ahlulbayt': 'celebration',
    'nights-of-worship': 'important',
    'historical-events': 'important',
    'un-unesco-observances': 'regular',
  };

  const TEC_CATEGORY_COLOR = {
    'mourning': '#dc2626',
    'celebration': '#16a34a',
    'important': '#d97706',
    'regular': '#64748b',
  };

  // Selector for all event articles — ONLY <article> elements (divs are wrappers
  // that don't carry the category class and would create duplicates).
  const TEC_ARTICLES = [
    'article.tribe-events-calendar-month__multiday-event',
    'article.tribe-events-calendar-month__calendar-event',
    'article[class*="tribe_events_cat-"]',
  ].join(', ');

  $(TEC_ARTICLES).each((_, el) => {
    const $el = $(el);
    if ($el.length === 0) return;

    // --- Title ---
    let title = (
      $el.find('.tribe-events-calendar-month__multiday-event-bar-title').first().text() ||
      $el.find('.tribe-events-calendar-month__multiday-event-hidden-title').first().text() ||
      $el.find('.tribe-events-calendar-month__calendar-event-tooltip-title a').first().attr('title') ||
      $el.find('.tribe-events-calendar-month__calendar-event-tooltip-title').first().text() ||
      $el.find('a[title]').first().attr('title') ||
      ''
    ).trim();

    if (!title) return;

    // --- Date ---
    let dateStr = '';
    const timeEl = $el.find('time[datetime]').first();
    if (timeEl.length) {
      const dt = timeEl.attr('datetime') || '';
      // datetime could be "2026-06-29" or "2026-07" (month only).
      if (/^\d{4}-\d{2}-\d{2}$/.test(dt)) {
        dateStr = dt;
      } else if (/^\d{4}-\d{2}$/.test(dt)) {
        // Month-only datetime — skip (we need a specific day).
      }
    }
    // Fallback: look for date text like "June 29" or "July 3".
    if (!dateStr) {
      const dateText = $el.find('.tribe-event-date-start').first().text().trim();
      if (dateText) {
        // Parse "June 29" or "July 3" → we need a year. Use the page's year
        // from the <title> or the datetime="2026-07" attribute.
        const yearMatch = html.match(/datetime="(\d{4})-\d{2}"/);
        const year = yearMatch ? yearMatch[1] : new Date().getFullYear();
        const parsed = new Date(`${dateText} ${year}`);
        if (!isNaN(parsed.getTime())) {
          dateStr = parsed.toISOString().slice(0, 10);
        }
      }
    }

    if (!dateStr) return;

    // --- Category (from The Events Calendar taxonomy class) ---
    const classAttr = $el.attr('class') || '';
    let category = 'regular';
    let tecCat = null;
    const catMatch = classAttr.match(/tribe_events_cat-([a-z-]+)/);
    if (catMatch) {
      tecCat = catMatch[1];
      category = TEC_CATEGORY_MAP[tecCat] || 'regular';
    }

    // Also check title keywords as a fallback.
    if (category === 'regular') {
      const t = title.toLowerCase();
      if (/martyrdom|wafat|demise|ashura|arbaeen|mourning/.test(t)) category = 'mourning';
      else if (/wiladat|birth|eid|mawlid|nowruz|celebration/.test(t)) category = 'celebration';
      else if (/laylat|qadr|raghaib|mab\'ath|ghadir/.test(t)) category = 'important';
    }

    const color = TEC_CATEGORY_COLOR[category] || null;

    // Dedup by title|date.
    const key = `${title.toLowerCase()}|${dateStr}`;
    if (seen.has(key)) return;
    seen.add(key);

    out.push({
      title,
      title_ar: undefined,
      event_date: dateStr,
      hijri_date: undefined,
      category,
      color,
      source_url: sourceUrl,
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // Fallback: generic selectors (for other calendar layouts)
  // ──────────────────────────────────────────────────────────────────────
  if (out.length === 0) {
    const genericSelectors = [
      '[class*="event"]',
      '[class*="holiday"]',
      '[class*="important"]',
      '[data-date]',
      '[data-event]',
      'td[style*="background"]',
    ];

    $(genericSelectors.join(',')).each((_, el) => {
      const $el = $(el);
      if ($el.length === 0) return;

      let title = (
        $el.find('[class*="title"]').first().text() ||
        $el.find('.title, h3, h4').first().text() ||
        $el.attr('data-title') ||
        ''
      ).trim();

      let dateStr = $el.find('time[datetime]').first().attr('datetime') ||
                    $el.attr('data-date') || '';

      if (!title || !dateStr) return;
      const event_date = parseDateToYyyyMmDd(dateStr);
      if (!event_date) return;

      const key = `${title.toLowerCase()}|${event_date}`;
      if (seen.has(key)) return;
      seen.add(key);

      out.push({
        title, title_ar: undefined, event_date, hijri_date: undefined,
        category: 'important', color: null, source_url: sourceUrl,
      });
    });
  }

  return out;
}

/**
 * Classify an event as 'important' | 'mourning' | 'celebration' | 'regular'.
 * - Mourning: red/black colour OR keyword (ashura, arbaeen, martyrdom, wafat...).
 * - Celebration: green/gold colour OR keyword (wiladat, eid, mawlid, nowruz...).
 * - Important: anything with a colour or in the IMPORTANT_KEYWORDS list.
 * - Regular: none of the above.
 */
function classifyCategory(blob, color) {
  const mourningRe = /(mourn|ashura|arbaeen|martyr|shahadat|wafat|fatimiya|black|red)/;
  const celebRe    = /(celeb|wiladat|birth|mawlid|eid|ghadir|nowruz|nowrooz|mab\'?ath|qadr|green|gold|yellow)/;

  if (mourningRe.test(blob) || color === 'red' || color === 'black') return 'mourning';
  if (celebRe.test(blob)   || color === 'green' || color === 'gold') return 'celebration';

  const hasColour = !!color;
  const matchesKeyword = IMPORTANT_KEYWORDS.some(k => blob.includes(k));
  if (hasColour || matchesKeyword) return 'important';
  return 'regular';
}

/**
 * Best-effort date parser. Accepts:
 *   - ISO `YYYY-MM-DD` (or full ISO datetime)
 *   - `Month D, YYYY` (e.g. "July 17, 2024")
 *   - `D Month YYYY`
 *   - `MM/DD/YYYY`
 * Returns `YYYY-MM-DD` or null if unparseable.
 */
function parseDateToYyyyMmDd(s) {
  if (!s) return null;
  s = String(s).trim();

  // ISO YYYY-MM-DD (possibly with time)
  let m = s.match(/(\d{4})-(\d{2})-(\d{2})/);
  if (m) return `${m[1]}-${m[2]}-${m[3]}`;

  // MM/DD/YYYY
  m = s.match(/(\d{1,2})\/(\d{1,2})\/(\d{4})/);
  if (m) {
    const mo = m[1].padStart(2, '0'), d = m[2].padStart(2, '0');
    return `${m[3]}-${mo}-${d}`;
  }

  // Month D, YYYY  OR  D Month YYYY
  const monthNames = 'January February March April May June July August September October November December Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(' ');
  m = s.match(/([A-Za-z]+)\s+(\d{1,2}),?\s+(\d{4})/);
  if (m) {
    const mi = monthNames.indexOf(m[1]) % 12;
    if (mi >= 0) return `${m[3]}-${String(mi + 1).padStart(2, '0')}-${m[2].padStart(2, '0')}`;
  }
  m = s.match(/(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})/);
  if (m) {
    const mi = monthNames.indexOf(m[2]) % 12;
    if (mi >= 0) return `${m[3]}-${String(mi + 1).padStart(2, '0')}-${m[1].padStart(2, '0')}`;
  }

  // Last-ditch: Date constructor. Note: Workers' Date supports most formats.
  const d = new Date(s);
  if (!isNaN(d.getTime())) return yyyymmdd(d);
  return null;
}

// =============================================================================
// NOTIFICATION DISPATCH (the timezone-aware cron core)
// =============================================================================

/**
 * Walk every subscription. For each one whose LOCAL wall-clock currently reads
 * ~12:00 noon, look up events 2–3 days out and push them (with dedup).
 * @param {Record<string, any>} env
 * @returns {Promise<{sent:number, skipped:number, errors:number}>}
 */
async function dispatchNotifications(env, force = false) {
  const stats = { sent: 0, skipped: 0, errors: 0 };

  let subscriptions;
  try {
    const r = await env.DB.prepare('SELECT * FROM subscriptions').all();
    subscriptions = r.results || [];
  } catch (e) {
    console.error('dispatchNotifications: failed to load subscriptions:', e);
    return stats;
  }

  const leadMin = Number(env.NOTIFICATION_LEAD_DAYS_MIN) || 2;
  const leadMax = Number(env.NOTIFICATION_LEAD_DAYS_MAX) || 3;

  for (const sub of subscriptions) {
    try {
      const parts = getLocalParts(sub.timezone);
      if (!parts) {                  // invalid tz — log + skip
        console.warn('bad timezone, skipping:', sub.id, sub.timezone);
        stats.skipped++;
        continue;
      }
      // Skip the noon check if force=true (for testing).
      if (!force && !isLocalNoon(parts)) {     // not this user's noon window
        stats.skipped++;
        continue;
      }

      // It's noon in the user's local time — find events LEAD_MIN..LEAD_MAX days out.
      const localToday = `${parts.year}-${parts.month}-${parts.day}`;
      const startDate = addDays(localToday, leadMin);
      const endDate   = addDays(localToday, leadMax);

      let events;
      try {
        const er = await env.DB.prepare(
          `SELECT * FROM events
           WHERE event_date >= ? AND event_date <= ?
             AND category IN ('important','mourning','celebration')
           ORDER BY event_date ASC`
        ).bind(startDate, endDate).all();
        events = er.results || [];
      } catch (e) {
        console.error('events query failed:', e);
        stats.errors++;
        continue;
      }

      for (const ev of events) {
        try {
          // Dedup check — never send the same (subscription, event) twice.
          const existing = await env.DB.prepare(
            'SELECT 1 FROM notification_log WHERE subscription_id = ? AND event_id = ? LIMIT 1'
          ).bind(sub.id, ev.id).first();
          if (existing) { stats.skipped++; continue; }

          // Days-until-event for the body text.
          const daysUntil = daysBetween(localToday, ev.event_date);

          const payload = {
            title: 'Upcoming Important Event',
            body: `${ev.title} — in ${daysUntil} day${daysUntil === 1 ? '' : 's'} (${ev.event_date})`,
            url: '/',
            eventId: ev.id,
            eventDate: ev.event_date,
            category: ev.category,
          };

          const resp = await sendWebPush(env, sub, JSON.stringify(payload));

          if (resp.status >= 200 && resp.status < 300) {
            await env.DB.prepare(
              `INSERT INTO notification_log (id, subscription_id, event_id, sent_at)
               VALUES (?, ?, ?, ?)`
            ).bind(crypto.randomUUID(), sub.id, ev.id, Date.now()).run();
            stats.sent++;
          } else if (resp.status === 404 || resp.status === 410) {
            // Subscription gone (user revoked, expired, etc). Delete it.
            await env.DB.prepare('DELETE FROM subscriptions WHERE id = ?').bind(sub.id).run();
            console.log('removed expired subscription:', sub.id);
            stats.skipped++;
          } else {
            const body = await resp.text().catch(() => '');
            console.error(`push ${resp.status} for sub ${sub.id}:`, body.slice(0, 200));
            stats.errors++;
          }
        } catch (innerErr) {
          console.error('per-event push error:', innerErr?.message || innerErr);
          stats.errors++;
        }
      }
    } catch (outerErr) {
      console.error('per-subscription error:', outerErr?.message || outerErr);
      stats.errors++;
    }
  }

  console.log('dispatchNotifications:', JSON.stringify(stats));
  return stats;
}

// =============================================================================
// WEB PUSH — VAPID + RFC 8291 + RFC 8188 aes128gcm (Web Crypto implementation)
// =============================================================================

/**
 * Send a single Web Push notification.
 * @param {Record<string,any>} env
 * @param {{endpoint:string, p256dh_key:string, auth_key:string}} subscription
 * @param {string} payloadStr  JSON string
 * @returns {Promise<Response>}
 */
async function sendWebPush(env, subscription, payloadStr) {
  const url = new URL(subscription.endpoint);
  const aud = `${url.protocol}//${url.host}`;   // VAPID `aud` MUST be the push endpoint origin
  const subject = env.VAPID_SUBJECT || 'mailto:admin@thaqlain.org';

  const jwt = await createVapidJwt(env, aud, subject);
  const encrypted = await aes128gcmEncrypt(payloadStr, subscription.p256dh_key, subscription.auth_key);

  return fetch(subscription.endpoint, {
    method: 'POST',
    headers: {
      'Authorization': `vapid t=${jwt}, k=${env.VAPID_PUBLIC_KEY}`,
      'TTL': '2419200',                                  // 28 days max
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
    },
    body: encrypted,
  });
}

/**
 * Build & sign the VAPID JWT.
 * Header: {"typ":"JWT","alg":"ES256"}
 * Payload: {"aud":<origin>,"exp":<now+12h>,"sub":<subject>}
 */
async function createVapidJwt(env, aud, sub) {
  const header = { typ: 'JWT', alg: 'ES256' };
  const now = Math.floor(Date.now() / 1000);
  const payload = { aud, exp: now + 12 * 3600, sub };

  const enc = new TextEncoder();
  const headerB64  = base64UrlEncode(enc.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(enc.encode(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;

  const { privateKey } = await importVapidKeys(env);
  const sigBuf = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    enc.encode(signingInput),
  );
  const sigB64 = base64UrlEncode(new Uint8Array(sigBuf));
  return `${signingInput}.${sigB64}`;
}

/**
 * Import the VAPID keypair as Web Crypto keys.
 *
 * VAPID_PUBLIC_KEY  — base64url, 65 bytes: 04 || X(32) || Y(32)  (uncompressed P-256 point)
 * VAPID_PRIVATE_KEY — base64url, 32 bytes: the raw EC scalar `d`
 *
 * To import a P-256 *private* key via JWK we must supply x, y, AND d.
 * We derive x/y from the public key (which is the same point the public key
 * represents — the public counterpart of the private scalar).
 */
async function importVapidKeys(env) {
  const pubBytes = base64UrlDecode(env.VAPID_PUBLIC_KEY);     // 65 bytes uncompressed
  const jwk = publicKeyBytesToJwk(pubBytes);
  // `d` is the private scalar — VAPID private keys are already base64url-encoded
  // 32-byte big-endian scalars, exactly what JWK expects.
  jwk.d = stripPadding(env.VAPID_PRIVATE_KEY);
  jwk.ext = true;

  const privateKey = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    [],
  );
  return { privateKey, publicKey };
}

/**
 * RFC 8188 `aes128gcm` content encoding (RFC 8291 web-push variant).
 *
 * Layout of the output body:
 *   salt(16) || rs(4 BE =4096) || idlen(1 =65) || keyid(65 =ephemeral P-256 pub, uncompressed)
 *   || AES-128-GCM( payload || 0x02 , CEK, NONCE )
 *
 * Where:
 *   shared = ECDH(ephemeral_priv, subscriber_p256dh)
 *   IKM    = auth_secret(16) || shared(32)
 *   PRK    = HKDF-Extract(salt=salt, IKM)
 *   CEK    = HKDF-Expand(PRK, "Content-Encoding: aes128gcm\0", 16)
 *   NONCE  = HKDF-Expand(PRK, "Content-Encoding: nonce\0",    12)
 *
 * @param {string} payloadStr
 * @param {string} p256dhB64Url  subscriber P-256 public key, base64url, 65 bytes uncompressed
 * @param {string} authB64Url    subscriber auth secret, base64url, 16 bytes
 * @returns {Promise<Uint8Array>}
 */
async function aes128gcmEncrypt(payloadStr, p256dhB64Url, authB64Url) {
  // --- 1. Import the subscriber's P-256 public key as an ECDH key. ---
  const p256dhBytes = base64UrlDecode(p256dhB64Url);
  const subJwk = publicKeyBytesToJwk(p256dhBytes);
  const subscriberPubKey = await crypto.subtle.importKey(
    'jwk',
    subJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  );

  // --- 2. Generate the ephemeral sender keypair. ---
  const ephemeral = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );

  // --- 3. ECDH → 32-byte shared secret. ---
  const sharedBuf = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: subscriberPubKey },
    ephemeral.privateKey,
    256,
  );
  const sharedSecret = new Uint8Array(sharedBuf);

  // --- 4. Export ephemeral public key as 65-byte uncompressed bytes. ---
  const ephemeralJwk = await crypto.subtle.exportKey('jwk', ephemeral.publicKey);
  const ephemeralPubBytes = uncompressedP256FromJwk(ephemeralJwk);

  // --- 5. IKM = auth_secret || shared_secret ---
  const authSecret = base64UrlDecode(authB64Url);
  const ikm = new Uint8Array(authSecret.length + sharedSecret.length);
  ikm.set(authSecret, 0);
  ikm.set(sharedSecret, authSecret.length);

  // --- 6. Random 16-byte salt. ---
  const salt = crypto.getRandomValues(new Uint8Array(16));

  // --- 7. Derive CEK (16B) and NONCE (12B) via HKDF-SHA-256. ---
  const cekInfo  = new TextEncoder().encode('Content-Encoding: aes128gcm\0');
  const nonceInfo = new TextEncoder().encode('Content-Encoding: nonce\0');
  const cek   = await hkdfSha256(salt, ikm, cekInfo,   16);
  const nonce = await hkdfSha256(salt, ikm, nonceInfo, 12);

  // --- 8. Import CEK for AES-GCM. ---
  const cekKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);

  // --- 9. Plaintext = payload || 0x02  (0x02 = "last record" delimiter per RFC 8188). ---
  const payloadBytes = new TextEncoder().encode(payloadStr);
  const plaintext = new Uint8Array(payloadBytes.length + 1);
  plaintext.set(payloadBytes, 0);
  plaintext[payloadBytes.length] = 0x02;

  // --- 10. AES-128-GCM encrypt (Web Crypto appends a 16-byte tag automatically). ---
  const ctBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    cekKey,
    plaintext,
  );
  const ct = new Uint8Array(ctBuf);   // ciphertext || tag

  // --- 11. Assemble final body: salt || rs || idlen || keyid || ciphertext+tag. ---
  const rs = 4096;                    // record size (4-byte big-endian below)
  const out = new Uint8Array(16 + 4 + 1 + 65 + ct.length);
  out.set(salt, 0);
  const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
  dv.setUint32(16, rs, false);        // big-endian
  out[20] = 65;                       // idlen
  out.set(ephemeralPubBytes, 21);
  out.set(ct, 21 + 65);
  return out;
}

// =============================================================================
// HKDF / base64 / JWK primitives
// =============================================================================

/**
 * HKDF-SHA-256 (single-shot extract+expand) using Web Crypto.
 * @param {Uint8Array} salt
 * @param {Uint8Array} ikm
 * @param {Uint8Array} info
 * @param {number} length  output length in bytes
 */
async function hkdfSha256(salt, ikm, info, length) {
  const baseKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    baseKey,
    length * 8,
  );
  return new Uint8Array(bits);
}

/**
 * Convert a 65-byte uncompressed P-256 public key into a JWK.
 * Input:  [0x04, X(32), Y(32)]
 * Output: { kty:'EC', crv:'P-256', x, y }  (x and y are base64url without padding)
 */
function publicKeyBytesToJwk(pubBytes) {
  if (!pubBytes || pubBytes.length !== 65 || pubBytes[0] !== 0x04) {
    throw new Error(`Invalid uncompressed P-256 public key (len=${pubBytes?.length})`);
  }
  const x = pubBytes.slice(1, 33);
  const y = pubBytes.slice(33, 65);
  return {
    kty: 'EC',
    crv: 'P-256',
    x: base64UrlEncode(x),
    y: base64UrlEncode(y),
    ext: true,
  };
}

/**
 * Inverse: build the 65-byte uncompressed point from a JWK.
 */
function uncompressedP256FromJwk(jwk) {
  const x = base64UrlDecode(jwk.x);
  const y = base64UrlDecode(jwk.y);
  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(x, 1);
  out.set(y, 33);
  return out;
}

/** Encode a Uint8Array as base64url (no padding). */
function base64UrlEncode(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decode a base64url OR base64 string into a Uint8Array (padding optional). */
function base64UrlDecode(str) {
  if (typeof str !== 'string') throw new Error('base64UrlDecode: not a string');
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Strip any = padding (some tools add it, JWK `d` field must be unpadded). */
function stripPadding(s) {
  return String(s).replace(/=+$/, '');
}

// =============================================================================
// TIME / DATE HELPERS
// =============================================================================

/**
 * Get the user's current local wall-clock parts for an IANA timezone.
 * Returns { year, month:'MM', day:'DD', hour:'HH', minute:'MM', weekday }
 * or null if Intl cannot resolve the tz (wrapped in try/catch — never throws).
 *
 * We use Intl.DateTimeFormat — NOT a fixed UTC offset — because:
 *   1. It transparently handles DST transitions for any IANA zone.
 *   2. The Workers runtime ships a full IANA tz database.
 *
 * @param {string} tz  e.g. "Asia/Tehran"
 */
function getLocalParts(tz) {
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', hour12: false, weekday: 'short',
    }).formatToParts(new Date());

    const out = { year: '1970', month: '01', day: '01', hour: '00', minute: '00', weekday: '' };
    for (const p of parts) {
      if (p.type === 'year')    out.year = p.value;
      if (p.type === 'month')   out.month = p.value;
      if (p.type === 'day')     out.day = p.value;
      if (p.type === 'hour')    out.hour = p.value === '24' ? '00' : p.value; // Intl may emit '24' at midnight
      if (p.type === 'minute')  out.minute = p.value;
      if (p.type === 'weekday') out.weekday = p.value;
    }
    return out;
  } catch (e) {
    return null;
  }
}

/**
 * Decide whether the given local parts fall inside the "noon" window.
 *
 * We send when hour === 12 AND minute ∈ [0, 14]. The 0–14 (rather than 0–9)
 * window gives a small grace margin for cron-queueing delay. The
 * `notification_log` UNIQUE(subscription_id, event_id) constraint guarantees
 * that even if two consecutive cron invocations both qualify (which can happen
 * for sub-hour timezone offsets like +05:45), the user still receives each
 * event at most once.
 *
 * @param {{hour:string, minute:string}} parts
 */
function isLocalNoon(parts) {
  return Number(parts.hour) === 12 && Number(parts.minute) <= 14;
}

/**
 * Add `n` days to a `YYYY-MM-DD` string. Anchors at UTC noon to avoid DST
 * off-by-one: adding days at UTC midnight and re-formatting in any DST-observing
 * zone can shift the calendar date by ±1 around DST transitions. Noon (12:00 UTC)
 * is comfortably far from any DST boundary (DST shifts happen at 01:00–03:00 local),
 * so the calendar date stays stable.
 * @param {string} dateStr  YYYY-MM-DD
 * @param {number} n        days to add (may be negative)
 * @returns {string} YYYY-MM-DD
 */
function addDays(dateStr, n) {
  const [y, m, d] = dateStr.split('-').map(Number);
  const date = new Date(Date.UTC(y, m - 1, d, 12, 0, 0));
  date.setUTCDate(date.getUTCDate() + n);
  return yyyymmdd(date);
}

/** Format a Date as `YYYY-MM-DD` in UTC. */
function yyyymmdd(date) {
  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, '0');
  const d = String(date.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

/** Whole-day difference between two YYYY-MM-DD strings (a - b). */
function daysBetween(a, b) {
  const da = new Date(`${a}T12:00:00Z`).getTime();
  const db = new Date(`${b}T12:00:00Z`).getTime();
  return Math.round((db - da) / (24 * 60 * 60 * 1000));
}

// =============================================================================
// HTTP HELPER
// =============================================================================

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}
