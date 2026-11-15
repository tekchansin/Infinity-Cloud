// Infinity Player community share API — Cloudflare Worker + D1.
// Anonymous: submitter gets an owner token back, the only way to delete later.
// Moderation = DELETE with X-Admin-Key (items go live immediately).

const TYPES = ['listening', 'harmonic'];
const DAPS = ['DX340', 'DX340MAX', 'DX320MAX', 'DX320', 'DX270', 'DX260MK2', 'DX180', 'UNKNOWN'];
const MAX_BODY = 32 * 1024;
const MAX_PAYLOAD = 24 * 1024;
const RATE_PER_HOUR = 10; // ponytail: per-IP submit cap via D1 count, move to a rate-limit binding if abused
const PAGE = 50;
const LIST_COLS = 'id, type, name, author, headphone, dap, amp, downloads, created';

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    // ACAO *: everything readable here is public, and the website's Community page reads it from the browser.
    // DELETE needs a preflight we never answer, so browsers still cannot delete cross-site.
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'access-control-allow-origin': '*' },
  });
const err = (status, message) => json({ error: message }, status);

async function sha256(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function randomId(len, alphabet) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return [...bytes].map((b) => alphabet[b % alphabet.length]).join('');
}

// Printable text only, collapsed whitespace, length-capped. Returns null when empty after cleaning.
function cleanText(v, max, required = true) {
  if (typeof v !== 'string') return required ? null : '';
  const s = v.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, ' ').replace(/\s+/g, ' ').trim();
  if (!s) return required ? null : '';
  return [...s].slice(0, max).join('');
}

async function list(url, env) {
  const type = url.searchParams.get('type');
  if (!TYPES.includes(type)) return err(400, 'bad type');
  const where = ['type = ?'];
  const args = [type];
  const dap = url.searchParams.get('dap');
  if (dap) {
    if (!DAPS.includes(dap)) return err(400, 'bad dap');
    where.push('dap = ?');
    args.push(dap);
  }
  const q = cleanText(url.searchParams.get('q') || '', 48, false);
  if (q) {
    // Escape LIKE wildcards so a search for "50%" is literal.
    const like = '%' + q.replace(/[\\%_]/g, (c) => '\\' + c) + '%';
    where.push("(name LIKE ? ESCAPE '\\' OR headphone LIKE ? ESCAPE '\\' OR author LIKE ? ESCAPE '\\')");
    args.push(like, like, like);
  }
  const order = url.searchParams.get('sort') === 'top' ? 'downloads DESC, created DESC' : 'created DESC';
  const offset = Math.max(0, Math.min(10000, parseInt(url.searchParams.get('offset') || '0', 10) || 0));
  const { results } = await env.DB.prepare(
    `SELECT ${LIST_COLS} FROM shares WHERE ${where.join(' AND ')} ORDER BY ${order} LIMIT ${PAGE + 1} OFFSET ?`
  ).bind(...args, offset).all();
  return json({ items: results.slice(0, PAGE), more: results.length > PAGE });
}

// Viewing the detail page must not count — the app calls /download only when the user imports.
async function getItem(id, env) {
  const row = await env.DB.prepare(`SELECT ${LIST_COLS}, payload FROM shares WHERE id = ?`).bind(id).first();
  if (!row) return err(404, 'not found');
  return json({ ...row, payload: JSON.parse(row.payload) });
}

async function countDownload(id, env) {
  const row = await env.DB.prepare('UPDATE shares SET downloads = downloads + 1 WHERE id = ? RETURNING downloads')
    .bind(id).first();
  return row ? json({ downloads: row.downloads }) : err(404, 'not found');
}

// JSON body capped at max (default MAX_BODY); returns the parsed object or an error Response.
async function readJson(request, max = MAX_BODY) {
  const len = parseInt(request.headers.get('content-length') || '0', 10);
  if (len > max) return err(413, 'too large');
  const raw = await request.text();
  if (raw.length > max) return err(413, 'too large');
  try {
    const body = JSON.parse(raw);
    return body && typeof body === 'object' && !Array.isArray(body) ? body : err(400, 'bad json');
  } catch { return err(400, 'bad json'); }
}

const ipHashOf = async (request, env) =>
  sha256((env.SALT || 'infinity-share') + (request.headers.get('cf-connecting-ip') || 'unknown'));

async function submit(request, env) {
  const body = await readJson(request);
  if (body instanceof Response) return body;

  const type = body.type;
  if (!TYPES.includes(type)) return err(400, 'bad type');
  const dap = body.dap;
  if (!DAPS.includes(dap)) return err(400, 'bad dap');
  const name = cleanText(body.name, 40);
  const author = cleanText(body.author, 32);
  if (!name || !author) return err(400, 'name and author required');
  const headphone = cleanText(body.headphone, 48, type === 'listening');
  if (headphone === null) return err(400, 'headphone required');
  // DAPs without an amp slot (DX270, DX180, …) or with a built-in one (DX340MAX) carry no amp card.
  const ampRaw = cleanText(body.amp, 24, false);
  const amp = /^(unknown|internal\b.*)$/i.test(ampRaw) ? '' : ampRaw;
  if (!body.payload || typeof body.payload !== 'object' || Array.isArray(body.payload)) return err(400, 'bad payload');
  const payload = JSON.stringify(body.payload);
  if (payload.length > MAX_PAYLOAD) return err(413, 'payload too large');

  const ipHash = await ipHashOf(request, env);
  const now = Date.now();
  const recent = await env.DB.prepare('SELECT COUNT(*) AS n FROM shares WHERE ip_hash = ? AND created > ?')
    .bind(ipHash, now - 3600_000).first();
  if (recent.n >= RATE_PER_HOUR) return err(429, 'too many submissions, try again later');

  await purgeIpHashes(env);
  const id = randomId(8, 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789');
  const token = randomId(32, '0123456789abcdef');
  await env.DB.prepare(
    'INSERT INTO shares (id, type, name, author, headphone, dap, amp, payload, downloads, created, owner_hash, ip_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)'
  ).bind(id, type, name, author, headphone, dap, amp, payload, now, await sha256(token), ipHash).run();
  return json({ id, token }, 201);
}

// an admin key, compared in constant time (this code is public: github.com/tekchansin/Infinity-Cloud)
function sameKey(given, want) {
  if (!given || !want) return false;
  const a = new TextEncoder().encode(given), b = new TextEncoder().encode(want);
  return a.byteLength === b.byteLength && crypto.subtle.timingSafeEqual(a, b);
}

async function remove(request, id, env) {
  if (sameKey(request.headers.get('x-admin-key'), env.ADMIN_KEY)) {
    await env.DB.prepare('DELETE FROM shares WHERE id = ?').bind(id).run();
    return json({ ok: true });
  }
  const auth = request.headers.get('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!token) return err(401, 'missing token');
  const res = await env.DB.prepare('DELETE FROM shares WHERE id = ? AND owner_hash = ?').bind(id, await sha256(token)).run();
  return res.meta.changes ? json({ ok: true }) : err(403, 'not owner');
}

// ── Website reviews ─────────────────────────────────────────────
// Written on anantarultimate.com/reviews.html, public only after an admin approves them.
const REVIEW_RATE_PER_HOUR = 3;
const REVIEW_COLS = 'id, author, dap, headphone, text, created';
// The form posts JSON and the admin page sends X-Admin-Key, so browsers preflight /v1/reviews*.
// Only those paths answer OPTIONS: Community DELETE (Authorization header) stays browser-proof.
const PREFLIGHT = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, DELETE',
  'access-control-allow-headers': 'content-type, x-admin-key',
  'access-control-max-age': '86400',
};

// REVIEW_ADMIN_KEY is the one kept in a browser (admin page), so it cannot delete Community shares.
const isReviewAdmin = (request, env) => {
  const k = request.headers.get('x-admin-key');
  return sameKey(k, env.REVIEW_ADMIN_KEY) || sameKey(k, env.ADMIN_KEY);
};

// Like cleanText but keeps paragraphs: line breaks survive, runs of blank lines collapse to one.
function cleanLong(v, max) {
  if (typeof v !== 'string') return null;
  const s = v.replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, ' ')
    .replace(/[ \t]+/g, ' ').replace(/ ?\n ?/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
  return s ? [...s].slice(0, max).join('') : null;
}

async function submitReview(request, env) {
  const body = await readJson(request);
  if (body instanceof Response) return body;
  if (body.website) return json({ ok: true }, 201); // honeypot: only bots fill the hidden field — drop it quietly
  const author = cleanText(body.author, 32);
  const text = cleanLong(body.text, 2000);
  if (!author || !text) return err(400, 'name and review required');
  if ([...text].length < 20) return err(400, 'review too short');
  const dap = body.dap || '';
  if (dap && (!DAPS.includes(dap) || dap === 'UNKNOWN')) return err(400, 'bad dap');
  const headphone = cleanText(body.headphone, 48, false);

  const ipHash = await ipHashOf(request, env);
  const now = Date.now();
  const recent = await env.DB.prepare('SELECT COUNT(*) AS n FROM reviews WHERE ip_hash = ? AND created > ?')
    .bind(ipHash, now - 3600_000).first();
  if (recent.n >= REVIEW_RATE_PER_HOUR) return err(429, 'too many reviews, try again later');

  await purgeIpHashes(env);
  await env.DB.prepare(
    "INSERT INTO reviews (id, author, dap, headphone, text, status, created, ip_hash) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)"
  ).bind(randomId(8, 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'), author, dap, headphone, text, now, ipHash).run();
  return json({ ok: true }, 201);
}

async function listReviews(env, status) {
  const { results } = await env.DB.prepare(
    `SELECT ${REVIEW_COLS} FROM reviews WHERE status = ? ORDER BY created DESC LIMIT 500` // ponytail: no paging, add when approved > 500
  ).bind(status).all();
  return json({ items: results });
}

async function reviewAdmin(request, url, env) {
  if (!isReviewAdmin(request, env)) return err(403, 'admin only');
  if (request.method === 'GET' && url.pathname === '/v1/reviews/pending') return listReviews(env, 'pending');
  const m = url.pathname.match(/^\/v1\/reviews\/([A-Z2-9]{8})(\/approve)?$/);
  if (!m) return err(404, 'not found');
  const res = request.method === 'POST' && m[2]
    ? await env.DB.prepare("UPDATE reviews SET status = 'approved' WHERE id = ?").bind(m[1]).run()
    : request.method === 'DELETE' && !m[2]
      ? await env.DB.prepare('DELETE FROM reviews WHERE id = ?').bind(m[1]).run()
      : null;
  if (!res) return err(404, 'not found');
  return res.meta.changes ? json({ ok: true }) : err(404, 'not found');
}

// ── Log reports ─────────────────────────────────────────────────
// Settings › Send Log Report on debug/beta app builds (release builds have no button).
// May hold song file names → readable only with ADMIN_KEY (not REVIEW_ADMIN_KEY), kept 30 days.
const MAX_LOG_BODY = 2 * 1024 * 1024; // raw JSON: escaping + UTF-8 can double the report size
const MAX_REPORT = 768 * 1024; // Infinity for Mac 1.0-beta2 sends up to 700 KB (D1 row limit 2 MB)
const LOG_RATE_PER_HOUR = 5;
const LOG_KEEP_MS = 30 * 86400_000;
const isAdmin = (request, env) => sameKey(request.headers.get('x-admin-key'), env.ADMIN_KEY);

async function submitLog(request, env) {
  const body = await readJson(request, MAX_LOG_BODY);
  if (body instanceof Response) return body;
  if (!DAPS.includes(body.dap)) return err(400, 'bad dap');
  const version = cleanText(body.version, 64);
  if (!version) return err(400, 'version required');
  const note = cleanLong(body.note, 1000) || '';
  if (typeof body.report !== 'string' || !body.report) return err(400, 'report required');
  if (body.report.length > MAX_REPORT) return err(413, 'report too large');

  const ipHash = await ipHashOf(request, env);
  const now = Date.now();
  const recent = await env.DB.prepare('SELECT COUNT(*) AS n FROM logs WHERE ip_hash = ? AND created > ?')
    .bind(ipHash, now - 3600_000).first();
  if (recent.n >= LOG_RATE_PER_HOUR) return err(429, 'too many reports, try again later');

  await purgeIpHashes(env);
  const id = randomId(8, 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789');
  await env.DB.prepare('INSERT INTO logs (id, dap, version, note, report, created, ip_hash) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(id, body.dap, version, note, body.report, now, ipHash).run();
  return json({ id }, 201);
}

async function logAdmin(request, url, env) {
  if (!isAdmin(request, env)) return err(403, 'admin only');
  if (request.method === 'GET' && url.pathname === '/v1/logs') {
    const { results } = await env.DB.prepare(
      'SELECT id, dap, version, note, created, length(report) AS size FROM logs ORDER BY created DESC LIMIT 200'
    ).all();
    return json({ items: results });
  }
  const m = url.pathname.match(/^\/v1\/logs\/([A-Z2-9]{8})$/);
  if (!m) return err(404, 'not found');
  if (request.method === 'DELETE') {
    const res = await env.DB.prepare('DELETE FROM logs WHERE id = ?').bind(m[1]).run();
    return res.meta.changes ? json({ ok: true }) : err(404, 'not found');
  }
  if (request.method !== 'GET') return err(404, 'not found');
  const row = await env.DB.prepare('SELECT * FROM logs WHERE id = ?').bind(m[1]).first();
  if (!row) return err(404, 'not found');
  const head = `${row.id}  ${row.dap}  ${row.version}  ${new Date(row.created).toISOString()}\nNote: ${row.note}\n\n`;
  return new Response(head + row.report, { headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } });
}

// GDPR: ip_hash exists only for the 1-hour submit rate limit — blank it once it is older than that.
// Runs hourly (cron) and on every submit, so the app can promise "erased within 1 hour".
const purgeIpHashes = (env) => {
  const cutoff = Date.now() - 3600_000;
  return env.DB.batch(['shares', 'reviews', 'logs'].map((t) =>
    env.DB.prepare(`UPDATE ${t} SET ip_hash = '' WHERE ip_hash != '' AND created < ?`).bind(cutoff)));
};

export default {
  async scheduled(event, env) {
    await purgeIpHashes(env);
    await env.DB.prepare('DELETE FROM logs WHERE created < ?').bind(Date.now() - LOG_KEEP_MS).run();
  },
  async fetch(request, env) {
    const url = new URL(request.url);
    const m = url.pathname.match(/^\/v1\/item\/([A-Z2-9]{8})$/);
    const dl = url.pathname.match(/^\/v1\/item\/([A-Z2-9]{8})\/download$/);
    try {
      // SOURCE_SHA256 = shasum -a 256 src/index.js at deploy (deploy.sh): the published copy hashes the same
      if (url.pathname === '/v1/health') return json({ ok: true, source: env.SOURCE_SHA256 ?? null });
      if (request.method === 'GET' && url.pathname === '/v1/list') return await list(url, env);
      if (request.method === 'GET' && m) return await getItem(m[1], env);
      if (request.method === 'POST' && dl) return await countDownload(dl[1], env);
      if (request.method === 'POST' && url.pathname === '/v1/submit') return await submit(request, env);
      if (request.method === 'DELETE' && m) return await remove(request, m[1], env);
      if (request.method === 'POST' && url.pathname === '/v1/logs') return await submitLog(request, env);
      if (url.pathname.startsWith('/v1/logs')) return await logAdmin(request, url, env);
      if (url.pathname.startsWith('/v1/reviews')) {
        if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: PREFLIGHT });
        if (request.method === 'GET' && url.pathname === '/v1/reviews') return await listReviews(env, 'approved');
        if (request.method === 'POST' && url.pathname === '/v1/reviews') return await submitReview(request, env);
        return await reviewAdmin(request, url, env);
      }
      return err(404, 'not found');
    } catch (e) {
      return err(500, 'server error');
    }
  },
};
