// infinity-meta — the "recipe server" (DESKTOP_PLAN §8): one shared cache of what the Mac app looks up about an artist,
// fetched here from the sources (MusicBrainz, Wikidata, Wikipedia, Deezer, Last.fm) — clients only read, so
// nobody can write a bio for everybody. API keys live here as secrets, never in the app. No photo files: answers carry
// the picture's address and the app downloads it from the source. A request carries the artist name and the language,
// nothing about the user (no IP stored).
//   GET /v1/artist?name=<name>&lang=<en|th|ja|zh|ko>  → the Core's /api/artistinfo shape, photo = URL ({status:'none'} if unknown)
const UA = 'InfinityRecipeServer/1.0 (https://anantarultimate.com)';
const KEEP_MS = 30 * 86400_000, RETRY_MS = 10 * 60_000, LANGS = ['en', 'th', 'ja', 'zh', 'ko'];
const WHO = new Set(['Q5', 'Q215380', 'Q5741069', 'Q2088357', 'Q9212979', 'Q216337', 'Q641066']);  // people / bands (Wikidata P31)
const SKIP = new Set(['references', 'external links', 'see also', 'notes', 'further reading', 'sources', 'bibliography', 'discography',
  'filmography', 'awards and nominations', 'footnotes', 'citations', 'track listing', 'personnel', 'charts', 'weekly charts',
  'year-end charts', 'certifications', 'certifications and sales', 'release history', 'credits and personnel']);

const json = (body, status = 200, extra = {}) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'access-control-allow-origin': '*', ...extra },
});
export const norm = (s) => s.replace(/[‐-—]/g, '-').replace(/\s+/g, ' ').trim().toLowerCase();
const get = (url, ms = 12000) => fetch(url, { headers: { 'user-agent': UA, accept: 'application/json' }, signal: AbortSignal.timeout(ms) });
async function getJson(url, ms) {
  try {
    const r = await get(url, ms);
    if (r.ok) return await r.json();
    console.log('upstream', r.status, new URL(url).host)  // error path only (wrangler tail)
  } catch (e) { console.log('upstream failed', new URL(url).host, String(e)) }
  return null;
}

// MusicBrainz asks for one call a second per client; here every user is one client, so the slot is shared through D1
async function mb(env, path, st) {
  for (let i = 0; i < 20; i++) {
    const now = Date.now();
    const r = await env.DB.prepare("UPDATE throttle SET at = ? WHERE name = 'mb' AND at <= ?").bind(now, now - 1100).run();
    if (r.meta.changes === 1) break;
    if (i === 0) await env.DB.prepare("INSERT OR IGNORE INTO throttle (name, at) VALUES ('mb', 0)").run();
    await new Promise((ok) => setTimeout(ok, 300));
  }
  const v = await getJson('https://musicbrainz.org/ws/2/' + path);
  if (!v) st.mbFailed = true;  // busy / no answer: what we got is kept only briefly (artist())
  return v;
}

// HTML of a Wikipedia article → intro + sections, article links as ⟦title|label⟧ (the Core's wikipediaLinked, same rules)
const text = (h) => h.replace(/<[^>]*>/g, '').replace(/&(#x?[0-9a-f]+|amp|quot|apos|lt|gt|nbsp);/gi, (m, e) => {
  const named = { amp: '&', quot: '"', apos: "'", lt: '<', gt: '>', nbsp: ' ' }[e.toLowerCase()];
  if (named) return named;
  const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
  return Number.isFinite(cp) ? String.fromCodePoint(cp === 160 ? 32 : cp) : m;
});
function dropBlocks(h, open, close) {
  for (let a; (a = h.indexOf(open)) !== -1;) {
    let depth = 0, at = a;
    for (;;) {
      const no = h.indexOf(open, at + 1), nc = h.indexOf(close, at + 1);
      if (nc === -1) return h.slice(0, a);
      if (no !== -1 && no < nc) { depth++; at = no; continue }
      if (depth === 0) { h = h.slice(0, a) + h.slice(nc + close.length); break }
      depth--; at = nc;
    }
  }
  return h;
}
export function linkedBio(html) {
  let h = html;
  for (const [o, c] of [['<table', '</table>'], ['<style', '</style>'], ['<sup', '</sup>'], ['<figure', '</figure>']]) h = dropBlocks(h, o, c);
  const titles = new Set();
  h = h.replace(/<a href="\/wiki\/([^"]*)"[^>]*>([\s\S]*?)<\/a>/g, (m, target, inner) => {
    const label = text(inner);
    let t;
    try { t = decodeURIComponent(target).replace(/_/g, ' ') } catch { t = target.replace(/_/g, ' ') }
    t = t.split('#')[0];
    if (!t || t.includes(':') || !label) return label;
    titles.add(t);
    return `⟦${t}|${label}⟧`;
  });
  let intro = null, cur = [], curTitle = '', curLevel = 0, skipping = false;
  const sections = [];
  const flush = () => {
    const t = cur.join('\n').trim();
    if (!skipping && t && sections.length < 14) sections.push({ title: curTitle, level: curLevel, text: t });
    cur = [];
  };
  for (const m of h.matchAll(/<(p|h2|h3)(?:\s[^>]*)?>([\s\S]*?)<\/\1>/g)) {
    if (m[1] === 'p') { const t = text(m[2]).trim(); if (t) cur.push(t); continue }
    const t = text(m[2]).trim();
    if (intro === null) { intro = cur.join('\n').trim(); cur = [] } else flush();
    curTitle = t; curLevel = m[1] === 'h2' ? 2 : 3;
    if (curLevel === 2) skipping = SKIP.has(t.toLowerCase());
  }
  if (intro === null) intro = cur.join('\n').trim(); else flush();
  return { intro, sections, titles: [...titles] };
}

async function wikipedia(lang, title) {
  const v = await getJson(`https://${lang}.wikipedia.org/w/api.php?action=parse&format=json&formatversion=2&redirects=1&prop=text` +
    `&disableeditsection=1&disabletoc=1&page=${encodeURIComponent(title)}`, 15000);
  const html = v?.parse?.text;
  if (!html) return null;
  const b = linkedBio(html);
  if (b.intro.length < 40) return null;
  // which linked titles are people / bands — the batches at once
  const batches = [];
  for (let i = 0; i < b.titles.length && i < 200; i += 50) batches.push(b.titles.slice(i, i + 50));
  const links = {};
  await Promise.all(batches.map(async (batch) => {
    const wd = await getJson(`https://www.wikidata.org/w/api.php?action=wbgetentities&format=json&props=claims|sitelinks&sitefilter=${lang}wiki` +
      `&sites=${lang}wiki&titles=${encodeURIComponent(batch.join('|'))}`, 15000);
    for (const e of Object.values(wd?.entities ?? {})) {
      const person = (e.claims?.P31 ?? []).some((c) => WHO.has(c.mainsnak?.datavalue?.value?.id));
      const t = e.sitelinks?.[lang + 'wiki']?.title;
      if (person && t) links[t] = 'artist';
    }
  }));
  const page = v.parse.title;
  return { lang, title: page, url: `https://${lang}.wikipedia.org/wiki/${encodeURIComponent(page.replace(/ /g, '_'))}`, intro: b.intro,
    sections: b.sections, links };
}

async function deezerPhoto(name) {
  const d = await getJson('https://api.deezer.com/search/artist?limit=6&q=' + encodeURIComponent(name));
  const want = norm(name);
  let best = null;
  for (const x of d?.data ?? []) {
    if (norm(x.name) === want && !String(x.picture_xl).includes('/artist//') && (!best || x.nb_fan > best.nb_fan)) best = x;
  }
  return best ? best.picture_xl.replace('1000x1000', '1500x1500') : '';
}

export async function fetchArtist(env, name, lang, st = { mbFailed: false }) {
  const want = norm(name);
  const out = { name };
  const photo = deezerPhoto(name);  // beside the MusicBrainz → Wikipedia chain
  const sr = await mb(env, 'artist/?fmt=json&limit=8&query=' + encodeURIComponent(`artist:"${name}"`), st);
  const hit = (sr?.artists ?? []).find((a) => a.score >= 90 && (norm(a.name) === want || (a.aliases ?? []).some((al) => norm(al.name) === want)));
  let qid = '';
  if (hit) {
    const a = await mb(env, `artist/${hit.id}?fmt=json&inc=url-rels+artist-rels+genres+tags`, st);
    if (a) {
      Object.assign(out, { mbid: hit.id, type: a.type ?? '', disambiguation: a.disambiguation ?? '', begin: a['life-span']?.begin ?? '',
        end: a['life-span']?.end ?? '', ended: !!a['life-span']?.ended, area: a.area?.name ?? '', beginArea: a['begin-area']?.name ?? '',
        endArea: a['end-area']?.name ?? '' });
      out.genres = (a.genres ?? []).sort((x, y) => y.count - x.count).slice(0, 5).map((g) => g.name);
      const people = new Map();
      for (const r of a.relations ?? []) {
        if (r.type !== 'member of band') continue;
        const back = r.direction === 'backward', k = (back ? 'm:' : 'g:') + r.artist.name;
        if (!people.has(k)) people.set(k, { name: r.artist.name, role: back ? 'member' : 'group', stints: [], instruments: [] });
        const p = people.get(k);
        p.stints.push({ begin: r.begin ?? '', end: r.end ?? '', ended: !!r.ended });
        for (const at of r.attributes ?? []) if (at !== 'original' && at !== 'founder' && !p.instruments.includes(at)) p.instruments.push(at);
      }
      out.members = [...people].filter(([k]) => k[0] === 'm').map(([, p]) => p);
      out.groups = [...people].filter(([k]) => k[0] === 'g').map(([, p]) => p);
      out.links = {};
      for (const r of a.relations ?? []) {
        const url = r.url?.resource;
        if (!url) continue;
        if (r.type === 'wikidata') qid = url.slice(url.lastIndexOf('/') + 1);
        else if (['official homepage', 'discogs', 'allmusic', 'last.fm'].includes(r.type) && !out.links[r.type]) out.links[r.type] = url;
      }
    }
  }
  let commons = '';
  if (qid) {
    out.wikidata = qid;
    const wd = await getJson(`https://www.wikidata.org/wiki/Special:EntityData/${qid}.json`);
    const e = wd?.entities?.[qid];
    for (const l of [lang, 'en']) {
      const title = e?.sitelinks?.[l + 'wiki']?.title;
      if (!title) continue;
      const bio = await wikipedia(l, title);
      if (bio) { out.bio = bio; break }
    }
    commons = e?.claims?.P18?.[0]?.mainsnak?.datavalue?.value ?? '';
  }
  // extras that need our key (fanart.tv dropped 2026-11-05 — owner: nothing showed it; Deezer + Commons photos are enough)
  const extras = [];
  if (env.LASTFM_KEY) extras.push(getJson(`https://ws.audioscrobbler.com/2.0/?method=artist.getsimilar&format=json&limit=12&autocorrect=1&artist=` +
    `${encodeURIComponent(name)}&api_key=${env.LASTFM_KEY}`).then((s) => { out.similar = (s?.similarartists?.artist ?? []).map((x) => x.name) }));
  await Promise.all(extras);
  let pic = await photo, source = 'Deezer';
  if (!pic && commons) { pic = `https://commons.wikimedia.org/wiki/Special:FilePath/${encodeURIComponent(commons.replace(/ /g, '_'))}?width=1600`; source = 'Wikimedia Commons' }
  if (pic) { out.photoUrl = pic; out.photoSource = source }
  out.status = out.mbid || out.photoUrl ? 'ok' : 'none';
  return out;
}

async function artist(request, url, env, ctx) {
  const name = (url.searchParams.get('name') ?? '').trim().slice(0, 200);
  const lang = LANGS.includes(url.searchParams.get('lang')) ? url.searchParams.get('lang') : 'en';
  if (!name) return json({ error: 'name required' }, 400);
  const key = norm(name);
  const row = await env.DB.prepare('SELECT json, fetched FROM answers WHERE kind = ? AND key = ? AND lang = ?').bind('artist', key, lang).first();
  const age = row ? Date.now() - row.fetched : Infinity;
  const cached = row ? JSON.parse(row.json) : null;
  if (cached && (age < KEEP_MS || (cached.status === 'none' && age < RETRY_MS))) return json(cached, 200, { 'cache-control': 'public, max-age=3600' });
  const st = { mbFailed: false };
  const fresh = await fetchArtist(env, name, lang, st);
  if (fresh.status === 'ok' || !cached) {
    // MusicBrainz did not answer: keep this half answer 10 minutes, then ask again
    const at = st.mbFailed && !fresh.mbid ? Date.now() - KEEP_MS + RETRY_MS : Date.now();
    if (st.mbFailed && !fresh.mbid) fresh.partial = true  // the Core keeps it 10 minutes too (metadata.cpp), not 30 days
    ctx.waitUntil(env.DB.prepare('INSERT OR REPLACE INTO answers (kind, key, lang, json, fetched) VALUES (?, ?, ?, ?, ?)')
      .bind('artist', key, lang, JSON.stringify(fresh), at).run());
  }
  return json(fresh.status === 'ok' || !cached ? fresh : cached);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      if (request.method === 'GET' && url.pathname === '/v1/artist') return await artist(request, url, env, ctx);
      // SOURCE_SHA256 = shasum -a 256 src/index.js at deploy (deploy.sh): the published copy hashes the same
      if (url.pathname === '/v1/health') return json({ ok: true, source: env.SOURCE_SHA256 ?? null });
      return json({ error: 'not found' }, 404);
    } catch (e) {
      return json({ error: 'server error' }, 500);
    }
  },
  async scheduled(event, env) {
    await env.DB.prepare('DELETE FROM answers WHERE fetched < ?').bind(Date.now() - 60 * 86400_000).run();
  },
};
