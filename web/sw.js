// Infinity Remote (shared/remote.svelte.ts): at player.anantarultimate.com every /api/ request of a page — fetch, <img>, …
// — is answered by that page itself, over its WebSocket to the computer. Where the Core serves the UI (http) it is never
// registered.
self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()))
self.addEventListener('fetch', (e) => {
  const u = new URL(e.request.url)
  if (u.origin !== self.location.origin || !u.pathname.startsWith('/api/')) return
  e.respondWith(viaPage(e, u))
})

async function viaPage(e, u) {
  const page = await self.clients.get(e.clientId)
  if (!page) return new Response('{"error":"no page"}', { status: 503, headers: { 'Content-Type': 'application/json' } })
  const body = e.request.method === 'GET' || e.request.method === 'HEAD' ? '' : await e.request.text()
  const ch = new MessageChannel()
  const r = await new Promise((resolve) => {
    ch.port1.onmessage = (m) => resolve(m.data)
    page.postMessage({ t: 'api', m: e.request.method, p: u.pathname + u.search, b: body }, [ch.port2])
  })
  const empty = r.st === 204 || r.st === 304
  return new Response(empty ? null : r.body, { status: r.st, headers: { 'Content-Type': r.ct || 'application/octet-stream' } })
}
