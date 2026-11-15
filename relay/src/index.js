// Remote access (owner 2026-11-07, MusicApp/docs/WEB_REMOTE_PLAN.md): player.anantarultimate.com — an iPad or a phone opens
// it and controls Infinity on a computer, at home or away. Two parts:
//   - the web app: InfinityDesktop's UI as static assets (deploy.sh copies ui/dist)
//   - a room per computer (Durable Object Room): the computer's Infinity Core keeps a WebSocket open to it (outbound: no
//     port forwarding, no certificate on the computer), each paired device's page opens its own, and the room passes
//     messages between them. What passes is sealed end to end between the device and the computer
//     (InfinityDesktop ui/shared/remote-crypto.ts): the room routes it and cannot read it.
// The room keeps: the SHA-256 of the computer's key, and the SHA-256s of the paired devices' tokens (the computer sends the
// list; a page whose token leaves it is closed at once). Nothing of the library or the music.
// Protocol (InfinityDesktop core/remote.cpp ⇄ ui/shared/remote.svelte.ts):
//   page → computer   text {t:'hi', dev, kid, nb} · {t:'x', c}   the room adds s (which page) and passes it on
//   computer → page   text {t:'hi'|'no', s, …} · binary [u32 n][JSON {s}][sealed]
//   computer → room   text {t:'allow', h: [token SHA-256 hex]}
//   room → page       text {t:'core', on}           room → computer  text {t:'peers', n} · {t:'gone', s}
import { DurableObject } from 'cloudflare:workers'

const ROOM = /^[0-9a-f]{32}$/   // 128-bit, made by the computer
const KEY = /^[0-9a-f]{64}$/    // the computer's 256-bit key · a device's token
const MAX_PAGES = 8

export default {
  async fetch(req, env) {
    const url = new URL(req.url)
    if (url.pathname.endsWith('/')) return env.ASSETS.fetch(new Request(new URL(url.pathname + 'index.html', url), req))  // / and /m/
    // SOURCE_SHA256 = shasum -a 256 src/index.js at deploy (deploy.sh): the published copy hashes the same
    if (url.pathname === '/v1/health') return Response.json({ ok: true, source: env.SOURCE_SHA256 ?? null })
    if (url.pathname !== '/v1/core' && url.pathname !== '/v1/client') return new Response('Not found', { status: 404 })
    if (req.headers.get('Upgrade')?.toLowerCase() !== 'websocket') return new Response('WebSocket only', { status: 426 })
    const room = url.searchParams.get('room') ?? ''
    if (!ROOM.test(room)) return new Response('Bad room', { status: 400 })
    return env.ROOM.get(env.ROOM.idFromName(room)).fetch(req)
  },
}

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')
const sha256 = async (s) => hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))
function same(a, b) {
  const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b)
  return x.byteLength === y.byteLength && crypto.subtle.timingSafeEqual(x, y)
}

export class Room extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env)
    // keep-alives ("ping" every 30 s from both ends) are answered without waking the room: an idle room costs nothing
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'))
  }

  pages(except) { return this.ctx.getWebSockets('c').filter((w) => w !== except) }
  cores(except) { return this.ctx.getWebSockets('core').filter((w) => w !== except) }
  toPages(m, except) { for (const w of this.pages(except)) try { w.send(JSON.stringify(m)) } catch {} }
  toCore(m) { for (const w of this.cores()) try { w.send(JSON.stringify(m)) } catch {} }

  async fetch(req) {
    const core = new URL(req.url).pathname === '/v1/core'
    if (core) {
      const key = req.headers.get('X-Room-Key') ?? ''
      if (!KEY.test(key)) return new Response('No key', { status: 401 })
      const hash = await sha256(key)
      const known = await this.ctx.storage.get('keyHash')
      if (!known) await this.ctx.storage.put('keyHash', hash)  // the computer that made the room
      else if (!same(known, hash)) return new Response('Wrong key', { status: 403 })
      const [client, server] = Object.values(new WebSocketPair())
      for (const w of this.cores()) try { w.close(4000, 'replaced') } catch {}  // the newest connection of the computer wins
      this.ctx.acceptWebSocket(server, ['core'])
      server.send(JSON.stringify({ t: 'peers', n: this.pages().length }))
      this.toPages({ t: 'core', on: true })
      return new Response(null, { status: 101, webSocket: client })
    }
    // a page: its device's token, offered as a subprotocol (a browser cannot set headers on a WebSocket)
    const offered = (req.headers.get('Sec-WebSocket-Protocol') ?? '').split(',').map((s) => s.trim())
    const token = (offered.find((p) => p.startsWith('k.')) ?? '').slice(2)
    if (!KEY.test(token)) return new Response('No token', { status: 401 })
    const th = await sha256(token)
    const allow = (await this.ctx.storage.get('allow')) ?? []
    if (!allow.some((h) => same(h, th))) {  // opened and closed with a reason: a refused upgrade tells a page nothing
      const [client, server] = Object.values(new WebSocketPair())
      server.accept()
      server.close(4003, 'not paired')
      return new Response(null, { status: 101, webSocket: client, headers: { 'Sec-WebSocket-Protocol': 'infinity.v1' } })
    }
    if (this.pages().length >= MAX_PAGES) return new Response('Too many open', { status: 429 })
    const [client, server] = Object.values(new WebSocketPair())
    const s = crypto.randomUUID().slice(0, 8)
    this.ctx.acceptWebSocket(server, ['c', 'c:' + s])
    server.serializeAttachment({ s, th })
    server.send(JSON.stringify({ t: 'core', on: this.cores().length > 0 }))
    this.toCore({ t: 'peers', n: this.pages().length })
    return new Response(null, { status: 101, webSocket: client, headers: { 'Sec-WebSocket-Protocol': 'infinity.v1' } })
  }

  async webSocketMessage(ws, msg) {
    if (this.ctx.getTags(ws).includes('core')) {
      let s
      try {
        if (typeof msg === 'string') {
          const m = JSON.parse(msg)
          if (m.t === 'allow' && Array.isArray(m.h)) {  // the paired devices now: the others' pages close
            const h = m.h.filter((x) => typeof x === 'string' && KEY.test(x)).slice(0, 1000)
            await this.ctx.storage.put('allow', h)
            for (const w of this.pages()) if (!h.includes(w.deserializeAttachment().th)) try { w.close(4003, 'not paired') } catch {}
            return
          }
          s = m.s
        } else {
          const n = new DataView(msg).getUint32(0)
          s = JSON.parse(new TextDecoder().decode(new Uint8Array(msg, 4, n))).s
        }
      } catch { return }
      if (typeof s === 'string') for (const w of this.ctx.getWebSockets('c:' + s)) try { w.send(msg) } catch {}
      return
    }
    if (typeof msg !== 'string' || msg.length > 1 << 20) return
    let m
    try { m = JSON.parse(msg) } catch { return }
    if (m.t !== 'hi' && m.t !== 'x') return
    m.s = ws.deserializeAttachment().s
    if (!this.cores().length) { ws.send(JSON.stringify({ t: 'core', on: false })); return }
    this.toCore(m)
  }

  webSocketClose(ws, code) {
    const core = this.ctx.getTags(ws).includes('core')
    try { ws.close(code === 1005 || code === 1006 ? 1000 : code) } catch {}
    if (core) this.toPages({ t: 'core', on: this.cores(ws).length > 0 }, ws)
    else {
      this.toCore({ t: 'gone', s: ws.deserializeAttachment().s })
      this.toCore({ t: 'peers', n: this.pages(ws).length })
    }
  }

  webSocketError(ws) { this.webSocketClose(ws, 1011) }
}
