import { tr, tk } from './i18n'
// Remote access (owner 2026-11-07, MusicApp/docs/WEB_REMOTE_PLAN.md): this UI opened at player.anantarultimate.com — on an
// iPad or a phone — controls Infinity on a computer through the computer's room (MusicApp/cloud/remote-worker). Every
// /api/ request of the page (fetch, <img>, …) goes through the Service Worker (public/sw.js) to here and over one
// WebSocket, sealed end to end (remote-crypto.ts); the player state comes the same way. Where the Core serves the UI itself
// (the app, the dev server: this computer's own address) none of this runs.
// This device's pairing (#pair=<room>.<dev>.<secret>, the computer's QR code / link) is kept in this browser; the computer
// gives it a secret of its own on its first visit, so the link it came with stops working.
import { b64, bytes, cat, deviceToken, random, Session, unb64, unhex } from './remote-crypto'
import { ingressBase } from './ingress'
import { reload } from './leave'

// Home Assistant's Ingress serves the Core's own UI at the box's address: not the Remote (it showed the pairing page there,
// owner 2026-11-08)
export const isRemote = !ingressBase && !['127.0.0.1', 'localhost', '[::1]'].includes(location.hostname)
export const REMOTE_API = 1  // what this page speaks; a computer saying less runs an older Infinity
// a phone that opens the desktop page goes to the phone UI (/m/) before anything starts here: a Service Worker registering
// while the page leaves never took the next page — the phone stayed on "Connecting…" (owner, away from home, 2026-11-07)
export const toPhone = isRemote && !location.pathname.startsWith('/m/') && matchMedia('(max-width: 700px)').matches

type Device = { room: string; dev: string; secret: string }  // secret: hex
export type Res = { st: number; ct: string; body: ArrayBuffer }
type Pending = { resolve: (r: Res) => void; parts: Uint8Array[]; st: number; ct: string; timer: ReturnType<typeof setTimeout> }

// paired: this browser has a device; socket: open to the room; core: the computer is there; ready: the sealed session is
// up; old: the computer runs an older Infinity; error: what stops it (no longer paired, …)
export const remoteState = $state<{ paired: boolean; socket: boolean; core: boolean | null; ready: boolean; old: boolean; error: string }>({
  paired: false, socket: false, core: null, ready: false, old: false, error: '',
})

const KEY = 'remote.device'
function readDevice(): Device | null {
  const m = location.hash.match(/^#pair=([0-9a-f]{32})\.([0-9a-f]{16})\.([0-9a-f]{64})$/)
  if (m) {
    save({ room: m[1], dev: m[2], secret: m[3] })
    history.replaceState(null, '', location.pathname + '#/home')  // the secret out of the address bar and the history
  }
  try {
    localStorage.removeItem('remote.link')  // the first test version's single link
    const d = JSON.parse(localStorage.getItem(KEY) ?? 'null') as Device | null
    return d && /^[0-9a-f]{32}$/.test(d.room) && /^[0-9a-f]{16}$/.test(d.dev) && /^[0-9a-f]{64}$/.test(d.secret) ? d : null
  } catch { return null }
}
function save(d: Device) { try { localStorage.setItem(KEY, JSON.stringify(d)) } catch {} }
let device = isRemote ? readDevice() : null
// this browser's device id (Settings marks it in the device list)
export const thisDevice = () => device?.dev ?? ''
remoteState.paired = !!device

let ws: WebSocket | null = null
let session: Session | null = null
let nb: Uint8Array = new Uint8Array()
let nextId = 1
const pending = new Map<number, Pending>()
const waiting: (() => void)[] = []  // requests made while the way to the computer is not up yet
const listeners = new Set<(state: unknown) => void>()
let backoff = 1000
let sendChain: Promise<unknown> = Promise.resolve()  // sealed in order, sent in order
let recvChain: Promise<unknown> = Promise.resolve()

const fake = (st: number, msg: string): Res => ({ st, ct: 'application/json', body: bytes(JSON.stringify({ error: msg })).buffer as ArrayBuffer })
function failAll() {
  for (const p of pending.values()) { clearTimeout(p.timer); p.resolve(fake(503, tk('Your computer is not reachable'))) }
  pending.clear()
}
function down() {
  session = null
  remoteState.ready = false
  failAll()
}

async function hello() {
  if (!device || !ws || ws.readyState !== WebSocket.OPEN) return
  const { kid } = await deviceToken(unhex(device.secret))
  nb = random(16)
  ws.send(JSON.stringify({ t: 'hi', dev: device.dev, kid, nb: b64(nb) }))
}

async function onText(d: string) {
  if (d === 'pong') return
  let m: { t?: string; on?: boolean; nc?: string; proof?: string; v?: number; why?: string }
  try { m = JSON.parse(d) } catch { return }
  if (m.t === 'core') {
    remoteState.core = !!m.on
    if (m.on) hello()
    else down()
  } else if (m.t === 'hi' && device) {
    const s = await Session.open(unhex(device.secret), nb, unb64(m.nc ?? ''), unb64(m.proof ?? ''))
    if (!s) { remoteState.error = tk('This is not your computer answering — the connection was closed.'); ws?.close(); return }
    session = s
    remoteState.ready = true
    remoteState.old = (m.v ?? 0) < REMOTE_API
    waiting.splice(0).forEach((f) => f())
  } else if (m.t === 'no') {
    remoteState.error = m.why === 'unknown'
      ? tk("This device is no longer paired with your computer. Pair it again: Infinity Core › Settings › Remote access › Add a device.")
      : tk("Your computer did not accept this device.")  // English, shown through tr() (RemoteGate): the startsWith below reads it
    stop()
  }
}

async function onBinary(buf: ArrayBuffer) {
  if (!session) return
  const n = new DataView(buf).getUint32(0)
  const plain = await session.unseal(new Uint8Array(buf, 4 + n))
  if (!plain) { ws?.close(); return }  // not from the computer, or out of order: a new session
  const m = new DataView(plain.buffer, plain.byteOffset).getUint32(0)
  const h = JSON.parse(new TextDecoder().decode(plain.subarray(4, 4 + m))) as { t: string; id?: number; st?: number; ct?: string; more?: boolean; secret?: string }
  const body = plain.subarray(4 + m)
  if (h.t === 'ev') {
    const state = JSON.parse(new TextDecoder().decode(body))
    for (const f of listeners) f(state)
  } else if (h.t === 'rekey' && device && h.secret && /^[0-9a-f]{64}$/.test(h.secret)) {
    device = { ...device, secret: h.secret }  // this device's own secret from now on: the link it came with is spent
    save(device)
  } else if (h.t === 'res' && h.id !== undefined) {
    const p = pending.get(h.id)
    if (!p) return
    if (h.st !== undefined) { p.st = h.st; p.ct = h.ct ?? '' }
    p.parts.push(body)
    if (h.more) return
    pending.delete(h.id)
    clearTimeout(p.timer)
    p.resolve({ st: p.st, ct: p.ct, body: cat(...p.parts).buffer as ArrayBuffer })
  }
}

let stopped = false
function stop() {
  stopped = true
  down()
  ws?.close()
}

async function connect() {
  if (!device || stopped) return
  const { token } = await deviceToken(unhex(device.secret))
  const s = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/v1/client?room=${device.room}`, ['infinity.v1', `k.${token}`])
  ws = s
  s.binaryType = 'arraybuffer'
  s.onopen = () => { remoteState.socket = true; backoff = 1000; if (!remoteState.error.startsWith('This device')) remoteState.error = '' }
  s.onmessage = (e) => {
    if (typeof e.data === 'string') { const d = e.data; recvChain = recvChain.then(() => onText(d)) }
    else { const b = e.data as ArrayBuffer; recvChain = recvChain.then(() => onBinary(b)) }
  }
  s.onclose = (e) => {
    if (ws !== s) return
    ws = null
    remoteState.socket = false
    remoteState.core = null
    down()
    // 4003 / a refused upgrade with nothing ever open: this device is not (or no longer) in the computer's list
    if (e.code === 4003) {
      remoteState.error = tk('This device is no longer paired with your computer. Pair it again: Infinity Core › Settings › Remote access › Add a device.')
      stopped = true
    }
    if (stopped) return
    setTimeout(connect, backoff)
    backoff = Math.min(backoff * 2, 15000)
  }
}
setInterval(() => { if (ws?.readyState === WebSocket.OPEN) ws.send('ping') }, 30000)  // the room answers without waking
// back from the background (a phone's screen was off): the socket may be gone without a word — check at once
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible' && ws?.readyState !== WebSocket.OPEN) ws?.close() })

// one API request to the computer (what /api/… fetches become); 503 when it is not reachable within 10 s
export function request(m: string, p: string, b: string): Promise<Res> {
  return new Promise((resolve) => {
    const go = () => {
      const id = nextId++
      const entry: Pending = { resolve, parts: [], st: 0, ct: '', timer: setTimeout(() => { pending.delete(id); resolve(fake(504, tk('No answer'))) }, 60000) }
      pending.set(id, entry)
      const s = session!, sock = ws!
      sendChain = sendChain.then(async () => {
        const sealed = await s.seal(bytes(JSON.stringify({ t: 'req', id, m, p, b })))
        if (session === s && sock.readyState === WebSocket.OPEN) sock.send(JSON.stringify({ t: 'x', c: b64(sealed) }))
      })
    }
    if (session && remoteState.ready) return go()
    if (stopped) return resolve(fake(403, remoteState.error))
    const t = setTimeout(() => {
      const i = waiting.indexOf(run)
      if (i >= 0) waiting.splice(i, 1)
      resolve(fake(503, tk('Your computer is not reachable')))
    }, 10000)
    const run = () => { clearTimeout(t); go() }
    waiting.push(run)
  })
}

// the player state as it changes (what EventSource('/api/events') gives in the app)
export function onRemoteState(f: (state: unknown) => void) { listeners.add(f) }

async function setup() {
  if (!device) return
  if (!('serviceWorker' in navigator)) { remoteState.error = tk('This browser cannot open Infinity Core here'); return }
  navigator.serviceWorker.addEventListener('message', (e) => {
    const d = e.data as { t?: string; m: string; p: string; b: string }
    if (d?.t !== 'api') return
    const port = e.ports[0]
    request(d.m, d.p, d.b).then((r) => port.postMessage(r, [r.body]))
  })
  navigator.serviceWorker.startMessages()  // the worker's messages are held until this
  try {
    await navigator.serviceWorker.register('/sw.js')
    if (!navigator.serviceWorker.controller) {
      const took = await new Promise<boolean>((r) => {
        navigator.serviceWorker.addEventListener('controllerchange', () => r(true), { once: true })
        setTimeout(() => r(!!navigator.serviceWorker.controller), 4000)
      })
      // not taken over (a registration left half-way): a page loaded under the worker always is — once
      if (!took) {
        let again = false
        try { again = !sessionStorage.getItem('remote.reloaded'); sessionStorage.setItem('remote.reloaded', '1') } catch {}
        if (again) { reload(); return }
        remoteState.error = tk('This browser did not start Infinity Core here — close the tab and open the page again.')
        return
      }
    }
  } catch {
    remoteState.error = tk('This browser cannot open Infinity Core here (private browsing?)')
    return
  }
  connect()
}
// what the page waits for before it asks the computer anything (at once outside Remote access)
export const ready: Promise<void> = isRemote && !toPhone ? setup() : Promise.resolve()
