// Remote access, end to end (MusicApp/docs/WEB_REMOTE_PLAN.md §Security): what passes the room at
// player.anantarultimate.com is sealed between this browser and the computer — the room routes it, cannot read it, cannot
// forge it, cannot replay it. Mirrored in InfinityDesktop core/remote.cpp (and tools/check_remote.mjs runs this file
// against it). WebCrypto only; plain TypeScript (Node runs it too).
//
// A device = {room, dev, secret} from the computer's pairing link (#pair=<room>.<dev>.<secret hex>):
//   token  = HMAC(secret, "infinity-room-token-v1")          → hex: what the room checks (it keeps SHA-256 of it)
//   kid    = SHA-256(token hex) hex [0..16)                   → tells the computer which secret (current / next)
// A connection: browser → {t:'hi', dev, kid, nb}  ·  computer → {t:'hi', nc, proof, v}
//   K = HMAC(secret, "infinity-session-v1" ‖ nb ‖ nc) · kEnc = HMAC(K, "enc") · kMac = HMAC(K, "mac")
//   proof = HMAC(kMac, "core-proof" ‖ nb)                     → the browser knows it is the computer
// A message: seq (8 bytes, from 0, +1 each, per direction) ‖ iv (16) ‖ AES-256-CTR(kEnc, iv) ‖ tag (32)
//   tag = HMAC(kMac, dir ‖ seq ‖ iv ‖ ct), dir 'B' (browser → computer) / 'C'
const te = new TextEncoder()
type B = Uint8Array<ArrayBuffer>

export const bytes = (s: string): B => te.encode(s) as B
export function cat(...parts: Uint8Array[]): B {
  const out = new Uint8Array(parts.reduce((a, p) => a + p.byteLength, 0))
  let at = 0
  for (const p of parts) { out.set(p, at); at += p.byteLength }
  return out
}
export const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('')
export const unhex = (s: string): B => new Uint8Array((s.match(/../g) ?? []).map((x) => parseInt(x, 16)))
export const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b))
export const unb64 = (s: string): B => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
export const random = (n: number): B => crypto.getRandomValues(new Uint8Array(n))

const hmacKey = (raw: Uint8Array) => crypto.subtle.importKey('raw', raw as B, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'])
export async function hmac(key: Uint8Array, data: Uint8Array): Promise<B> {
  return new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(key), data as B))
}
export const sha256 = async (data: Uint8Array): Promise<B> => new Uint8Array(await crypto.subtle.digest('SHA-256', data as B))

export async function deviceToken(secret: Uint8Array) {
  const token = hex(await hmac(secret, bytes('infinity-room-token-v1')))
  return { token, kid: hex(await sha256(bytes(token))).slice(0, 16) }
}

export class Session {
  private seqOut = 0n
  private seqIn = 0n
  private enc: CryptoKey
  private mac: CryptoKey
  private inDir: number
  private outDir: number
  private constructor(enc: CryptoKey, mac: CryptoKey, inDir: number, outDir: number) {  // (no parameter properties: Node strips types only)
    this.enc = enc
    this.mac = mac
    this.inDir = inDir
    this.outDir = outDir
  }

  // the browser's side: K from its secret and both nonces; the computer's proof checked
  static async open(secret: Uint8Array, nb: Uint8Array, nc: Uint8Array, proof: Uint8Array): Promise<Session | null> {
    const K = await hmac(secret, cat(bytes('infinity-session-v1'), nb, nc))
    const kMac = await hmacKey(await hmac(K, bytes('mac')))
    if (!(await crypto.subtle.verify('HMAC', kMac, proof as B, cat(bytes('core-proof'), nb)))) return null
    const kEnc = await crypto.subtle.importKey('raw', await hmac(K, bytes('enc')), 'AES-CTR', false, ['encrypt', 'decrypt'])
    return new Session(kEnc, kMac, 0x43, 0x42)
  }
  // the computer's side (tests stand in for it)
  static async accept(secret: Uint8Array, nb: Uint8Array, nc: Uint8Array): Promise<{ session: Session; proof: B }> {
    const K = await hmac(secret, cat(bytes('infinity-session-v1'), nb, nc))
    const macRaw = await hmac(K, bytes('mac'))
    const kEnc = await crypto.subtle.importKey('raw', await hmac(K, bytes('enc')), 'AES-CTR', false, ['encrypt', 'decrypt'])
    return { session: new Session(kEnc, await hmacKey(macRaw), 0x42, 0x43), proof: await hmac(macRaw, cat(bytes('core-proof'), nb)) }
  }

  async seal(plain: Uint8Array): Promise<B> {
    const seq = new Uint8Array(8)
    new DataView(seq.buffer).setBigUint64(0, this.seqOut++)
    const iv = random(16)
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CTR', counter: iv, length: 128 }, this.enc, plain as B))
    const tag = new Uint8Array(await crypto.subtle.sign('HMAC', this.mac, cat(new Uint8Array([this.outDir]), seq, iv, ct)))
    return cat(seq, iv, ct, tag)
  }

  // null: not in order, or not from the other end — the connection is dropped
  async unseal(m: Uint8Array): Promise<B | null> {
    if (m.byteLength < 56) return null
    const seq = new DataView(m.buffer, m.byteOffset, 8).getBigUint64(0)
    if (seq !== this.seqIn) return null
    const iv = m.subarray(8, 24), ct = m.subarray(24, m.byteLength - 32), tag = m.subarray(m.byteLength - 32)
    if (!(await crypto.subtle.verify('HMAC', this.mac, tag as B, cat(new Uint8Array([this.inDir]), m.subarray(0, 8), iv, ct)))) return null
    this.seqIn++
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CTR', counter: iv as B, length: 128 }, this.enc, ct as B))
  }
}
