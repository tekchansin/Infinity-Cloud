# Infinity Cloud — the code behind our online services

Infinity Core (Mac, Windows, Home Assistant) and Infinity Player / Infinity OS (iBasso DAPs) are our own software, and
they are not open source. A few things they do go through servers we run. This repository is the code of those servers,
and of both sides of Remote access's encryption, so anyone can read what happens to what the apps send. It is published
for review; see [LICENSE](LICENSE).

Every online feature of the apps, in plain language: [Privacy](https://anantarultimate.com/privacy.html).

## What is here

| Folder | What it is | Runs on |
|---|---|---|
| `relay/` | **Remote access** — `player.anantarultimate.com`: one Durable Object ("room") per computer, passing encrypted messages between your iPad / phone and your computer. | Cloudflare Workers |
| `core/` | Infinity Core's side of Remote access: pairing, the handshake, sealing / opening every message, and what a paired device may ask for (`allowed()` in `remote.cpp`). | Your computer |
| `web/` | The page's side of Remote access: the same handshake and sealing in WebCrypto (`remote-crypto.ts`), the connection, the service worker. | Your iPad / phone |
| `share/` | **`share.anantarultimate.com`** — Send Log Report, Community Share (Listening Profiles, Custom Harmonic) and the website's reviews. | Cloudflare Workers + D1 |
| `meta/` | **`meta.anantarultimate.com`** — artist information (biography, photo, members, similar artists) gathered once from public sources and shared by everyone who asks. | Cloudflare Workers + D1 |

The files are copied as they ship from our own repositories; the only change is that `wrangler.toml` has no account or
database ids. `schema.sql` in each folder is everything that service stores.

## In short

**Remote access** (`relay/`, `core/`, `web/` — the details: [SECURITY.md](SECURITY.md))
- Off by default; switched off, Infinity Core makes no connection to the relay.
- Each device you pair gets its own 256-bit secret from a QR code shown on the computer. The relay never sees a secret.
- Every message is encrypted (AES-256-CTR) and authenticated (HMAC-SHA-256) with keys only your computer and your device
  have: the relay can drop a message, but not read, change, replay or invent one.
- A paired device may browse and play; it can never change settings, sign in or out of a service, install updates or add
  a device (`allowed()` in `core/remote.cpp`).

**Log reports, Community Share, reviews** (`share/`)
- A log report goes out only when you press Send Log Report — or, on a beta, when the app crashes and you said yes when
  it asked. Kept 30 days, readable only with our admin key (`isAdmin`), deleted by the hourly cron.
- Your IP address is never stored. A salted SHA-256 of it (`ipHashOf`) is kept for one hour for the rate limit, then blanked
  by the same cron (`purgeIpHashes`).
- A shared profile is public by design; only its name, nickname, headphone, DAP model, amp card and settings. You delete
  it with the token your app keeps (only its SHA-256 is stored). Reviews are public only after we approve them.

**Artist information** (`meta/`)
- The apps send an artist's name and the language of their interface — nothing else. Answers come from MusicBrainz,
  Wikidata, Wikipedia, Deezer and Last.fm and are kept so the next person gets them at once: asked again after 30 days, deleted after 60 (the daily cron).

## Is this what runs?

Each service answers `GET /v1/health` with the SHA-256 of the source it was deployed from (`deploy.sh` sets it):

```sh
curl -s https://share.anantarultimate.com/v1/health      # {"ok":true,"source":"…"}
shasum -a 256 share/src/index.js                          # the same hash
```

`meta.anantarultimate.com/v1/health` and `player.anantarultimate.com/v1/health` the same way (`meta/src/index.js`,
`relay/src/index.js`). This shows which version we say we run; no one outside can prove what a server runs. That is why
Remote access does not rely on the relay: what keeps your messages private is the code on your own computer (`core/`) and
device (`web/`).

## What this repository does not cover

- **The page Remote access shows** is Infinity Core's full interface, served by the relay; only its encryption and
  connection (`web/`) are here. A tampered page could act as a paired device while it is open — still held to `allowed()`.
  If that is not acceptable to you, leave Remote access off.
- **The apps themselves** are not published. What they send online is listed on the [Privacy](https://anantarultimate.com/privacy.html) page.
- **Other servers**: updates and downloads are static files (`dl.anantarultimate.com`), the website is static pages.

Found a security problem? See [SECURITY.md](SECURITY.md#reporting-a-problem).
