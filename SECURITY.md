# How Remote access is secured

Three parties: **the computer** (Infinity Core, `core/`), **a device** (a browser page, `web/`) and **the relay**
(`relay/`, at `player.anantarultimate.com`). The relay passes messages; it is not trusted with anything it could read or
forge.

## Switching it on

With Remote access off, Infinity Core opens no connection (`run()` in `core/remote.cpp` waits). Switched on, the computer
makes a random 128-bit room id and a random 256-bit computer key (once, kept on the computer) and keeps one outgoing
WebSocket to its room. The relay stores the SHA-256 of the computer key the first time and refuses any other key for that
room afterwards.

## Pairing a device

On the computer (Settings › Remote access › Add a device), Infinity Core makes a random 256-bit **secret** for the device
and shows a link as a QR code: `https://player.anantarultimate.com/#pair=<room>.<device id>.<secret>`. The secret is in the
URL fragment, which browsers never send to a server. The link works once, for 15 minutes; on first use the computer gives
the device a fresh secret inside the encrypted session (`rekey`), so the one that was on screen stops working.

Devices can be added only on the computer. A paired device may list, rename and remove devices (a lost phone can be removed
from another), but not add one or switch Remote access on or off (`allowed()` in `core/remote.cpp`).

## What the relay keeps

- the room id and the SHA-256 of the computer key;
- for each paired device, the SHA-256 of its **token** = HMAC-SHA-256(secret, `"infinity-room-token-v1"`). The computer sends
  this list; a page whose token is not on it is closed at once. The token cannot be turned back into the secret, and the
  token alone cannot open a session.

Nothing of the library, the music or what is playing. IP addresses are seen while connected, not stored.

## A session

```
device → computer   {t:'hi', dev, kid, nb}        nb = 16 random bytes; kid = SHA-256(token hex)[0..16) picks the secret
computer → device   {t:'hi', nc, proof, v}        nc = 16 random bytes

K     = HMAC-SHA-256(secret, "infinity-session-v1" ‖ nb ‖ nc)
kEnc  = HMAC-SHA-256(K, "enc")          kMac = HMAC-SHA-256(K, "mac")
proof = HMAC-SHA-256(kMac, "core-proof" ‖ nb)      the device checks it: it is talking to the computer
```

Every message after that, each way:

```
seq (8 bytes, from 0, +1 per message, per direction) ‖ iv (16 random bytes) ‖ AES-256-CTR(kEnc, iv, plaintext) ‖ tag
tag = HMAC-SHA-256(kMac, dir ‖ seq ‖ iv ‖ ciphertext)      dir = "B" device → computer, "C" computer → device
```

The computer checks the sequence number and the tag in constant time (`crypto::same`); a message out of order or with a
wrong tag ends that session (`sealed()` in `core/remote.cpp`). The device checks the same way and drops such a message
(`open()` in `web/remote-crypto.ts`). The relay can drop or delay messages; it cannot read, change, replay or invent one.

## What a paired device may ask for

A request inside the session is an ordinary call to Infinity Core's local API, checked by `allowed()` before it runs:

- **Reading:** the library and catalogue pages, the queue and player state, playlists, favourites, sound settings, which
  Qobuz / TIDAL account is signed in. Never the folder picker (`/api/fs`), settings (`/api/settings`), sign-in
  (`/api/qobuz…`), updates, crash or log reports, the event stream, the network apps' pairing code (`/api/lan`), the tag
  editor or a DAP's file transfer.
- **Changing:** play, queue, transport, seek, volume, output / zone, sleep timer, playlists, favourites, Listen Later, tags,
  streaming-service favourites and playlists, radio, autoplay, Infinity DSP, EQ, AutoEQ, AirPlay pairing; Remote access
  devices: rename / remove only. Everything else is refused.

The library's folder view lists only what is inside the music folders (a path with `..` is refused), and station pictures
are fetched from the internet only, never from the home network.

## Known limits

- **The page comes from the relay.** The device runs the page the relay serves. A tampered page could act as that paired
  device while it is open — held to the list above. Leave Remote access off if that is not acceptable.
- **The pairing link is the secret.** Anyone who has the link within its 15 minutes, before the device uses it, can pair
  in its place. Scan it from the screen; if you send it as a link, send it only to yourself.
- **A paired device is trusted to the list above.** Remove a lost device on the computer or from another paired device.

## Reporting a problem

Please report a security problem privately, through this repository's **Security › Report a vulnerability** on GitHub —
not in a public issue. Tell us what you found and how to see it; we answer there.
