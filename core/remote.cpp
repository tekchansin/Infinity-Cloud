// remote.h. One WebSocket to this computer's room (ws.h, outbound). Each device is paired here (Settings › Remote access ›
// Add a device: a QR code / link carrying its own secret, which never passes the room) and can be removed one by one.
// Everything between a device and this Core is sealed end to end (crypto.h; the spec: ui/shared/remote-crypto.ts): the
// room routes it but cannot read, forge or replay it. A request is checked against what another device may do
// (allowed()) and answered by this Core's own API on loopback — the very routes the app uses. Room protocol:
// MusicApp/cloud/remote-worker/src/index.js.
#include "remote.h"

#include "crypto.h"
#include "library.h"
#include "stoppable.h"
#include "ws.h"

#include <httplib.h>

#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <map>
#include <mutex>
#include <thread>

namespace remote {
namespace {
using namespace std::chrono_literals;

constexpr int kApi = 1;                  // what the page checks: a newer page tells an older computer to update
constexpr long long kPendingSecs = 900;  // a device's link that was never used works for 15 minutes

// the room server; INFINITY_REMOTE_URL (tests: `wrangler dev` → ws://127.0.0.1:8787) points elsewhere
const std::string kBase = getenv("INFINITY_REMOTE_URL") ? getenv("INFINITY_REMOTE_URL") : "wss://player.anantarultimate.com";
const std::string kPage = (kBase.rfind("wss://", 0) == 0 ? "https://" : "http://") + kBase.substr(kBase.find("//") + 2);  // the web app

struct Session {  // one open browser of a paired device
    std::string dev, enc, mac;
    std::mutex mu;  // seal + send in seq order
    unsigned long long seqOut = 0, seqIn = 0;
};

struct State {
    std::mutex mu;
    std::condition_variable cv;
    Library* lib = nullptr;
    int port = 0;
    std::shared_ptr<ws::Socket> sock;  // the open connection, if any
    long long gen = 0;                 // which connection the callbacks belong to
    bool connected = false, closed = true;
    std::string error;
    std::map<std::string, std::shared_ptr<Session>> sessions;  // by the room's browser id
    std::string lastEvent;             // the newest player state: for a device that opens later
    std::deque<json::Value> jobs;      // requests waiting for a worker
    bool quit = false;                 // the Core stops: every thread here ends
    httplib::Client* events = nullptr;  // the /api/events stream open now (the stop ends it)
};
State& S() {
    static State s;
    return s;
}
std::mutex cfgMu;  // the setting: read-modify-write

long long now() { return (long long)time(nullptr); }

json::Value config() {  // {on, room, key, devices: [{id, name, secret, next?, added, lastSeen, pending}]}
    json::Value v;
    json::parse(S().lib->setting("remote", "{}"), v);
    return v;
}
void save(const json::Value& c) { S().lib->setSetting("remote", json::dump(c)); }

std::string token(const std::string& secretHex) { return crypto::hex(crypto::hmac(crypto::unhex(secretHex), "infinity-room-token-v1")); }
std::string tokenHash(const std::string& secretHex) { return crypto::hex(crypto::sha256(token(secretHex))); }

// What another device may do: browse and play, the queue, volume and outputs, playlists, favourites, tags, Listen Later,
// radio, EQ / DSP — and see whether Qobuz / TIDAL are signed in (its pages need it). Never this computer's files (the
// folder picker), its settings, signing in or out, updates, reports, a new Infinity Link address (the Core would connect
// wherever it says), nor Remote access itself.
bool allowed(const std::string& method, const std::string& path, const std::string& body) {
    const std::string p = path.substr(0, path.find('?'));
    auto under = [&](const char* x) {
        const size_t n = strlen(x);
        return p.compare(0, n, x) == 0 && (p.size() == n || p[n] == '/');
    };
    // Remote access itself: its devices are seen, renamed, removed from a paired device too (a lost phone removed from
    // another); switching it on / off is not (from afar off would lock every device out until home), and a new device is
    // added on the computer only (owner 2026-11-13, a tester's "backdoor" worry: a stolen phone or a tampered page must not
    // be able to pair a hidden device — it was allowed from 2026-11-07)
    if (p == "/api/remote") {
        if (method == "GET") return true;
        json::Value v;
        return method == "POST" && json::parse(body, v) && v.type == json::Value::Obj && !v.has("on") && !v.has("add");
    }
    for (const char* x : {"/api/fs", "/api/settings", "/api/qobuz", "/api/update", "/api/crash", "/api/logreport",
                          "/api/events", "/api/outputs/link",
                          "/api/lan",  // apps on the network: its pairing code is for this network only

                          "/api/dap/transfer", "/api/dap/sync", "/api/tagedit",
                          "/api/backups/drive"})  // the Google sign-in: on this computer only  // a DAP's file server + its password, writing to it: a page on the same network only
        if (under(x)) return false;
    if (method == "GET") return under("/api");
    if (method != "POST") return false;
    for (const char* x : {"/api/play", "/api/queue", "/api/transport", "/api/seek", "/api/volume", "/api/zone", "/api/outputs", "/api/sleep",
                          "/api/takeback", "/api/playlists", "/api/favorites", "/api/later", "/api/tags", "/api/svc/favorite",
                          "/api/svc/playlist", "/api/radio/play", "/api/radio/saved", "/api/rp/play", "/api/autoplay", "/api/dsp", "/api/eq",
                          "/api/autoeq/apply", "/api/airplay"})  // AirPlay 2 pairing: a code typed on the phone
        if (under(x)) return true;
    return false;
}

std::shared_ptr<ws::Socket> current() {
    std::lock_guard<std::mutex> l(S().mu);
    return S().connected ? S().sock : nullptr;
}
void sendText(const json::Value& m) {
    if (auto sock = current()) ws::send(*sock, json::dump(m), false);
}

// the room learns which device tokens may open a browser here (it keeps their SHA-256; a token not in it is closed)
void pushAllow(const json::Value& c) {
    json::Value m, h;
    h.type = json::Value::Arr;
    for (auto& d : c["devices"].arr) {
        h.push(json::str(tokenHash(d["secret"].str())));
        if (!d["next"].str().empty()) h.push(json::str(tokenHash(d["next"].str())));
    }
    m.set("t", json::str("allow"));
    m.set("h", h);
    sendText(m);
}

// devices whose link was never used, past its 15 minutes, are forgotten
bool dropExpired(json::Value& c) {
    json::Value keep;
    keep.type = json::Value::Arr;
    bool dropped = false;
    for (auto& d : c["devices"].arr) {
        if (d["pending"].boolean() && !d["lastSeen"].i64() && now() - d["added"].i64() > kPendingSecs) dropped = true;
        else keep.push(d);
    }
    if (dropped) c.set("devices", keep);
    return dropped;
}

// one sealed message to one browser: [u32 n]{"s":…}[seq ‖ iv ‖ ct ‖ tag], the plaintext [u32 m][inner JSON][body]
bool sealTo(const std::string& s, Session& x, const json::Value& inner, const std::string& body) {
    auto sock = current();
    if (!sock) return false;
    const std::string ih = json::dump(inner);
    std::string plain(4, '\0');
    for (int i = 0; i < 4; i++) plain[i] = (char)((ih.size() >> (24 - 8 * i)) & 0xff);
    plain += ih;
    plain += body;
    std::lock_guard<std::mutex> l(x.mu);
    std::string seq(8, '\0');
    for (int i = 0; i < 8; i++) seq[i] = (char)((x.seqOut >> (56 - 8 * i)) & 0xff);
    x.seqOut++;
    const std::string iv = crypto::random(16), ct = crypto::aesCtr(x.enc, iv, plain);
    const std::string tag = crypto::hmac(x.mac, "C" + seq + iv + ct);
    const std::string hs = "{\"s\":" + json::quote(s) + "}";
    std::string frame(4, '\0');
    for (int i = 0; i < 4; i++) frame[i] = (char)((hs.size() >> (24 - 8 * i)) & 0xff);
    frame += hs + seq + iv + ct + tag;
    return ws::send(*sock, frame, true);
}
std::shared_ptr<Session> session(const std::string& s) {
    std::lock_guard<std::mutex> l(S().mu);
    auto it = S().sessions.find(s);
    return it == S().sessions.end() ? nullptr : it->second;
}

// a response, in pieces of 256 KB
void reply(const std::string& s, long long id, int st, const std::string& ct, const std::string& body) {
    auto x = session(s);
    if (!x) return;
    size_t at = 0;
    do {
        const size_t n = std::min<size_t>(256 << 10, body.size() - at);
        json::Value h;
        h.set("t", json::str("res"));
        h.set("id", json::num(id));
        if (!at) {
            h.set("st", json::num(st));
            h.set("ct", json::str(ct));
        }
        h.set("more", json::boolean(at + n < body.size()));
        if (!sealTo(s, *x, h, body.substr(at, n))) return;
        at += n;
    } while (at < body.size());
}

void handle(const json::Value& j) {
    const std::string m = j["m"].str("GET"), p = j["p"].str();
    int st = 403;
    std::string ct = "application/json", body = "{\"error\":\"Not from another device\"}";
    if (p.rfind("/api/", 0) == 0 && allowed(m, p, j["b"].str())) {
        httplib::Client c("127.0.0.1", S().port);
        c.set_read_timeout(120, 0);
        // marked: from another device (an iPad, a phone) — /api/host then says the Core is not on the one showing it
        const httplib::Headers h{{"X-Infinity-Remote", "1"}};
        auto r = m == "POST" ? c.Post(p, h, j["b"].str(), "application/json") : c.Get(p, h);
        if (!r) st = 502, body = "{\"error\":\"Infinity Core did not answer\"}";
        else st = r->status, ct = r->get_header_value("Content-Type"), body = std::move(r->body);
    }
    reply(j["s"].str(), j["id"].i64(), st, ct, body);
}

void worker() {
    for (;;) {
        json::Value j;
        {
            std::unique_lock<std::mutex> l(S().mu);
            S().cv.wait(l, [] { return !S().jobs.empty() || S().quit; });
            if (S().quit) return;
            j = std::move(S().jobs.front());
            S().jobs.pop_front();
        }
        handle(j);
    }
}

// a browser says who it is: {dev, kid, nb}. Its secret (the current one, or the next one it was just given) makes the
// session; the computer proves it knows it too
void hello(const json::Value& m) {
    const std::string s = m["s"].str(), dev = m["dev"].str(), kid = m["kid"].str();
    std::string nb;
    auto no = [&](const char* why) {
        json::Value r;
        r.set("t", json::str("no"));
        r.set("s", json::str(s));
        r.set("why", json::str(why));
        sendText(r);
    };
    if (!crypto::unb64(m["nb"].str(), nb) || nb.size() != 16) return no("bad");
    std::string secretHex, rekey;
    {
        std::lock_guard<std::mutex> l(cfgMu);
        json::Value c = config();
        dropExpired(c);
        json::Value devs = c["devices"];  // a copy to change (the reads are const), put back below
        json::Value* d = nullptr;
        for (auto& x : devs.arr)
            if (x["id"].str() == dev) d = &x;
        if (!d) { save(c); return no("unknown"); }
        const std::string cur = (*d)["secret"].str(), next = (*d)["next"].str();
        bool changed = false;
        if (tokenHash(cur).substr(0, 16) == kid) secretHex = cur;
        else if (!next.empty() && tokenHash(next).substr(0, 16) == kid) {  // it took the new secret: the link is spent now
            secretHex = next;
            d->set("secret", json::str(next));
            d->set("next", json::str(""));
            d->set("pending", json::boolean(false));
            changed = true;
        } else return no("unknown");
        d->set("lastSeen", json::num(now()));
        if ((*d)["pending"].boolean() && (*d)["next"].str().empty()) {  // first use of its link: a secret of its own, sealed
            rekey = crypto::hex(crypto::random(32));
            d->set("next", json::str(rekey));
            changed = true;
        }
        c.set("devices", devs);
        save(c);
        if (changed) pushAllow(c);
    }
    const std::string secret = crypto::unhex(secretHex), nc = crypto::random(16);
    const std::string K = crypto::hmac(secret, "infinity-session-v1" + nb + nc);
    auto x = std::make_shared<Session>();
    x->dev = dev;
    x->enc = crypto::hmac(K, "enc");
    x->mac = crypto::hmac(K, "mac");
    std::string last;
    {
        std::lock_guard<std::mutex> l(S().mu);
        S().sessions[s] = x;
        last = S().lastEvent;
    }
    json::Value r;
    r.set("t", json::str("hi"));
    r.set("s", json::str(s));
    r.set("nc", json::str(crypto::b64(nc)));
    r.set("proof", json::str(crypto::b64(crypto::hmac(x->mac, "core-proof" + nb))));
    r.set("v", json::num(kApi));
    sendText(r);
    if (!rekey.empty()) {
        json::Value k;
        k.set("t", json::str("rekey"));
        k.set("secret", json::str(rekey));
        sealTo(s, *x, k, "");
    }
    json::Value ev;
    ev.set("t", json::str("ev"));
    if (!last.empty()) sealTo(s, *x, ev, last);
    S().cv.notify_all();  // the events stream starts with the first open device
}

// a sealed message from a browser: in order and from the device, or its session ends (it says hello again)
void sealed(const json::Value& m) {
    const std::string s = m["s"].str();
    auto x = session(s);
    std::string c;
    if (!x || !crypto::unb64(m["c"].str(), c) || c.size() < 56) return;
    std::string plain;
    {
        std::lock_guard<std::mutex> l(x->mu);
        std::string seq(8, '\0');
        for (int i = 0; i < 8; i++) seq[i] = (char)((x->seqIn >> (56 - 8 * i)) & 0xff);
        const std::string iv = c.substr(8, 16), ct = c.substr(24, c.size() - 56), tag = c.substr(c.size() - 32);
        if (c.compare(0, 8, seq) != 0 || !crypto::same(tag, crypto::hmac(x->mac, "B" + c.substr(0, 8) + iv + ct))) {
            fprintf(stderr, "remote: a message that was not in order or not from the device — its session ends\n");
            std::lock_guard<std::mutex> g(S().mu);
            S().sessions.erase(s);
            return;
        }
        x->seqIn++;
        plain = crypto::aesCtr(x->enc, iv, ct);
    }
    json::Value j;
    if (!json::parse(plain, j) || j["t"].str() != "req") return;
    j.set("s", json::str(s));
    {
        std::lock_guard<std::mutex> l(S().mu);
        if (S().jobs.size() < 256) S().jobs.push_back(std::move(j));
    }
    S().cv.notify_all();
}

void onMessage(long long gen, std::string&& data, bool binary) {
    if (binary || data == "pong") return;
    json::Value m;
    if (!json::parse(data, m)) return;
    {
        std::lock_guard<std::mutex> l(S().mu);
        if (gen != S().gen) return;
    }
    const std::string t = m["t"].str();
    if (t == "hi") hello(m);
    else if (t == "x") sealed(m);
    else if (t == "gone") {
        std::lock_guard<std::mutex> l(S().mu);
        S().sessions.erase(m["s"].str());
    }
}

// the player state to every open device. The position alone moving (every 500 ms while it plays) goes out at most every
// 5 s — the page moves its bar by itself; anything else at once; the stream's 15 s keep-alive (the same state) not at all
void events() {
    for (;;) {
        long long gen;
        {
            std::unique_lock<std::mutex> l(S().mu);
            S().cv.wait(l, [] { return S().quit || (S().connected && !S().sessions.empty()); });
            if (S().quit) return;
            gen = S().gen;
        }
        httplib::Client c("127.0.0.1", S().port);
        c.set_read_timeout(24 * 3600, 0);
        {
            std::lock_guard<std::mutex> l(S().mu);
            if (S().quit) return;
            S().events = &c;
        }
        std::string buf, lastData, lastKey;
        auto lastSent = std::chrono::steady_clock::now() - 1h;
        c.Get("/api/events", [&](const char* d, size_t n) {
            buf.append(d, n);
            for (size_t e; (e = buf.find("\n\n")) != std::string::npos;) {
                std::string ev = buf.substr(0, e);
                buf.erase(0, e + 2);
                if (ev.rfind("data: ", 0) != 0) continue;
                std::string data = ev.substr(6);
                if (data == lastData) continue;
                std::string key = data;
                if (size_t at = key.find("\"positionMs\":"); at != std::string::npos) key.erase(at, key.find_first_of(",}", at) - at);
                const auto t = std::chrono::steady_clock::now();
                std::map<std::string, std::shared_ptr<Session>> to;
                {
                    std::lock_guard<std::mutex> l(S().mu);
                    S().lastEvent = data;
                    to = S().sessions;
                }
                if (key == lastKey && t - lastSent < 5s) continue;
                lastData = data, lastKey = key, lastSent = t;
                json::Value h;
                h.set("t", json::str("ev"));
                for (auto& [s, x] : to) sealTo(s, *x, h, data);
            }
            std::lock_guard<std::mutex> l(S().mu);
            return S().connected && !S().sessions.empty() && S().gen == gen && !S().quit;
        });
        {
            std::lock_guard<std::mutex> l(S().mu);
            S().events = nullptr;
        }
        std::this_thread::sleep_for(300ms);
    }
}

// the connection: open while the setting is on, again after a drop (1 s, 2 s, … 60 s apart), a "ping" every 30 s (the room
// answers it without waking: an idle connection costs nothing)
void run() {
    int backoff = 1;
    for (;;) {
        json::Value c = config();
        if (!c["on"].boolean()) {
            std::unique_lock<std::mutex> l(S().mu);
            S().error.clear();
            if (!S().quit) S().cv.wait_for(l, 60s);
            if (S().quit) return;
            continue;
        }
        const std::string room = c["room"].str(), key = c["key"].str();
        long long gen;
        {
            std::lock_guard<std::mutex> l(S().mu);
            gen = ++S().gen;
            S().connected = false, S().closed = false;
            S().sessions.clear();
        }
        ws::Events ev;
        ev.open = [gen] {
            {
                std::lock_guard<std::mutex> l(S().mu);
                if (gen != S().gen) return;
                S().connected = true;
                S().error.clear();
            }
            fprintf(stderr, "remote: connected to %s\n", kBase.c_str());
            std::lock_guard<std::mutex> l(cfgMu);
            pushAllow(config());
            S().cv.notify_all();
        };
        ev.message = [gen](std::string&& d, bool bin) { onMessage(gen, std::move(d), bin); };
        ev.closed = [gen](const std::string& why) {
            {
                std::lock_guard<std::mutex> l(S().mu);
                if (gen != S().gen) return;
                if (S().connected) fprintf(stderr, "remote: connection ended (%s)\n", why.c_str());
                S().connected = false, S().closed = true, S().error = why;
                S().sessions.clear();
            }
            S().cv.notify_all();
        };
        auto sock = ws::connect(kBase + "/v1/core?room=" + room, {{"X-Room-Key", key}}, ev);
        if (!sock) {
            std::unique_lock<std::mutex> l(S().mu);
            S().error = "Remote access is not available on this computer yet";
            S().closed = true;
            if (!S().quit) S().cv.wait_for(l, 60s);
            if (S().quit) return;
            continue;
        }
        const auto opened = std::chrono::steady_clock::now();
        {
            std::unique_lock<std::mutex> l(S().mu);
            S().sock = sock;
            while (!S().closed && !S().quit) {
                const bool tick = S().cv.wait_for(l, 30s) == std::cv_status::timeout;
                l.unlock();
                json::Value cur = config();
                const bool keep = cur["on"].boolean() && cur["room"].str() == room;
                if (!keep) ws::close(*sock);  // turned off: the closed callback ends the wait
                else if (tick) {
                    ws::send(*sock, "ping", false);
                    std::lock_guard<std::mutex> g(cfgMu);
                    if (dropExpired(cur)) { save(cur); pushAllow(cur); }
                }
                l.lock();
            }
            S().sock.reset();
        }
        ws::close(*sock);
        backoff = std::chrono::steady_clock::now() - opened > 60s ? 1 : std::min(backoff * 2, 60);
        std::unique_lock<std::mutex> l(S().mu);
        if (S().cv.wait_for(l, std::chrono::seconds(backoff), [] { return S().quit; })) return;
    }
}
}  // namespace

void start(Library& lib, int port) {
    S().lib = &lib;
    S().port = port;
    joinOnStop(std::thread(run));
    joinOnStop(std::thread(events));
    for (int i = 0; i < 6; i++) joinOnStop(std::thread(worker));  // covers and lists of a page in parallel
    onStop([] {  // runs before the joins above: the connection closes (run), the events stream ends, the workers wake
        {
            std::lock_guard<std::mutex> l(S().mu);
            S().quit = true;
            if (S().events) S().events->stop();
        }
        S().cv.notify_all();
    });
}

json::Value status() {
    json::Value c;
    {
        std::lock_guard<std::mutex> l(cfgMu);
        c = config();
        if (dropExpired(c)) save(c);
    }
    json::Value o, devs;
    devs.type = json::Value::Arr;
    const bool on = c["on"].boolean();
    o.set("on", json::boolean(on));
    std::lock_guard<std::mutex> l(S().mu);
    o.set("connected", json::boolean(on && S().connected));
    if (on && !S().connected && !S().error.empty()) o.set("error", json::str(S().error));
    int open = 0;
    for (auto& d : c["devices"].arr) {
        int n = 0;
        for (auto& [s, x] : S().sessions) n += x->dev == d["id"].str();
        open += n;
        json::Value j;
        j.set("id", d["id"]);
        j.set("name", d["name"]);
        j.set("added", d["added"]);
        j.set("lastSeen", d["lastSeen"]);
        j.set("online", json::boolean(n > 0));
        const bool waiting = d["pending"].boolean() && !d["lastSeen"].i64();
        j.set("waiting", json::boolean(waiting));  // its link not opened yet
        if (waiting) j.set("expiresIn", json::num(std::max(0LL, kPendingSecs - (now() - d["added"].i64()))));
        devs.push(j);
    }
    o.set("open", json::num(open));
    o.set("devices", devs);
    return o;
}

json::Value set(const json::Value& v) {
    std::string link;
    {
        std::lock_guard<std::mutex> l(cfgMu);
        json::Value c = config();
        if (c["room"].str().size() != 32 || c["key"].str().size() != 64) {
            c.set("room", json::str(crypto::hex(crypto::random(16))));
            c.set("key", json::str(crypto::hex(crypto::random(32))));
        }
        if (v.has("on")) c.set("on", json::boolean(v["on"].boolean()));
        if (!c.has("devices")) {
            json::Value a;
            a.type = json::Value::Arr;
            c.set("devices", a);
        }
        if (v.has("add")) {  // a new device: its own secret, in the link (QR) shown once
            std::string name = v["add"].str();
            if (name.empty()) name = "Device";
            if (name.size() > 60) name.resize(60);
            json::Value d;
            const std::string id = crypto::hex(crypto::random(8)), secret = crypto::hex(crypto::random(32));
            d.set("id", json::str(id));
            d.set("name", json::str(name));
            d.set("secret", json::str(secret));
            d.set("added", json::num(now()));
            d.set("lastSeen", json::num(0));
            d.set("pending", json::boolean(true));
            json::Value devs = c["devices"];
            devs.push(d);
            c.set("devices", devs);
            link = kPage + "/#pair=" + c["room"].str() + "." + id + "." + secret;
        }
        if (v.has("remove")) {  // gone from the room's list at once: its open pages are closed there
            json::Value keep;
            keep.type = json::Value::Arr;
            for (auto& d : c["devices"].arr)
                if (d["id"].str() != v["remove"].str()) keep.push(d);
            c.set("devices", keep);
            std::lock_guard<std::mutex> g(S().mu);
            for (auto it = S().sessions.begin(); it != S().sessions.end();)
                it = it->second->dev == v["remove"].str() ? S().sessions.erase(it) : std::next(it);
        }
        if (v.has("rename")) {
            json::Value devs = c["devices"];
            for (auto& d : devs.arr)
                if (d["id"].str() == v["rename"].str()) d.set("name", json::str(v["name"].str().substr(0, 60)));
            c.set("devices", devs);
        }
        dropExpired(c);
        save(c);
        pushAllow(c);
    }
    S().cv.notify_all();
    json::Value o = status();
    if (!link.empty()) o.set("link", json::str(link));
    return o;
}
}  // namespace remote
