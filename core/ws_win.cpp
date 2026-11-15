// ws.h on Windows: WinHTTP's WebSocket (TLS, proxies and certificates as the system has them). One thread per connection
// reads; sends take turns (WinHTTP allows one send and one receive at a time).
#include "ws.h"

#include <windows.h>
#include <winhttp.h>

#include <atomic>
#include <cstdlib>
#include <mutex>
#include <thread>

namespace ws {
struct Socket {
    HINTERNET session = nullptr, conn = nullptr, ws = nullptr;
    Events ev;
    std::atomic<bool> done{false};
    std::mutex sendMu, closeMu;
    void finish(const std::string& why) {
        if (!done.exchange(true) && ev.closed) ev.closed(why);
    }
    ~Socket() {
        if (ws) WinHttpCloseHandle(ws);
        if (conn) WinHttpCloseHandle(conn);
        if (session) WinHttpCloseHandle(session);
    }
};

namespace {
std::wstring wide(const std::string& s) {
    if (s.empty()) return L"";
    std::wstring w(MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), (int)w.size());
    return w;
}
std::string err(const char* what) { return std::string(what) + " (" + std::to_string(GetLastError()) + ")"; }

void run(std::shared_ptr<Socket> s, std::string url, std::vector<std::pair<std::string, std::string>> headers) {
    const bool tls = url.rfind("wss://", 0) == 0;  // ws:// only for tests on this computer
    std::string rest = url.substr(url.find("//") + 2);
    const size_t slash = rest.find('/');
    std::string host = rest.substr(0, slash), path = slash == std::string::npos ? "/" : rest.substr(slash);
    INTERNET_PORT port = tls ? 443 : 80;
    if (size_t c = host.rfind(':'); c != std::string::npos) port = (INTERNET_PORT)atoi(host.c_str() + c + 1), host.resize(c);

    s->session = WinHttpOpen(L"Infinity", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s->session) return s->finish(err("no WinHTTP"));
    // nothing for 75 s is a dead connection: the computer pings every 30 s and the room answers
    WinHttpSetTimeouts(s->session, 15000, 15000, 30000, 75000);
    s->conn = WinHttpConnect(s->session, wide(host).c_str(), port, 0);
    HINTERNET req = s->conn ? WinHttpOpenRequest(s->conn, L"GET", wide(path).c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                 tls ? WINHTTP_FLAG_SECURE : 0)
                            : nullptr;
    if (!req) return s->finish(err("cannot reach the server"));
    std::wstring hs;
    for (auto& [k, v] : headers) hs += wide(k) + L": " + wide(v) + L"\r\n";
    DWORD status = 0, size = sizeof status;
    const bool ok = WinHttpSetOption(req, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0) &&
                    (hs.empty() || WinHttpAddRequestHeaders(req, hs.c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD)) &&
                    WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0) && WinHttpReceiveResponse(req, nullptr) &&
                    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &size,
                                        WINHTTP_NO_HEADER_INDEX);
    if (!ok || status != 101) {
        const std::string why = ok ? "refused (" + std::to_string(status) + ")" : err("failed");
        WinHttpCloseHandle(req);
        return s->finish(why);
    }
    {
        std::lock_guard<std::mutex> l(s->closeMu);
        s->ws = WinHttpWebSocketCompleteUpgrade(req, 0);
    }
    WinHttpCloseHandle(req);
    if (!s->ws) return s->finish(err("no WebSocket"));
    if (s->ev.open) s->ev.open();
    std::string msg, buf(64 << 10, '\0');
    for (;;) {
        DWORD got = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE type;
        if (WinHttpWebSocketReceive(s->ws, buf.data(), (DWORD)buf.size(), &got, &type) != NO_ERROR) break;
        if (type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) break;
        msg.append(buf.data(), got);
        if (type == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE || type == WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE) continue;
        if (s->ev.message) s->ev.message(std::move(msg), type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE);
        msg.clear();
    }
    s->finish("closed");
}
}  // namespace

std::shared_ptr<Socket> connect(const std::string& url, const std::vector<std::pair<std::string, std::string>>& headers, Events ev) {
    auto s = std::make_shared<Socket>();
    s->ev = std::move(ev);
    std::thread(run, s, url, headers).detach();  // the thread holds it until the connection ends
    return s;
}

bool send(Socket& s, const std::string& data, bool binary) {
    if (s.done || !s.ws) return false;
    std::lock_guard<std::mutex> l(s.sendMu);
    return WinHttpWebSocketSend(s.ws, binary ? WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE : WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                                (PVOID)data.data(), (DWORD)data.size()) == NO_ERROR;
}

// the close frame; the reading thread sees the answer (or the error) and ends the connection
void close(Socket& s) {
    std::lock_guard<std::mutex> l(s.closeMu);
    if (s.ws && !s.done) WinHttpWebSocketShutdown(s.ws, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
}
}  // namespace ws
