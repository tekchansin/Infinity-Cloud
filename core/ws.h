// A WebSocket client (wss://) on the system's own network stack: Network.framework on macOS (ws_mac.cpp), WinHTTP on
// Windows (ws_win.cpp) — the Mac's libcurl has no WebSocket. For Infinity Remote (remote.cpp).
#pragma once
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace ws {
struct Socket;  // the platform's connection
struct Events {
    std::function<void()> open;
    std::function<void(std::string&& data, bool binary)> message;  // one thread, in order: hand long work to another
    std::function<void(const std::string& why)> closed;            // once, whatever ended it (a connect that failed too)
};
// connecting starts at once; nullptr = not possible here
std::shared_ptr<Socket> connect(const std::string& url, const std::vector<std::pair<std::string, std::string>>& headers, Events ev);
bool send(Socket& s, const std::string& data, bool binary);  // any thread; false: it is closed
void close(Socket& s);
}  // namespace ws
