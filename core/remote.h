// Infinity Remote (owner 2026-11-07, MusicApp/docs/WEB_REMOTE_PLAN.md): Settings › Remote access puts this Core in a room
// at player.anantarultimate.com (MusicApp/cloud/remote-worker), where an iPad or a phone with the room's link controls it —
// at home or away, no port forwarding (the Core connects out). Off by default.
#pragma once
#include "network/json.h"

class Library;

namespace remote {
void start(Library& lib, int port);  // follows the setting from now on (main, once)
json::Value status();                // {on, connected, peers, link, error}
json::Value set(const json::Value& v);  // {on} · {renew: true} = a new room and key: every link given out stops working
}  // namespace remote
