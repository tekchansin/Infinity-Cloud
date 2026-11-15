// ws.h on macOS: Network.framework's WebSocket (nw_ws), TLS and proxies as the system has them
#include "ws.h"

#include <Network/Network.h>
#include <dispatch/dispatch.h>

#include <atomic>

namespace ws {
struct Socket {
    nw_connection_t c = nullptr;
    dispatch_queue_t q = nullptr;
    Events ev;
    std::atomic<bool> done{false};
    ~Socket() {
        if (c) { nw_connection_cancel(c); nw_release(c); }
        if (q) dispatch_release(q);
    }
    void finish(const std::string& why) {
        if (!done.exchange(true) && ev.closed) ev.closed(why);
    }
};

namespace {
std::string why(nw_error_t e, const char* dflt) {
    if (!e) return dflt;
    return std::string(dflt) + " (" + std::to_string(nw_error_get_error_domain(e)) + "/" + std::to_string(nw_error_get_error_code(e)) + ")";
}

void receive(std::shared_ptr<Socket> s) {
    nw_connection_receive_message(s->c, ^(dispatch_data_t content, nw_content_context_t ctx, bool, nw_error_t err) {
        if (err || s->done) { nw_connection_cancel(s->c); return; }
        nw_ws_opcode_t op = nw_ws_opcode_invalid;
        if (ctx) {
            nw_protocol_definition_t def = nw_protocol_copy_ws_definition();
            if (nw_protocol_metadata_t md = nw_content_context_copy_protocol_metadata(ctx, def)) {
                op = nw_ws_metadata_get_opcode(md);
                nw_release(md);
            }
            nw_release(def);
        }
        if (op == nw_ws_opcode_close) { nw_connection_cancel(s->c); return; }
        if (op == nw_ws_opcode_text || op == nw_ws_opcode_binary) {
            __block std::string data;
            if (content) {
                data.reserve(dispatch_data_get_size(content));
                dispatch_data_apply(content, ^bool(dispatch_data_t, size_t, const void* buf, size_t n) {
                    data.append(static_cast<const char*>(buf), n);
                    return true;
                });
            }
            if (s->ev.message) s->ev.message(std::move(data), op == nw_ws_opcode_binary);
        }
        receive(s);
    });
}
}  // namespace

std::shared_ptr<Socket> connect(const std::string& url, const std::vector<std::pair<std::string, std::string>>& headers, Events ev) {
    nw_endpoint_t ep = nw_endpoint_create_url(url.c_str());
    if (!ep) return nullptr;
    auto s = std::make_shared<Socket>();
    s->ev = std::move(ev);
    const bool tls = url.rfind("wss://", 0) == 0;  // ws:// only for tests on this computer
    nw_parameters_t params = nw_parameters_create_secure_tcp(tls ? NW_PARAMETERS_DEFAULT_CONFIGURATION : NW_PARAMETERS_DISABLE_PROTOCOL,
                                                             NW_PARAMETERS_DEFAULT_CONFIGURATION);
    nw_protocol_options_t wso = nw_ws_create_options(nw_ws_version_13);
    for (auto& [k, v] : headers) nw_ws_options_add_additional_header(wso, k.c_str(), v.c_str());
    nw_ws_options_set_auto_reply_ping(wso, true);
    nw_ws_options_set_maximum_message_size(wso, 64 << 20);
    nw_protocol_stack_t stack = nw_parameters_copy_default_protocol_stack(params);
    nw_protocol_stack_prepend_application_protocol(stack, wso);
    nw_release(stack);
    nw_release(wso);
    s->c = nw_connection_create(ep, params);
    nw_release(ep);
    nw_release(params);
    s->q = dispatch_queue_create("infinity.ws", DISPATCH_QUEUE_SERIAL);
    nw_connection_set_queue(s->c, s->q);
    // the state handler holds it weakly (the caller owns it); a pending receive holds it until the connection ends — so
    // the caller ends it with close() before letting go
    std::weak_ptr<Socket> wk = s;
    nw_connection_set_state_changed_handler(s->c, ^(nw_connection_state_t st, nw_error_t err) {
        std::shared_ptr<Socket> self = wk.lock();
        if (!self) return;
        if (st == nw_connection_state_ready) {
            if (self->ev.open) self->ev.open();
            receive(self);
        } else if (st == nw_connection_state_waiting || st == nw_connection_state_failed) {
            self->finish(why(err, st == nw_connection_state_waiting ? "no route" : "failed"));  // the caller tries again later
            nw_connection_cancel(self->c);
        } else if (st == nw_connection_state_cancelled) {
            self->finish("closed");
        }
    });
    nw_connection_start(s->c);
    return s;
}

bool send(Socket& s, const std::string& data, bool binary) {
    if (s.done) return false;
    nw_protocol_metadata_t md = nw_ws_create_metadata(binary ? nw_ws_opcode_binary : nw_ws_opcode_text);
    nw_content_context_t ctx = nw_content_context_create("msg");
    nw_content_context_set_metadata_for_protocol(ctx, md);
    auto* copy = new std::string(data);
    dispatch_data_t d = dispatch_data_create(copy->data(), copy->size(), nullptr, ^{ delete copy; });
    nw_connection_send(s.c, d, ctx, true, ^(nw_error_t) {});
    dispatch_release(d);
    nw_release(ctx);
    nw_release(md);
    return true;
}

void close(Socket& s) { nw_connection_cancel(s.c); }
}  // namespace ws
