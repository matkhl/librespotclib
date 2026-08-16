#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace librespotc::connect {

// Minimal WSS client built on WinHTTP WebSocket API (Windows 8+).
class WebSocket {
public:
    WebSocket();
    ~WebSocket();
    WebSocket(const WebSocket&) = delete;
    WebSocket& operator=(const WebSocket&) = delete;

    // Connect to wss://<host>:<port><path>. Optional extra headers.
    bool connect(const std::string& url,
                 const std::map<std::string, std::string>& extra_headers = {});

    // Send a UTF-8 text frame.
    bool send_text(const std::string& text);

    // Receive next message (text or binary). Returns true on success.
    // Frames are reassembled (CONTINUATION handled by WinHTTP).
    bool recv(std::string& out, bool& is_text);

    void close();
    bool is_open() const;

private:
    void* hSession_ = nullptr;
    void* hConn_   = nullptr;
    void* hRequest_ = nullptr;
    void* hWebsocket_ = nullptr;
    bool open_ = false;
};

} // namespace librespotc::connect
