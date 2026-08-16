#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <string>

namespace librespotc::zeroconf {

struct HttpRequest {
    std::string method;
    std::string path;
    std::map<std::string, std::string> query;  // url-decoded
    std::map<std::string, std::string> form;   // url-decoded body params (POST)
    std::string body;
};

struct HttpResponse {
    int status = 200;
    std::string status_text = "OK";
    std::string content_type = "application/json";
    std::string body;
};

using Handler = std::function<HttpResponse(const HttpRequest&)>;

// Minimal HTTP/1.1 server. Binds to 0.0.0.0:port. Blocks in accept loop on
// the calling thread; spawns a thread per connection. Single handler routes
// everything.
class HttpServer {
public:
    HttpServer();
    ~HttpServer();

    bool start(uint16_t port);   // 0 = OS-assigned
    void stop();
    uint16_t local_port() const { return port_; }
    void set_handler(Handler h) { handler_ = std::move(h); }

    // Run accept loop until stop() is called.
    void run();

private:
    uintptr_t listen_fd_ = (uintptr_t)-1;
    uint16_t port_ = 0;
    Handler handler_;
    bool running_ = false;
};

} // namespace librespotc::zeroconf
