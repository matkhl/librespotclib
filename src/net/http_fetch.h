#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <functional>

namespace librespotc::net {

struct HttpFetchResult {
    int status = 0;
    std::string status_text;
    std::vector<uint8_t> body;
};

// HTTPS GET to arbitrary URL. Supports optional Range header.
// range_start/range_end inclusive. If both 0, no Range header.
HttpFetchResult https_get(const std::string& url,
                          const std::map<std::string,std::string>& headers = {},
                          uint64_t range_start = 0,
                          uint64_t range_end = 0);

// Streaming HTTPS GET. Callback is invoked for each received chunk.
// Return false from callback to abort.
using ChunkSink = std::function<bool(const uint8_t* data, size_t len)>;
struct HttpStreamResult {
    int status = 0;
    std::string status_text;
    uint64_t bytes_read = 0;
    uint64_t content_length = 0;
    bool content_length_known = false;
    bool complete = false;
    bool aborted_by_sink = false;
    uint32_t winhttp_error = 0;
    std::string phase;
    bool timed_out = false;
};

HttpStreamResult https_get_stream(const std::string& url,
                                  const std::map<std::string,std::string>& headers,
                                  ChunkSink on_chunk);

// HTTPS POST. content_type is sent as Content-Type header.
HttpFetchResult https_post(const std::string& url,
                           const std::string& content_type,
                           const uint8_t* body, size_t body_len,
                           const std::map<std::string,std::string>& headers = {});

// HTTPS request with custom method (PUT, DELETE, etc.).
HttpFetchResult https_request(const std::string& method,
                              const std::string& url,
                              const std::string& content_type,
                              const uint8_t* body, size_t body_len,
                              const std::map<std::string,std::string>& headers = {});

} // namespace librespotc::net
