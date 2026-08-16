#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace librespotc::net {

struct ApEndpoint {
    std::string host;
    uint16_t port;
};

// Returns list of accesspoint endpoints from apresolve.spotify.com.
// Throws std::runtime_error on hard failure. Falls back to a default ap-gew4 host
// if the HTTPS request fails or returns empty.
std::vector<ApEndpoint> resolve_accesspoints();

} // namespace librespotc::net
