#pragma once
#include <cstdint>
#include <string>

namespace librespotc::zeroconf {

// Advertises a single _spotify-connect._tcp service. Uses Windows DNS-SD
// (DnsServiceRegister, Windows 10 1809+) where available and falls back to
// direct UDP mDNS under Wine or when DNS-SD is unavailable.
class MdnsAdvertiser {
public:
    MdnsAdvertiser();
    ~MdnsAdvertiser();

    // Register/refresh advertisement. Service name = instance host part of "<device_name>".
    bool advertise(const std::string& device_name, uint16_t port);
    void stop();

private:
    struct Impl;
    Impl* impl_;
};

} // namespace librespotc::zeroconf
