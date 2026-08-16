#include "mdns.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace librespotc::zeroconf {

namespace {

constexpr uint16_t kMdnsPort = 5353;
constexpr uint32_t kRecordTtlSeconds = 120;
constexpr const char* kServiceType = "_spotify-connect._tcp.local";
constexpr const char* kMulticastAddr = "224.0.0.251";

using DnsServiceConstructInstanceFn = DNS_SERVICE_INSTANCE*(WINAPI*)(
    PCWSTR, PCWSTR, PIP4_ADDRESS, PIP6_ADDRESS, WORD, WORD, WORD, DWORD,
    PCWSTR*, PCWSTR*);
using DnsServiceRegisterFn = DNS_STATUS(WINAPI*)(
    PDNS_SERVICE_REGISTER_REQUEST, PDNS_SERVICE_CANCEL);
using DnsServiceDeRegisterFn = DNS_STATUS(WINAPI*)(
    PDNS_SERVICE_REGISTER_REQUEST, PDNS_SERVICE_CANCEL);
using DnsServiceFreeInstanceFn = VOID(WINAPI*)(PDNS_SERVICE_INSTANCE);

struct DnsApi {
    HMODULE module = nullptr;
    DnsServiceConstructInstanceFn construct_instance = nullptr;
    DnsServiceRegisterFn register_service = nullptr;
    DnsServiceDeRegisterFn deregister_service = nullptr;
    DnsServiceFreeInstanceFn free_instance = nullptr;
};

static bool running_under_wine() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    return ntdll && GetProcAddress(ntdll, "wine_get_version");
}

static DnsApi load_dnsapi() {
    DnsApi api;
    api.module = LoadLibraryW(L"dnsapi.dll");
    if (!api.module) return api;
    api.construct_instance = reinterpret_cast<DnsServiceConstructInstanceFn>(
        GetProcAddress(api.module, "DnsServiceConstructInstance"));
    api.register_service = reinterpret_cast<DnsServiceRegisterFn>(
        GetProcAddress(api.module, "DnsServiceRegister"));
    api.deregister_service = reinterpret_cast<DnsServiceDeRegisterFn>(
        GetProcAddress(api.module, "DnsServiceDeRegister"));
    api.free_instance = reinterpret_cast<DnsServiceFreeInstanceFn>(
        GetProcAddress(api.module, "DnsServiceFreeInstance"));
    return api;
}

static std::string to_lower_ascii(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

static std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                                nullptr, 0);
    std::wstring w(n, 0);
    if (n > 0) {
        MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                            w.data(), n);
    }
    return w;
}

static std::string sanitize_label(const std::string& in,
                                  const std::string& fallback) {
    std::string out;
    out.reserve(in.size());
    for (unsigned char c : in) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9')) {
            out.push_back(static_cast<char>(c));
        } else if (c == '-' || c == '_') {
            out.push_back('-');
        }
    }
    while (!out.empty() && out.front() == '-') out.erase(out.begin());
    while (!out.empty() && out.back() == '-') out.pop_back();
    if (out.empty()) out = fallback;
    if (out.size() > 63) out.resize(63);
    return out;
}

static std::string local_host_name() {
    char host[256] = {};
    DWORD len = static_cast<DWORD>(sizeof(host));
    if (!GetComputerNameExA(ComputerNameDnsHostname, host, &len) || len == 0) {
        len = static_cast<DWORD>(sizeof(host));
        if (!GetComputerNameA(host, &len) || len == 0) {
            std::strcpy(host, "librespotc");
        }
    }
    return sanitize_label(std::string(host), "librespotc") + ".local";
}

static void put_u16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(v & 0xff));
}

static void put_u32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(v & 0xff));
}

static void patch_u16(std::vector<uint8_t>& out, size_t pos, uint16_t v) {
    out[pos] = static_cast<uint8_t>((v >> 8) & 0xff);
    out[pos + 1] = static_cast<uint8_t>(v & 0xff);
}

static void put_name(std::vector<uint8_t>& out, const std::string& name) {
    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) dot = name.size();
        size_t len = dot - start;
        if (len > 0) {
            if (len > 63) len = 63;
            out.push_back(static_cast<uint8_t>(len));
            out.insert(out.end(), name.begin() + start, name.begin() + start + len);
        }
        start = dot + 1;
    }
    out.push_back(0);
}

static bool read_name(const uint8_t* data, size_t size, size_t& offset,
                      std::string& out) {
    out.clear();
    size_t pos = offset;
    size_t next = offset;
    bool jumped = false;
    int jumps = 0;

    while (pos < size) {
        uint8_t len = data[pos++];
        if (len == 0) {
            if (!jumped) next = pos;
            offset = next;
            return true;
        }
        if ((len & 0xc0) == 0xc0) {
            if (pos >= size || ++jumps > 8) return false;
            uint16_t ptr = static_cast<uint16_t>(((len & 0x3f) << 8) | data[pos++]);
            if (ptr >= size) return false;
            if (!jumped) next = pos;
            pos = ptr;
            jumped = true;
            continue;
        }
        if ((len & 0xc0) != 0 || pos + len > size) return false;
        if (!out.empty()) out.push_back('.');
        out.append(reinterpret_cast<const char*>(data + pos), len);
        pos += len;
        if (!jumped) next = pos;
    }
    return false;
}

static bool is_loopback_ipv4(uint32_t addr_net) {
    uint32_t addr = ntohl(addr_net);
    return (addr >> 24) == 127;
}

static std::vector<uint32_t> local_ipv4_addresses() {
    std::set<uint32_t> unique;

    SOCKET probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (probe != INVALID_SOCKET) {
        sockaddr_in remote{};
        remote.sin_family = AF_INET;
        remote.sin_port = htons(53);
        inet_pton(AF_INET, "8.8.8.8", &remote.sin_addr);
        connect(probe, reinterpret_cast<sockaddr*>(&remote), sizeof(remote));

        sockaddr_in local{};
        int len = sizeof(local);
        if (getsockname(probe, reinterpret_cast<sockaddr*>(&local), &len) == 0 &&
            local.sin_addr.s_addr != INADDR_ANY &&
            !is_loopback_ipv4(local.sin_addr.s_addr)) {
            unique.insert(local.sin_addr.s_addr);
        }
        closesocket(probe);
    }

    char host[256] = {};
    if (gethostname(host, sizeof(host)) == 0) {
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        addrinfo* res = nullptr;
        if (getaddrinfo(host, nullptr, &hints, &res) == 0) {
            for (addrinfo* it = res; it; it = it->ai_next) {
                auto* sin = reinterpret_cast<sockaddr_in*>(it->ai_addr);
                if (sin && sin->sin_addr.s_addr != INADDR_ANY &&
                    !is_loopback_ipv4(sin->sin_addr.s_addr)) {
                    unique.insert(sin->sin_addr.s_addr);
                }
            }
            freeaddrinfo(res);
        }
    }

    return std::vector<uint32_t>(unique.begin(), unique.end());
}

static void add_record_header(std::vector<uint8_t>& packet,
                              const std::string& name,
                              uint16_t type,
                              uint16_t klass,
                              uint32_t ttl,
                              size_t& rdlen_pos) {
    put_name(packet, name);
    put_u16(packet, type);
    put_u16(packet, klass);
    put_u32(packet, ttl);
    rdlen_pos = packet.size();
    put_u16(packet, 0);
}

static std::vector<uint8_t> build_response_packet(const std::string& instance_name,
                                                  const std::string& host_name,
                                                  uint16_t port,
                                                  const std::vector<uint32_t>& ips) {
    std::vector<uint8_t> packet;
    packet.reserve(512);

    put_u16(packet, 0);      // transaction ID
    put_u16(packet, 0x8400); // response + authoritative answer
    put_u16(packet, 0);      // questions

    const uint16_t answer_count =
        static_cast<uint16_t>(3 + static_cast<uint16_t>(ips.size()));
    put_u16(packet, answer_count);
    put_u16(packet, 0);      // authority
    put_u16(packet, 0);      // additional

    size_t rdlen_pos = 0;
    size_t rdata_start = 0;

    add_record_header(packet, kServiceType, 12, 0x0001, kRecordTtlSeconds,
                      rdlen_pos); // PTR
    rdata_start = packet.size();
    put_name(packet, instance_name);
    patch_u16(packet, rdlen_pos,
              static_cast<uint16_t>(packet.size() - rdata_start));

    add_record_header(packet, instance_name, 33, 0x8001, kRecordTtlSeconds,
                      rdlen_pos); // SRV + cache flush
    rdata_start = packet.size();
    put_u16(packet, 0); // priority
    put_u16(packet, 0); // weight
    put_u16(packet, port);
    put_name(packet, host_name);
    patch_u16(packet, rdlen_pos,
              static_cast<uint16_t>(packet.size() - rdata_start));

    add_record_header(packet, instance_name, 16, 0x8001, kRecordTtlSeconds,
                      rdlen_pos); // TXT + cache flush
    rdata_start = packet.size();
    packet.push_back(0); // DNS-SD empty TXT record
    patch_u16(packet, rdlen_pos,
              static_cast<uint16_t>(packet.size() - rdata_start));

    for (uint32_t ip : ips) {
        add_record_header(packet, host_name, 1, 0x8001, kRecordTtlSeconds,
                          rdlen_pos); // A + cache flush
        rdata_start = packet.size();
        packet.insert(packet.end(),
                      reinterpret_cast<const uint8_t*>(&ip),
                      reinterpret_cast<const uint8_t*>(&ip) + 4);
        patch_u16(packet, rdlen_pos,
                  static_cast<uint16_t>(packet.size() - rdata_start));
    }

    return packet;
}

static bool query_matches(const uint8_t* data, size_t size,
                          const std::string& instance_name,
                          const std::string& host_name) {
    if (size < 12) return false;
    uint16_t qdcount = static_cast<uint16_t>((data[4] << 8) | data[5]);
    size_t offset = 12;
    const std::string service_l = to_lower_ascii(kServiceType);
    const std::string instance_l = to_lower_ascii(instance_name);
    const std::string host_l = to_lower_ascii(host_name);

    for (uint16_t i = 0; i < qdcount; ++i) {
        std::string qname;
        if (!read_name(data, size, offset, qname) || offset + 4 > size) {
            return false;
        }
        uint16_t qtype = static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
        offset += 4; // type + class

        qname = to_lower_ascii(qname);
        if ((qname == service_l && (qtype == 12 || qtype == 255)) ||
            (qname == instance_l && (qtype == 16 || qtype == 33 || qtype == 255)) ||
            (qname == host_l && (qtype == 1 || qtype == 255))) {
            return true;
        }
    }
    return false;
}

static void send_multicast(SOCKET s, const std::vector<uint8_t>& packet) {
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(kMdnsPort);
    inet_pton(AF_INET, kMulticastAddr, &dst.sin_addr);
    sendto(s, reinterpret_cast<const char*>(packet.data()),
           static_cast<int>(packet.size()), 0,
           reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
}

static void CALLBACK reg_callback(DWORD /*status*/, PVOID ctx,
                                  PDNS_SERVICE_INSTANCE p) {
    auto* api = static_cast<DnsApi*>(ctx);
    if (p && api && api->free_instance) api->free_instance(p);
}

} // namespace

struct MdnsAdvertiser::Impl {
    DnsApi dns;
    DNS_SERVICE_INSTANCE* dns_instance = nullptr;
    bool dns_registered = false;
    std::wstring service_name_w;
    std::wstring host_w;

    std::atomic<bool> udp_running{false};
    std::thread udp_thread;
    SOCKET udp_tx = INVALID_SOCKET;
    SOCKET udp_rx = INVALID_SOCKET;
    std::string instance_name;
    std::string host_name;
    uint16_t port = 0;
    std::vector<uint32_t> ipv4;

    bool advertise_dnsapi(const std::string& device_name, uint16_t port);
    bool advertise_udp(const std::string& device_name, uint16_t port);
    void stop_dnsapi();
    void stop_udp();
    void udp_loop();
};

MdnsAdvertiser::MdnsAdvertiser() : impl_(new Impl()) {}
MdnsAdvertiser::~MdnsAdvertiser() {
    stop();
    delete impl_;
}

bool MdnsAdvertiser::Impl::advertise_dnsapi(const std::string& device_name,
                                            uint16_t listen_port) {
    if (running_under_wine()) {
        std::fprintf(stderr, "[mdns] Wine detected; using UDP mDNS fallback\n");
        return false;
    }

    dns = load_dnsapi();
    if (!dns.construct_instance || !dns.register_service ||
        !dns.deregister_service || !dns.free_instance) {
        std::fprintf(stderr, "[mdns] Windows DNS-SD unavailable; using UDP mDNS fallback\n");
        return false;
    }

    service_name_w = widen(device_name + "." + kServiceType);

    wchar_t host_buf[256] = {0};
    DWORD host_buf_len = static_cast<DWORD>(sizeof(host_buf) / sizeof(wchar_t));
    if (!GetComputerNameExW(ComputerNameDnsHostname, host_buf, &host_buf_len)) {
        wcscpy_s(host_buf, L"librespotc");
    }
    host_w = std::wstring(host_buf) + L".local";

    DNS_SERVICE_INSTANCE* inst = dns.construct_instance(
        service_name_w.c_str(),
        host_w.c_str(),
        nullptr,
        nullptr,
        listen_port,
        0,
        0,
        0,
        nullptr,
        nullptr);

    if (!inst) {
        std::fprintf(stderr, "[mdns] DnsServiceConstructInstance failed; using UDP mDNS fallback\n");
        return false;
    }
    dns_instance = inst;

    DNS_SERVICE_REGISTER_REQUEST req{};
    req.Version = DNS_QUERY_REQUEST_VERSION1;
    req.InterfaceIndex = 0;
    req.pServiceInstance = inst;
    req.pRegisterCompletionCallback = reg_callback;
    req.pQueryContext = &dns;
    req.hCredentials = nullptr;
    req.unicastEnabled = FALSE;

    DWORD rc = dns.register_service(&req, nullptr);
    if (rc != DNS_REQUEST_PENDING && rc != ERROR_SUCCESS) {
        std::fprintf(stderr, "[mdns] DnsServiceRegister failed: %lu; using UDP mDNS fallback\n", rc);
        dns.free_instance(inst);
        dns_instance = nullptr;
        return false;
    }
    dns_registered = true;
    std::fprintf(stderr, "[mdns] Windows DNS-SD advertiser active\n");
    return true;
}

bool MdnsAdvertiser::Impl::advertise_udp(const std::string& device_name,
                                         uint16_t listen_port) {
    instance_name = device_name + "." + kServiceType;
    host_name = local_host_name();
    port = listen_port;
    ipv4 = local_ipv4_addresses();

    udp_tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_tx == INVALID_SOCKET) {
        std::fprintf(stderr, "[mdns] UDP fallback socket failed: %d\n", WSAGetLastError());
        return false;
    }

    DWORD ttl = 255;
    setsockopt(udp_tx, IPPROTO_IP, IP_MULTICAST_TTL,
               reinterpret_cast<const char*>(&ttl), sizeof(ttl));
    BOOL loop = TRUE;
    setsockopt(udp_tx, IPPROTO_IP, IP_MULTICAST_LOOP,
               reinterpret_cast<const char*>(&loop), sizeof(loop));

    udp_rx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_rx != INVALID_SOCKET) {
        BOOL yes = TRUE;
        setsockopt(udp_rx, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&yes), sizeof(yes));
        sockaddr_in bind_addr{};
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = htons(kMdnsPort);
        bind_addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(udp_rx, reinterpret_cast<sockaddr*>(&bind_addr),
                 sizeof(bind_addr)) == SOCKET_ERROR) {
            closesocket(udp_rx);
            udp_rx = INVALID_SOCKET;
        } else {
            ip_mreq mreq{};
            inet_pton(AF_INET, kMulticastAddr, &mreq.imr_multiaddr);
            mreq.imr_interface.s_addr = INADDR_ANY;
            setsockopt(udp_rx, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                       reinterpret_cast<const char*>(&mreq), sizeof(mreq));
        }
    }

    udp_running.store(true, std::memory_order_release);
    udp_thread = std::thread(&MdnsAdvertiser::Impl::udp_loop, this);
    std::fprintf(stderr,
                 "[mdns] UDP mDNS fallback active for '%s' on port %u (%zu IPv4 records)\n",
                 instance_name.c_str(), static_cast<unsigned>(port), ipv4.size());
    return true;
}

void MdnsAdvertiser::Impl::udp_loop() {
    using clock = std::chrono::steady_clock;
    auto packet = build_response_packet(instance_name, host_name, port, ipv4);
    auto next_announce = clock::now();
    int fast_announces = 3;

    while (udp_running.load(std::memory_order_acquire)) {
        if (clock::now() >= next_announce) {
            send_multicast(udp_tx, packet);
            if (fast_announces > 0) {
                --fast_announces;
                next_announce = clock::now() + std::chrono::seconds(1);
            } else {
                next_announce = clock::now() + std::chrono::seconds(30);
            }
        }

        if (udp_rx == INVALID_SOCKET) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(udp_rx, &readfds);
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 250000;
        int ready = select(0, &readfds, nullptr, nullptr, &tv);
        if (ready <= 0 || !FD_ISSET(udp_rx, &readfds)) continue;

        uint8_t buf[1500];
        sockaddr_in from{};
        int from_len = sizeof(from);
        int n = recvfrom(udp_rx, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                         reinterpret_cast<sockaddr*>(&from), &from_len);
        if (n > 0 &&
            query_matches(buf, static_cast<size_t>(n), instance_name, host_name)) {
            send_multicast(udp_tx, packet);
        }
    }
}

void MdnsAdvertiser::Impl::stop_dnsapi() {
    if (dns_registered && dns_instance && dns.deregister_service) {
        DNS_SERVICE_REGISTER_REQUEST req{};
        req.Version = DNS_QUERY_REQUEST_VERSION1;
        req.pServiceInstance = dns_instance;
        req.pRegisterCompletionCallback = reg_callback;
        req.pQueryContext = &dns;
        dns.deregister_service(&req, nullptr);
    }
    if (dns_instance && dns.free_instance) {
        dns.free_instance(dns_instance);
        dns_instance = nullptr;
    }
    dns_registered = false;
}

void MdnsAdvertiser::Impl::stop_udp() {
    udp_running.store(false, std::memory_order_release);
    if (udp_rx != INVALID_SOCKET) {
        closesocket(udp_rx);
        udp_rx = INVALID_SOCKET;
    }
    if (udp_thread.joinable()) udp_thread.join();
    if (udp_tx != INVALID_SOCKET) {
        closesocket(udp_tx);
        udp_tx = INVALID_SOCKET;
    }
}

bool MdnsAdvertiser::advertise(const std::string& device_name, uint16_t port) {
    stop();
    if (impl_->advertise_dnsapi(device_name, port)) return true;
    return impl_->advertise_udp(device_name, port);
}

void MdnsAdvertiser::stop() {
    impl_->stop_udp();
    impl_->stop_dnsapi();
}

} // namespace librespotc::zeroconf
