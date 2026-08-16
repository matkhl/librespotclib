#include "authentication.h"
#include "pb_codec.h"

namespace librespotc::proto {

// CpuFamily.CPU_X86_64 = 2; Os.OS_WINDOWS = 1
constexpr int CPU_X86_64 = 2;
constexpr int OS_WINDOWS = 1;

std::vector<uint8_t> encode_client_response_encrypted(
    const std::string& username,
    AuthType type,
    const std::vector<uint8_t>& auth_data,
    const std::string& device_id) {

    Writer w;
    // login_credentials (10, submessage): username(10), typ(20), auth_data(30)
    w.write_submessage(10, [&](Writer& lc) {
        if (!username.empty()) lc.write_string(10, username);
        lc.write_enum(20, (int32_t)type);
        if (!auth_data.empty()) lc.write_bytes(30, auth_data);
    });
    // system_info (50, submessage): cpu_family(10), os(60), device_id(100)
    w.write_submessage(50, [&](Writer& si) {
        si.write_enum(10, CPU_X86_64);
        si.write_enum(60, OS_WINDOWS);
        si.write_string(90, "librespotc-0.1.0");
        si.write_string(100, device_id);
    });
    // version_string (70, string)
    w.write_string(70, "librespotc-0.1.0");
    return w.take();
}

ApWelcome decode_ap_welcome(const uint8_t* data, size_t len) {
    Reader r(data, len);
    ApWelcome out;
    while (!r.at_end()) {
        uint32_t f, wt;
        if (!r.read_tag(f, wt)) break;
        if      (f == 10 && wt == WIRE_LEN)    out.canonical_username = r.read_string();
        else if (f == 30 && wt == WIRE_VARINT) out.reusable_auth_credentials_type = (int32_t)r.read_varint();
        else if (f == 40 && wt == WIRE_LEN)    out.reusable_auth_credentials = r.read_bytes();
        else r.skip_field(wt);
    }
    return out;
}

AuthFailure decode_auth_failure(const uint8_t* data, size_t len) {
    // APLoginFailed shape (from keyexchange): error_code(10), retry_delay(20), expiry(30), error_description(40)
    Reader r(data, len);
    AuthFailure out;
    while (!r.at_end()) {
        uint32_t f, wt;
        if (!r.read_tag(f, wt)) break;
        if      (f == 10 && wt == WIRE_VARINT) out.error_code = (int32_t)r.read_varint();
        else if (f == 40 && wt == WIRE_LEN)    out.error_desc = r.read_string();
        else r.skip_field(wt);
    }
    return out;
}

} // namespace librespotc::proto
