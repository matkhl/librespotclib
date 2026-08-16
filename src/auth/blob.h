#pragma once
#include <cstdint>
#include <vector>
#include <string>

namespace librespotc::auth {

// Parsed credentials (post blob-decrypt). auth_type matches proto::AuthType.
struct Credentials {
    std::string username;          // canonical username from server
    int32_t auth_type = 0;
    std::vector<uint8_t> auth_data;
};

// Decrypt a Zeroconf-handoff blob with the inner AES-192-ECB layer and
// parse out (auth_type, auth_data).
//
// `outer_decrypted` is what Zeroconf addUser handler produced after the
// AES-128-CTR step; it is base64-encoded plaintext.
// `device_id` is the stable lowercase-hex device id advertised in mDNS/getInfo.
Credentials parse_zeroconf_blob(const std::string& username,
                                const std::vector<uint8_t>& outer_decrypted,
                                const std::string& device_id);

// Cache to disk. Format: simple length-prefixed binary in cache_dir/credentials.dat.
bool save_to_cache(const std::string& cache_dir, const Credentials& c);
bool load_from_cache(const std::string& cache_dir, Credentials& out);

} // namespace librespotc::auth
