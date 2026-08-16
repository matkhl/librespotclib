#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace librespotc { class Dispatcher; }

namespace librespotc::audio {

// Resolve CDN URLs for a given 20-byte file_id.
// Tries Mercury endpoint hm://storage-resolve/files/audio/interactive/<file_id_hex>.
bool storage_resolve_audio(Dispatcher& disp,
                           const uint8_t file_id[20],
                           std::vector<std::string>& out_urls,
                           uint32_t timeout_ms = 8000,
                           const std::string& web_api_token = std::string());

std::string storage_resolve_audio_ex(Dispatcher& disp,
                                     const uint8_t file_id[20],
                                     std::vector<std::string>& out_urls,
                                     uint32_t timeout_ms = 8000,
                                     const std::string& web_api_token = std::string());

// One-time init of client_token + login5 providers. Call after successful
// AP_WELCOME with the auth blob and username from cached/server credentials.
void init_login5_provider(const std::string& device_id,
                          const std::string& username,
                          const std::vector<uint8_t>& stored_blob);

} // namespace librespotc::audio

namespace librespotc::auth { class ClientTokenProvider; class Login5Provider; }

namespace librespotc::audio {
// Accessors for the static providers initialized above.
auth::ClientTokenProvider* get_client_token_provider();
auth::Login5Provider*      get_login5_provider();
bool make_spclient_auth_headers(std::map<std::string,std::string>& headers,
                                std::string& err,
                                bool force_refresh = false,
                                const std::string& bearer_override = std::string());

} // namespace librespotc::audio
