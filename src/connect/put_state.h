#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "context_state.h"

namespace librespotc::connect {

struct DeviceConfig {
    std::string device_id;         // 40-char hex
    std::string device_name;       // shown in picker
    std::string client_id;         // KEYMASTER_CLIENT_ID for Windows
    int32_t     device_type = 4;   // SPEAKER
    uint32_t    initial_volume = 32768;  // 0..65535
};

// Encode PutStateRequest as protobuf (proto3 wire format).
// is_active: true if we're actively playing; false for idle registration.
// put_state_reason: 1=SPIRC_HELLO, 3=NEW_DEVICE, 4=PLAYER_STATE_CHANGED, etc.
struct LastCommand {
    std::string sent_by_device_id;
    uint32_t    message_id = 0;
};

std::vector<uint8_t> encode_put_state(const DeviceConfig& dev,
                                       bool is_active,
                                       int32_t put_state_reason,
                                       uint32_t message_id,
                                       const std::string& current_track_uri = "",
                                       bool is_playing = false,
                                       uint32_t position_ms = 0,
                                       uint32_t duration_ms = 0,
                                       const LastCommand* last = nullptr,
                                       const std::string& context_uri = "",
                                       const std::string& context_url = "",
                                       const ContextState::Snapshot* ctx = nullptr,
                                       uint32_t current_volume = 0);

} // namespace librespotc::connect
