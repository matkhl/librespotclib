#include "put_state.h"
#include "../proto/pb_codec.h"

#include <chrono>

namespace librespotc::connect {

// Field numbers from connect.proto (spotify.connectstate):
//
// PutStateRequest:
//   callback_url=1, device=2, member_type=3, is_active=4, put_state_reason=5,
//   message_id=6, last_command_sent_by_device_id=7, last_command_message_id=8,
//   started_playing_at=9, has_been_playing_for_ms=11,
//   client_side_timestamp=12, only_write_player_state=13
//
// Device:
//   device_info=1, player_state=2, private_device_info=3, transfer_data=4
//
// DeviceInfo:
//   can_play=1, volume=2, name=3, capabilities=4, device_software_version=6,
//   device_type=7, spirc_version=9, device_id=10, is_private_session=11,
//   is_social_connect=12, client_id=13, brand=14, model=15, ...
//
// Capabilities:
//   can_be_player=2, restrict_to_local=3, gaia_eq_connect_id=5,
//   supports_logout=6, is_observable=7, volume_steps=8, supported_types=9 (rep),
//   command_acks=10, supports_rename=11, hidden=12, disable_volume=13,
//   connect_disabled=14, supports_playlist_v2=15, is_controllable=16,
//   supports_external_episodes=17, supports_set_backend_metadata=18,
//   supports_transfer_command=19, supports_command_request=20,
//   is_voice_enabled=21, needs_full_player_state=22, supports_gzip_pushes=23,
//   supports_set_options_command=25, supports_hifi=26, connect_capabilities=27,
//   supports_rooms=28, supports_dj=29, supported_audio_quality=30
//
// PlayerState: many fields; for minimal idle device we only need
//   session_id=14 (string) and timestamp=1 (int64)

constexpr int MEMBER_TYPE_CONNECT_STATE = 2;

std::vector<uint8_t> encode_put_state(const DeviceConfig& dev,
                                       bool is_active,
                                       int32_t put_state_reason,
                                       uint32_t message_id,
                                       const std::string& current_track_uri,
                                       bool is_playing,
                                       uint32_t position_ms,
                                       uint32_t duration_ms,
                                       const LastCommand* last,
                                       const std::string& context_uri,
                                       const std::string& context_url,
                                       const ContextState::Snapshot* ctx,
                                       uint32_t current_volume) {
    proto::Writer w;
    // device (2)
    w.write_submessage(2, [&](proto::Writer& d) {
        // device_info (1)
        d.write_submessage(1, [&](proto::Writer& di) {
            di.write_bool   (1, true);                          // can_play
            // Prefer the live current volume; fall back to initial when caller
            // didn't supply one (or sent 0, which would silence the device).
            di.write_uint32 (2, current_volume ? current_volume
                                                : dev.initial_volume);
            di.write_string (3, dev.device_name);               // name
            di.write_submessage(4, [&](proto::Writer& cap) {
                cap.write_bool(2,  true);   // can_be_player
                cap.write_bool(5,  true);   // gaia_eq_connect_id
                cap.write_bool(6,  false);  // supports_logout
                cap.write_bool(7,  true);   // is_observable
                cap.write_int32(8, 64);     // volume_steps
                cap.write_string(9, "audio/track");
                cap.write_string(9, "audio/episode");
                cap.write_bool(10, true);   // command_acks
                cap.write_bool(11, false);  // supports_rename
                cap.write_bool(12, false);  // hidden
                cap.write_bool(13, false);  // disable_volume
                cap.write_bool(14, false);  // connect_disabled
                cap.write_bool(15, true);   // supports_playlist_v2
                cap.write_bool(16, true);   // is_controllable
                cap.write_bool(17, false);  // supports_external_episodes
                cap.write_bool(18, false);  // supports_set_backend_metadata
                cap.write_bool(19, true);   // supports_transfer_command
                cap.write_bool(20, true);   // supports_command_request
                cap.write_bool(21, false);  // is_voice_enabled
                cap.write_bool(22, true);   // needs_full_player_state
                cap.write_bool(23, false);  // supports_gzip_pushes (turn off until we add gunzip)
                cap.write_bool(25, true);   // supports_set_options_command
            });
            di.write_string (6,  "1.0.0");                      // device_software_version
            di.write_enum   (7,  dev.device_type);               // device_type
            di.write_string (9,  "3.2.6");                       // spirc_version
            di.write_string (10, dev.device_id);                 // device_id
            di.write_string (13, dev.client_id);                 // client_id
            di.write_string (14, "librespotc");                  // brand
            di.write_string (15, "librespotc-1.0");              // model
        });
        // player_state (2)
        d.write_submessage(2, [&](proto::Writer& ps) {
            uint64_t now_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            // timestamp = 1 (int64)
            ps.write_tag(1, proto::WIRE_VARINT);
            ps.write_varint(now_ms);
            if (!current_track_uri.empty()) {
                const std::string& ctx_uri = context_uri.empty()
                    ? current_track_uri : context_uri;
                const std::string& ctx_url = context_url.empty()
                    ? current_track_uri : context_url;
                ps.write_string(2, ctx_uri);            // context_uri
                ps.write_string(3, ctx_url);            // context_url

                // play_origin = 5 (PlayOrigin). Echo verbatim from the
                // inbound transfer/play command so cloud accepts our state
                // as the same session. Fall back to a stable librespotc
                // identity if we haven't seen one yet.
                ps.write_submessage(5, [&](proto::Writer& po) {
                    const PlayOrigin* echo = (ctx ? &ctx->play_origin : nullptr);
                    auto write_or = [&](uint32_t f, const std::string& v,
                                        const std::string& fallback) {
                        if (!v.empty()) po.write_string(f, v);
                        else if (!fallback.empty()) po.write_string(f, fallback);
                    };
                    write_or(1, echo ? echo->feature_identifier : "", "librespotc");
                    write_or(2, echo ? echo->feature_version    : "", "1.0.0");
                    if (echo && !echo->view_uri.empty())
                        po.write_string(3, echo->view_uri);
                    if (echo && !echo->referrer_identifier.empty())
                        po.write_string(5, echo->referrer_identifier);
                    if (echo && !echo->device_identifier.empty())
                        po.write_string(6, echo->device_identifier);
                });

                // index = 6 (ContextIndex { page=1, track=2 })
                if (ctx && ctx->has_tracks) {
                    ps.write_submessage(6, [&](proto::Writer& idx) {
                        // page = 0 (we don't paginate yet)
                        idx.write_uint32(1, 0);
                        idx.write_uint32(2, ctx->index_track);
                    });
                }

                // track = 7 (ProvidedTrack)
                auto write_provided_track = [&](proto::Writer& pt,
                                                 const std::string& uri,
                                                 const std::string& uid,
                                                 const std::string& md_ctx,
                                                 const std::string& md_entity,
                                                 const std::string& album_uri,
                                                 const std::string& artist_uri,
                                                 const std::string& provider) {
                    pt.write_string(1, uri);
                    if (!uid.empty()) pt.write_string(2, uid);
                    // metadata = 3, map<string,string> encoded as repeated msg
                    if (!md_ctx.empty()) {
                        pt.write_submessage(3, [&](proto::Writer& kv) {
                            kv.write_string(1, "context_uri");
                            kv.write_string(2, md_ctx);
                        });
                    }
                    if (!md_entity.empty()) {
                        pt.write_submessage(3, [&](proto::Writer& kv) {
                            kv.write_string(1, "entity_uri");
                            kv.write_string(2, md_entity);
                        });
                    }
                    pt.write_string(6, provider.empty() ? "context" : provider);
                    if (!album_uri.empty())  pt.write_string(8,  album_uri);
                    if (!artist_uri.empty()) pt.write_string(10, artist_uri);
                };
                ps.write_submessage(7, [&](proto::Writer& pt) {
                    if (ctx && ctx->has_tracks) {
                        write_provided_track(pt,
                            ctx->current.uri, ctx->current.uid,
                            ctx->current.metadata_context_uri,
                            ctx->current.metadata_entity_uri,
                            ctx->current.album_uri,
                            ctx->current.artist_uri,
                            ctx->current.provider);
                    } else {
                        // No context resolved — minimal track with current URI.
                        write_provided_track(pt, current_track_uri,
                            /*uid*/"",
                            /*md_ctx*/ctx_uri,
                            /*md_entity*/ctx_uri,
                            /*album_uri*/"", /*artist_uri*/"",
                            /*provider*/"context");
                    }
                });

                // playback_id = 8
                ps.write_string(8, dev.device_id);
                // playback_speed = 9 (double)
                ps.write_double(9, is_playing ? 1.0 : 0.0);
                // position_as_of_timestamp = 10 (int64)
                ps.write_tag(10, proto::WIRE_VARINT);
                ps.write_varint((uint64_t)position_ms);
                // duration = 11
                if (duration_ms > 0) {
                    ps.write_tag(11, proto::WIRE_VARINT);
                    ps.write_varint((uint64_t)duration_ms);
                }
                bool is_paused = !is_playing;
                ps.write_bool(12, true);          // is_playing
                ps.write_bool(13, is_paused);     // is_paused
                ps.write_bool(14, is_paused);     // is_buffering

                // options = 16 (ContextPlayerOptions).
                //   1 bool shuffling_context
                //   2 bool repeating_context
                //   3 bool repeating_track
                // Emit current state so cloud reflects the actual shuffle /
                // repeat flags in the phone UI.
                ps.write_submessage(16, [&](proto::Writer& po) {
                    bool sh = ctx ? ctx->options.shuffling_context : false;
                    bool rc = ctx ? ctx->options.repeating_context : false;
                    bool rt = ctx ? ctx->options.repeating_track   : false;
                    po.write_bool(1, sh);
                    po.write_bool(2, rc);
                    po.write_bool(3, rt);
                });

                // restrictions = 17 (Restrictions).
                // Empty submessage = no disallow_* reasons = everything allowed.
                // Explicitly emit so cloud knows the >> button on the phone
                // should be enabled (per librespot reference).
                ps.write_submessage(17, [&](proto::Writer& /*r*/) {
                    // Intentionally empty — all repeated string fields
                    // default to empty list = "allowed".
                });

                // prev_tracks = 19 (repeated ProvidedTrack)
                if (ctx) {
                    for (auto& t : ctx->prev_tracks) {
                        ps.write_submessage(19, [&](proto::Writer& pt) {
                            write_provided_track(pt, t.uri, t.uid,
                                t.metadata_context_uri, t.metadata_entity_uri,
                                t.album_uri, t.artist_uri, t.provider);
                        });
                    }
                    // next_tracks = 20 (repeated ProvidedTrack)
                    for (auto& t : ctx->next_tracks) {
                        ps.write_submessage(20, [&](proto::Writer& pt) {
                            write_provided_track(pt, t.uri, t.uid,
                                t.metadata_context_uri, t.metadata_entity_uri,
                                t.album_uri, t.artist_uri, t.provider);
                        });
                    }
                }
            }
            // session_id = 23
            ps.write_string(23, dev.device_id);
            // queue_revision = 24 (string hash of next_tracks URIs)
            if (ctx && !ctx->queue_revision.empty()) {
                ps.write_string(24, ctx->queue_revision);
            }
        });
    });
    // member_type (3)
    w.write_enum  (3,  MEMBER_TYPE_CONNECT_STATE);
    // is_active (4)
    w.write_bool  (4,  is_active);
    // put_state_reason (5)
    w.write_enum  (5,  put_state_reason);
    // message_id (6)
    w.write_uint32(6,  message_id);
    if (last) {
        w.write_string(7, last->sent_by_device_id);  // last_command_sent_by_device_id
        w.write_uint32(8, last->message_id);          // last_command_message_id
    }
    uint64_t now_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    // started_playing_at (9, uint64) — required by cluster when is_active=true
    if (is_active) {
        w.write_tag(9, proto::WIRE_VARINT);
        w.write_varint(now_ms);
        // has_been_playing_for_ms (11, uint64) — 0 here, host can refine later
        w.write_tag(11, proto::WIRE_VARINT);
        w.write_varint(0);
    }
    // client_side_timestamp (12)
    w.write_tag(12, proto::WIRE_VARINT);
    w.write_varint(now_ms);
    return w.take();
}

} // namespace librespotc::connect
