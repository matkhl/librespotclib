#pragma once

// librespotc — C++ Spotify Connect library (audio source).
// Host calls play_track / pause / seek / stop_track directly. Library delivers
// PCM via on_audio callback on its own playback thread. No Spotify Web API
// used internally — host drives.

#include <cstdint>
#include <cstddef>
#include <array>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace librespotc {

enum class Bitrate : uint16_t {
    K96  = 96,
    K160 = 160,
    K320 = 320,
};

enum class DeviceType : uint8_t {
    Speaker = 4,
};

// PCM format delivered to on_audio.
// Always: S16LE, interleaved, native rate from the decoded stream (typically
// 44100 Hz for Spotify Vorbis), native channel count (typically 2).
struct AudioFormat {
    uint32_t sample_rate     = 44100;
    uint16_t channels        = 2;
    uint16_t bits_per_sample = 16;
};

struct TrackInfo {
    std::string track_id;     // hex
    std::string title;
    std::string artist;
    std::string album;
    uint32_t    duration_ms = 0;
    std::string artwork_key;  // Spotify image file id hex, empty if unavailable
    std::string artwork_url;  // direct i.scdn.co image URL, empty if unavailable
    std::string artwork_mime;
    bool artwork_loading = false;
};

inline constexpr size_t kEqualizerBandCount = 5;

struct EqualizerConfig {
    bool enabled = false;
    // 5-band EQ in dB. Values outside [-6, +6] are clamped internally.
    std::array<float, kEqualizerBandCount> bands_db{0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
};

// on_audio callback contract:
//   - pcm: interleaved int16_t, length = frame_count * format.channels
//   - frame_count: multi-channel frames (e.g. 689 frames ≈ 15.6 ms @ 44.1 kHz)
//   - Threading: invoked on library's playback thread, one call at a time
//   - Re-entrancy: host MUST NOT call play_track/pause/resume/seek/stop_track/
//                  disconnect from inside this callback (deadlock)
//   - Backpressure: return false → library pauses delivery, waits, then retries
//                   with the SAME frame until it is accepted or stop_track/
//                   disconnect arrives. Track is NOT aborted on false.
//   - Pacing: library throttles to wall-clock with ~500 ms lead. Callback fires
//             at real-time + ~500 ms ahead, not faster.
using AudioCallback       = std::function<bool(const int16_t* pcm,
                                               size_t frame_count,
                                               const AudioFormat& format)>;

using TrackChangeCallback = std::function<void(const TrackInfo& track)>;

struct TrackArtwork {
    std::string track_id;     // hex, matches TrackInfo::track_id
    std::string artwork_key;  // Spotify image file id hex
    std::string artwork_url;  // direct i.scdn.co image URL
    std::string artwork_mime;
    std::vector<uint8_t> artwork_bytes;
    bool available = false;   // true only when artwork_bytes is populated
    bool loading = false;     // true after track change while fetch is pending
};

// Optional artwork callback contract:
//   - Fired once on the playback thread immediately after TrackChange with
//     available=false to clear stale host artwork for the new track.
//   - Fired later from a library worker thread with available=true when image
//     bytes were downloaded from Spotify's image CDN.
//   - Network I/O never runs on the audio/Vorbis callback path.
//   - Late results for older tracks are discarded inside the library.
using TrackArtworkCallback = std::function<void(const TrackArtwork& artwork)>;

// ---- Vorbis-packet tap (alternative output to on_audio) ----
//
// When either on_vorbis_stream or on_vorbis_packet is set, the library skips
// its internal Vorbis-decode-to-PCM step and instead emits raw Vorbis
// bitstream packets to the host. Saves CPU and gives bit-perfect data for
// consumers that have their own Vorbis decoder (e.g. FMOD FSB5 codec).
//
// Frame: the library delivers **raw Vorbis packets**, NOT OGG-framed pages.
// Each packet is a self-contained Vorbis bitstream block. The three setup
// headers (identification + comment + setup) are concatenated and delivered
// once via on_vorbis_stream BEFORE the first audio packet.
//
// If on_audio is also set, the Vorbis tap takes priority and on_audio is
// not invoked.

struct VorbisStreamInfo {
    const uint8_t* setup_data;       // identification + comment + setup, concatenated
    size_t         setup_bytes;
    uint32_t       sample_rate;      // 44100 for Spotify
    uint16_t       channels;         // 2 for Spotify
    uint32_t       bitrate_nominal_bps;  // 96k / 160k / 320k
};

using VorbisStreamCallback = std::function<void(const VorbisStreamInfo& info)>;

// on_vorbis_packet contract:
//   - data: raw Vorbis bitstream bytes (no OGG headers, no lacing prefix)
//   - bytes: length of the packet
//   - pts_ms: approximate playback timestamp for this packet (from OGG page
//             granule position; may be 0 for packets before any page boundary)
//   - Threading: invoked on the library's playback thread; one call at a time
//   - Re-entrancy: same as on_audio — host must NOT call Session methods from
//                  inside the callback
//   - Backpressure: return false → library pauses + retries with the SAME
//                   packet until accepted or stop_track / disconnect arrives
//   - Pacing: same real-time + ~500 ms lead as on_audio
using VorbisPacketCallback = std::function<bool(const uint8_t* data,
                                                size_t bytes,
                                                uint64_t pts_ms)>;

enum class EventType : uint8_t {
    TrackEnded,         // current track finished playing to end
    TrackError,         // current track failed (detail = reason)
    Reconnecting,       // AP socket dropped or initial connect retry started
    Reconnected,        // AP socket re-established, sessions usable again
    PlaybackStarted,    // local play_track succeeded OR cloud sent transfer/play
    PlaybackPaused,     // local pause() OR cloud sent pause
    TrackChanged,       // new track loaded — detail = track URI, source = origin
    VolumeChanged,      // cloud sent set_volume — detail = "<0..65535>"
    SkipNextRequested,  // cloud sent skip_next but library couldn't satisfy
                        //   locally (empty queue, no track URI in command).
                        //   Host should drive via Web API POST /me/player/next.
    SkipPrevRequested,  // same, for skip_prev (empty history).
    ContextChanged,       // cloud transitioned us into a new playback context
                          // (playlist/album). detail = context URI. Fires
                          // alongside the play/transfer that set it.
    BecameInactive,       // cloud's cluster update shows active_device_id !=
                          // ours — phone pressed Stop or transferred to
                          // another device. Library has stopped playback.
                          // detail = new active device id (empty if none).
};

enum class EventSource : uint8_t {
    Local = 0,          // host called direct API method
    Cloud = 1,          // received over Spotify Connect dealer
};

struct Event {
    EventType   type;
    EventSource source = EventSource::Local;
    std::string detail;
};

using EventCallback = std::function<void(const Event&)>;

enum class ConnectError {
    None = 0,
    NoCredentials,
    NetworkError,
    HandshakeFailed,
    AuthFailed,
    PremiumRequired,
    ZeroconfTimeout,
    Internal,
};

struct Config {
    // Required.
    std::string  device_name;                       // e.g. "Living Room Receiver"
    std::string  device_id;                         // optional 40-char hex Spotify Connect identity
    DeviceType   device_type   = DeviceType::Speaker;
    std::string  cache_dir;                         // credentials.dat persisted here
    AudioCallback        on_audio;
    TrackChangeCallback  on_track_change;
    TrackArtworkCallback on_track_artwork;

    // Optional Vorbis-packet tap (alternative to on_audio — see above).
    VorbisStreamCallback on_vorbis_stream;
    VorbisPacketCallback on_vorbis_packet;

    // Optional.
    EventCallback on_event;
    Bitrate       bitrate    = Bitrate::K160;
    std::string   client_id;
    std::string   oauth_token;                      // OAuth path (scopes: streaming app-remote-control user-read-email user-read-private)
    uint16_t      zeroconf_port = 0;

    // When true, library applies cloud-sent volume (0..65535) as linear
    // gain to PCM in on_audio before delivery. When false (default), host
    // is responsible for gain — VolumeChanged event still fires but the
    // PCM samples are unmodified. Set this true only if the host doesn't
    // do its own volume mixing.
    bool          apply_volume_gain = false;

    // Maximum PCM multiplier used when apply_volume_gain is true and Spotify
    // Connect volume is 65535. Default 1.0 preserves normal Spotify semantics;
    // hosts can raise this for output paths that need extra headroom.
    float         volume_gain_max = 1.0f;

    // When true, library applies Spotify's per-track ReplayGain metadata
    // before Connect volume gain. This uses the same defaults as librespot's
    // normal playback path: track normalisation, 0 dB pregain, -2 dBFS
    // dynamic limiter threshold, 5 ms attack, 100 ms release, 5 dB knee.
    // Defaults false so existing hosts keep their exact PCM behavior unless
    // they opt in.
    bool          apply_replaygain = false;

    // Optional local equalizer. This is device-side DSP and is not a Spotify
    // Connect API feature. Processing is bounded to +/-6 dB per band with
    // automatic headroom to avoid clipping from boosted bands.
    EqualizerConfig equalizer;

    // Initial Connect device volume (0..65535). Used for first PUT state
    // registration and, when apply_volume_gain is true, initial PCM gain before
    // the cloud sends a live set_volume/cluster update.
    uint32_t      initial_volume = 32768;
};

class Session {
public:
    static std::unique_ptr<Session> create(const Config& config);
    ~Session();

    // Login bootstrap. Tries in order: cached blob → oauth_token → Zeroconf.
    bool connect();

    // Direct entry points.
    bool connect_with_oauth_token(const std::string& access_token);
    bool connect_via_zeroconf(uint32_t timeout_ms = 0);

    // Playback. play_track returns immediately; PCM + events arrive
    // asynchronously on the library thread.
    //
    // play_track clears the queue and pushes the current track (if any) to
    // history, then starts the given URI as the new "current" track.
    // History is preserved so previous() can step back.
    bool play_track(const std::string& spotify_uri);
    void pause();
    // Request pause from the playback thread at the next PCM/Vorbis output
    // boundary. This is intended for hosts that mute their own output first
    // and need Connect state to pause at the last accepted audio frame, without
    // racing a cross-thread seek or reporting decoder lead as heard playback.
    void pause_at_audio_boundary();
    void resume();
    bool seek(uint32_t position_ms);
    uint32_t current_position_ms() const;
    void stop_track();

    // ---- Queue ----
    //
    // The library maintains a FIFO queue + history of previously-played tracks.
    // When the current track ends naturally:
    //   - If the queue is non-empty, the library pops the head, fires
    //     TrackChanged (source=Local), and starts playing it. TrackEnded does
    //     NOT fire for the host.
    //   - If the queue is empty, TrackEnded fires for the host as before.
    //
    // SPIRC skip_next / skip_prev from the cloud also drive the queue: if the
    // queue (or history) has tracks, the library advances locally. If empty,
    // the SPIRC command is acked but no advance happens — host bridge can
    // still drive via Web API as before.
    //
    // enqueue appends; enqueue_next pushes to the front of the queue (plays
    // immediately after the current track). If nothing is currently playing,
    // enqueue starts playback immediately.
    void enqueue(const std::string& spotify_uri);
    void enqueue_next(const std::string& spotify_uri);
    void clear_queue();
    size_t queue_size() const;
    std::vector<std::string> queue_snapshot() const;

    // next/previous return false when the queue or history is empty.
    bool next();
    bool previous();

    // Connection lifecycle.
    void disconnect();
    bool is_connected() const;

    // State.
    TrackInfo    current_track() const;
    ConnectError last_error() const;
    std::string  last_error_message() const;

    // Spotify-side device id (40-char hex). Defaults to SHA-1(device_name)
    // unless Config::device_id supplies a host-owned stable identity. Host
    // targets this id in Web API calls like
    // `PUT /me/player/play?device_id=<id>`.
    std::string  spotify_device_id() const;

    // Internal Spotify access token (login5 bearer). Same token the library
    // uses for spclient/connect-state PUTs. Has user-level scopes including
    // user-modify-playback-state, so it's usable for Web API endpoints like
    // POST /me/player/next. Returns empty if not yet logged in.
    //
    // Refreshes if expired. Cheap to call repeatedly — caches internally.
    std::string  access_token() const;

    // Current cloud-reported volume (0..65535). Updated from SPIRC
    // set_volume commands. If Config::apply_volume_gain is false the host
    // can read this and apply its own gain.
    uint32_t     current_volume() const;

    // Toggle per-track ReplayGain loudness normalization at runtime. Applies
    // to newly decoded PCM immediately; hosts can persist the preference.
    void         set_replaygain_enabled(bool enabled);
    bool         replaygain_enabled() const;

    // Toggle host-requested extra Connect volume headroom at runtime. When
    // disabled, effective Connect gain is capped at 1.0x even if
    // Config::volume_gain_max is higher.
    void         set_extra_volume_headroom_enabled(bool enabled);
    bool         extra_volume_headroom_enabled() const;

    // Runtime local equalizer control. Applies to newly decoded PCM
    // immediately without restarting playback.
    void         set_equalizer_enabled(bool enabled);
    bool         equalizer_enabled() const;
    void         set_equalizer_bands(const std::array<float, kEqualizerBandCount>& bands_db);
    std::array<float, kEqualizerBandCount> equalizer_bands() const;

private:
    Session();
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace librespotc
