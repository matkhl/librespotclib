#pragma once
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace librespotc::connect {

// Subset of spotify.player.proto.ProvidedTrack — only the fields we echo
// back to cloud in PutState.
struct ProvidedTrack {
    std::string uri;          // "spotify:track:..."
    std::string uid;           // 32-hex (server-provided or generated)
    std::string provider;      // "context" | "queue" | "autoplay"
    std::string album_uri;
    std::string artist_uri;
    // metadata: only context_uri + entity_uri keys for now.
    std::string metadata_context_uri;
    std::string metadata_entity_uri;
};

// Subset of spotify.player.proto.PlayOrigin — must echo verbatim from the
// inbound transfer/play command, else cloud rejects our state as a different
// session.
struct PlayOrigin {
    std::string feature_identifier;
    std::string feature_version;
    std::string view_uri;
    std::string referrer_identifier;
    std::string device_identifier;
};

// Tracks current playback context (album/playlist) + position + next/prev
// lookahead. SpircDevice holds one instance and mutates it on:
//   - cloud transfer/play     (set context, current track, play_origin)
//   - context-resolve complete (fill `tracks` from spclient response)
//   - natural track advance    (move current_index forward)
// Reads happen from notify_state PUT-state encoders on a different thread, so
// all access is mutex-guarded.
class ContextState {
public:
    void set_play_origin(const PlayOrigin& po);
    void set_context(const std::string& uri, const std::string& url);
    void clear();
    // Replace track list (called when context-resolve completes).
    void set_tracks(std::vector<ProvidedTrack> tracks);
    // Set current track URI; recomputes current_index by searching the
    // resolved track list. Returns true if track was found in context.
    bool set_current_track_uri(const std::string& track_uri);
    // Same, by track UID.
    bool set_current_by_uid(const std::string& uid);
    // Set current by direct index into tracks_. Returns false on OOB.
    bool set_current_by_index(size_t idx);
    // Choose the first playable track for a context-only play command.
    // In shuffle mode, this uses the shuffled playback order; otherwise it
    // starts at the natural head of the context.
    std::string start_context_playback(size_t avoid_index = (size_t)-1);
    // Resolve a SkipToHint-ish triple to the matching ProvidedTrack URI,
    // updating current_index accordingly. Returns "" if nothing matched.
    std::string resolve_skip_to(const std::string& track_uri,
                                 const std::string& track_uid,
                                 int track_index);
    // Advance current_index by +1 / -1; clamps. Returns true if moved.
    bool advance_next(bool force_wrap = false,
                      bool ignore_repeat_track = false);
    bool advance_prev(bool ignore_repeat_track = false);

    // True if we're within `threshold` tracks of the end — caller should
    // kick the autoplay resolver to keep the queue topped up.
    bool tracks_near_end(size_t threshold = 2) const;
    // Append more tracks to the existing list without resetting the index.
    // Used by autoplay continuation.
    size_t append_tracks(std::vector<ProvidedTrack> more);
    // Apply a cloud-observed playback order. Returns the number of ordered
    // tracks applied after the current track.
    size_t apply_playback_order(const std::string& current_track_uri,
                                const std::vector<std::string>& ordered_uris);

    // Playback options. Echoed in PUT state's options field; also affect
    // advance_next/advance_prev behavior. Cloud sends these on transfer /
    // play / set_options.
    struct Options {
        bool shuffling_context = false;
        bool repeating_context = false;
        bool repeating_track   = false;
    };
    void set_options(const Options& o);
    Options options() const;

    // Snapshot reader — atomic copy under lock so encoder thread sees a
    // consistent view.
    struct Snapshot {
        std::string context_uri;
        std::string context_url;
        PlayOrigin play_origin;
        ProvidedTrack current;
        std::vector<ProvidedTrack> prev_tracks;
        std::vector<ProvidedTrack> next_tracks;
        uint32_t index_track = 0;
        size_t track_count = 0;
        std::string queue_revision;
        bool has_tracks = false;
        Options options;
    };
    Snapshot snapshot(size_t prev_window = 16, size_t next_window = 16) const;

    // Helpers exposed for tests / fallback.
    static std::string compute_queue_revision(const std::vector<ProvidedTrack>& next);
    static std::string generate_uid();   // 32-hex random

private:
    mutable std::mutex m_;
    std::string context_uri_;
    std::string context_url_;
    PlayOrigin play_origin_;
    std::vector<ProvidedTrack> tracks_;
    size_t current_index_ = 0;
    bool has_index_ = false;
    Options options_;
    // Shuffle permutation: shuffle_order_[i] = physical index in tracks_
    // of the i-th track in shuffled playback order. Empty when shuffle off.
    std::vector<size_t> shuffle_order_;
    void rebuild_shuffle_order_locked();
    void append_shuffle_indices_locked(size_t first_new_index, size_t count);
    size_t find_track_index_locked(const std::string& uri) const;
};

} // namespace librespotc::connect
