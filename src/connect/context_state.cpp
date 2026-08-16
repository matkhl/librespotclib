#include "context_state.h"

#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#include <cstdio>
#include <sstream>

namespace librespotc::connect {

void ContextState::set_play_origin(const PlayOrigin& po) {
    std::lock_guard<std::mutex> g(m_);
    play_origin_ = po;
}

void ContextState::set_context(const std::string& uri, const std::string& url) {
    std::lock_guard<std::mutex> g(m_);
    if (uri != context_uri_) {
        // Different context — invalidate index until tracks resolve again.
        tracks_.clear();
        current_index_ = 0;
        has_index_ = false;
        shuffle_order_.clear();
    }
    context_uri_ = uri;
    context_url_ = url.empty() ? uri : url;
}

void ContextState::clear() {
    std::lock_guard<std::mutex> g(m_);
    context_uri_.clear();
    context_url_.clear();
    play_origin_ = PlayOrigin{};
    tracks_.clear();
    current_index_ = 0;
    has_index_ = false;
    options_ = Options{};
    shuffle_order_.clear();
}

void ContextState::set_tracks(std::vector<ProvidedTrack> tracks) {
    std::lock_guard<std::mutex> g(m_);
    tracks_ = std::move(tracks);
    current_index_ = 0;
    has_index_ = false;
    shuffle_order_.clear();
    if (options_.shuffling_context) rebuild_shuffle_order_locked();
}

bool ContextState::set_current_track_uri(const std::string& track_uri) {
    std::lock_guard<std::mutex> g(m_);
    for (size_t i = 0; i < tracks_.size(); ++i) {
        if (tracks_[i].uri == track_uri) {
            current_index_ = i;
            has_index_ = true;
            return true;
        }
    }
    return false;
}

bool ContextState::set_current_by_uid(const std::string& uid) {
    if (uid.empty()) return false;
    std::lock_guard<std::mutex> g(m_);
    for (size_t i = 0; i < tracks_.size(); ++i) {
        if (tracks_[i].uid == uid) {
            current_index_ = i;
            has_index_ = true;
            return true;
        }
    }
    return false;
}

bool ContextState::set_current_by_index(size_t idx) {
    std::lock_guard<std::mutex> g(m_);
    if (idx >= tracks_.size()) return false;
    current_index_ = idx;
    has_index_ = true;
    return true;
}

std::string ContextState::start_context_playback(size_t avoid_index) {
    std::lock_guard<std::mutex> g(m_);
    if (tracks_.empty()) return {};
    if (options_.shuffling_context) {
        if (shuffle_order_.empty()) rebuild_shuffle_order_locked();
        if (!shuffle_order_.empty()) {
            if (avoid_index < tracks_.size()
                && shuffle_order_.front() == avoid_index
                && shuffle_order_.size() > 1) {
                for (size_t i = 1; i < shuffle_order_.size(); ++i) {
                    if (shuffle_order_[i] != avoid_index) {
                        std::swap(shuffle_order_[0], shuffle_order_[i]);
                        break;
                    }
                }
            }
            current_index_ = shuffle_order_.front();
        }
    } else {
        current_index_ = 0;
    }
    has_index_ = true;
    return tracks_[current_index_].uri;
}

std::string ContextState::resolve_skip_to(const std::string& track_uri,
                                          const std::string& track_uid,
                                          int track_index) {
    if (!track_uri.empty() && set_current_track_uri(track_uri))
        return track_uri;
    if (!track_uid.empty() && set_current_by_uid(track_uid)) {
        std::lock_guard<std::mutex> g(m_);
        return tracks_[current_index_].uri;
    }
    if (track_index >= 0 && set_current_by_index((size_t)track_index)) {
        std::lock_guard<std::mutex> g(m_);
        return tracks_[current_index_].uri;
    }
    return {};
}

// Map the current physical index to its position in shuffle_order_.
// Returns shuffle_order_.size() if not found (shouldn't happen normally).
static size_t find_shuffle_pos(const std::vector<size_t>& order, size_t phys_idx) {
    for (size_t i = 0; i < order.size(); ++i)
        if (order[i] == phys_idx) return i;
    return order.size();
}

size_t ContextState::find_track_index_locked(const std::string& uri) const {
    for (size_t i = 0; i < tracks_.size(); ++i) {
        if (tracks_[i].uri == uri) return i;
    }
    return tracks_.size();
}

bool ContextState::advance_next(bool force_wrap,
                                bool ignore_repeat_track) {
    std::lock_guard<std::mutex> g(m_);
    if (!has_index_ || tracks_.empty()) return false;
    if (options_.repeating_track && !ignore_repeat_track) {
        // Stay on current track. Caller will re-play it.
        return true;
    }
    if (options_.shuffling_context && !shuffle_order_.empty()) {
        size_t pos = find_shuffle_pos(shuffle_order_, current_index_);
        if (pos + 1 >= shuffle_order_.size()) {
            if (!options_.repeating_context && !force_wrap) return false;
            current_index_ = shuffle_order_.front();
        } else {
            current_index_ = shuffle_order_[pos + 1];
        }
        return true;
    }
    if (current_index_ + 1 >= tracks_.size()) {
        if (!options_.repeating_context && !force_wrap) return false;
        current_index_ = 0;
        return true;
    }
    ++current_index_;
    return true;
}

bool ContextState::advance_prev(bool ignore_repeat_track) {
    std::lock_guard<std::mutex> g(m_);
    if (!has_index_ || tracks_.empty()) return false;
    if (options_.repeating_track && !ignore_repeat_track) return true;
    if (options_.shuffling_context && !shuffle_order_.empty()) {
        size_t pos = find_shuffle_pos(shuffle_order_, current_index_);
        if (pos == 0) {
            if (!options_.repeating_context) return false;
            current_index_ = shuffle_order_.back();
        } else {
            current_index_ = shuffle_order_[pos - 1];
        }
        return true;
    }
    if (current_index_ == 0) {
        if (!options_.repeating_context) return false;
        current_index_ = tracks_.size() - 1;
        return true;
    }
    --current_index_;
    return true;
}

void ContextState::set_options(const Options& o) {
    std::lock_guard<std::mutex> g(m_);
    bool shuffle_changed = (o.shuffling_context != options_.shuffling_context);
    options_ = o;
    if (shuffle_changed) {
        if (options_.shuffling_context) rebuild_shuffle_order_locked();
        else shuffle_order_.clear();
    }
}

ContextState::Options ContextState::options() const {
    std::lock_guard<std::mutex> g(m_);
    return options_;
}

void ContextState::rebuild_shuffle_order_locked() {
    // Fisher-Yates over [0..N-1]. If playback already has a current track,
    // pin it as the first element so toggling shuffle does not make it look
    // like a previous track. For a brand-new context with no current track,
    // shuffle the whole list so context-only playlist starts are not always
    // physical index 0.
    shuffle_order_.resize(tracks_.size());
    for (size_t i = 0; i < tracks_.size(); ++i) shuffle_order_[i] = i;
    if (shuffle_order_.empty()) return;
    size_t first_shuffle_pos = 0;
    if (has_index_) {
        for (size_t i = 0; i < shuffle_order_.size(); ++i) {
            if (shuffle_order_[i] == current_index_) {
                std::swap(shuffle_order_[0], shuffle_order_[i]);
                break;
            }
        }
        first_shuffle_pos = 1;
    }
    uint8_t rbuf[8];
    BCryptGenRandom(nullptr, rbuf, sizeof(rbuf),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    uint64_t seed = 0;
    for (auto b : rbuf) seed = (seed << 8) | b;
    auto rnd = [&](size_t bound) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        return (size_t)(seed % bound);
    };
    for (size_t i = shuffle_order_.size() - 1; i > first_shuffle_pos; --i) {
        size_t j = first_shuffle_pos + rnd(i - first_shuffle_pos + 1);
        std::swap(shuffle_order_[i], shuffle_order_[j]);
    }
}

void ContextState::append_shuffle_indices_locked(size_t first_new_index,
                                                 size_t count) {
    if (count == 0) return;
    std::vector<size_t> add;
    add.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        add.push_back(first_new_index + i);
    }

    uint8_t rbuf[8];
    BCryptGenRandom(nullptr, rbuf, sizeof(rbuf),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    uint64_t seed = 0;
    for (auto b : rbuf) seed = (seed << 8) | b;
    auto rnd = [&](size_t bound) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        return (size_t)(seed % bound);
    };
    for (size_t i = add.size(); i > 1; --i) {
        size_t j = rnd(i);
        std::swap(add[i - 1], add[j]);
    }
    shuffle_order_.insert(shuffle_order_.end(), add.begin(), add.end());
}

bool ContextState::tracks_near_end(size_t threshold) const {
    std::lock_guard<std::mutex> g(m_);
    if (!has_index_ || tracks_.empty()) return false;
    if (options_.shuffling_context && !shuffle_order_.empty()) {
        size_t pos = find_shuffle_pos(shuffle_order_, current_index_);
        if (pos >= shuffle_order_.size()) return true;
        size_t remaining = shuffle_order_.size() - pos - 1;
        return remaining <= threshold;
    }
    size_t remaining = tracks_.size() - current_index_ - 1;
    return remaining <= threshold;
}

size_t ContextState::append_tracks(std::vector<ProvidedTrack> more) {
    std::lock_guard<std::mutex> g(m_);
    size_t first_new = tracks_.size();
    size_t count = 0;
    for (auto& track : more) {
        if (track.uri.empty()) continue;
        if (find_track_index_locked(track.uri) < tracks_.size()) continue;
        tracks_.push_back(std::move(track));
        ++count;
    }
    if (options_.shuffling_context) {
        if (shuffle_order_.empty()) rebuild_shuffle_order_locked();
        else append_shuffle_indices_locked(first_new, count);
    }
    return count;
}

size_t ContextState::apply_playback_order(
        const std::string& current_track_uri,
        const std::vector<std::string>& ordered_uris) {
    std::lock_guard<std::mutex> g(m_);
    if (tracks_.empty() || current_track_uri.empty()) return 0;

    size_t current = find_track_index_locked(current_track_uri);
    if (current >= tracks_.size()) return 0;
    current_index_ = current;
    has_index_ = true;

    std::vector<uint8_t> used(tracks_.size(), 0);
    std::vector<size_t> order;
    order.reserve(tracks_.size());
    order.push_back(current);
    used[current] = 1;

    bool seen_current = false;
    size_t applied_after_current = 0;
    for (const auto& uri : ordered_uris) {
        size_t idx = find_track_index_locked(uri);
        if (idx >= tracks_.size()) continue;
        if (idx == current) {
            seen_current = true;
            continue;
        }
        if (!seen_current && !order.empty()) {
            // The cluster extraction can include earlier metadata/prev tracks
            // before the current track. Only use the queue tail after current.
            continue;
        }
        if (used[idx]) continue;
        order.push_back(idx);
        used[idx] = 1;
        ++applied_after_current;
    }

    if (applied_after_current == 0) return 0;

    for (size_t i = 0; i < tracks_.size(); ++i) {
        if (!used[i]) order.push_back(i);
    }
    shuffle_order_ = std::move(order);
    return applied_after_current;
}

ContextState::Snapshot ContextState::snapshot(size_t prev_window,
                                              size_t next_window) const {
    std::lock_guard<std::mutex> g(m_);
    Snapshot s;
    s.context_uri = context_uri_;
    s.context_url = context_url_;
    s.play_origin = play_origin_;
    s.options = options_;
    s.track_count = tracks_.size();
    s.has_tracks = !tracks_.empty() && has_index_;
    if (s.has_tracks) {
        s.current = tracks_[current_index_];
        s.index_track = (uint32_t)current_index_;
        // Walk playback order — shuffle_order_ when shuffling, otherwise
        // natural track order.
        if (options_.shuffling_context && !shuffle_order_.empty()) {
            size_t pos = find_shuffle_pos(shuffle_order_, current_index_);
            size_t prev_start = pos < prev_window ? 0 : pos - prev_window;
            for (size_t i = prev_start; i < pos; ++i)
                s.prev_tracks.push_back(tracks_[shuffle_order_[i]]);
            size_t next_end = pos + 1 + next_window;
            if (next_end > shuffle_order_.size()) next_end = shuffle_order_.size();
            for (size_t i = pos + 1; i < next_end; ++i)
                s.next_tracks.push_back(tracks_[shuffle_order_[i]]);
        } else {
            size_t prev_count = current_index_ < prev_window ? current_index_ : prev_window;
            for (size_t i = current_index_ - prev_count; i < current_index_; ++i)
                s.prev_tracks.push_back(tracks_[i]);
            size_t end = current_index_ + 1 + next_window;
            if (end > tracks_.size()) end = tracks_.size();
            for (size_t i = current_index_ + 1; i < end; ++i)
                s.next_tracks.push_back(tracks_[i]);
        }
    }
    s.queue_revision = compute_queue_revision(s.next_tracks);
    return s;
}

std::string ContextState::compute_queue_revision(
        const std::vector<ProvidedTrack>& next) {
    // FNV-1a 64-bit over concatenated URIs, base16-encoded. Cloud + web client
    // only require the value to be stable + change when next_tracks changes.
    uint64_t h = 0xcbf29ce484222325ULL;
    for (auto& t : next) {
        for (unsigned char c : t.uri) {
            h ^= (uint64_t)c;
            h *= 0x100000001b3ULL;
        }
        h ^= 0xff;
        h *= 0x100000001b3ULL;
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)h);
    return std::string(buf);
}

std::string ContextState::generate_uid() {
    uint8_t bytes[16];
    BCryptGenRandom(nullptr, bytes, sizeof(bytes),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    static const char hex[] = "0123456789abcdef";
    std::string s;
    s.reserve(32);
    for (auto b : bytes) {
        s.push_back(hex[b >> 4]);
        s.push_back(hex[b & 0xf]);
    }
    return s;
}

} // namespace librespotc::connect
