#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace librespotc::audio {

struct ReplayGainData {
    double track_gain_db = 0.0;
    double track_peak = 1.0;
    double album_gain_db = 0.0;
    double album_peak = 1.0;
};

struct ReplayGainConfig {
    bool enabled = false;
    const std::atomic<bool>* enabled_flag = nullptr;
    bool use_album = false;
    double pregain_db = 0.0;
    double threshold_dbfs = -2.0;
    double attack_ms = 5.0;
    double release_ms = 100.0;
    double knee_db = 5.0;
};

ReplayGainData parse_spotify_replaygain_header(const uint8_t* header, size_t len);

class ReplayGainProcessor {
public:
    void configure(const ReplayGainConfig& config,
                   const ReplayGainData& data,
                   int sample_rate,
                   int channels);

    float process(float sample);

private:
    bool enabled_ = false;
    int channel_count_ = 2;
    int next_channel_ = 0;
    double factor_ = 1.0;
    double threshold_dbfs_ = -2.0;
    double knee_db_ = 5.0;
    double knee_factor_ = 0.0;
    double attack_cf_ = 0.0;
    double release_cf_ = 0.0;
    double integrators_[2] = {};
    double peaks_[2] = {};
    const std::atomic<bool>* enabled_flag_ = nullptr;
};

} // namespace librespotc::audio
