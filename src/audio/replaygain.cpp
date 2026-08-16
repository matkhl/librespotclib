#include "replaygain.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>

namespace librespotc::audio {

namespace {

constexpr size_t kSpotifyNormalizationOffset = 144;
constexpr size_t kSpotifyNormalizationBytes = 16;
constexpr double kDbVoltageRatio = 20.0;

double db_to_ratio(double db) {
    return std::pow(10.0, db / kDbVoltageRatio);
}

double ratio_to_db(double ratio) {
    return std::log10(ratio) * kDbVoltageRatio;
}

double duration_to_coefficient(double milliseconds, int sample_rate) {
    if (milliseconds <= 0.0 || sample_rate <= 0) return 0.0;
    return std::exp(-1.0 / ((milliseconds / 1000.0) * sample_rate));
}

float read_le_f32(const uint8_t* p) {
    float value = 0.0f;
    std::memcpy(&value, p, sizeof(value));
    return value;
}

} // namespace

ReplayGainData parse_spotify_replaygain_header(const uint8_t* header, size_t len) {
    ReplayGainData data;
    if (!header || len < kSpotifyNormalizationOffset + kSpotifyNormalizationBytes) {
        return data;
    }

    const uint8_t* p = header + kSpotifyNormalizationOffset;
    data.track_gain_db = read_le_f32(p + 0);
    data.track_peak = read_le_f32(p + 4);
    data.album_gain_db = read_le_f32(p + 8);
    data.album_peak = read_le_f32(p + 12);

    if (!std::isfinite(data.track_gain_db)) data.track_gain_db = 0.0;
    if (!std::isfinite(data.album_gain_db)) data.album_gain_db = 0.0;
    if (!std::isfinite(data.track_peak) || data.track_peak <= 0.0) data.track_peak = 1.0;
    if (!std::isfinite(data.album_peak) || data.album_peak <= 0.0) data.album_peak = 1.0;
    return data;
}

void ReplayGainProcessor::configure(const ReplayGainConfig& config,
                                    const ReplayGainData& data,
                                    int sample_rate,
                                    int channels) {
    enabled_ = config.enabled;
    enabled_flag_ = config.enabled_flag;
    channel_count_ = std::clamp(channels, 1, 2);
    next_channel_ = 0;
    integrators_[0] = integrators_[1] = 0.0;
    peaks_[0] = peaks_[1] = 0.0;

    const double gain_db = config.use_album ? data.album_gain_db : data.track_gain_db;
    factor_ = db_to_ratio(gain_db + config.pregain_db);
    threshold_dbfs_ = config.threshold_dbfs;
    knee_db_ = std::max(config.knee_db, 0.0);
    knee_factor_ = knee_db_ > 0.0 ? (1.0 / (2.0 * knee_db_ * 4.0)) : 0.0;
    attack_cf_ = duration_to_coefficient(config.attack_ms, sample_rate);
    release_cf_ = duration_to_coefficient(config.release_ms, sample_rate);
}

float ReplayGainProcessor::process(float input) {
    const bool enabled = enabled_flag_
        ? enabled_flag_->load(std::memory_order_relaxed)
        : enabled_;
    if (!enabled) return input;

    double sample = static_cast<double>(input) * factor_;

    const double limiter_db = [&]() {
        sample += std::numeric_limits<double>::min();
        const double bias_db = ratio_to_db(std::abs(sample)) - threshold_dbfs_;
        const double knee_boundary_db = bias_db * 2.0;
        if (knee_db_ <= 0.0) {
            return std::max(0.0, bias_db);
        }
        if (knee_boundary_db < -knee_db_) {
            return 0.0;
        }
        if (std::abs(knee_boundary_db) <= knee_db_) {
            const double term = knee_boundary_db + knee_db_;
            return term * term * knee_factor_;
        }
        return bias_db;
    }();

    const int channel = next_channel_;
    next_channel_ = (next_channel_ + 1) % channel_count_;

    integrators_[channel] = std::max(
        limiter_db,
        release_cf_ * integrators_[channel] + (1.0 - release_cf_) * limiter_db);
    peaks_[channel] = attack_cf_ * peaks_[channel]
        + (1.0 - attack_cf_) * integrators_[channel];

    const double max_peak = std::max(peaks_[0], peaks_[1]);
    sample *= db_to_ratio(-max_peak);
    return static_cast<float>(sample);
}

} // namespace librespotc::audio
