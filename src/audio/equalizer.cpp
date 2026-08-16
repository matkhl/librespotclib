#include "equalizer.h"

#include <algorithm>
#include <cmath>

namespace librespotc::audio {

namespace {

constexpr double kPi = 3.14159265358979323846264338327950288;
constexpr std::array<double, kEqualizerBandCount> kBandHz{
    60.0, 250.0, 1000.0, 4000.0, 12000.0
};
constexpr std::array<double, kEqualizerBandCount> kBandQ{
    0.62, 0.72, 0.90, 0.90, 0.85
};
constexpr float kMaxBandDb = 6.0f;
constexpr float kMinBandDb = -6.0f;

float clamp_band(float db) {
    if (!std::isfinite(db)) return 0.0f;
    return std::clamp(db, kMinBandDb, kMaxBandDb);
}

double db_to_ratio(double db) {
    return std::pow(10.0, db / 20.0);
}

EqualizerProcessor::Coeff make_peaking(double sample_rate,
                                       double freq,
                                       double q,
                                       double gain_db) {
    EqualizerProcessor::Coeff c;
    if (sample_rate <= 0.0 || freq <= 0.0 ||
        freq >= sample_rate * 0.49 || std::abs(gain_db) < 0.01) {
        return c;
    }

    const double a = std::pow(10.0, gain_db / 40.0);
    const double w0 = 2.0 * kPi * freq / sample_rate;
    const double sn = std::sin(w0);
    const double cs = std::cos(w0);
    const double alpha = sn / (2.0 * q);

    const double b0 = 1.0 + alpha * a;
    const double b1 = -2.0 * cs;
    const double b2 = 1.0 - alpha * a;
    const double a0 = 1.0 + alpha / a;
    const double a1 = -2.0 * cs;
    const double a2 = 1.0 - alpha / a;

    c.b0 = b0 / a0;
    c.b1 = b1 / a0;
    c.b2 = b2 / a0;
    c.a1 = a1 / a0;
    c.a2 = a2 / a0;
    return c;
}

} // namespace

void EqualizerProcessor::configure(const EqualizerRuntimeConfig& config,
                                   int sample_rate,
                                   int channels) {
    config_ = config;
    sample_rate_ = sample_rate > 0 ? sample_rate : 44100;
    channel_count_ = std::clamp(channels, 1, 2);
    next_channel_ = 0;
    for (auto& band : states_) {
        for (auto& state : band) {
            state = {};
        }
    }
    enabled_ = config_.enabled;
    for (size_t i = 0; i < bands_db_.size(); ++i) {
        bands_db_[i] = clamp_band(config_.bands_db[i]);
    }
    rebuild_coefficients();
}

void EqualizerProcessor::refresh_if_needed() {
    bool enabled = config_.enabled_flag
        ? config_.enabled_flag->load(std::memory_order_relaxed)
        : config_.enabled;

    bool changed = enabled != enabled_;
    std::array<float, kEqualizerBandCount> next{};
    for (size_t i = 0; i < next.size(); ++i) {
        next[i] = clamp_band(config_.band_flags[i]
            ? config_.band_flags[i]->load(std::memory_order_relaxed)
            : config_.bands_db[i]);
        if (std::abs(next[i] - bands_db_[i]) > 0.01f) {
            changed = true;
        }
    }

    if (!changed) return;
    enabled_ = enabled;
    bands_db_ = next;
    rebuild_coefficients();
}

void EqualizerProcessor::rebuild_coefficients() {
    float max_positive = 0.0f;
    float positive_sum = 0.0f;
    for (float db : bands_db_) {
        if (db > 0.0f) {
            max_positive = std::max(max_positive, db);
            positive_sum += db;
        }
    }

    // Leave extra margin for downstream filters when low bands are boosted.
    const float stacked_positive = positive_sum - max_positive;
    const float low_positive = std::max(0.0f, bands_db_[0]) * 0.70f
                             + std::max(0.0f, bands_db_[1]) * 0.45f;
    const float headroom_db = std::min(
        5.5f,
        std::max(max_positive * 0.35f + stacked_positive * 0.10f,
                 low_positive));
    const float preamp_db = -headroom_db;
    preamp_ = enabled_ && positive_sum > 0.01f
        ? static_cast<float>(db_to_ratio(preamp_db))
        : 1.0f;

    for (size_t i = 0; i < coeffs_.size(); ++i) {
        coeffs_[i] = enabled_
            ? make_peaking(static_cast<double>(sample_rate_), kBandHz[i], kBandQ[i], bands_db_[i])
            : Coeff{};
    }
}

float EqualizerProcessor::process(float input) {
    if (next_channel_ == 0) refresh_if_needed();
    if (!enabled_) {
        next_channel_ = (next_channel_ + 1) % channel_count_;
        return input;
    }

    const int channel = next_channel_;
    next_channel_ = (next_channel_ + 1) % channel_count_;

    double sample = static_cast<double>(input) * preamp_;
    for (size_t i = 0; i < coeffs_.size(); ++i) {
        const auto& c = coeffs_[i];
        auto& s = states_[i][channel];
        const double y = c.b0 * sample + s.z1;
        s.z1 = c.b1 * sample - c.a1 * y + s.z2;
        s.z2 = c.b2 * sample - c.a2 * y;
        sample = y;
    }

    if (sample > 1.0) return 1.0f;
    if (sample < -1.0) return -1.0f;
    return static_cast<float>(sample);
}

} // namespace librespotc::audio
