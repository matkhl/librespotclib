#pragma once

#include "../../include/librespotc/librespotc.h"

#include <array>
#include <atomic>

namespace librespotc::audio {

struct EqualizerRuntimeConfig {
    bool enabled = false;
    const std::atomic<bool>* enabled_flag = nullptr;
    std::array<float, kEqualizerBandCount> bands_db{};
    std::array<const std::atomic<float>*, kEqualizerBandCount> band_flags{};
};

class EqualizerProcessor {
public:
    struct Coeff {
        double b0 = 1.0;
        double b1 = 0.0;
        double b2 = 0.0;
        double a1 = 0.0;
        double a2 = 0.0;
    };

    void configure(const EqualizerRuntimeConfig& config,
                   int sample_rate,
                   int channels);

    float process(float sample);

private:
    struct State {
        double z1 = 0.0;
        double z2 = 0.0;
    };

    void refresh_if_needed();
    void rebuild_coefficients();

    EqualizerRuntimeConfig config_{};
    int sample_rate_ = 44100;
    int channel_count_ = 2;
    int next_channel_ = 0;
    bool enabled_ = false;
    std::array<float, kEqualizerBandCount> bands_db_{};
    std::array<Coeff, kEqualizerBandCount> coeffs_{};
    std::array<std::array<State, 2>, kEqualizerBandCount> states_{};
    float preamp_ = 1.0f;
};

} // namespace librespotc::audio
