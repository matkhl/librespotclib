#pragma once
#include <cstdint>
#include <functional>
#include <vector>

#include "equalizer.h"
#include "replaygain.h"

namespace librespotc::audio {

// One-shot decode (kept for legacy/testing).
struct VorbisDecoded {
    int channels = 0;
    int sample_rate = 0;
    std::vector<int16_t> pcm;
};
bool decode_ogg_vorbis(const uint8_t* data, size_t len, VorbisDecoded& out);

// Streaming Vorbis decoder using stb_vorbis pushdata API.
// Feed bytes via push(); receive PCM frames via on_frame callback as they decode.
class StreamingDecoder {
public:
    using FrameSink = std::function<bool(const int16_t* pcm,
                                         size_t frame_count,
                                         int sample_rate,
                                         int channels)>;

    explicit StreamingDecoder(FrameSink sink,
                              ReplayGainConfig replaygain_config = {},
                              ReplayGainData replaygain_data = {},
                              EqualizerRuntimeConfig equalizer_config = {});
    ~StreamingDecoder();
    StreamingDecoder(const StreamingDecoder&) = delete;
    StreamingDecoder& operator=(const StreamingDecoder&) = delete;

    // Push bytes; returns false if a fatal decode error occurred or sink returned false.
    bool push(const uint8_t* data, size_t len);

    // Signal end of stream. Drains any remaining buffered data.
    bool finish();

    int sample_rate() const { return sample_rate_; }
    int channels() const { return channels_; }

private:
    void* vorbis_ = nullptr; // opaque stb_vorbis*
    FrameSink sink_;
    ReplayGainConfig replaygain_config_;
    ReplayGainData replaygain_data_;
    ReplayGainProcessor replaygain_;
    EqualizerRuntimeConfig equalizer_config_;
    EqualizerProcessor equalizer_;
    std::vector<uint8_t> buf_; // accumulating bytes not yet consumed
    int sample_rate_ = 0;
    int channels_ = 0;
    bool open_attempted_ = false;
};

} // namespace librespotc::audio
