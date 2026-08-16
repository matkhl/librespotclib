// Wrapper around stb_vorbis (built from deps/stb/stb_vorbis.c as C).

#include "vorbis.h"

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cmath>

struct stb_vorbis;
struct stb_vorbis_alloc;
struct stb_vorbis_info {
    unsigned int sample_rate;
    int channels;
    unsigned int setup_memory_required;
    unsigned int setup_temp_memory_required;
    unsigned int temp_memory_required;
    int max_frame_size;
};

extern "C" {
    int stb_vorbis_decode_memory(const unsigned char* mem, int len,
                                 int* channels, int* sample_rate,
                                 short** output);

    stb_vorbis* stb_vorbis_open_pushdata(const unsigned char* data, int data_len,
                                         int* consumed, int* error,
                                         const stb_vorbis_alloc* alloc_buffer);

    int stb_vorbis_decode_frame_pushdata(stb_vorbis* f,
                                          const unsigned char* data, int data_len,
                                          int* channels, float*** output,
                                          int* samples);

    void stb_vorbis_close(stb_vorbis* f);
    stb_vorbis_info stb_vorbis_get_info(stb_vorbis* f);
}

namespace librespotc::audio {

bool decode_ogg_vorbis(const uint8_t* data, size_t len, VorbisDecoded& out) {
    int channels = 0, rate = 0;
    short* pcm = nullptr;
    int samples_per_channel = stb_vorbis_decode_memory(data, (int)len,
                                                       &channels, &rate, &pcm);
    if (samples_per_channel <= 0 || !pcm) {
        if (pcm) std::free(pcm);
        return false;
    }
    out.channels = channels;
    out.sample_rate = rate;
    out.pcm.assign(pcm, pcm + (size_t)samples_per_channel * (size_t)channels);
    std::free(pcm);
    return true;
}

StreamingDecoder::StreamingDecoder(FrameSink sink,
                                   ReplayGainConfig replaygain_config,
                                   ReplayGainData replaygain_data,
                                   EqualizerRuntimeConfig equalizer_config)
    : sink_(std::move(sink)),
      replaygain_config_(replaygain_config),
      replaygain_data_(replaygain_data),
      equalizer_config_(equalizer_config) {}
StreamingDecoder::~StreamingDecoder() {
    if (vorbis_) stb_vorbis_close((stb_vorbis*)vorbis_);
}

static int16_t float_to_s16(float f) {
    if (!std::isfinite(f)) f = 0.0f;
    if (f >  1.0f) f =  1.0f;
    if (f < -1.0f) f = -1.0f;
    int v = (int)(f * 32767.0f);
    if (v >  32767) v =  32767;
    if (v < -32768) v = -32768;
    return (int16_t)v;
}

bool StreamingDecoder::push(const uint8_t* data, size_t len) {
    if (len) buf_.insert(buf_.end(), data, data + len);

    // Try to open the decoder if not yet open.
    if (!vorbis_) {
        // stb_vorbis needs enough header data to find headers and codebook.
        // Retry until either it opens or buffer keeps growing.
        int consumed = 0, err = 0;
        auto* v = stb_vorbis_open_pushdata(buf_.data(), (int)buf_.size(),
                                           &consumed, &err, nullptr);
        if (!v) {
            // VORBIS_need_more_data == 1. Anything else is fatal once we have
            // enough header room; tolerate until we've buffered ~256 KB.
            if (err == 1 || buf_.size() < 256 * 1024) return true;
            std::fprintf(stderr, "[vorbis] open_pushdata error=%d (have %zu bytes)\n",
                         err, buf_.size());
            return false;
        }
        vorbis_ = v;
        auto info = stb_vorbis_get_info(v);
        sample_rate_ = (int)info.sample_rate;
        channels_ = info.channels;
        replaygain_.configure(replaygain_config_, replaygain_data_,
                              sample_rate_, channels_);
        equalizer_.configure(equalizer_config_, sample_rate_, channels_);
        std::fprintf(stderr, "[vorbis] opened: %d Hz x %d ch\n",
                     sample_rate_, channels_);
        buf_.erase(buf_.begin(), buf_.begin() + consumed);
    }

    // Decode frames until decoder needs more data.
    while (true) {
        int ch = 0, samples = 0;
        float** out = nullptr;
        int consumed = stb_vorbis_decode_frame_pushdata(
            (stb_vorbis*)vorbis_, buf_.data(), (int)buf_.size(),
            &ch, &out, &samples);
        if (consumed == 0) break; // need more data
        if (samples > 0 && out && ch > 0) {
            // Convert float planar → int16 interleaved.
            std::vector<int16_t> pcm((size_t)samples * (size_t)ch);
            for (int i = 0; i < samples; ++i) {
                for (int c = 0; c < ch; ++c) {
                    float sample = replaygain_.process(out[c][i]);
                    sample = equalizer_.process(sample);
                    pcm[(size_t)i * (size_t)ch + (size_t)c] = float_to_s16(sample);
                }
            }
            if (sink_ && !sink_(pcm.data(), (size_t)samples, sample_rate_, ch)) {
                buf_.erase(buf_.begin(), buf_.begin() + consumed);
                return false;
            }
        }
        buf_.erase(buf_.begin(), buf_.begin() + consumed);
        if (buf_.empty()) break;
    }
    return true;
}

bool StreamingDecoder::finish() {
    // Final flush: continue calling decode until consumed == 0 with no progress.
    while (vorbis_ && !buf_.empty()) {
        int ch = 0, samples = 0;
        float** out = nullptr;
        int consumed = stb_vorbis_decode_frame_pushdata(
            (stb_vorbis*)vorbis_, buf_.data(), (int)buf_.size(),
            &ch, &out, &samples);
        if (consumed == 0) break;
        if (samples > 0 && out && ch > 0) {
            std::vector<int16_t> pcm((size_t)samples * (size_t)ch);
            for (int i = 0; i < samples; ++i) {
                for (int c = 0; c < ch; ++c) {
                    float sample = replaygain_.process(out[c][i]);
                    sample = equalizer_.process(sample);
                    pcm[(size_t)i * (size_t)ch + (size_t)c] = float_to_s16(sample);
                }
            }
            if (sink_ && !sink_(pcm.data(), (size_t)samples, sample_rate_, ch))
                return false;
        }
        buf_.erase(buf_.begin(), buf_.begin() + consumed);
    }
    return true;
}

} // namespace librespotc::audio
