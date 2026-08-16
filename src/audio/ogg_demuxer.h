#pragma once
#include <cstdint>
#include <cstddef>
#include <functional>
#include <vector>

namespace librespotc::audio {

// Streaming OGG container demuxer. Push bytes via push(); demuxer fires
// callbacks for each complete Vorbis packet found. The first three packets
// are Vorbis setup headers (identification, comment, setup); the remainder
// are audio packets.
class OggDemuxer {
public:
    // Fired once when the three setup headers are complete.
    // headers_concat = identification + comment + setup, concatenated.
    using HeadersSink = std::function<void(const uint8_t* headers_concat, size_t bytes,
                                           uint32_t sample_rate, uint16_t channels,
                                           uint32_t bitrate_nominal_bps)>;

    // Fired for each audio packet. pts_ms is the granule position of the
    // OGG page containing the END of this packet, converted to ms (0 if not
    // yet known). Return false to apply backpressure — demuxer will buffer
    // and re-fire the same packet on next push() call.
    using PacketSink  = std::function<bool(const uint8_t* data, size_t bytes,
                                           uint64_t pts_ms)>;

    OggDemuxer(HeadersSink hs, PacketSink ps);

    // Push more bytes. Returns false on protocol error or if a sink call
    // signalled fatal stop.
    bool push(const uint8_t* data, size_t len);

private:
    HeadersSink hs_;
    PacketSink  ps_;

    std::vector<uint8_t> buf_;           // unparsed bytes
    std::vector<uint8_t> current_packet_;  // packet being reassembled across pages
    std::vector<uint8_t> headers_concat_;  // first 3 packets joined
    int headers_emitted_ = 0;             // 0..3 (after 3 we fire headers_)
    bool headers_fired_ = false;

    // Held-back packet when sink rejected; re-tried on next push.
    std::vector<uint8_t> pending_packet_bytes_;
    uint64_t             pending_pts_ms_ = 0;
    bool                 has_pending_ = false;

    uint32_t sample_rate_ = 44100;
    uint16_t channels_ = 2;
    uint32_t bitrate_nominal_bps_ = 0;

    bool try_parse_pages();
    bool emit_packet(std::vector<uint8_t>&& pkt, uint64_t pts_ms);
};

} // namespace librespotc::audio
