#include "ogg_demuxer.h"

#include <cstdio>
#include <cstring>

namespace librespotc::audio {

OggDemuxer::OggDemuxer(HeadersSink hs, PacketSink ps)
    : hs_(std::move(hs)), ps_(std::move(ps)) {}

// OGG page header layout (27 fixed bytes + segment table):
//   0..3   "OggS"
//   4      version (0)
//   5      header_type
//   6..13  granule_position (i64 LE)
//   14..17 bitstream_serial (u32 LE)
//   18..21 page_sequence (u32 LE)
//   22..25 crc_checksum (u32 LE)
//   26     number_page_segments (u8)
//   27..27+N segment_table (N bytes of lacing)
//   27+N..  page_data (sum(segment_table))
//
// Packets within a page are formed by concatenating segments. A segment with
// length < 255 terminates the current packet. A segment with length == 255
// indicates the packet continues into the next segment (and possibly the
// next page).

static uint64_t read_u64_le(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}
static uint32_t read_u32_le(const uint8_t* p) {
    return  (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

bool OggDemuxer::emit_packet(std::vector<uint8_t>&& pkt, uint64_t pts_ms) {
    if (headers_emitted_ < 3) {
        // First three packets are Vorbis setup headers.
        // Parse identification (packet[0]) for rate/channels/bitrate.
        if (headers_emitted_ == 0 && pkt.size() >= 30
            && pkt[0] == 0x01 && std::memcmp(&pkt[1], "vorbis", 6) == 0) {
            // version u32 LE @ 7
            // channels u8 @ 11
            // sample_rate u32 LE @ 12
            // bitrate_max i32 LE @ 16
            // bitrate_nominal i32 LE @ 20
            channels_           = pkt[11];
            sample_rate_        = read_u32_le(&pkt[12]);
            bitrate_nominal_bps_= read_u32_le(&pkt[20]);
        }
        headers_concat_.insert(headers_concat_.end(), pkt.begin(), pkt.end());
        ++headers_emitted_;
        if (headers_emitted_ == 3 && !headers_fired_ && hs_) {
            hs_(headers_concat_.data(), headers_concat_.size(),
                sample_rate_, channels_, bitrate_nominal_bps_);
            headers_fired_ = true;
        }
        return true;
    }
    // Audio packet — defer to sink with backpressure handling.
    if (ps_) {
        bool ok = ps_(pkt.data(), pkt.size(), pts_ms);
        if (!ok) {
            pending_packet_bytes_ = std::move(pkt);
            pending_pts_ms_ = pts_ms;
            has_pending_ = true;
            return false;
        }
    }
    return true;
}

bool OggDemuxer::push(const uint8_t* data, size_t len) {
    if (len) buf_.insert(buf_.end(), data, data + len);

    // Retry pending packet first.
    if (has_pending_) {
        if (!ps_) { has_pending_ = false; }
        else {
            bool ok = ps_(pending_packet_bytes_.data(),
                          pending_packet_bytes_.size(), pending_pts_ms_);
            if (!ok) return false; // still rejected; defer more
            has_pending_ = false;
            pending_packet_bytes_.clear();
        }
    }
    return try_parse_pages();
}

bool OggDemuxer::try_parse_pages() {
    size_t pos = 0;
    while (true) {
        if (buf_.size() - pos < 27) break;
        if (std::memcmp(&buf_[pos], "OggS", 4) != 0) {
            // Resync: search forward for next "OggS"
            size_t scan = pos + 1;
            while (scan + 4 <= buf_.size()
                   && std::memcmp(&buf_[scan], "OggS", 4) != 0) ++scan;
            if (scan + 4 > buf_.size()) break;
            pos = scan;
            continue;
        }
        uint8_t  hdr_type     = buf_[pos + 5];
        uint64_t granule_pos  = read_u64_le(&buf_[pos + 6]);
        uint8_t  n_segments   = buf_[pos + 26];
        size_t   header_size  = 27 + (size_t)n_segments;
        if (buf_.size() - pos < header_size) break;
        // Sum segments to get page_data size.
        size_t data_size = 0;
        for (size_t i = 0; i < n_segments; ++i) data_size += buf_[pos + 27 + i];
        if (buf_.size() - pos < header_size + data_size) break;

        const uint8_t* seg_table = &buf_[pos + 27];
        const uint8_t* page_data = &buf_[pos + header_size];
        size_t data_off = 0;
        // Page-level granule → ms only at end of last packet that ends in this page.
        // For simplicity attribute granule to ALL packets that terminate in this
        // page (i.e. last packet in lacing if final segment < 255).
        uint64_t pts_ms = sample_rate_ ? (granule_pos * 1000ULL / sample_rate_) : 0;

        // continued flag (0x01) means first segment(s) belong to previous packet
        // — already in current_packet_.
        (void)hdr_type;

        for (size_t i = 0; i < n_segments; ++i) {
            uint8_t seg_len = seg_table[i];
            current_packet_.insert(current_packet_.end(),
                                   page_data + data_off,
                                   page_data + data_off + seg_len);
            data_off += seg_len;
            if (seg_len < 255) {
                // Packet boundary.
                std::vector<uint8_t> pkt = std::move(current_packet_);
                current_packet_.clear();
                bool last_in_page = (i + 1 == n_segments);
                uint64_t this_pts = last_in_page ? pts_ms : 0;
                if (!emit_packet(std::move(pkt), this_pts)) {
                    // Backpressure: consume this page from buf_ and stop.
                    pos += header_size + data_size;
                    buf_.erase(buf_.begin(), buf_.begin() + pos);
                    return true; // not fatal; caller will push more later
                }
            }
        }
        pos += header_size + data_size;
    }
    if (pos) buf_.erase(buf_.begin(), buf_.begin() + pos);
    return true;
}

} // namespace librespotc::audio
