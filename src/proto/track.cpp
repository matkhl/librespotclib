#include "track.h"
#include "pb_codec.h"

#include <utility>

namespace librespotc::proto {

static std::string parse_artist_name(Reader r) {
    while (!r.at_end()) {
        uint32_t f, wt;
        if (!r.read_tag(f, wt)) break;
        if (f == 2 && wt == WIRE_LEN) return r.read_string();
        r.skip_field(wt);
    }
    return {};
}

static TrackImage parse_image(Reader r) {
    TrackImage out;
    while (!r.at_end()) {
        uint32_t f, wt;
        if (!r.read_tag(f, wt)) break;
        if (f == 1 && wt == WIRE_LEN) out.file_id = r.read_bytes();
        else if (f == 2 && wt == WIRE_VARINT) out.size = (int32_t)r.read_varint();
        else if (f == 3 && wt == WIRE_VARINT) {
            uint64_t v = r.read_varint();
            out.width = (int32_t)((v >> 1) ^ (uint64_t)(-(int64_t)(v & 1)));
        }
        else if (f == 4 && wt == WIRE_VARINT) {
            uint64_t v = r.read_varint();
            out.height = (int32_t)((v >> 1) ^ (uint64_t)(-(int64_t)(v & 1)));
        }
        else r.skip_field(wt);
    }
    return out;
}

static void parse_image_group(Reader r, std::vector<TrackImage>& images) {
    while (!r.at_end()) {
        uint32_t f, wt;
        if (!r.read_tag(f, wt)) break;
        if (f == 1 && wt == WIRE_LEN) {
            auto image = parse_image(r.read_len_delim());
            if (image.file_id.size() == 20) images.push_back(std::move(image));
        } else r.skip_field(wt);
    }
}

struct AlbumParseResult {
    std::string name;
    std::vector<TrackImage> images;
};

static AlbumParseResult parse_album(Reader r) {
    AlbumParseResult out;
    while (!r.at_end()) {
        uint32_t f, wt;
        if (!r.read_tag(f, wt)) break;
        if (f == 2 && wt == WIRE_LEN) out.name = r.read_string();
        else if (f == 9 && wt == WIRE_LEN) {
            auto image = parse_image(r.read_len_delim());
            if (image.file_id.size() == 20) out.images.push_back(std::move(image));
        }
        else if (f == 17 && wt == WIRE_LEN) parse_image_group(r.read_len_delim(), out.images);
        else r.skip_field(wt);
    }
    return out;
}

static TrackFile parse_audiofile(Reader r) {
    TrackFile f;
    while (!r.at_end()) {
        uint32_t fn, wt;
        if (!r.read_tag(fn, wt)) break;
        if (fn == 1 && wt == WIRE_LEN)       f.file_id = r.read_bytes();
        else if (fn == 2 && wt == WIRE_VARINT) f.format = (int32_t)r.read_varint();
        else r.skip_field(wt);
    }
    return f;
}

static TrackRestriction parse_restriction(Reader r) {
    TrackRestriction out;
    while (!r.at_end()) {
        uint32_t fn, wt;
        if (!r.read_tag(fn, wt)) break;
        if (fn == 2 && wt == WIRE_LEN) out.countries_allowed = r.read_string();
        else if (fn == 3 && wt == WIRE_LEN) out.countries_forbidden = r.read_string();
        else if (fn == 5 && wt == WIRE_LEN) out.catalogue_strs.push_back(r.read_string());
        else r.skip_field(wt);
    }
    return out;
}

bool parse_track(const uint8_t* data, size_t len, ParsedTrack& out) {
    try {
        out = ParsedTrack{};
        Reader r(data, len);
        bool got_artist = false;
        while (!r.at_end()) {
            uint32_t fn, wt;
            if (!r.read_tag(fn, wt)) break;
            if (fn == 1  && wt == WIRE_LEN)    out.gid = r.read_bytes();
            else if (fn == 2  && wt == WIRE_LEN) out.name = r.read_string();
            else if (fn == 3  && wt == WIRE_LEN) {
                auto album = parse_album(r.read_len_delim());
                out.album = std::move(album.name);
                out.album_images = std::move(album.images);
            }
            else if (fn == 4  && wt == WIRE_LEN) {
                auto sub = r.read_len_delim();
                if (!got_artist) {
                    out.artist = parse_artist_name(sub);
                    if (!out.artist.empty()) got_artist = true;
                }
            }
            else if (fn == 7  && wt == WIRE_VARINT) {
                uint64_t v = r.read_varint();
                // sint32 zigzag
                int32_t dec = (int32_t)((v >> 1) ^ (uint64_t)(-(int64_t)(v & 1)));
                out.duration_ms = dec;
            }
            else if (fn == 14 && wt == WIRE_LEN) out.restrictions.push_back(parse_restriction(r.read_len_delim()));
            else if (fn == 12 && wt == WIRE_LEN) out.files.push_back(parse_audiofile(r.read_len_delim()));
            else if (fn == 13 && wt == WIRE_LEN) {
                // Track.alternative = repeated Track (field 13 in modern
                // proto — NOT 26). Cloud uses these as region/license
                // substitutes when the primary track has empty audio_files.
                // We only capture the alt's `gid` (field 1) so the caller
                // can re-fetch full metadata for it.
                auto alt = r.read_len_delim();
                while (!alt.at_end()) {
                    uint32_t af, awt;
                    if (!alt.read_tag(af, awt)) break;
                    if (af == 1 && awt == WIRE_LEN) {
                        out.alternative_gids.push_back(alt.read_bytes());
                    } else alt.skip_field(awt);
                }
            }
            else r.skip_field(wt);
        }
        return true;
    } catch (...) { return false; }
}

bool parse_storage_resolve(const uint8_t* data, size_t len, StorageResolve& out) {
    try {
        Reader r(data, len);
        while (!r.at_end()) {
            uint32_t f, wt;
            if (!r.read_tag(f, wt)) break;
            if (f == 1 && wt == WIRE_VARINT) out.result = (int32_t)r.read_varint();
            else if (f == 2 && wt == WIRE_LEN) out.cdn_urls.push_back(r.read_string());
            else r.skip_field(wt);
        }
        return true;
    } catch (...) { return false; }
}

std::vector<uint8_t> encode_extended_metadata_request(const std::string& entity_uri,
                                                      int32_t extension_kind,
                                                      const std::string& country,
                                                      const std::string& catalogue) {
    Writer w;
    if (!country.empty() || !catalogue.empty()) {
        w.write_submessage(1, [&](Writer& h) {
            if (!country.empty()) h.write_string(1, country);
            if (!catalogue.empty()) h.write_string(2, catalogue);
        });
    }
    w.write_submessage(2, [&](Writer& er) {
        er.write_string(1, entity_uri);
        er.write_submessage(2, [&](Writer& q) {
            q.write_enum(1, extension_kind);
        });
    });
    return w.take();
}

static bool parse_any_value(Reader r, std::vector<uint8_t>& value) {
    while (!r.at_end()) {
        uint32_t f, wt;
        if (!r.read_tag(f, wt)) break;
        if (f == 2 && wt == WIRE_LEN) value = r.read_bytes();
        else r.skip_field(wt);
    }
    return !value.empty();
}

static bool parse_entity_extension_data(Reader r, std::vector<uint8_t>& payload) {
    while (!r.at_end()) {
        uint32_t f, wt;
        if (!r.read_tag(f, wt)) break;
        if (f == 3 && wt == WIRE_LEN) {
            if (parse_any_value(r.read_len_delim(), payload)) return true;
        } else r.skip_field(wt);
    }
    return false;
}

static bool parse_extension_array(Reader r, int32_t expected_kind,
                                  std::vector<uint8_t>& payload) {
    int32_t kind = -1;
    std::vector<std::vector<uint8_t>> candidates;
    while (!r.at_end()) {
        uint32_t f, wt;
        if (!r.read_tag(f, wt)) break;
        if (f == 2 && wt == WIRE_VARINT) {
            kind = (int32_t)r.read_varint();
        } else if (f == 3 && wt == WIRE_LEN) {
            std::vector<uint8_t> p;
            if (parse_entity_extension_data(r.read_len_delim(), p)) {
                candidates.push_back(std::move(p));
            }
        } else r.skip_field(wt);
    }
    if (kind != expected_kind || candidates.empty()) return false;
    payload = std::move(candidates.front());
    return true;
}

bool parse_extended_metadata_response(const uint8_t* data, size_t len,
                                      int32_t expected_extension_kind,
                                      std::vector<uint8_t>& payload) {
    try {
        payload.clear();
        Reader r(data, len);
        while (!r.at_end()) {
            uint32_t f, wt;
            if (!r.read_tag(f, wt)) break;
            if (f == 2 && wt == WIRE_LEN) {
                if (parse_extension_array(r.read_len_delim(),
                                          expected_extension_kind,
                                          payload)) {
                    return true;
                }
            } else r.skip_field(wt);
        }
        return false;
    } catch (...) { return false; }
}

} // namespace librespotc::proto
