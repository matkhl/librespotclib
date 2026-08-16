#pragma once
#include <cstdint>
#include <vector>
#include <string>

namespace librespotc::proto {

enum class AudioFormat : int32_t {
    OGG_VORBIS_96  = 0,
    OGG_VORBIS_160 = 1,
    OGG_VORBIS_320 = 2,
};

struct TrackFile {
    std::vector<uint8_t> file_id; // 20 bytes
    int32_t format = -1;
};

struct TrackRestriction {
    std::string countries_allowed;
    std::string countries_forbidden;
    std::vector<std::string> catalogue_strs;
};

struct TrackImage {
    std::vector<uint8_t> file_id; // 20 bytes
    int32_t size = -1;
    int32_t width = 0;
    int32_t height = 0;
};

struct ParsedTrack {
    std::vector<uint8_t> gid;
    std::string name;
    std::string artist;            // first
    std::string album;
    int32_t duration_ms = 0;
    std::vector<TrackFile> files;
    std::vector<TrackImage> album_images;
    std::vector<TrackRestriction> restrictions;
    // Alternative track GIDs — Spotify fills `alternative` (Track field 13)
    // when the primary track is region-restricted in the user's market.
    // Library should retry metadata fetch against the first alternative if
    // the primary has no playable audio_files.
    std::vector<std::vector<uint8_t>> alternative_gids;
};

bool parse_track(const uint8_t* data, size_t len, ParsedTrack& out);

std::vector<uint8_t> encode_extended_metadata_request(const std::string& entity_uri,
                                                      int32_t extension_kind,
                                                      const std::string& country = {},
                                                      const std::string& catalogue = {});
bool parse_extended_metadata_response(const uint8_t* data, size_t len,
                                      int32_t expected_extension_kind,
                                      std::vector<uint8_t>& payload);

// Parse StorageResolveResponse (proto3): result(1, enum), cdnurl(2, repeated string), fileid(4, bytes)
struct StorageResolve {
    int32_t result = 0; // 0=CDN, 1=STORAGE, 3=RESTRICTED
    std::vector<std::string> cdn_urls;
};
bool parse_storage_resolve(const uint8_t* data, size_t len, StorageResolve& out);

} // namespace librespotc::proto
