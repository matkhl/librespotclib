#pragma once
#include "context_state.h"
#include <string>
#include <vector>

namespace librespotc::auth {
class ClientTokenProvider;
class Login5Provider;
}

namespace librespotc::connect {

// Fetch the track list of a Spotify context (playlist / album / artist).
// Calls GET https://<spclient>/context-resolve/v1/<context_uri> with
// Authorization: Bearer + client-token, parses the JSON-encoded protobuf
// response, and produces a flat ProvidedTrack list (only audio tracks —
// episodes / ads skipped).
//
// Blocking; caller should run on a worker thread, not the dealer reader.
// Returns true on success.
bool resolve_context_tracks(const std::string& context_uri,
                             auth::ClientTokenProvider& ct,
                             auth::Login5Provider& l5,
                             const std::string& spclient_base,
                             std::vector<ProvidedTrack>& out_tracks);

// Fetch the autoplay continuation for the given seed context. Returns a
// flat track list to append after the user's chosen context ends — same
// pattern Bose / Sonos use to keep music flowing forever.
// Endpoint: GET https://<spclient>/context-resolve/autoplay?uri=<seed_uri>
bool resolve_autoplay_tracks(const std::string& seed_context_uri,
                              auth::ClientTokenProvider& ct,
                              auth::Login5Provider& l5,
                              const std::string& spclient_base,
                              std::vector<ProvidedTrack>& out_tracks);

} // namespace librespotc::connect
