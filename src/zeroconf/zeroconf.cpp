#include "zeroconf.h"
#include "mdns.h"

#include "../crypto/bcrypt_wrap.h"
#include "../crypto/bigint.h"
#include "../crypto/base64.h"
#include "../../deps/nlohmann/json.hpp"

#include <thread>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <cstring>
#include <cstdio>

namespace librespotc::zeroconf {

// Same DH MODP-768 as handshake.
static const uint8_t DH_PRIME_BE[] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xc9,0x0f,0xda,0xa2,0x21,0x68,0xc2,0x34,
    0xc4,0xc6,0x62,0x8b,0x80,0xdc,0x1c,0xd1,0x29,0x02,0x4e,0x08,0x8a,0x67,0xcc,0x74,
    0x02,0x0b,0xbe,0xa6,0x3b,0x13,0x9b,0x22,0x51,0x4a,0x08,0x79,0x8e,0x34,0x04,0xdd,
    0xef,0x95,0x19,0xb3,0xcd,0x3a,0x43,0x1b,0x30,0x2b,0x0a,0x6d,0xf2,0x5f,0x14,0x37,
    0x4f,0xe1,0x35,0x6d,0x6d,0x51,0xc2,0x45,0xe4,0x85,0xb5,0x76,0x62,0x5e,0x7e,0xc6,
    0xf4,0x4c,0x42,0xe9,0xa6,0x3a,0x36,0x20,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
};

struct ZeroconfService::Impl {
    Config cfg;
    HttpServer http;
    std::thread http_thread;
    std::unique_ptr<MdnsAdvertiser> mdns;

    crypto::BigUint private_key;
    std::vector<uint8_t> public_key_be; // 96 bytes nominal

    std::mutex m;
    std::condition_variable cv;
    std::optional<auth::Credentials> creds;

    Impl(const Config& c) : cfg(c) {
        // Generate DH keypair
        uint8_t priv_bytes[95];
        crypto::random_bytes(priv_bytes, sizeof(priv_bytes));
        private_key = crypto::BigUint::from_le(priv_bytes, sizeof(priv_bytes));
        auto g = crypto::BigUint::from_u32(2);
        auto p = crypto::BigUint::from_be(DH_PRIME_BE, sizeof(DH_PRIME_BE));
        auto pub = crypto::BigUint::modexp(g, private_key, p);
        public_key_be = pub.to_be();
    }

    HttpResponse handle_get_info() const {
        nlohmann::json j;
        j["status"] = 101;
        j["statusString"] = "OK";
        j["spotifyError"] = 0;
        j["version"] = "2.9.0";
        j["deviceID"] = cfg.device_id;
        j["deviceType"] = cfg.device_type;
        j["remoteName"] = cfg.device_name;
        j["publicKey"] = crypto::b64_encode(public_key_be);
        j["brandDisplayName"] = "librespotc";
        j["modelDisplayName"] = "librespotc";
        j["libraryVersion"] = "0.1.0";
        j["resolverVersion"] = "1";
        j["groupStatus"] = "NONE";
        j["tokenType"] = "default";
        j["clientID"] = cfg.client_id;
        j["productID"] = 0;
        j["scope"] = "streaming,client-authorization-universal";
        j["availability"] = "";
        j["supported_drm_media_formats"] = nlohmann::json::array();
        j["supported_capabilities"] = 1;
        j["accountReq"] = "PREMIUM";
        j["activeUser"] = "";
        j["aliases"] = nlohmann::json::array();
        HttpResponse r;
        r.status = 200;
        r.status_text = "OK";
        r.content_type = "application/json";
        r.body = j.dump();
        return r;
    }

    HttpResponse handle_add_user(const HttpRequest& req) {
        auto find = [&](const std::string& k) -> std::string {
            auto it = req.form.find(k);
            if (it != req.form.end()) return it->second;
            auto qt = req.query.find(k);
            if (qt != req.query.end()) return qt->second;
            return {};
        };

        std::string username = find("userName");
        std::string blob_b64 = find("blob");
        std::string client_b64 = find("clientKey");
        if (username.empty() || blob_b64.empty() || client_b64.empty()) {
            nlohmann::json j;
            j["status"] = 301;
            j["statusString"] = "ERROR-MISSING-PARAM";
            j["spotifyError"] = 1;
            HttpResponse r; r.body = j.dump(); return r;
        }

        try {
            auto enc_blob = crypto::b64_decode(blob_b64);
            auto client_key_bytes = crypto::b64_decode(client_b64);
            if (enc_blob.size() < 16 + 20) throw std::runtime_error("blob too short");

            auto p = crypto::BigUint::from_be(DH_PRIME_BE, sizeof(DH_PRIME_BE));
            auto remote = crypto::BigUint::from_be(client_key_bytes.data(),
                                                   client_key_bytes.size());
            auto shared = crypto::BigUint::modexp(remote, private_key, p);
            auto shared_be = shared.to_be();

            auto base_key_full = crypto::sha1(shared_be.data(), shared_be.size());
            std::vector<uint8_t> base_key(base_key_full.begin(),
                                          base_key_full.begin() + 16);
            static const uint8_t s_check[] = {'c','h','e','c','k','s','u','m'};
            static const uint8_t s_enc[]   = {'e','n','c','r','y','p','t','i','o','n'};
            auto checksum_key = crypto::hmac_sha1(base_key.data(), 16,
                                                  s_check, sizeof(s_check));
            auto enc_key_full = crypto::hmac_sha1(base_key.data(), 16,
                                                  s_enc, sizeof(s_enc));

            size_t L = enc_blob.size();
            const uint8_t* iv  = enc_blob.data();
            const uint8_t* enc = enc_blob.data() + 16;
            size_t enc_len = L - 16 - 20;
            const uint8_t* cksum = enc_blob.data() + L - 20;

            auto cksum_calc = crypto::hmac_sha1(checksum_key.data(),
                                                checksum_key.size(),
                                                enc, enc_len);
            if (cksum_calc.size() != 20 ||
                std::memcmp(cksum_calc.data(), cksum, 20) != 0) {
                throw std::runtime_error("HMAC mismatch");
            }

            std::vector<uint8_t> decrypted(enc, enc + enc_len);
            uint8_t ekey[16];  std::memcpy(ekey, enc_key_full.data(), 16);
            uint8_t iv16[16];  std::memcpy(iv16, iv, 16);
            crypto::aes128_ctr(ekey, iv16, decrypted.data(), decrypted.size());

            auto creds_parsed = auth::parse_zeroconf_blob(username, decrypted,
                                                          cfg.device_id);
            {
                std::lock_guard<std::mutex> g(m);
                creds = std::move(creds_parsed);
            }
            cv.notify_all();

            nlohmann::json j;
            j["status"] = 101;
            j["statusString"] = "OK";
            j["spotifyError"] = 0;
            HttpResponse r; r.body = j.dump(); return r;
        } catch (const std::exception& e) {
            std::fprintf(stderr, "[zeroconf] addUser failed: %s\n", e.what());
            nlohmann::json j;
            j["status"] = 102;
            j["statusString"] = std::string("ERROR ") + e.what();
            j["spotifyError"] = 1;
            HttpResponse r; r.body = j.dump(); return r;
        }
    }

    HttpResponse handle(const HttpRequest& req) {
        std::string action;
        auto it = req.query.find("action");
        if (it != req.query.end()) action = it->second;
        if (action.empty()) {
            auto it2 = req.form.find("action");
            if (it2 != req.form.end()) action = it2->second;
        }

        if (req.method == "GET" && action == "getInfo")  return handle_get_info();
        if (req.method == "POST" && action == "addUser") return handle_add_user(req);

        HttpResponse r;
        r.status = 404; r.status_text = "Not Found";
        r.content_type = "text/plain"; r.body = "Not Found";
        return r;
    }
};

ZeroconfService::ZeroconfService(const Config& cfg)
    : impl_(std::make_unique<Impl>(cfg)) {}

ZeroconfService::~ZeroconfService() { stop(); }

bool ZeroconfService::start() {
    if (!impl_->http.start(impl_->cfg.port)) return false;
    impl_->http.set_handler([this](const HttpRequest& r) { return impl_->handle(r); });
    impl_->http_thread = std::thread([this]{ impl_->http.run(); });

    impl_->mdns = std::make_unique<MdnsAdvertiser>();
    impl_->mdns->advertise(impl_->cfg.device_name, impl_->http.local_port());

    std::fprintf(stderr, "[zeroconf] HTTP listening on port %u, mDNS advertising '%s'\n",
                 (unsigned)impl_->http.local_port(),
                 impl_->cfg.device_name.c_str());
    return true;
}

void ZeroconfService::stop() {
    if (impl_->mdns) impl_->mdns->stop();
    impl_->http.stop();
    if (impl_->http_thread.joinable()) impl_->http_thread.join();
}

bool ZeroconfService::wait_for_credentials(auth::Credentials& out, uint32_t timeout_ms) {
    std::unique_lock<std::mutex> lk(impl_->m);
    if (timeout_ms == 0) {
        impl_->cv.wait(lk, [this]{ return impl_->creds.has_value(); });
    } else {
        if (!impl_->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                                [this]{ return impl_->creds.has_value(); })) {
            return false;
        }
    }
    out = *impl_->creds;
    return true;
}

uint16_t ZeroconfService::local_port() const { return impl_->http.local_port(); }

} // namespace librespotc::zeroconf
