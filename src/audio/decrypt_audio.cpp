#include "decrypt_audio.h"
#include "../crypto/bcrypt_wrap.h"

namespace librespotc::audio {

const uint8_t AUDIO_IV[16] = {
    0x72, 0xe0, 0x67, 0xfb, 0xdd, 0xcb, 0xcf, 0x77,
    0xeb, 0xe8, 0xbc, 0x64, 0x3f, 0x63, 0x0d, 0x93,
};

void decrypt_full(const uint8_t key[16], uint8_t* buf, size_t len) {
    crypto::aes128_ctr(key, AUDIO_IV, buf, len);
}

} // namespace librespotc::audio
