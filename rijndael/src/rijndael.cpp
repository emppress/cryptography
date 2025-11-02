#include "rijndael.h"


#include "GF_math.h"
#include "rijndael_key.h"
#include "rijndael_transform.h"

crypto::rijndael::RijndaelCipher::RijndaelCipher(size_t block_size, size_t key_size, uint8_t mod) : _block_size(
    block_size) {
    if (block_size != 16 && block_size != 24 && block_size != 32) {
        throw std::invalid_argument("Invalid block size");
    }
    if (key_size != 16 && key_size != 24 && key_size != 32) {
        throw std::invalid_argument("Invalid key size");
    }
    auto s_box = generate_s_box(mod);
    auto inv_s_box = generate_inv_s_box(mod);
    _enc_transform = std::make_unique<RijndaelEncTransform>(s_box, mod, key_size);
    _dec_transform = std::make_unique<RijndaelDecTransform>(inv_s_box, mod, key_size);
    _key_expansion = std::make_unique<RijndaelKeyExpansion>(s_box, mod, block_size);
}

std::vector<uint8_t> crypto::rijndael::RijndaelCipher::encrypt(std::span<const uint8_t> block) const {
    return _enc_transform->transform(block, _keys);
}

std::vector<uint8_t> crypto::rijndael::RijndaelCipher::decrypt(std::span<const uint8_t> block) const {
    return _dec_transform->transform(block, _keys);
}

void crypto::rijndael::RijndaelCipher::set_round_keys(std::span<const uint8_t> encryption_key) {
    _keys.clear();
    auto words = _key_expansion->generate_round_keys(encryption_key);
    for (const auto &word: words) {
        for (auto byte: word) {
            _keys.push_back(byte);
        }
    }
}

size_t crypto::rijndael::RijndaelCipher::get_block_size() const {
    return _block_size;
}

std::vector<uint8_t> crypto::rijndael::RijndaelCipher::generate_s_box(uint8_t mod) {
    std::vector<uint8_t> s_box(256, 0);
    uint8_t byte = 0;
    do {
        uint8_t inv = byte == 0 ? 0 : gf::inverse(byte, mod);
        s_box[byte] = inv ^ shift_left(inv, 1) ^
                      shift_left(inv, 2) ^
                      shift_left(inv, 3) ^
                      shift_left(inv, 4) ^
                      0x63;
    } while (byte++ != 255);
    return s_box;
}

std::vector<uint8_t> crypto::rijndael::RijndaelCipher::generate_inv_s_box(uint8_t mod) {
    std::vector<uint8_t> inv_s_box(256, 0);
    uint8_t byte = 0;
    do {
        uint8_t res = (shift_left(byte, 1) ^
                       shift_left(byte, 3) ^
                       shift_left(byte, 6) ^
                       0x05);
        inv_s_box[byte] = res == 0 ? 0 : gf::inverse(res, mod);
    } while (byte++ != 255);
    return inv_s_box;
}

uint8_t crypto::rijndael::RijndaelCipher::shift_left(uint8_t &num, uint8_t shift) noexcept {
    return ((num >> (8 - shift)) | (num << shift));
}
