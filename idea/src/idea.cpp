#include "idea.h"

#include <stdexcept>
#include <tuple>


std::vector<uint8_t> crypto::IDEACipher::encryption_transform(std::span<const uint8_t> block, bool enc) const {
    if (block.size() != 8)
        throw std::invalid_argument("Invalid block size");
    if (!_key_is_set)
        throw std::invalid_argument("Keys is not set");

    auto keys = (enc ? _enc_keys : _dec_keys).cbegin();
    uint16_t x1 = (block[0] << 8) | block[1];
    uint16_t x2 = (block[2] << 8) | block[3];
    uint16_t x3 = (block[4] << 8) | block[5];
    uint16_t x4 = (block[6] << 8) | block[7];
    for (auto i = 0; i < 8; ++i) {
        x1 = mult(x1, keys[0]);
        x2 = x2 + keys[1];
        x3 = x3 + keys[2];
        x4 = mult(x4, keys[3]);

        uint16_t p = x1 ^ x3;
        uint16_t q = x2 ^ x4;
        uint16_t t0 = mult(p, keys[4]);
        uint16_t t1 = mult(t0 + q, keys[5]);
        uint16_t t2 = t0 + t1;
        x1 = x1 ^ t1;
        std::tie(x2, x3) = std::tuple(x3 ^ t1, x2 ^ t2);
        x4 = x4 ^ t2;
        keys += 6;
    }
    x1 = mult(x1, keys[0]);
    std::tie(x2, x3) = std::tuple(x3 + keys[1], x2 + keys[2]);
    x4 = mult(x4, keys[3]);
    return {
        static_cast<uint8_t>((x1 >> 8) & 0xFF), static_cast<uint8_t>(x1 & 0xFF),
        static_cast<uint8_t>((x2 >> 8) & 0xFF), static_cast<uint8_t>(x2 & 0xFF),
        static_cast<uint8_t>((x3 >> 8) & 0xFF), static_cast<uint8_t>(x3 & 0xFF),
        static_cast<uint8_t>((x4 >> 8) & 0xFF), static_cast<uint8_t>(x4 & 0xFF)
    };
}

std::vector<uint8_t> crypto::IDEACipher::encrypt(std::span<const uint8_t> block) const {
    return encryption_transform(block, true);
}

std::vector<uint8_t> crypto::IDEACipher::decrypt(std::span<const uint8_t> block) const {
    return encryption_transform(block, false);
}

void crypto::IDEACipher::set_round_keys(std::span<const uint8_t> encryption_key) {
    if (encryption_key.size() != 16)
        throw std::invalid_argument("Invalid key size");

    _key_is_set = true;

    for (size_t i = 0; i < 8; ++i) {
        _enc_keys[i] = (encryption_key[2 * i] << 8) | encryption_key[2 * i + 1];
    }

    auto from = _enc_keys.begin();
    auto to = from + 8;
    for (size_t i = 0; i < 6; ++i) {
        to[0] = ((from[1] << 9) | (from[2] >> 7)) & 0xFFFF;
        to[1] = ((from[2] << 9) | (from[3] >> 7)) & 0xFFFF;
        to[2] = ((from[3] << 9) | (from[4] >> 7)) & 0xFFFF;
        to[3] = ((from[4] << 9) | (from[5] >> 7)) & 0xFFFF;
        if (i == 5) break;
        to[4] = ((from[5] << 9) | (from[6] >> 7)) & 0xFFFF;
        to[5] = ((from[6] << 9) | (from[7] >> 7)) & 0xFFFF;
        to[6] = ((from[7] << 9) | (from[0] >> 7)) & 0xFFFF;
        to[7] = ((from[0] << 9) | (from[1] >> 7)) & 0xFFFF;

        to += 8;
        from += 8;
    }

    _dec_keys[0] = inverse(_enc_keys[48]);
    _dec_keys[1] = (0x10000 - _enc_keys[49]) & 0xFFFF;
    _dec_keys[2] = (0x10000 - _enc_keys[50]) & 0xFFFF;
    _dec_keys[3] = inverse(_enc_keys[51]);
    _dec_keys[4] = _enc_keys[46];
    _dec_keys[5] = _enc_keys[47];

    from = _enc_keys.end() - 10;
    to = _dec_keys.begin() + 6;
    for (size_t i = 0; i < 7; ++i) {
        to[0] = inverse(from[0]);
        to[1] = (0x10000 - from[2]) & 0xFFFF;
        to[2] = (0x10000 - from[1]) & 0xFFFF;
        to[3] = inverse(from[3]);
        from -= 6;
        to[4] = from[4];
        to[5] = from[5];
        to += 6;
    }
    to[0] = inverse(from[0]);
    to[1] = (0x10000 - from[1]) & 0xFFFF;
    to[2] = (0x10000 - from[2]) & 0xFFFF;
    to[3] = inverse(from[3]);
}

size_t crypto::IDEACipher::get_block_size() const { return 8; }

uint16_t crypto::IDEACipher::mult(uint16_t a, uint16_t b) noexcept {
    if (a == 0)
        return 0x10001 - b;
    if (b == 0)
        return 0x10001 - a;
    const uint32_t c = a * b;
    uint32_t res = (c & 0xFFFF) - (c >> 16);
    if (res >> 16) {
        res += 0x10001;
    }
    return res;
}

uint16_t crypto::IDEACipher::inverse(uint16_t num) noexcept {
    if (num <= 1) return num;

    uint32_t t0 = 0, t1 = 1;
    uint32_t a = 0x10001;
    uint16_t b = num;
    while (b != 1) {
        uint16_t q = a / b;
        uint32_t tmp = a - b * q;
        a = b;
        b = tmp;
        tmp = t1;
        t1 = t0 - q * t1;
        t0 = tmp;
    }
    return (t1 >> 16 ? t1 + 0x10001 : t1) & 0xFFFF;
}
