#include "deal.h"

static const uint8_t expansion_key[] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF};

std::vector<uint8_t> crypto::deal::DESAdapter::transform(std::span<const uint8_t> input_block,
                                                         std::span<const uint8_t> round_key) const {
    des::DESCipher des;
    des.set_round_keys(round_key);
    return des.encrypt(input_block);
}

std::vector<std::vector<uint8_t> > crypto::deal::DEALKeyExpansion::generate_round_keys(
    std::span<const uint8_t> input_key) {
    if (input_key.size() != 16 && input_key.size() != 24 && input_key.size() != 32)
        throw std::invalid_argument("invalid key size");

    size_t rounds = input_key.size() == 16 ? 6 : 8;
    des::DESCipher des;
    des.set_round_keys(expansion_key);
    std::vector<std::vector<uint8_t> > res;
    res.reserve(rounds);
    std::vector<uint8_t> prev(8, 0);
    if (input_key.size() == 16) {
        for (size_t i = 0; i < rounds; ++i) {
            for (size_t j = 0; j < 8; ++j) {
                prev[j] ^= input_key[(i * 8 + j) % input_key.size()];
            }
            prev = des.encrypt(prev);
            res.push_back(prev);
        }
    }
    else if (input_key.size() == 24) {
        for (size_t i = 0; i < rounds; ++i) {
            for (size_t j = 0; j < 8; ++j) {
                prev[j] ^= input_key[(i * 8 + j) % ((i < rounds - 1) ? 16 : 24)];
            }
            prev = des.encrypt(prev);
            res.push_back(prev);
        }
    }
    else {
        for (size_t i = 0; i < rounds; ++i) {
            for (size_t j = 0; j < 8; ++j) {
                prev[j] ^= input_key[(i * 8 + j) % input_key.size()];
            }
            prev = des.encrypt(prev);
            res.push_back(prev);
        }
    }
    return res;
}

void crypto::deal::DEALCipher::set_round_keys(std::span<const uint8_t> encryption_key) {
    set_rounds_count(encryption_key.size() == 16 ? 6 : 8);
    FeistelNetwork::set_round_keys(encryption_key);
}

size_t crypto::deal::DEALCipher::get_block_size() const { return 16; }
