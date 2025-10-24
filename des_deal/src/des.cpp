#include "des.h"
#include "bit_operations.h"

namespace crypto::des {
    const static uint16_t PC1[] = {
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    };

    const static uint16_t PC2[] = {
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    };

    const static uint16_t E[] = {
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    };

    const static uint8_t SHIFTS[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

    const static uint8_t S[8][4][16] = {
        {
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
            {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
            {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
            {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
        },
        {
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
            {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        },
        {
            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
            {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
            {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
        },
        {
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
            {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
            {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
            {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
        },
        {
            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
            {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
            {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
            {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
        },
        {
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
            {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
            {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
        },
        {
            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
            {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
            {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
        },
        {
            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
            {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
            {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
            {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
        }
    };

    const static uint16_t P[] = {
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    };

    const static uint16_t IP[] = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };

    const static uint16_t IP_INVERSE[] = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    };

    std::vector<std::vector<uint8_t> > DESKeyExpansion::generate_round_keys(std::span<const uint8_t> input_key) {
        if (input_key.size() != 8) {
            throw std::invalid_argument("input key must be 8 bytes");
        }
        std::vector<std::vector<uint8_t> > round_keys;
        round_keys.reserve(16);
        const auto permuted_vec = bits::permute_bits(input_key, PC1, bits::BitIndexing::MSB_FIRST, bits::StartBit::ONE);
        uint64_t permuted = 0;
        for (int i = 0; i < 7; i++) {
            permuted <<= 8;
            permuted |= permuted_vec[i];
        }
        uint32_t left = permuted >> 28;
        uint32_t right = permuted & ((1 << 28) - 1);
        for (int i = 0; i < 16; ++i) {
            bits::shift_left(left, SHIFTS[i]);
            bits::shift_left(right, SHIFTS[i]);
            uint64_t joined = (static_cast<uint64_t>(left) << 28) | right;
            std::vector<uint8_t> joined_vec(7, 0);
            for (int j = 6; j >= 0; j--) {
                joined_vec[j] = joined & 0xFF;
                joined >>= 8;
            }
            round_keys.push_back(bits::permute_bits(joined_vec, PC2, bits::BitIndexing::MSB_FIRST,
                                                    bits::StartBit::ONE));
        }
        return round_keys;
    }


    std::vector<uint8_t> DESEncryptionTransform::transform(std::span<const uint8_t> input_block,
                                                           std::span<const uint8_t> round_key) const {
        if (input_block.size() != 4)
            throw std::invalid_argument("input block must be 4 bytes");
        if (round_key.size() != 6)
            throw std::invalid_argument("round_key must be 6 bytes");

        const auto extended = bits::permute_bits(
            input_block, E, bits::BitIndexing::MSB_FIRST, bits::StartBit::ONE);
        std::vector<uint8_t> xor_bytes(extended.size());
        for (auto i = 0; i < extended.size(); ++i) {
            xor_bytes[i] = extended[i] ^ round_key[i];
        }

        std::vector<bool> bits;
        for (uint8_t byte: xor_bytes) {
            for (int i = 7; i >= 0; --i) {
                bits.push_back((byte >> i) & 1u);
            }
        }

        std::vector<uint8_t> s_box_bits;
        for (auto i = 0; i < 8; ++i) {
            uint8_t six_bits = 0;
            for (int j = 0; j < 6; ++j) {
                six_bits = (six_bits << 1) | (bits[i * 6 + j] ? 1u : 0u);
            }
            uint8_t row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
            uint8_t col = (six_bits >> 1) & 0x0F;
            uint8_t s_value = S[i][row][col];
            for (int j = 3; j >= 0; --j) {
                s_box_bits.push_back((s_value >> j) & 1u);
            }
        }
        std::vector<uint8_t> s_box_output(4, 0);
        for (size_t i = 0; i < s_box_bits.size(); ++i) {
            if (s_box_bits[i]) {
                s_box_output[i / 8] |= 1u << (7 - (i % 8));
            }
        }
        return bits::permute_bits(s_box_output, P, bits::BitIndexing::MSB_FIRST, bits::StartBit::ONE);
    }

    std::vector<uint8_t> DESCipher::encrypt(std::span<const uint8_t> block) const {
        if (block.size() != 8) {
            throw std::invalid_argument("input block must be 8 bytes");
        }
        auto permuted = bits::permute_bits(block, IP, bits::BitIndexing::MSB_FIRST, bits::StartBit::ONE);
        permuted = FeistelNetwork::encrypt(permuted);
        return bits::permute_bits(permuted, IP_INVERSE, bits::BitIndexing::MSB_FIRST, bits::StartBit::ONE);
    }

    std::vector<uint8_t> DESCipher::decrypt(std::span<const uint8_t> block) const {
        if (block.size() != 8) {
            throw std::invalid_argument("input block must be 8 bytes");
        }
        auto permuted = bits::permute_bits(block, IP, bits::BitIndexing::MSB_FIRST, bits::StartBit::ONE);
        permuted = FeistelNetwork::decrypt(permuted);
        return bits::permute_bits(permuted, IP_INVERSE, bits::BitIndexing::MSB_FIRST, bits::StartBit::ONE);
    }

    size_t DESCipher::get_block_size() const { return 8; }
}
