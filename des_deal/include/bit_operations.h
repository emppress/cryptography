#ifndef BIT_OPERATIONS_H
#define BIT_OPERATIONS_H

#include <vector>
#include <cstdint>
#include <span>

namespace crypto::bits {
    enum class BitIndexing {
        LSB_FIRST, // младший бит первый, индекс 0
        MSB_FIRST // старший бит первый, индекс 0
    };

    enum class StartBit {
        ZERO, // начальный бит = 0
        ONE // начальный бит = 1
    };

    std::vector<uint8_t> permute_bits(
        std::span<const uint8_t> data,
        std::span<const uint16_t> p_block,
        BitIndexing bit_indexing,
        StartBit start_bit
    );

    bool get_bit(uint8_t byte, size_t position, BitIndexing indexing);

    void set_bit(uint8_t &byte, size_t position, bool value, BitIndexing indexing);

    void shift_left(uint32_t &num, uint8_t shift) noexcept;
} // crypto::bits

#endif //BIT_OPERATIONS_H
