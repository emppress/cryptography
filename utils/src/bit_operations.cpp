#include "bit_operations.h"

namespace crypto::bits {
    std::vector<uint8_t> permute_bits(std::span<const uint8_t> data, std::span<const uint16_t> p_block,
                                      BitIndexing bit_indexing, StartBit start_bit) {
        const size_t result_bytes = (p_block.size() + 7) / 8;
        std::vector<uint8_t> result(result_bytes, 0);

        for (size_t i = 0; i < p_block.size(); ++i) {
            uint16_t source_bit_pos = p_block[i];

            if (start_bit == StartBit::ONE) {
                source_bit_pos -= 1;
            }
            const uint16_t source_byte_idx = source_bit_pos / 8;
            const uint16_t source_bit_idx = source_bit_pos % 8;
            const uint16_t result_byte_idx = i / 8;
            const uint16_t result_bit_idx = i % 8;

            if (bit_indexing == BitIndexing::LSB_FIRST) {
                bool bit_value = (data[source_byte_idx] >> source_bit_idx) & 1;
                if (bit_value) result[result_byte_idx] |= (1 << result_bit_idx);
            }
            else {
                bool bit_value = (data[source_byte_idx] >> (7 - source_bit_idx)) & 1;
                if (bit_value) {
                    result[result_byte_idx] |= (1 << (7 - result_bit_idx));
                }
            }
        }

        return result;
    }

    void shift_left(uint32_t &num, uint8_t shift) noexcept {
        num = ((num >> (32 - shift)) | (num << shift)) & ((1 << 28) - 1);
    }
}
