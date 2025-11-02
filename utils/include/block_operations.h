#ifndef BLOCK_OPERATIONS_H
#define BLOCK_OPERATIONS_H

#include <vector>
#include <cstdint>
#include <span>
#include "cipher_modes.h"

namespace crypto::block {
    /**
     * Добавляет набивку к данным согласно выбранному режиму
     */
    std::vector<uint8_t> pad_data(
        std::span<const uint8_t> data,
        mode::PaddingMode mode,
        size_t block_size
    );

    /**
     * Удаляет набивку из данных согласно выбранному режиму
     */
    std::vector<uint8_t> unpad_data(
        std::span<const uint8_t> data,
        mode::PaddingMode mode
    );

    /**
     * Разбивает данные на блоки фиксированного размера
     */
    std::vector<std::vector<uint8_t> > split_blocks(
        std::span<const uint8_t> data,
        size_t block_size);

    /**
     * Объединяет блоки в единый массив данных
     */
    std::vector<uint8_t> join_blocks(std::span<const std::vector<uint8_t>> blocks);

    /**
     * Генерируeт случайные байты
     */
    std::vector<uint8_t> random_bytes(size_t length);
}

#endif //BLOCK_OPERATIONS_H
