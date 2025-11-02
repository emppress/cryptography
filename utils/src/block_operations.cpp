#include "block_operations.h"
#include <stdexcept>
#include <algorithm>
#include <iostream>
#include <ostream>
#include <random>

namespace crypto::block {
    std::vector<uint8_t> pad_data(
        std::span<const uint8_t> data,
        mode::PaddingMode mode,
        size_t block_size
    ) {
        if (block_size == 0) {
            throw std::invalid_argument("Invalid block size");
        }

        const size_t pad_len = block_size - (data.size() % block_size);
        const size_t total_length = data.size() + pad_len;

        std::vector result(data.begin(), data.end());
        result.resize(total_length, 0);

        switch (mode) {
            case mode::PaddingMode::Zeros:
                break;

            case mode::PaddingMode::ANSI_X923:
                // Все байты кроме последнего = 0, последний = длина
                for (size_t i = data.size(); i < total_length - 1; ++i) {
                    result[i] = 0;
                }
                result[total_length - 1] = static_cast<uint8_t>(pad_len);
                break;

            case mode::PaddingMode::PKCS7:
                // Все байты набивки = длина
                for (size_t i = data.size(); i < total_length; ++i) {
                    result[i] = static_cast<uint8_t>(pad_len);
                }
                break;

            case mode::PaddingMode::ISO_10126:
                // Случайные байты + последний = длина
                if (pad_len > 1) {
                    auto random = random_bytes(pad_len - 1);
                    std::copy(random.begin(), random.end(),
                              result.begin() + static_cast<ptrdiff_t>(data.size()));
                }
                result[total_length - 1] = static_cast<uint8_t>(pad_len);
                break;
        }

        return result;
    }

    std::vector<uint8_t> unpad_data(
        std::span<const uint8_t> data,
        mode::PaddingMode mode
    ) {
        if (data.empty()) {
            return {};
        }
        switch (mode) {
            case mode::PaddingMode::Zeros: {
                auto it = std::find_if(data.rbegin(), data.rend(),
                                       [](uint8_t byte) { return byte != 0; });

                if (it == data.rend()) {
                    return {};
                }

                const auto end_index = std::distance(data.begin(), it.base());
                return {data.begin(), data.begin() + end_index};
            }
            case mode::PaddingMode::ANSI_X923:
            case mode::PaddingMode::PKCS7:
            case mode::PaddingMode::ISO_10126: {
                const uint8_t pad_len = data[data.size() - 1];
                if (pad_len == 0 || pad_len > data.size()) {
                    throw std::invalid_argument("Invalid padding length");
                }

                if (mode == mode::PaddingMode::PKCS7) {
                    for (size_t i = data.size() - pad_len; i < data.size(); ++i) {
                        if (data[i] != pad_len) {
                            throw std::invalid_argument("Invalid PKCS7 padding");
                        }
                    }
                }
                else if (mode == mode::PaddingMode::ANSI_X923) {
                    for (size_t i = data.size() - pad_len; i < data.size() - 1; ++i) {
                        if (data[i] != 0) {
                            throw std::invalid_argument("Invalid ANSI X.923 padding");
                        }
                    }
                }
                return {data.begin(), data.end() - pad_len};
            }
            default: {
                throw std::invalid_argument("Invalid padding mod");
            }
        }
    }

    std::vector<std::vector<uint8_t> > split_blocks(
        std::span<const uint8_t> data,
        size_t block_size
    ) {
        if (block_size == 0) {
            throw std::invalid_argument("Invalid block size");
        }
        if (data.size() % block_size != 0) {
            throw std::invalid_argument("Data length must be multiple of block size");
        }

        std::vector<std::vector<uint8_t> > blocks;
        blocks.reserve(data.size() / block_size);

        for (size_t i = 0; i < data.size(); i += block_size) {
            blocks.emplace_back(data.begin() + i, data.begin() + i + block_size);
        }

        return blocks;
    }

    std::vector<uint8_t> join_blocks(
        std::span<const std::vector<uint8_t>> blocks
    ) {
        size_t total_length = 0;
        for (const auto &block: blocks) {
            total_length += block.size();
        }

        std::vector<uint8_t> result;
        result.reserve(total_length);
        for (const auto &block: blocks) {
            result.insert(result.end(), block.begin(), block.end());
        }
        return result;
    }

    std::vector<uint8_t> random_bytes(size_t length) {
        std::vector<uint8_t> result(length);
        std::random_device rd;
        std::mt19937 mt(rd());
        std::uniform_int_distribution<uint8_t> dist(0, 255);
        for (size_t i = 0; i < length; ++i) {
            result[i] = dist(mt);
        }
        return result;
    }
}
