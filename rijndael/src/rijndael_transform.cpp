#include "rijndael_transform.h"
#include "GF_math.h"
#include <algorithm>

void crypto::rijndael::RijndaelBaseTransform::add_round_key(std::vector<uint8_t> &state,
                                                            std::span<const uint8_t> key) {
    for (size_t i = 0; i < state.size(); ++i) {
        state[i] ^= key[i];
    }
}

void crypto::rijndael::RijndaelBaseTransform::sub_bytes(std::vector<uint8_t> &state) const {
    for (auto &byte: state) {
        byte = _s_box[byte];
    }
}

size_t crypto::rijndael::RijndaelBaseTransform::validate_sizes(size_t block_size,
                                                               size_t keys_size) const {
    size_t num_rounds{};
    switch (block_size) {
        case 16:
            switch (_key_size) {
                case 16: num_rounds = 10;
                    break;
                case 24: num_rounds = 12;
                    break;
                case 32: num_rounds = 14;
                    break;
            }
            break;
        case 24:
            switch (_key_size) {
                case 16:
                case 24: num_rounds = 12;
                    break;
                case 32: num_rounds = 14;
                    break;
            }
            break;
        case 32:
            switch (_key_size) {
                case 16:
                case 24:
                case 32: num_rounds = 14;
                    break;
            }
            break;
        default: throw std::invalid_argument("Invalid block size");
    }
    if (keys_size != block_size * (num_rounds + 1))
        throw std::invalid_argument("Invalid round_key size");
    return num_rounds;
}

std::vector<uint8_t> crypto::rijndael::RijndaelEncTransform::transform(std::span<const uint8_t> input_block,
                                                                       std::span<const uint8_t> round_key) const {
    const size_t block_size = input_block.size();
    size_t num_rounds = validate_sizes(block_size, round_key.size());
    std::vector state(input_block.begin(), input_block.end());
    add_round_key(state, round_key.subspan(0, block_size));
    size_t last_idx = num_rounds * block_size;
    for (auto offset = block_size; offset < last_idx; offset += block_size) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_key.subspan(offset, block_size));
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_key.subspan(last_idx, block_size));
    return state;
}

void crypto::rijndael::RijndaelEncTransform::shift_rows(std::vector<uint8_t> &state) {
    const auto nb = state.size() / 4;
    std::array<uint8_t, 8> col{};
    // str 1
    const auto first = state[1];
    for (size_t i = 1; i + 4 < state.size(); i += 4) {
        state[i] = state[i + 4];
    }
    state[state.size() - 3] = first;
    // str 2
    auto shift = nb == 8 ? 3 : 2;
    for (size_t i = 0; i < nb; ++i) {
        col[i] = state[i * 4 + 2];
    }
    for (size_t i = 0; i < nb; ++i) {
        state[i * 4 + 2] = col[(i + shift) % nb];
    }
    // str 3
    shift = nb == 8 ? 4 : 3;
    for (size_t i = 0; i < nb; ++i) {
        col[i] = state[i * 4 + 3];
    }
    for (size_t i = 0; i < nb; ++i) {
        state[i * 4 + 3] = col[(i + shift) % nb];
    }
}

void crypto::rijndael::RijndaelEncTransform::mix_columns(std::vector<uint8_t> &state) const {
    for (auto it = state.begin(); it != state.end(); it += 4) {
        std::array<uint8_t, 4> res{};
        for (auto i = 0; i < 4; ++i) {
            for (auto j = 0; j < 4; ++j) {
                res[i] = gf::add(res[i], gf::multiply(_a_matrix[i][j], it[j], _mod));
            }
        }
        std::ranges::copy(res.begin(), res.end(), it);
    }
}

std::vector<uint8_t> crypto::rijndael::RijndaelDecTransform::transform(std::span<const uint8_t> input_block,
                                                                       std::span<const uint8_t> round_key) const {
    const size_t block_size = input_block.size();
    size_t num_rounds = validate_sizes(block_size, round_key.size());
    std::vector state(input_block.begin(), input_block.end());
    size_t last_idx = num_rounds * block_size;
    add_round_key(state, round_key.subspan(last_idx, block_size));
    for (auto offset = last_idx - block_size; offset > 0; offset -= block_size) {
        inv_shift_rows(state);
        sub_bytes(state);
        add_round_key(state, round_key.subspan(offset, block_size));
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    sub_bytes(state);
    add_round_key(state, round_key.subspan(0, block_size));
    return state;
}

void crypto::rijndael::RijndaelDecTransform::inv_shift_rows(std::vector<uint8_t> &state) {
    const auto nb = state.size() / 4;
    std::array<uint8_t, 8> col{};
    // str 1
    const auto last = state[state.size() - 3];
    for (size_t i = state.size() - 3; i >= 4; i -= 4) {
        state[i] = state[i - 4];
    }
    state[1] = last;
    // str 2
    auto shift = nb == 8 ? 3 : 2;
    for (size_t i = 0; i < nb; ++i) {
        col[i] = state[i * 4 + 2];
    }
    for (size_t i = 0; i < nb; ++i) {
        state[i * 4 + 2] = col[(i + nb - shift) % nb];
    }
    // str 3
    shift = nb == 8 ? 4 : 3;
    for (size_t i = 0; i < nb; ++i) {
        col[i] = state[i * 4 + 3];
    }
    for (size_t i = 0; i < nb; ++i) {
        state[i * 4 + 3] = col[(i + nb - shift) % nb];
    }
}

void crypto::rijndael::RijndaelDecTransform::inv_mix_columns(std::vector<uint8_t> &state) const {
    for (auto it = state.begin(); it != state.end(); it += 4) {
        std::array<uint8_t, 4> res{};
        for (auto i = 0; i < 4; ++i) {
            for (auto j = 0; j < 4; ++j) {
                res[i] = gf::add(res[i], gf::multiply(_inv_a_matrix[i][j], it[j], _mod));
            }
        }
        std::ranges::copy(res.begin(), res.end(), it);
    }
}
