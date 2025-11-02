#include "rijndael_key.h"
#include "GF_math.h"

#include <stdexcept>

void crypto::rijndael::RijndaelKeyExpansion::sub_word(std::vector<uint8_t> &word) const {
    for (auto &byte: word) {
        byte = _s_box[byte];
    }
}

void crypto::rijndael::RijndaelKeyExpansion::rot_word(std::vector<uint8_t> &word) noexcept {
    auto first = word[0];
    for (auto i = 0; i < 3; ++i) {
        word[i] = word[i + 1];
    }
    word[3] = first;
}

std::vector<std::vector<uint8_t> > crypto::rijndael::RijndaelKeyExpansion::generate_round_keys(
    std::span<const uint8_t> input_key) {
    const auto key_size = input_key.size();
    const auto nr = find_rounds_count(key_size);
    const auto nb = _block_size / 4;
    const auto nk = key_size / 4;
    const auto words_count = nb * (nr + 1);
    std::vector<std::vector<uint8_t> > round_keys;
    round_keys.reserve(words_count);
    auto it = input_key.begin();
    while (it != input_key.end()) {
        round_keys.emplace_back(it, it + 4);
        it += 4;
    }
    uint8_t rcon = 1;
    for (auto i = nk; i < words_count; ++i) {
        std::vector temp{round_keys[i - 1]};
        if (i % nk == 0) {
            rot_word(temp);
            sub_word(temp);
            temp[0] ^= rcon;
            rcon = gf::multiply(rcon, 0x02, _mod);
        }
        else if (nk > 6 && i % nk == 4) {
            sub_word(temp);
        }
        for (auto j = 0; j < 4; ++j) {
            temp[j] ^= round_keys[i - nk][j];
        }
        round_keys.emplace_back(std::move(temp));
    }
    return round_keys;
}

size_t crypto::rijndael::RijndaelKeyExpansion::find_rounds_count(size_t key_size) const {
    size_t num_rounds{};
    switch (key_size) {
        case 16:
            switch (_block_size) {
                case 16: num_rounds = 10;
                    break;
                case 24: num_rounds = 12;
                    break;
                case 32: num_rounds = 14;
                    break;
            }
            break;
        case 24:
            switch (_block_size) {
                case 16:
                case 24: num_rounds = 12;
                    break;
                case 32: num_rounds = 14;
                    break;
            }
            break;
        case 32:
            switch (_block_size) {
                case 16:
                case 24:
                case 32: num_rounds = 14;
                    break;
            }
            break;;
        default:
            throw std::invalid_argument("Invalid key size");
    }
    return num_rounds;
}
