#include "rc4.h"

#include <stdexcept>
#include <fstream>
#include <iostream>


void crypto::RC4::Gen::reset(std::span<const uint8_t> key) {
    if (!key.size())
        throw std::invalid_argument("Key is empty");
    uint8_t i{}, j{};
    do { _s_box[i] = i; } while (i++ < 255);
    i = 0;
    do {
        j += _s_box[i] + key[i % key.size()];
        std::swap(_s_box[i], _s_box[j]);
    } while (i++ < 255);
    _i = _j = 0;
}

uint8_t crypto::RC4::Gen::operator()() noexcept {
    ++_i;
    _j += _s_box[_i];
    std::swap(_s_box[_i], _s_box[_j]);
    return _s_box[static_cast<uint8_t>(_s_box[_i] + _s_box[_j])];
}

void crypto::RC4::set_key(std::span<const uint8_t> key) {
    if (key.size() == 0 || key.size() > 256)
        throw std::invalid_argument("Invalid key size");

    _key = std::vector(key.begin(), key.end());
}

std::vector<uint8_t> crypto::RC4::encrypt(std::span<const uint8_t> input_data) {
    std::vector<uint8_t> res;
    res.reserve(input_data.size());
    _gen.reset(_key);
    for (auto byte: input_data) {
        res.push_back(byte ^ _gen());
    }
    return res;
}

std::vector<uint8_t> crypto::RC4::decrypt(std::span<const uint8_t> input_data) {
    return encrypt(input_data);
}

std::future<std::filesystem::path> crypto::RC4::encrypt_async(const std::filesystem::path &input_file,
                                                              const std::filesystem::path &output_file) {
    auto out_file = output_file;
    if (output_file.empty()) {
        out_file = input_file;
        out_file.replace_extension(".encrypted");
    }
    Gen new_gen{};
    new_gen.reset(_key);
    auto task = [input_file, output_file = std::move(out_file), gen = std::move(new_gen)]() mutable {
        std::ifstream in(input_file, std::ios::binary);
        std::ofstream out(output_file, std::ios::binary);
        if (!in.is_open())
            throw std::invalid_argument("failed to open input file");
        if (!out.is_open())
            throw std::invalid_argument("failed to open output file");

        std::istreambuf_iterator in_it(in);
        std::istreambuf_iterator<char> end_it;
        std::ostreambuf_iterator out_it(out);
        while (in_it != end_it) {
            *out_it = *in_it ^ gen();
            ++in_it, ++out_it;
        }
        return output_file;
    };
    return std::async(std::move(task));
}

std::future<std::filesystem::path> crypto::RC4::decrypt_async(const std::filesystem::path &input_file,
                                                              const std::filesystem::path &output_file) {
    auto out_file = output_file;
    if (output_file.empty()) {
        out_file = input_file;
        out_file.replace_extension(".decrypted");
    }
    return encrypt_async(input_file, out_file);
}

