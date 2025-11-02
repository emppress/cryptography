#ifndef RIJNDAEL_TRANSFORM_H
#define RIJNDAEL_TRANSFORM_H
#include "interfaces.h"

namespace crypto::rijndael {
    class RijndaelBaseTransform : public IEncryptionTransform {
    protected:
        const uint8_t _mod;
        const size_t _key_size;
        const std::vector<uint8_t> _s_box;

        RijndaelBaseTransform(std::span<const uint8_t> s_box, uint8_t mod, size_t key_size) : _mod(mod),
            _key_size(key_size), _s_box(s_box.begin(), s_box.end()) {};

        static void add_round_key(std::vector<uint8_t> &state, std::span<const uint8_t> key);

        void sub_bytes(std::vector<uint8_t> &state) const;

        [[nodiscard]] size_t validate_sizes(size_t block_size, size_t keys_size) const;
    };

    class RijndaelEncTransform : public RijndaelBaseTransform {
        static constexpr uint8_t _a_matrix[8][8] = {
            {2, 3, 1, 1},
            {1, 2, 3, 1},
            {1, 1, 2, 3},
            {3, 1, 1, 2}
        };

    public:
        RijndaelEncTransform(std::span<const uint8_t> s_box, uint8_t mod, size_t key_size) : RijndaelBaseTransform(
            s_box, mod, key_size) {};

        std::vector<uint8_t> transform(std::span<const uint8_t> input_block,
                                       std::span<const uint8_t> round_key) const override;

    private:
        static void shift_rows(std::vector<uint8_t> &state);

        void mix_columns(std::vector<uint8_t> &state) const;
    };

    class RijndaelDecTransform : public RijndaelBaseTransform {
        static constexpr uint8_t _inv_a_matrix[8][8] = {
            {0x0E, 0x0B, 0x0D, 0x09},
            {0x09, 0x0E, 0x0B, 0x0D},
            {0x0D, 0x09, 0x0E, 0x0B},
            {0x0B, 0x0D, 0x09, 0x0E}
        };

    public:
        RijndaelDecTransform(std::span<const uint8_t> s_box, uint8_t mod, size_t key_size) : RijndaelBaseTransform(
            s_box, mod, key_size) {};

        std::vector<uint8_t> transform(std::span<const uint8_t> input_block,
                                       std::span<const uint8_t> round_key) const override;

    private:
        static void inv_shift_rows(std::vector<uint8_t> &state);

        void inv_mix_columns(std::vector<uint8_t> &state) const;
    };
};

#endif //RIJNDAEL_TRANSFORM_H
