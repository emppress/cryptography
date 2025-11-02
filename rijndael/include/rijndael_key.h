#ifndef RIJNDAEL_KEY_H
#define RIJNDAEL_KEY_H

#include "interfaces.h"

namespace crypto::rijndael {
    class RijndaelKeyExpansion : public IKeyExpansion {
        const size_t _block_size;
        const std::vector<uint8_t> _s_box;
        size_t _mod;

    public:
        RijndaelKeyExpansion(std::span<const uint8_t> s_box, uint8_t mod, size_t block_size) : _block_size(block_size),
            _s_box(s_box.begin(), s_box.end()), _mod(mod) {};

        std::vector<std::vector<uint8_t> > generate_round_keys(std::span<const uint8_t> input_key) override;

    private:
        [[nodiscard]] size_t find_rounds_count(size_t key_size) const;

        void sub_word(std::vector<uint8_t> &word) const;

        static void rot_word(std::vector<uint8_t> &word) noexcept;
    };
}


#endif //RIJNDAEL_KEY_H
