#ifndef IDEA_H
#define IDEA_H

#include "interfaces.h"

namespace crypto {
    class IDEACipher : public ISymmetricAlgorithm {
        std::array<uint16_t, 52> _enc_keys{};
        std::array<uint16_t, 52> _dec_keys{};
        bool _key_is_set{false};

    public:
        [[nodiscard]] std::vector<uint8_t> encrypt(std::span<const uint8_t> block) const override;

        [[nodiscard]] std::vector<uint8_t> decrypt(std::span<const uint8_t> block) const override;

        void set_round_keys(std::span<const uint8_t> encryption_key) override;

        [[nodiscard]] size_t get_block_size() const override;

    private:
        static uint16_t mult(uint16_t a, uint16_t b) noexcept;

        static uint16_t inverse(uint16_t num) noexcept;

        [[nodiscard]] std::vector<uint8_t> encryption_transform(std::span<const uint8_t> block, bool enc = true) const;
    };
}


#endif //IDEA_H
