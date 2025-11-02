#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#include <memory>
#include "interfaces.h"

namespace crypto::rijndael {
    class RijndaelCipher : public ISymmetricAlgorithm {
        size_t _block_size;
        std::vector<uint8_t> _keys{};
        std::unique_ptr<IEncryptionTransform> _enc_transform;
        std::unique_ptr<IEncryptionTransform> _dec_transform;
        std::unique_ptr<IKeyExpansion> _key_expansion;

    public:
        RijndaelCipher(size_t block_size, size_t key_size, uint8_t mod);

        [[nodiscard]] std::vector<uint8_t> encrypt(std::span<const uint8_t> block) const override;

        [[nodiscard]] std::vector<uint8_t> decrypt(std::span<const uint8_t> block) const override;

        void set_round_keys(std::span<const uint8_t> encryption_key) override;

        size_t get_block_size() const override;

    private:
        [[nodiscard]] static std::vector<uint8_t> generate_s_box(uint8_t mod);

        [[nodiscard]] static std::vector<uint8_t> generate_inv_s_box(uint8_t mod);

        static uint8_t shift_left(uint8_t &num, uint8_t shift) noexcept;
    };
}


#endif //RIJNDAEL_H
