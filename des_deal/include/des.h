#ifndef DES_H
#define DES_H

#include "feistel_network.h"
#include "interfaces.h"

namespace crypto::des {
    class DESKeyExpansion final : public IKeyExpansion {
    public:
        std::vector<std::vector<uint8_t> > generate_round_keys(std::span<const uint8_t> input_key) override;
    };

    class DESEncryptionTransform final : public IEncryptionTransform {
    public:
        std::vector<uint8_t> transform(std::span<const uint8_t> input_block,
                                       std::span<const uint8_t> round_key) const override;
    };

    class DESCipher : public FeistelNetwork {
    public:
        DESCipher() : FeistelNetwork(std::make_unique<DESKeyExpansion>(),
                                     std::make_unique<DESEncryptionTransform>(),
                                     16) {}

        std::vector<uint8_t> encrypt(std::span<const uint8_t> block) const override;

        std::vector<uint8_t> decrypt(std::span<const uint8_t> block) const override;

        [[nodiscard]] size_t get_block_size() const override;
    };
}

#endif //DES_H
