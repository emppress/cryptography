#ifndef DEAL_H
#define DEAL_H

#include "interfaces.h"
#include "feistel_network.h"
#include "des.h"


namespace crypto::deal {
    class DESAdapter final : public IEncryptionTransform {
    public:
        std::vector<uint8_t> transform(std::span<const uint8_t> input_block,
                                       std::span<const uint8_t> round_key) const override;
    };


    class DEALKeyExpansion final : public IKeyExpansion {
    public:
        std::vector<std::vector<uint8_t> > generate_round_keys(std::span<const uint8_t> input_key) override;
    };


    class DEALCipher : public FeistelNetwork {
    public:
        DEALCipher() : FeistelNetwork(std::make_unique<DEALKeyExpansion>(),
                                      std::make_unique<DESAdapter>()) {}

        void set_round_keys(std::span<const uint8_t> encryption_key) override;

        [[nodiscard]] size_t get_block_size() const override;
    };
}


#endif //DEAL_H
