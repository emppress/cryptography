#ifndef TRIPLE_DES_H
#define TRIPLE_DES_H

#include "des.h"
#include "feistel_network.h"
#include "interfaces.h"

namespace crypto::triple_des {
    class TripleDESCipher : public ISymmetricAlgorithm {
        std::array<des::DESCipher, 3> _des_cyphers;

    public:
        TripleDESCipher() = default;

        std::vector<uint8_t> encrypt(std::span<const uint8_t> block) const override;

        std::vector<uint8_t> decrypt(std::span<const uint8_t> block) const override;

        void set_round_keys(std::span<const uint8_t> encryption_key) override;

        size_t get_block_size() const override;
    };
}


#endif //TRIPLE_DES_H
