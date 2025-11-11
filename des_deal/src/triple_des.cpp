#include "triple_des.h"

std::vector<uint8_t> crypto::triple_des::TripleDESCipher::encrypt(std::span<const uint8_t> block) const {
    auto res = _des_cyphers[0].encrypt(block);
    res = _des_cyphers[1].decrypt(res);
    return _des_cyphers[2].encrypt(res);
}

std::vector<uint8_t> crypto::triple_des::TripleDESCipher::decrypt(std::span<const uint8_t> block) const {
    auto res = _des_cyphers[2].decrypt(block);
    res = _des_cyphers[1].encrypt(res);
    return _des_cyphers[0].decrypt(res);
}

void crypto::triple_des::TripleDESCipher::set_round_keys(std::span<const uint8_t> encryption_key) {
    auto key_size = encryption_key.size();
    if (key_size != 8 && key_size != 16 && key_size != 24)
        throw std::invalid_argument("Wrong encryption key size");

    _des_cyphers[0].set_round_keys(encryption_key.subspan(0, 8));
    _des_cyphers[1].set_round_keys(encryption_key.subspan(key_size > 8 ? 8 : 0, 8));
    _des_cyphers[2].set_round_keys(encryption_key.subspan(key_size == 24 ? 16 : 0, 8));
}

size_t crypto::triple_des::TripleDESCipher::get_block_size() const { return 8; }
