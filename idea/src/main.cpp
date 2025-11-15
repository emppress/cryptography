#include <iostream>
#include <cstdint>
#include <cstring>

#include "idea.h"


int main() {
    crypto::IDEACipher enc;
    uint8_t key[16]{0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0xff, 0xf5, 0x00, 0x06, 0x00, 0xf7, 0x09, 0x66};
    uint16_t block_[] = {2000, 1000, 5000, 9000};
    uint8_t block[8];
    memcpy(block, block_, sizeof(block_));
    enc.set_round_keys(key);
    auto res = enc.encrypt(block);
    res = enc.decrypt(res);
    memcpy(block_, res.data(), sizeof(block_));
    for (auto byte: block_) {
        std::cout << byte << std::endl;
    }
}
