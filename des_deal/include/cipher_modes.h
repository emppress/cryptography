#ifndef CIPHER_MODES_H
#define CIPHER_MODES_H

namespace crypto::mode{
enum class CipherMode {
    ECB,
    CBC,
    PCBC,
    CFB,
    OFB,
    CTR,
    RandomDelta
};

enum class PaddingMode {
    Zeros,
    ANSI_X923,
    PKCS7,
    ISO_10126
};
} //crypto::mode
#endif //CIPHER_MODES_H
