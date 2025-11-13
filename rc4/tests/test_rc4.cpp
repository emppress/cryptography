#include "rc4.h"
#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include <vector>
#include <algorithm>

class RC4Test : public ::testing::Test {
protected:
    crypto::RC4 rc4;
};

TEST_F(RC4Test, BasicEncryptDecrypt) {
    std::vector<uint8_t> key = {0x12, 0x23, 0x34, 0x56};
    std::vector<uint8_t> data = {0x12, 0x23, 0x34, 0x56, 0x12, 0x23, 0x34, 0x56};

    rc4.set_key(key);
    auto encrypted = rc4.encrypt(data);
    auto decrypted = rc4.decrypt(encrypted);

    EXPECT_EQ(data, decrypted);
    EXPECT_NE(data, encrypted);
}

TEST_F(RC4Test, Symmetry) {
    std::vector<uint8_t> key = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> data = {0x41, 0x42, 0x43, 0x44, 0x45};

    rc4.set_key(key);
    auto encrypted1 = rc4.encrypt(data);
    auto encrypted2 = rc4.decrypt(data);

    EXPECT_EQ(encrypted1, encrypted2);
}

TEST_F(RC4Test, DifferentKeysProduceDifferentResults) {
    std::vector<uint8_t> data = {0x61, 0x62, 0x63, 0x64};
    std::vector<uint8_t> key1 = {0x11, 0x22, 0x33};
    std::vector<uint8_t> key2 = {0x44, 0x55, 0x66};

    rc4.set_key(key1);
    auto encrypted1 = rc4.encrypt(data);

    rc4.set_key(key2);
    auto encrypted2 = rc4.encrypt(data);

    EXPECT_NE(encrypted1, encrypted2);
}

TEST_F(RC4Test, EmptyData) {
    std::vector<uint8_t> key = {0x12, 0x34};
    std::vector<uint8_t> empty_data;

    rc4.set_key(key);
    auto encrypted = rc4.encrypt(empty_data);
    auto decrypted = rc4.decrypt(encrypted);

    EXPECT_TRUE(encrypted.empty());
    EXPECT_TRUE(decrypted.empty());
}

TEST_F(RC4Test, LongKey) {
    std::vector<uint8_t> long_key(256, 0x42);
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};

    rc4.set_key(long_key);
    auto encrypted = rc4.encrypt(data);
    auto decrypted = rc4.decrypt(encrypted);

    EXPECT_EQ(data, decrypted);
}

TEST_F(RC4Test, InvalidKeyThrowsException) {
    std::vector<uint8_t> empty_key;
    std::vector<uint8_t> too_long_key(257, 0x01); // Слишком длинный ключ

    EXPECT_THROW(rc4.set_key(empty_key), std::invalid_argument);
    EXPECT_THROW(rc4.set_key(too_long_key), std::invalid_argument);
}

TEST_F(RC4Test, AsyncTextEncryptionDecryption) {
    std::vector<uint8_t> key = {0x12, 0x23, 0x34, 0x56};
    rc4.set_key(key);

    auto encrypt_future = rc4.encrypt_async("test_files/text.txt");
    auto encrypted_path = encrypt_future.get();
    EXPECT_TRUE(std::filesystem::exists(encrypted_path));
    auto decrypt_future = rc4.decrypt_async(encrypted_path);
    auto decrypted_path = decrypt_future.get();
    EXPECT_TRUE(std::filesystem::exists(decrypted_path));
    std::ifstream original("test_files/text.txt", std::ios::binary);
    std::ifstream decrypted(decrypted_path, std::ios::binary);
    EXPECT_TRUE(std::equal(
        std::istreambuf_iterator<char>(original),
        std::istreambuf_iterator<char>(),
        std::istreambuf_iterator<char>(decrypted)
    ));
}

TEST_F(RC4Test, AsyncImgEncryptionDecryption) {
    std::vector<uint8_t> key = {0x12, 0x23, 0x34, 0x56};
    rc4.set_key(key);

    auto encrypt_future = rc4.encrypt_async("test_files/img.png");
    auto encrypted_path = encrypt_future.get();
    EXPECT_TRUE(std::filesystem::exists(encrypted_path));
    auto decrypt_future = rc4.decrypt_async(encrypted_path, "test_files/img_dec.png");
    auto decrypted_path = decrypt_future.get();
    EXPECT_TRUE(std::filesystem::exists(decrypted_path));
    std::ifstream original("test_files/img.png", std::ios::binary);
    std::ifstream decrypted(decrypted_path, std::ios::binary);
    EXPECT_TRUE(std::equal(
        std::istreambuf_iterator<char>(original),
        std::istreambuf_iterator<char>(),
        std::istreambuf_iterator<char>(decrypted)
    ));
}

TEST_F(RC4Test, AsyncAudioEncryptionDecryption) {
    std::vector<uint8_t> key = {0x12, 0x23, 0x34, 0x56};
    rc4.set_key(key);

    auto encrypt_future = rc4.encrypt_async("test_files/audio.mp3");
    auto encrypted_path = encrypt_future.get();
    EXPECT_TRUE(std::filesystem::exists(encrypted_path));
    auto decrypt_future = rc4.decrypt_async(encrypted_path, "test_files/audio_dec.mp3");
    auto decrypted_path = decrypt_future.get();
    EXPECT_TRUE(std::filesystem::exists(decrypted_path));
    std::ifstream original("test_files/audio.mp3", std::ios::binary);
    std::ifstream decrypted(decrypted_path, std::ios::binary);
    EXPECT_TRUE(std::equal(
        std::istreambuf_iterator<char>(original),
        std::istreambuf_iterator<char>(),
        std::istreambuf_iterator<char>(decrypted)
    ));
}

TEST_F(RC4Test, Consistency) {
    std::vector<uint8_t> key = {0x01, 0x02, 0x03};
    std::vector<uint8_t> data = {0x41, 0x42, 0x43, 0x44};

    rc4.set_key(key);

    auto enc1 = rc4.encrypt(data);
    auto enc2 = rc4.encrypt(data);
    auto enc3 = rc4.encrypt(data);

    EXPECT_EQ(enc1, enc2);
    EXPECT_EQ(enc2, enc3);

    auto dec1 = rc4.decrypt(enc1);
    auto dec2 = rc4.decrypt(enc2);
    auto dec3 = rc4.decrypt(enc3);

    EXPECT_EQ(dec1, data);
    EXPECT_EQ(dec2, data);
    EXPECT_EQ(dec3, data);
}

TEST_F(RC4Test, VariousDataSizes) {
    std::vector<uint8_t> key = {0x66, 0x77, 0x88};

    std::vector<std::vector<uint8_t> > test_cases = {
        {0x01},
        {0x01, 0x02},
        {0x01, 0x02, 0x03, 0x04},
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
        std::vector<uint8_t>(100, 0x42)
    };

    rc4.set_key(key);

    for (const auto &data: test_cases) {
        auto encrypted = rc4.encrypt(data);
        auto decrypted = rc4.decrypt(encrypted);
        EXPECT_EQ(data, decrypted);
    }
}

TEST_F(RC4Test, EncryptionActuallyChangesData) {
    std::vector<uint8_t> key = {0x99, 0x88, 0x77};
    std::vector<uint8_t> data = {0x41, 0x42, 0x43, 0x44, 0x45};

    rc4.set_key(key);
    auto encrypted = rc4.encrypt(data);
    bool data_changed = false;
    for (size_t i = 0; i < data.size(); ++i) {
        if (data[i] != encrypted[i]) {
            data_changed = true;
            break;
        }
    }

    EXPECT_TRUE(data_changed) << "Encryption should change the data";
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
