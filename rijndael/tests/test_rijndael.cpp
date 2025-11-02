#include <gtest/gtest.h>
#include "context.h"
#include "rijndael.h"
#include "GF_math.h"
#include <random>
#include <fstream>
#include <filesystem>

namespace crypto::test {
    class RijndaelTest : public ::testing::Test {
    protected:
        void SetUp() override {
            test_data_1000 = generateRandomData(1000);
            test_data_2000 = generateRandomData(2000);
            test_data_10000 = generateRandomData(10000);
            irreducible_polys = gf::find_irreducible_polynomials();
        }

        std::vector<uint8_t> generateRandomData(size_t size) {
            std::vector<uint8_t> data(size);
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);

            for (auto &byte: data) {
                byte = static_cast<uint8_t>(dis(gen));
            }
            return data;
        }

        std::vector<uint8_t> generateIV(size_t block_size) {
            return generateRandomData(block_size);
        }

        bool compareFiles(const std::filesystem::path &file1, const std::filesystem::path &file2) {
            std::ifstream f1(file1, std::ios::binary);
            std::ifstream f2(file2, std::ios::binary);

            if (!f1 || !f2) return false;

            return std::equal(
                std::istreambuf_iterator<char>(f1),
                std::istreambuf_iterator<char>(),
                std::istreambuf_iterator<char>(f2)
            );
        }

        const std::vector<uint8_t> test_key_128{
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x97, 0x56, 0x19, 0x88, 0x09, 0xcf
        };
        const std::vector<uint8_t> test_key_192{
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
            0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
            0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
        };
        const std::vector<uint8_t> test_key_256{
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
        };

        std::vector<uint8_t> test_data_1000;
        std::vector<uint8_t> test_data_2000;
        std::vector<uint8_t> test_data_10000;
        std::vector<uint8_t> irreducible_polys;
    };

    // Тесты с разными модулями
    TEST_F(RijndaelTest, DifferentPolynomials_AES128_ECB_PKCS7) {
        for (auto mod: irreducible_polys) {
            auto rijndael = std::make_shared<crypto::rijndael::RijndaelCipher>(16, 16, mod);
            rijndael->set_round_keys(test_key_128);

            CryptoContext context(rijndael, mode::CipherMode::ECB, mode::PaddingMode::PKCS7);

            auto encrypted = context.encrypt_async(test_data_1000).get();
            auto decrypted = context.decrypt_async(encrypted).get();

            EXPECT_EQ(test_data_1000, decrypted) << "Failed with polynomial: 0x" << std::hex << (int) mod;
        }
    }

    // Тест для ECB режима
    TEST_F(RijndaelTest, ECB_PKCS7_DataEncryption_AES128) {
        auto rijndael = std::make_shared<crypto::rijndael::RijndaelCipher>(16, 16, 0x1B);
        rijndael->set_round_keys(test_key_128);

        CryptoContext context(rijndael, mode::CipherMode::ECB, mode::PaddingMode::PKCS7);

        auto encrypted = context.encrypt_async(test_data_1000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_1000, decrypted);
    }

    // Тест для CBC режима
    TEST_F(RijndaelTest, CBC_ANSI_X923_DataEncryption_AES192) {
        auto rijndael = std::make_shared<crypto::rijndael::RijndaelCipher>(16, 24, 0x1B);
        rijndael->set_round_keys(test_key_192);

        auto test_iv = generateIV(16);
        CryptoContext context(rijndael, mode::CipherMode::CBC, mode::PaddingMode::ANSI_X923, test_iv);

        auto encrypted = context.encrypt_async(test_data_2000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_2000, decrypted);
    }

    // Тест для PCBC режима
    TEST_F(RijndaelTest, PCBC_ISO_10126_DataEncryption_AES256) {
        auto rijndael = std::make_shared<crypto::rijndael::RijndaelCipher>(16, 32, 0x1B);
        rijndael->set_round_keys(test_key_256);

        auto test_iv = generateIV(16);
        CryptoContext context(rijndael, mode::CipherMode::PCBC, mode::PaddingMode::ISO_10126, test_iv);

        auto encrypted = context.encrypt_async(test_data_10000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_10000, decrypted);
    }

    // Тест для CFB режима
    TEST_F(RijndaelTest, CFB_Zeros_DataEncryption_Rijndael192) {
        auto rijndael = std::make_shared<crypto::rijndael::RijndaelCipher>(24, 24, 0x1B);
        rijndael->set_round_keys(test_key_192);

        auto test_iv = generateIV(24);
        CryptoContext context(rijndael, mode::CipherMode::CFB, mode::PaddingMode::Zeros, test_iv);
        auto encrypted = context.encrypt_async(test_data_2000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_2000, decrypted);
    }

    // Тест для OFB режима
    TEST_F(RijndaelTest, OFB_PKCS7_DataEncryption_Rijndael256) {
        auto rijndael = std::make_shared<crypto::rijndael::RijndaelCipher>(32, 32, 0x1B);
        rijndael->set_round_keys(test_key_256);

        auto test_iv = generateIV(32);
        CryptoContext context(rijndael, mode::CipherMode::OFB, mode::PaddingMode::PKCS7, test_iv);

        auto test_data = generateRandomData(999);
        auto encrypted = context.encrypt_async(test_data).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data, decrypted);
    }

    // Тест для CTR режима
    TEST_F(RijndaelTest, CTR_ANSI_X923_DataEncryption_AES128) {
        auto rijndael = std::make_shared<crypto::rijndael::RijndaelCipher>(16, 16, 0x1B);
        rijndael->set_round_keys(test_key_128);

        auto test_iv = generateIV(16);
        CryptoContext context(rijndael, mode::CipherMode::CTR, mode::PaddingMode::ANSI_X923, test_iv);

        auto encrypted = context.encrypt_async(test_data_2000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_2000, decrypted);
    }

    // Тест для RandomDelta режима
    TEST_F(RijndaelTest, RandomDelta_ISO_10126_DataEncryption_AES256) {
        auto rijndael = std::make_shared<crypto::rijndael::RijndaelCipher>(16, 32, 0x1B);
        rijndael->set_round_keys(test_key_256);

        CryptoContext context(rijndael, mode::CipherMode::RandomDelta, mode::PaddingMode::ISO_10126);

        auto test_data = generateRandomData(1600);
        auto encrypted = context.encrypt_async(test_data).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data, decrypted);
    }

    // Тесты шифрования файлов

    TEST_F(RijndaelTest, CBC_PKCS7_TextFileEncryption_AES192) {
        auto rijndael = std::make_shared<crypto::rijndael::RijndaelCipher>(16, 24, 0x1B);
        rijndael->set_round_keys(test_key_192);

        auto test_iv = generateIV(16);
        CryptoContext context(rijndael, mode::CipherMode::CBC, mode::PaddingMode::PKCS7, test_iv);

        auto encrypted = context.encrypt_async("test_files/text.txt", "test_files/text_encrypted.bin").get();
        auto decrypted = context.decrypt_async("test_files/text_encrypted.bin", "test_files/text_decrypted.txt").
                get();

        EXPECT_TRUE(compareFiles("test_files/text.txt", "test_files/text_decrypted.txt"));
    }

    TEST_F(RijndaelTest, ECB_ANSI_X923_ImageEncryption_Rijndael256) {
        auto rijndael = std::make_shared<crypto::rijndael::RijndaelCipher>(32, 32, 0x1B);
        rijndael->set_round_keys(test_key_256);

        CryptoContext context(rijndael, mode::CipherMode::ECB, mode::PaddingMode::ANSI_X923);

        auto encrypted = context.encrypt_async("test_files/img.png", "test_files/img_encrypted.bin").get();
        auto decrypted = context.decrypt_async("test_files/img_encrypted.bin", "test_files/img_decrypted.png").get();

        EXPECT_TRUE(compareFiles("test_files/img.png", "test_files/img_decrypted.png"));
    }

    TEST_F(RijndaelTest, CFB_Zeros_AudioEncryption_AES128) {
        auto rijndael = std::make_shared<crypto::rijndael::RijndaelCipher>(16, 16, 0x1B);
        rijndael->set_round_keys(test_key_128);

        auto test_iv = generateIV(16);
        CryptoContext context(rijndael, mode::CipherMode::CFB, mode::PaddingMode::Zeros, test_iv);

        auto encrypted = context.encrypt_async("test_files/audio.mp3", "test_files/audio_encrypted.bin").get();
        auto decrypted = context.decrypt_async("test_files/audio_encrypted.bin", "test_files/audio_decrypted.mp3").
                get();

        EXPECT_TRUE(compareFiles("test_files/audio.mp3", "test_files/audio_decrypted.mp3"));
    }

    // Тест с разными размерами данных
    TEST_F(RijndaelTest, VariousDataSizes_AES128) {
        auto rijndael = std::make_shared<crypto::rijndael::RijndaelCipher>(16, 16, 0x1B);
        rijndael->set_round_keys(test_key_128);

        auto test_iv = generateIV(16);
        CryptoContext context(rijndael, mode::CipherMode::CBC, mode::PaddingMode::PKCS7, test_iv);

        // Тестируем разные размеры данных
        std::vector<size_t> sizes = {1, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 511, 512, 1023, 1024};

        for (size_t size: sizes) {
            auto test_data = generateRandomData(size);
            auto encrypted = context.encrypt_async(test_data).get();
            auto decrypted = context.decrypt_async(encrypted).get();

            EXPECT_EQ(test_data, decrypted) << "Failed for data size: " << size;
        }
    }

    // Тест на пустые данные
    TEST_F(RijndaelTest, EmptyData_AES128) {
        auto rijndael = std::make_shared<crypto::rijndael::RijndaelCipher>(16, 16, 0x1B);
        rijndael->set_round_keys(test_key_128);

        CryptoContext context(rijndael, mode::CipherMode::ECB, mode::PaddingMode::PKCS7);

        std::vector<uint8_t> empty_data;

        EXPECT_THROW(context.encrypt_async(empty_data).get(), std::invalid_argument);
    }

    // Тест разных комбинаций размеров блоков и ключей
    TEST_F(RijndaelTest, VariousBlockKeySizes) {
        std::vector<std::pair<size_t, size_t> > configurations = {
            {16, 16}, {16, 24}, {16, 32}, // AES
            {24, 16}, {24, 24}, {24, 32}, // Rijndael-192
            {32, 16}, {32, 24}, {32, 32} // Rijndael-256
        };

        for (auto [block_size, key_size]: configurations) {
            auto test_key = generateRandomData(key_size);
            auto rijndael = std::make_shared<crypto::rijndael::RijndaelCipher>(block_size, key_size, 0x1B);
            rijndael->set_round_keys(test_key);

            auto test_iv = generateIV(block_size);
            CryptoContext context(rijndael, mode::CipherMode::CBC, mode::PaddingMode::PKCS7, test_iv);

            auto test_data = generateRandomData(500);
            auto encrypted = context.encrypt_async(test_data).get();
            auto decrypted = context.decrypt_async(encrypted).get();

            EXPECT_EQ(test_data, decrypted)
                << "Failed for block_size: " << block_size << ", key_size: " << key_size;
        }
    }
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
