#include <gtest/gtest.h>
#include "context.h"
#include "deal.h"
#include <random>
#include <fstream>
#include <filesystem>

namespace crypto::test {
    class CryptoTest : public ::testing::Test {
    protected:
        void SetUp() override {
            test_data_1000 = generateRandomData(1000);
            test_data_2000 = generateRandomData(2000);
            test_data_10000 = generateRandomData(10000);
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
            0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
        };
        const std::vector<uint8_t> test_key_192{
            0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
        };
        const std::vector<uint8_t> test_key_256{
            0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
        };
        const std::vector<uint8_t> test_iv{
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
        };

        std::vector<uint8_t> test_data_1000;
        std::vector<uint8_t> test_data_2000;
        std::vector<uint8_t> test_data_10000;
    };

    // DEAL тесты с ключом 128 бит

    TEST_F(CryptoTest, DEAL_128_ECB_PKCS7_DataEncryption) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_128);

        CryptoContext context(deal, mode::CipherMode::ECB, mode::PaddingMode::PKCS7);

        auto encrypted = context.encrypt_async(test_data_1000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_1000, decrypted);
    }

    TEST_F(CryptoTest, DEAL_128_CBC_ANSI_X923_DataEncryption) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_128);

        CryptoContext context(deal, mode::CipherMode::CBC, mode::PaddingMode::ANSI_X923, test_iv);

        auto encrypted = context.encrypt_async(test_data_2000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_2000, decrypted);
    }

    TEST_F(CryptoTest, DEAL_128_PCBC_ISO_10126_DataEncryption) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_128);

        CryptoContext context(deal, mode::CipherMode::PCBC, mode::PaddingMode::ISO_10126, test_iv);

        auto encrypted = context.encrypt_async(test_data_10000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_10000, decrypted);
    }

    TEST_F(CryptoTest, DEAL_128_CFB_Zeros_DataEncryption) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_128);

        CryptoContext context(deal, mode::CipherMode::CFB, mode::PaddingMode::Zeros, test_iv);
        auto encrypted = context.encrypt_async(test_data_2000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_2000, decrypted);
    }

    TEST_F(CryptoTest, DEAL_128_OFB_PKCS7_DataEncryption) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_128);

        CryptoContext context(deal, mode::CipherMode::OFB, mode::PaddingMode::PKCS7, test_iv);

        auto test_data = generateRandomData(999);
        auto encrypted = context.encrypt_async(test_data).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data, decrypted);
    }

    TEST_F(CryptoTest, DEAL_128_CTR_ANSI_X923_DataEncryption) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_128);

        CryptoContext context(deal, mode::CipherMode::CTR, mode::PaddingMode::ANSI_X923, test_iv);

        auto encrypted = context.encrypt_async(test_data_2000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_2000, decrypted);
    }

    TEST_F(CryptoTest, DEAL_128_RandomDelta_ISO_10126_DataEncryption) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_128);

        CryptoContext context(deal, mode::CipherMode::RandomDelta, mode::PaddingMode::ISO_10126);

        auto test_data = generateRandomData(1600);
        auto encrypted = context.encrypt_async(test_data).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data, decrypted);
    }

    // DEAL тесты с ключом 192 бита

    TEST_F(CryptoTest, DEAL_192_ECB_PKCS7_DataEncryption) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_192);

        CryptoContext context(deal, mode::CipherMode::ECB, mode::PaddingMode::PKCS7);

        auto encrypted = context.encrypt_async(test_data_1000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_1000, decrypted);
    }

    TEST_F(CryptoTest, DEAL_192_CBC_ANSI_X923_DataEncryption) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_192);

        CryptoContext context(deal, mode::CipherMode::CBC, mode::PaddingMode::ANSI_X923, test_iv);

        auto encrypted = context.encrypt_async(test_data_2000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_2000, decrypted);
    }

    TEST_F(CryptoTest, DEAL_192_PCBC_ISO_10126_DataEncryption) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_192);

        CryptoContext context(deal, mode::CipherMode::PCBC, mode::PaddingMode::ISO_10126, test_iv);

        auto encrypted = context.encrypt_async(test_data_10000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_10000, decrypted);
    }

    TEST_F(CryptoTest, DEAL_192_CFB_Zeros_DataEncryption) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_192);

        CryptoContext context(deal, mode::CipherMode::CFB, mode::PaddingMode::Zeros, test_iv);
        auto encrypted = context.encrypt_async(test_data_2000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_2000, decrypted);
    }

    // DEAL тесты с ключом 256 бит

    TEST_F(CryptoTest, DEAL_256_ECB_PKCS7_DataEncryption) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_256);

        CryptoContext context(deal, mode::CipherMode::ECB, mode::PaddingMode::PKCS7);

        auto encrypted = context.encrypt_async(test_data_1000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_1000, decrypted);
    }

    TEST_F(CryptoTest, DEAL_256_CBC_ANSI_X923_DataEncryption) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_256);

        CryptoContext context(deal, mode::CipherMode::CBC, mode::PaddingMode::ANSI_X923, test_iv);

        auto encrypted = context.encrypt_async(test_data_2000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_2000, decrypted);
    }

    TEST_F(CryptoTest, DEAL_256_PCBC_ISO_10126_DataEncryption) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_256);

        CryptoContext context(deal, mode::CipherMode::PCBC, mode::PaddingMode::ISO_10126, test_iv);

        auto encrypted = context.encrypt_async(test_data_10000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_10000, decrypted);
    }

    // DEAL тесты шифрования файлов

    TEST_F(CryptoTest, DEAL_128_CBC_PKCS7_TextFileEncryption) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_128);

        CryptoContext context(deal, mode::CipherMode::CBC, mode::PaddingMode::PKCS7, test_iv);

        auto encrypted = context.encrypt_async("test_files/text.txt", "test_files/text_deal_encrypted.bin").get();
        auto decrypted = context.decrypt_async("test_files/text_deal_encrypted.bin",
                                               "test_files/text_deal_decrypted.txt").get();

        EXPECT_TRUE(compareFiles("test_files/text.txt", "test_files/text_deal_decrypted.txt"));
    }

    TEST_F(CryptoTest, DEAL_192_ECB_ANSI_X923_ImageEncryption) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_192);

        CryptoContext context(deal, mode::CipherMode::ECB, mode::PaddingMode::ANSI_X923);

        auto encrypted = context.encrypt_async("test_files/img.png", "test_files/img_deal_encrypted.bin").get();
        auto decrypted = context.decrypt_async("test_files/img_deal_encrypted.bin", "test_files/img_deal_decrypted.png")
                .get();

        EXPECT_TRUE(compareFiles("test_files/img.png", "test_files/img_deal_decrypted.png"));
    }

    TEST_F(CryptoTest, DEAL_256_CFB_Zeros_AudioEncryption) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_256);

        CryptoContext context(deal, mode::CipherMode::CFB, mode::PaddingMode::Zeros, test_iv);

        auto encrypted = context.encrypt_async("test_files/audio.mp3", "test_files/audio_deal_encrypted.bin").get();
        auto decrypted = context.decrypt_async("test_files/audio_deal_encrypted.bin",
                                               "test_files/audio_deal_decrypted.mp3").get();

        EXPECT_TRUE(compareFiles("test_files/audio.mp3", "test_files/audio_deal_decrypted.mp3"));
    }

    // DEAL тесты с разными размерами данных

    TEST_F(CryptoTest, DEAL_128_VariousDataSizes) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_128);

        CryptoContext context(deal, mode::CipherMode::CBC, mode::PaddingMode::PKCS7, test_iv);

        std::vector<size_t> sizes = {1, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256};

        for (size_t size: sizes) {
            auto test_data = generateRandomData(size);
            auto encrypted = context.encrypt_async(test_data).get();
            auto decrypted = context.decrypt_async(encrypted).get();

            EXPECT_EQ(test_data, decrypted) << "Failed for data size: " << size;
        }
    }

    // DEAL тест на пустые данные
    TEST_F(CryptoTest, DEAL_EmptyData) {
        auto deal = std::make_shared<crypto::deal::DEALCipher>();
        deal->set_round_keys(test_key_128);

        CryptoContext context(deal, mode::CipherMode::ECB, mode::PaddingMode::PKCS7);

        std::vector<uint8_t> empty_data;

        EXPECT_THROW(context.encrypt_async(empty_data).get(), std::invalid_argument);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
