#include <gtest/gtest.h>
#include "context.h"
#include "triple_des.h"
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

        const std::vector<uint8_t> test_key{
            0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
            0x24, 0x46, 0x68, 0x8A, 0xAC, 0xCE, 0xE0, 0x02,
            0x35, 0x57, 0x79, 0x9B, 0xBD, 0xDF, 0xF1, 0x13
        };
        const std::vector<uint8_t> test_iv{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

        std::vector<uint8_t> test_data_1000;
        std::vector<uint8_t> test_data_2000;
        std::vector<uint8_t> test_data_10000;
    };

    // Тест для ECB режима
    TEST_F(CryptoTest, ECB_PKCS7_DataEncryption) {
        auto des = std::make_shared<triple_des::TripleDESCipher>();
        des->set_round_keys(test_key);

        CryptoContext context(des, mode::CipherMode::ECB, mode::PaddingMode::PKCS7);

        auto encrypted = context.encrypt_async(test_data_1000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_1000, decrypted);
    }

    // Тест для CBC режима
    TEST_F(CryptoTest, CBC_ANSI_X923_DataEncryption) {
        auto des = std::make_shared<triple_des::TripleDESCipher>();
        des->set_round_keys(test_key);

        CryptoContext context(des, mode::CipherMode::CBC, mode::PaddingMode::ANSI_X923, test_iv);

        auto encrypted = context.encrypt_async(test_data_2000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_2000, decrypted);
    }

    // Тест для PCBC режима
    TEST_F(CryptoTest, PCBC_ISO_10126_DataEncryption) {
        auto des = std::make_shared<triple_des::TripleDESCipher>();
        des->set_round_keys(test_key);

        CryptoContext context(des, mode::CipherMode::PCBC, mode::PaddingMode::ISO_10126, test_iv);

        auto encrypted = context.encrypt_async(test_data_10000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_10000, decrypted);
    }

    // Тест для CFB режима
    TEST_F(CryptoTest, CFB_Zeros_DataEncryption) {
        auto des = std::make_shared<triple_des::TripleDESCipher>();
        des->set_round_keys(test_key);

        CryptoContext context(des, mode::CipherMode::CFB, mode::PaddingMode::Zeros, test_iv);
        auto encrypted = context.encrypt_async(test_data_2000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_2000, decrypted);
    }

    // Тест для OFB режима
    TEST_F(CryptoTest, OFB_PKCS7_DataEncryption) {
        auto des = std::make_shared<triple_des::TripleDESCipher>();
        des->set_round_keys(test_key);

        CryptoContext context(des, mode::CipherMode::OFB, mode::PaddingMode::PKCS7, test_iv);

        auto test_data = generateRandomData(999);
        auto encrypted = context.encrypt_async(test_data).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data, decrypted);
    }

    // Тест для CTR режима
    TEST_F(CryptoTest, CTR_ANSI_X923_DataEncryption) {
        auto des = std::make_shared<triple_des::TripleDESCipher>();
        des->set_round_keys(test_key);

        CryptoContext context(des, mode::CipherMode::CTR, mode::PaddingMode::ANSI_X923, test_iv);

        auto encrypted = context.encrypt_async(test_data_2000).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data_2000, decrypted);
    }

    // Тест для RandomDelta режима
    TEST_F(CryptoTest, RandomDelta_ISO_10126_DataEncryption) {
        auto des = std::make_shared<triple_des::TripleDESCipher>();
        des->set_round_keys(test_key);

        CryptoContext context(des, mode::CipherMode::RandomDelta, mode::PaddingMode::ISO_10126);

        auto test_data = generateRandomData(1600);
        auto encrypted = context.encrypt_async(test_data).get();
        auto decrypted = context.decrypt_async(encrypted).get();

        EXPECT_EQ(test_data, decrypted);
    }

    // Тесты шифрования файлов

    TEST_F(CryptoTest, CBC_PKCS7_TextFileEncryption) {
        auto des = std::make_shared<triple_des::TripleDESCipher>();
        des->set_round_keys(test_key);

        CryptoContext context(des, mode::CipherMode::CBC, mode::PaddingMode::PKCS7, test_iv);

        auto encrypted = context.encrypt_async("test_files/text.txt", "test_files/text_encrypted.bin").get();
        auto decrypted = context.decrypt_async("test_files/text_encrypted.bin", "test_files/text_decrypted.txt").get();

        EXPECT_TRUE(compareFiles("test_files/text.txt", "test_files/text_decrypted.txt"));
    }

    TEST_F(CryptoTest, ECB_ANSI_X923_ImageEncryption) {
        auto des = std::make_shared<triple_des::TripleDESCipher>();
        des->set_round_keys(test_key);

        CryptoContext context(des, mode::CipherMode::ECB, mode::PaddingMode::ANSI_X923);

        auto encrypted = context.encrypt_async("test_files/img.png", "test_files/img_encrypted.bin").get();
        auto decrypted = context.decrypt_async("test_files/img_encrypted.bin", "test_files/img_decrypted.png").
                get();

        EXPECT_TRUE(compareFiles("test_files/img.png", "test_files/img_decrypted.png"));
    }

    TEST_F(CryptoTest, CFB_Zeros_AudioEncryption) {
        auto des = std::make_shared<triple_des::TripleDESCipher>();
        des->set_round_keys(test_key);

        CryptoContext context(des, mode::CipherMode::CFB, mode::PaddingMode::Zeros, test_iv);

        auto encrypted = context.encrypt_async("test_files/audio.mp3", "test_files/audio_encrypted.bin").get();
        auto decrypted = context.decrypt_async("test_files/audio_encrypted.bin", "test_files/audio_decrypted.mp3").
                get();

        EXPECT_TRUE(compareFiles("test_files/audio.mp3", "test_files/audio_decrypted.mp3"));
    }

    // Тест с разными размерами данных
    TEST_F(CryptoTest, VariousDataSizes) {
        auto des = std::make_shared<triple_des::TripleDESCipher>();
        des->set_round_keys(test_key);

        CryptoContext context(des, mode::CipherMode::CBC, mode::PaddingMode::PKCS7, test_iv);

        // Тестируем разные размеры данных
        std::vector<size_t> sizes = {1, 7, 8, 15, 16, 63, 64, 127, 128, 255, 256, 511, 512};

        for (size_t size: sizes) {
            auto test_data = generateRandomData(size);
            auto encrypted = context.encrypt_async(test_data).get();
            auto decrypted = context.decrypt_async(encrypted).get();

            EXPECT_EQ(test_data, decrypted) << "Failed for data size: " << size;
        }
    }

    // Тест на пустые данные
    TEST_F(CryptoTest, EmptyData) {
        auto des = std::make_shared<triple_des::TripleDESCipher>();
        des->set_round_keys(test_key);

        CryptoContext context(des, mode::CipherMode::ECB, mode::PaddingMode::PKCS7);

        std::vector<uint8_t> empty_data;

        EXPECT_THROW(context.encrypt_async(empty_data).get(), std::invalid_argument);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
