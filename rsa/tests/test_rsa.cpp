#include <gtest/gtest.h>
#include "rsa.h"
#include <exception>

class RSACryptoTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        rsa_miller = std::make_unique<crypto::rsa::RSACryptoService>(
            crypto::rsa::RSACryptoService::PrimalityTestType::MILLER_RABIN,
            0.999,
            2048
        );

        rsa_fermat = std::make_unique<crypto::rsa::RSACryptoService>(
            crypto::rsa::RSACryptoService::PrimalityTestType::FERMAT,
            0.999,
            1024
        );

        rsa_strassen = std::make_unique<crypto::rsa::RSACryptoService>(
            crypto::rsa::RSACryptoService::PrimalityTestType::SOLOVAY_STRASSEN,
            0.999,
            1024
        );

        // Генерируем ключи ОДИН РАЗ для всех тестов
        rsa_miller->generate_key_pair();
        rsa_fermat->generate_key_pair();
        rsa_strassen->generate_key_pair();
    }

    static void TearDownTestSuite() {
        rsa_miller.reset();
        rsa_fermat.reset();
        rsa_strassen.reset();
    }

    void SetUp() override {}

    static std::unique_ptr<crypto::rsa::RSACryptoService> rsa_miller;
    static std::unique_ptr<crypto::rsa::RSACryptoService> rsa_fermat;
    static std::unique_ptr<crypto::rsa::RSACryptoService> rsa_strassen;

    crypto::big_int test_data1 = crypto::big_int("4534534423124345677654323456543234654325345676543");
    crypto::big_int test_data2 = crypto::big_int("12345678901234567890");
    crypto::big_int zero = crypto::big_int(0);
    crypto::big_int one = crypto::big_int(1);
};

std::unique_ptr<crypto::rsa::RSACryptoService> RSACryptoTest::rsa_miller = nullptr;
std::unique_ptr<crypto::rsa::RSACryptoService> RSACryptoTest::rsa_fermat = nullptr;
std::unique_ptr<crypto::rsa::RSACryptoService> RSACryptoTest::rsa_strassen = nullptr;

// Тест 1: Базовая шифровка/дешифровка для всех алгоритмов
TEST_F(RSACryptoTest, BasicEncryptionDecryption) {
    // Miller-Rabin
    crypto::big_int ciphertext_miller = rsa_miller->encrypt(test_data1);
    crypto::big_int decrypted_miller = rsa_miller->decrypt(ciphertext_miller);
    EXPECT_EQ(test_data1, decrypted_miller);
    EXPECT_NE(test_data1, ciphertext_miller);

    // Fermat
    crypto::big_int ciphertext_fermat = rsa_fermat->encrypt(test_data1);
    crypto::big_int decrypted_fermat = rsa_fermat->decrypt(ciphertext_fermat);
    EXPECT_EQ(test_data1, decrypted_fermat);
    EXPECT_NE(test_data1, ciphertext_fermat);

    // Solovay-Strassen
    crypto::big_int ciphertext_strassen = rsa_strassen->encrypt(test_data1);
    crypto::big_int decrypted_strassen = rsa_strassen->decrypt(ciphertext_strassen);
    EXPECT_EQ(test_data1, decrypted_strassen);
    EXPECT_NE(test_data1, ciphertext_strassen);
}

// Тест 2: Разные данные для всех алгоритмов
TEST_F(RSACryptoTest, DifferentData) {
    crypto::big_int data_small("123");
    crypto::big_int data_medium("1234567890");
    crypto::big_int data_large("12345678901234567890");

    // Miller-Rabin
    crypto::big_int cipher_small_miller = rsa_miller->encrypt(data_small);
    crypto::big_int cipher_medium_miller = rsa_miller->encrypt(data_medium);
    crypto::big_int cipher_large_miller = rsa_miller->encrypt(data_large);

    EXPECT_EQ(data_small, rsa_miller->decrypt(cipher_small_miller));
    EXPECT_EQ(data_medium, rsa_miller->decrypt(cipher_medium_miller));
    EXPECT_EQ(data_large, rsa_miller->decrypt(cipher_large_miller));

    // Fermat
    crypto::big_int cipher_small_fermat = rsa_fermat->encrypt(data_small);
    crypto::big_int cipher_medium_fermat = rsa_fermat->encrypt(data_medium);
    crypto::big_int cipher_large_fermat = rsa_fermat->encrypt(data_large);

    EXPECT_EQ(data_small, rsa_fermat->decrypt(cipher_small_fermat));
    EXPECT_EQ(data_medium, rsa_fermat->decrypt(cipher_medium_fermat));
    EXPECT_EQ(data_large, rsa_fermat->decrypt(cipher_large_fermat));

    // Solovay-Strassen
    crypto::big_int cipher_small_strassen = rsa_strassen->encrypt(data_small);
    crypto::big_int cipher_medium_strassen = rsa_strassen->encrypt(data_medium);
    crypto::big_int cipher_large_strassen = rsa_strassen->encrypt(data_large);

    EXPECT_EQ(data_small, rsa_strassen->decrypt(cipher_small_strassen));
    EXPECT_EQ(data_medium, rsa_strassen->decrypt(cipher_medium_strassen));
    EXPECT_EQ(data_large, rsa_strassen->decrypt(cipher_large_strassen));
}

// Тест 3: Пограничные значения
TEST_F(RSACryptoTest, EdgeCases) {
    EXPECT_THROW(rsa_miller->encrypt(zero), std::invalid_argument);
    EXPECT_THROW(rsa_miller->encrypt(one), std::invalid_argument);
    EXPECT_THROW(rsa_miller->encrypt(rsa_miller->get_public_key().modulus + 1000), std::invalid_argument);
}

// Тест 4: Множественные шифрования (один ключ - много данных)
TEST_F(RSACryptoTest, MultipleEncryptionsSameKey) {
    std::vector test_data = {
        crypto::big_int("1111111111111111111111111122222222222222222222222222"),
        crypto::big_int("2222222222222222222222222211111111111111111111111111"),
        crypto::big_int("3333333344444444333333333444444444333333333444444444"),
        crypto::big_int("4444444444333333333355555555566666666666777777777777"),
        crypto::big_int("5555555555555555551111111111111111111119999999999999")
    };

    // Miller-Rabin
    for (const auto &data: test_data) {
        crypto::big_int ciphertext = rsa_miller->encrypt(data);
        crypto::big_int decrypted = rsa_miller->decrypt(ciphertext);
        EXPECT_EQ(data, decrypted);
    }

    // Fermat
    for (const auto &data: test_data) {
        crypto::big_int ciphertext = rsa_fermat->encrypt(data);
        crypto::big_int decrypted = rsa_fermat->decrypt(ciphertext);
        EXPECT_EQ(data, decrypted);
    }

    // Solovay-Strassen
    for (const auto &data: test_data) {
        crypto::big_int ciphertext = rsa_strassen->encrypt(data);
        crypto::big_int decrypted = rsa_strassen->decrypt(ciphertext);
        EXPECT_EQ(data, decrypted);
    }
}

// Тест 5: Сравнение работы разных алгоритмов на одних данных
TEST_F(RSACryptoTest, CrossAlgorithmConsistency) {
    crypto::big_int data(
        "424242424242423432000000000432432492349239492349192392193929399346547654332345654323456542345676543292");

    // Все алгоритмы должны корректно шифровать/дешифровать
    crypto::big_int cipher_miller = rsa_miller->encrypt(data);
    crypto::big_int cipher_fermat = rsa_fermat->encrypt(data);
    crypto::big_int cipher_strassen = rsa_strassen->encrypt(data);

    EXPECT_EQ(data, rsa_miller->decrypt(cipher_miller));
    EXPECT_EQ(data, rsa_fermat->decrypt(cipher_fermat));
    EXPECT_EQ(data, rsa_strassen->decrypt(cipher_strassen));

    // Шифротексты должны быть разными (из-за разных ключей)
    EXPECT_NE(cipher_miller, cipher_fermat);
    EXPECT_NE(cipher_miller, cipher_strassen);
    EXPECT_NE(cipher_fermat, cipher_strassen);
}

// Тест 6: Нет уязвимости к Wiener attack
TEST_F(RSACryptoTest, WienerAttackResistance) {
    EXPECT_FALSE(std::get<0>(crypto::rsa::WienerAttack::attack(*rsa_fermat)));
    EXPECT_FALSE(std::get<0>(crypto::rsa::WienerAttack::attack(*rsa_miller)));
    EXPECT_FALSE(std::get<0>(crypto::rsa::WienerAttack::attack(*rsa_strassen)));
}

TEST(BigRSACryptoTest, rsa_4096) {
    crypto::rsa::RSACryptoService rsa_4096(
        crypto::rsa::RSACryptoService::PrimalityTestType::SOLOVAY_STRASSEN, 0.999, 4096);
    crypto::big_int data(
        "424242424242423432000000000432432492349239492349192392193929399346547654332345654323456542345676543292");
    rsa_4096.generate_key_pair();
    auto cipher = rsa_4096.encrypt(data);
    EXPECT_EQ(data, rsa_4096.decrypt(cipher));
}

TEST(RSAAttack, WienerAttack) {
    crypto::rsa::RSACryptoService rsa(crypto::rsa::RSACryptoService::PrimalityTestType::MILLER_RABIN, 0.999, 1024);
    crypto::rsa::WienerAttack::generate_weak_key_pair(rsa);
    auto [ok, d, phi, convs] = crypto::rsa::WienerAttack::attack(rsa);
    EXPECT_TRUE(ok);
    EXPECT_EQ(d, rsa.get_priv_key().exponent);
    EXPECT_GT(convs.size(), 0);
    std::cout << "D: " << d << std::endl;
    std::cout << "Phi: " << convs.size() << std::endl;
    std::cout << "Convergents size: " << convs.size() << std::endl;
}
