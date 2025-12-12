#ifndef _RSA_H_
#define _RSA_H_

#include <future>
#include <filesystem>
#include <memory>
#include <vector>
#include "math.h"

namespace crypto::rsa {
    class RSACryptoService final {
    public:
        enum class PrimalityTestType {
            FERMAT,
            SOLOVAY_STRASSEN,
            MILLER_RABIN,
        };

        struct KeyRSA {
            big_int exponent;
            big_int modulus;
        };

        RSACryptoService(RSACryptoService &) = delete;

        RSACryptoService(RSACryptoService &&) = default;

        RSACryptoService &operator=(RSACryptoService &) = delete;

        RSACryptoService &operator=(RSACryptoService &&) = default;

    private:
        class RSAKeyGenerator {
        public:
            RSAKeyGenerator(PrimalityTestType test_type, double min_probability, size_t bit_len);

            struct KeyPairRSA {
                KeyRSA publicKey;
                KeyRSA privateKey;
            };

            [[nodiscard]] KeyPairRSA generate_key_pair() const;

            [[nodiscard]] KeyPairRSA generate_weak_key_pair() const;

        private:
            PrimalityTestType _test_type;
            double _min_probability;
            size_t _prime_bit_len;

            [[nodiscard]] std::pair<big_int, big_int> generate_prime_pair() const;

            [[nodiscard]] big_int generate_prime_candidate() const;
        };

    public:
        RSACryptoService(PrimalityTestType test_type, double min_probability, size_t prime_bit_len);

        [[nodiscard]] big_int encrypt(const big_int &data) const;

        [[nodiscard]] big_int decrypt(const big_int &data) const;

        [[nodiscard]] std::future<void> encrypt(const std::filesystem::path &in_path,
                                                const std::filesystem::path &out_path) const;

        [[nodiscard]] std::future<void> decrypt(const std::filesystem::path &in_path,
                                                const std::filesystem::path &out_path) const;

        void generate_key_pair();

        [[nodiscard]] KeyRSA get_public_key() const;

        [[nodiscard]] KeyRSA get_priv_key() const {
            return _key_pair.privateKey;
        }

        void set_public_key(KeyRSA pub_key);

    private:
        std::unique_ptr<RSAKeyGenerator> _key_generator;
        RSAKeyGenerator::KeyPairRSA _key_pair;

        void generate_weak_key_pair();

        friend class WienerAttack;
    };


    class WienerAttack final {
        static std::vector<big_int> continued_fraction(const rational &x);

        static std::vector<rational> calculate_convergents(const std::vector<big_int> &cf);

        static std::pair<bool, big_int> test_candidate(const big_int &n, const big_int &e, const rational &conv);

    public:
        static std::tuple<bool, big_int, big_int, std::vector<rational> > attack(const RSACryptoService &rsa);

        static void generate_weak_key_pair(RSACryptoService &rsa);
    };
}
#endif //_RSA_H_
