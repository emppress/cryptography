#include "rsa.h"

#include <bitset>
#include <future>

#include "primary_tests.h"
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <memory>


namespace crypto::rsa {
    RSACryptoService::RSACryptoService(PrimalityTestType test_type,
                                       double min_probability,
                                       size_t bit_len)
        : _key_generator(std::make_unique<RSAKeyGenerator>(test_type, min_probability, bit_len)) {}

    big_int RSACryptoService::encrypt(const big_int &data) const {
        if (data >= _key_pair.publicKey.modulus)
            throw std::invalid_argument("data >= mod");
        if (data == 1 or math::gcd(_key_pair.publicKey.modulus, data) != 1) {
            throw std::invalid_argument("gcd(data, mod) != 1 or data == 1");
        }

        return math::mod_pow(data, _key_pair.publicKey.exponent, _key_pair.publicKey.modulus);
    }

    big_int RSACryptoService::decrypt(const big_int &data) const {
        if (data >= _key_pair.privateKey.modulus)
            throw std::invalid_argument("data >= mod");
        return math::mod_pow(data, _key_pair.privateKey.exponent, _key_pair.privateKey.modulus);
    }

    void RSACryptoService::generate_key_pair() {
        _key_pair = _key_generator->generate_key_pair();
    }

    void RSACryptoService::generate_weak_key_pair() {
        _key_pair = _key_generator->generate_weak_key_pair();
    }

    RSACryptoService::KeyRSA RSACryptoService::get_public_key() const {
        return _key_pair.publicKey;
    }

    void RSACryptoService::set_public_key(KeyRSA pub_key) {
        _key_pair.publicKey = std::move(pub_key);
    }


    RSACryptoService::RSAKeyGenerator::KeyPairRSA RSACryptoService::RSAKeyGenerator::generate_key_pair() const {
        static const big_int exponents[] = {big_int(17), big_int(257), big_int(65537)};

        auto [p, q] = generate_prime_pair();
        big_int N = p * q;
        big_int phi = (p - 1) * (q - 1);
        big_int encrypt_exp{0};
        big_int decrypt_exp{0};

        for (const auto &e: exponents) {
            if (math::gcd(e, phi) == 1) {
                big_int inverse = std::get<1>(math::egcd(e, phi));
                decrypt_exp = (inverse % phi + phi) % phi;
                if (boost::multiprecision::pow(decrypt_exp, 4) * 81 >= N) {
                    encrypt_exp = e;
                    break;
                }
            }
        }
        if (!encrypt_exp) {
            while (true) {
                namespace rnd = boost::random;
                static rnd::mt19937 gen(static_cast<unsigned int>(std::time(nullptr)));
                const rnd::uniform_int_distribution<big_int> dist(big_int(3), phi - 1);
                big_int e = dist(gen) | 1;
                big_int gcd = math::gcd(e, phi);
                if (gcd == 1) {
                    big_int inverse = std::get<1>(math::egcd(e, phi));
                    decrypt_exp = (inverse % phi + phi) % phi;
                    if (boost::multiprecision::pow(decrypt_exp, 4) * 81 >= N) {
                        encrypt_exp = e;
                        break;
                    }
                }
            }
        }
        return KeyPairRSA{
            {std::move(encrypt_exp), N},
            {std::move(decrypt_exp), std::move(N)}
        };
    }

    RSACryptoService::RSAKeyGenerator::KeyPairRSA RSACryptoService::RSAKeyGenerator::generate_weak_key_pair() const {
        namespace rnd = boost::random;
        static rnd::mt19937 gen(static_cast<unsigned int>(std::time(nullptr)));
        auto [p, q] = generate_prime_pair();
        big_int N = p * q;
        big_int phi = (p - 1) * (q - 1);
        const rnd::uniform_int_distribution dist(big_int(3), mp::sqrt(mp::sqrt(N)) / 3);
        big_int decrypt_exp{0};
        big_int encrypt_exp{0};
        while (true) {
            decrypt_exp = dist(gen);
            if (math::gcd(decrypt_exp, phi) != 1) continue;
            auto inverse = std::get<1>(math::egcd(decrypt_exp, phi));
            encrypt_exp = (inverse % phi + phi) % phi;
            if (math::gcd(encrypt_exp, phi) == 1) {
                break;
            }
        }
        return KeyPairRSA{
            {std::move(encrypt_exp), N},
            {std::move(decrypt_exp), std::move(N)}
        };
    }

    RSACryptoService::RSAKeyGenerator::RSAKeyGenerator(PrimalityTestType test_type, double min_probability,
                                                       size_t prime_bit_len)
        : _test_type{test_type},
          _min_probability{min_probability},
          _prime_bit_len{prime_bit_len} {}

    big_int RSACryptoService::RSAKeyGenerator::generate_prime_candidate() const {
        namespace rnd = boost::random;
        static rnd::mt19937 gen(static_cast<unsigned int>(std::time(nullptr)));
        big_int l_border = mp::pow(big_int(2), _prime_bit_len - 1);
        big_int r_border = (l_border * 2) - 1;
        const rnd::uniform_int_distribution dist(std::move(l_border), std::move(r_border));
        return dist(gen) | 1;
    }


    std::pair<big_int, big_int> RSACryptoService::RSAKeyGenerator::generate_prime_pair() const {
        const big_int set_mask = (big_int(0xFF) << (_prime_bit_len - 8));
        const big_int clear_mask = ((big_int(1) << _prime_bit_len) - 1) ^ (big_int(0xFF) << (_prime_bit_len - 8 - 1));
        big_int p, q;
        std::unique_ptr<primary::IProbabilisticPrimalityTest> test;
        switch (_test_type) {
            case PrimalityTestType::FERMAT:
                test = std::make_unique<primary::FermatTest>();
                break;
            case PrimalityTestType::SOLOVAY_STRASSEN:
                test = std::make_unique<primary::SolovayStrassenTest>();
                break;
            case PrimalityTestType::MILLER_RABIN:
                test = std::make_unique<primary::MillerRabinTest>();
                break;
        }
        auto func = [this, &test, &set_mask]() {
            while (true) {
                big_int p = generate_prime_candidate();
                p |= set_mask;
                if (test->is_primary(p, _min_probability)) {
                    return p;
                }
            }
        };
        auto p_fut = std::async(std::launch::async, func);
        while (true) {
            q = generate_prime_candidate();
            q &= clear_mask;
            if (test->is_primary(q, _min_probability)) break;
        }
        return {p_fut.get(), q};
    }

    std::vector<big_int> WienerAttack::continued_fraction(const rational &x) {
        std::vector<big_int> result;
        rational remainder = x;
        while (true) {
            big_int integer_part = mp::numerator(remainder) / denominator(remainder);
            result.push_back(integer_part);
            remainder = remainder - integer_part;
            if (remainder == 0) break;
            remainder = 1 / remainder;
        }
        return result;
    }

    std::vector<rational> WienerAttack::calculate_convergents(const std::vector<big_int> &cf) {
        std::vector<rational> result;
        if (cf.empty()) return result;

        big_int p1 = 0, q1 = 1;
        big_int p0 = 1, q0 = 0;

        for (size_t i = 0; i < cf.size(); ++i) {
            big_int p = cf[i] * p0 + p1;
            big_int q = cf[i] * q0 + q1;
            result.emplace_back(p, q);
            p1 = std::move(p0);
            q1 = std::move(q0);
            p0 = std::move(p);
            q0 = std::move(q);
        }
        return result;
    }

    std::pair<bool, big_int> WienerAttack::test_candidate(const big_int &n, const big_int &e, const rational &conv) {
        big_int k = mp::numerator(conv);
        big_int d = mp::denominator(conv);

        if (k == 0 || d == 0) return {false, 0};
        if ((e * d - 1) % k != 0) return {false, 0};
        big_int phi = (e * d - 1) / k;

        // Решаем уравнение: x^2 - (n - phi + 1)x + n = 0 из т. Виета
        big_int b = n - phi + 1;
        big_int discriminant = b * b - 4 * n;
        if (discriminant < 0) return {false, 0};

        big_int root = sqrt(discriminant);
        if (root * root != discriminant) return {false, 0};

        big_int p = (b + root) / 2;
        big_int q = (b - root) / 2;
        if (p > 1 && q > 1 && p * q == n) return {true, phi};
        return {false, 0};
    }

    std::tuple<bool, big_int, big_int, std::vector<rational> > WienerAttack::attack(const RSACryptoService &rsa) {
        auto [e, n] = rsa._key_pair.publicKey;
        rational e_over_n(e, n);
        const std::vector<big_int> cf = continued_fraction(e_over_n);
        if (cf.empty()) return {false, 0, 0, {}};

        std::vector<rational> convs;
        big_int p1 = 0, q1 = 1;
        big_int p0 = 1, q0 = 0;

        for (const auto &a: cf) {
            big_int p = a * p0 + p1;
            big_int q = a * q0 + q1;
            convs.emplace_back(p, q);
            auto [ok, phi] = test_candidate(n, e, convs.back());
            if (ok) {
                return {true, mp::denominator(convs.back()), phi, convs};
            }
            p1 = std::move(p0);
            q1 = std::move(q0);
            p0 = std::move(p);
            q0 = std::move(q);
        }
        return {false, 0, 0, convs};
    }

    void WienerAttack::generate_weak_key_pair(RSACryptoService &rsa) {
        rsa.generate_weak_key_pair();
    }
}
