#include "dh.h"
#include "primary_tests.h"

#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>

crypto::DH::DH(Group group) {
    set_group_params(group);
    generate_private_key();
    _public_key = mp::powm(_g, _private_key, _p);
}

crypto::DH::DH(big_int g, big_int p) {
    if (g <= 1)
        throw std::invalid_argument("g is bad");
    auto bits = mp::msb(p) + 1;
    if (bits < 512)
        throw std::invalid_argument("p is small");
    primary::MillerRabinTest test;
    if (!test.is_primary(p, 0.999))
        throw std::invalid_argument("p is not prime");
    _q = (p - 1) / 2;
    if (!test.is_primary(_q, 0.999))
        throw std::invalid_argument("p is not safe prime");
    if (mp::powm(g, _q, p) != 1)
        throw std::invalid_argument("g is bad");
    _p = std::move(p);
    _g = std::move(g);
    _private_min_bit_len = std::max(bits / 8, 225ul);
    generate_private_key();
    _public_key = mp::powm(_g, _private_key, _p);
}

bool crypto::DH::compute_shared_secret(const big_int &other_pub) {
    if (!validate_public_key(other_pub)) return false;
    _shared_secret = powm(other_pub, _private_key, _p);
    return true;
}

void crypto::DH::generate_private_key() {
    auto border = big_int{1} << _private_min_bit_len;
    boost::random::uniform_int_distribution<big_int> dist(border, (border << 1) - 1);
    boost::random::mt19937 gen(_rd());
    _private_key = dist(gen);
}

bool crypto::DH::validate_public_key(const big_int &key) const {
    if (key < 2 || key >= _p - 1) return false;
    return mp::powm(key, _q, _p) == 1;
}

const crypto::big_int &crypto::DH::get_shared_secret() const {
    if (_shared_secret.is_zero())
        throw std::invalid_argument("zero shared secret");
    return _shared_secret;
}

const crypto::big_int &crypto::DH::get_public_key() const {
    return _public_key;
}

const crypto::big_int &crypto::DH::get_generator() const {
    return _g;
}

const crypto::big_int &crypto::DH::get_prime_mod() const {
    return _p;
}

std::pair<crypto::big_int, crypto::big_int> crypto::DH::generate_prime_and_g(size_t bit_len) {
    static boost::random::mt19937 gen(std::random_device{}());
    big_int l_border = mp::pow(big_int(2), bit_len - 1);
    big_int r_border = (l_border * 2) - 1;
    const boost::random::uniform_int_distribution dist(std::move(l_border), std::move(r_border));
    primary::MillerRabinTest test;
    big_int num, q;

    do {
        num = dist(gen) | 1;
        q = (num - 1) / 2;
    } while (!test.is_primary(num, 0.999) || !test.is_primary(q, 0.999));

    big_int g = 2;
    while (g < num - 1) {
        if (mp::powm(g, q, num) == 1) {
            break;
        }
        ++g;
    }
    return {num, g};
}
