#ifndef _MATH_H_
#define _MATH_H_
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/gmp.hpp>

namespace crypto {
    namespace mp = boost::multiprecision;
    using big_int = mp::mpz_int;
    using rational = mp::mpq_rational;
}

namespace crypto::math {
    inline big_int mod_pow(big_int a, big_int pow, const big_int &mod) {
        if (pow < 0) {
            throw std::invalid_argument("степень должна быть положительной");
        }
        a = (a % mod + mod) % mod;
        big_int res = 1;
        while (pow > 0) {
            if (pow & 1) {
                res = (res * a) % mod;
            }
            a = (a * a) % mod;
            pow >>= 1;
        }
        return res;
    }

    inline big_int gcd(const big_int &a, const big_int &b) {
        big_int p1 = boost::multiprecision::abs(a);
        big_int p2 = boost::multiprecision::abs(b);
        while (p2 != 0) {
            std::tie(p1, p2) = std::tuple(p2, big_int(p1 % p2));
        }
        return p1;
    }

    /// @returns [gcd, x, y]
    inline std::tuple<big_int, big_int, big_int> egcd(const big_int &a, const big_int &n) {
        if (a == 0) {
            return {n, 0, 1};
        }
        auto [d, x1, y1] = egcd(n % a, a);
        big_int x = y1 - (n / a) * x1;
        big_int y = x1;
        return {d, x, y};
    }

    /// Source: http://www.uic.unn.ru/~zny/compalg/Lectures/ca_02_quadraticresidue.pdf
    /// Source: https://ru.wikipedia.org/wiki/Символ_Якоби#Пример_вычисления
    inline int jacobi_symbol(big_int a, big_int n) {
        if (n < 2) {
            throw std::invalid_argument("p < 2");
        }
        if ((n & 1) == 0) {
            throw std::invalid_argument("n - чётное");
        }
        if (gcd(a, n) != 1) { return 0; }
        int r = 1;
        if (a < 0) {
            a = -a;
            if (n % 4 == 3) { r *= -1; }
        }
        while (a != 0) {
            size_t t = 0;
            while ((a & 1) == 0) {
                t++;
                a >>= 1;
            }
            if ((t & 1) == 1) {
                if (big_int mod8 = n % 8; mod8 == 3 || mod8 == 5) { r *= -1; }
            }
            if (a % 4 == 3 && n % 4 == 3) { r *= -1; }
            std::tie(a, n) = std::tuple(big_int(n % a), a);
        }
        return r;
    }

    inline int legendre_symbol(const big_int &a, const big_int &p) {
        return jacobi_symbol(a, p);
    }
} // namespace crypto::math

#endif // _MATH_H_
