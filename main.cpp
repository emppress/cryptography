#include <iostream>
#include "rsa.h"


int main() {
    auto rsa = crypto::rsa::RSACryptoService(crypto::rsa::RSACryptoService::PrimalityTestType::MILLER_RABIN, 0.9,
                                             4096);
    rsa.generate_key_pair();

    crypto::big_int data = crypto::big_int("4534534423124345677654323456543234654325345676543");
    crypto::big_int c = rsa.encrypt(data);
    std::cout << "DATA: " << data << std::endl;
    std::cout << "C = " << c << std::endl;
    crypto::big_int res = rsa.decrypt(c);
    std::cout << "RES = " << res << " IS ok: " << std::boolalpha << (data == res) << std::endl;

    return 0;
}
