#include <gtest/gtest.h>
#include "dh.h"

using namespace crypto;
namespace mp = boost::multiprecision;

TEST(DHTests, ConstructorFromGroupFfdhe2048) {
    DH alice(DH::Group::ffdhe2048);
    DH bob(DH::Group::ffdhe2048);

    bob.compute_shared_secret(alice.get_public_key());
    alice.compute_shared_secret(bob.get_public_key());;

    EXPECT_EQ(alice.get_shared_secret(), bob.get_shared_secret());
    std::cout << "(ffdhe2048) shared bit len: " << mp::msb(alice.get_shared_secret()) + 1 << std::endl;
}

TEST(DHTests, ConstructorFromGroupFfdhe3072) {
    DH alice(DH::Group::ffdhe3072);
    DH bob(DH::Group::ffdhe3072);

    bob.compute_shared_secret(alice.get_public_key());
    alice.compute_shared_secret(bob.get_public_key());;

    EXPECT_EQ(alice.get_shared_secret(), bob.get_shared_secret());
    std::cout << "(ffdhe3072) shared bit len: " << mp::msb(alice.get_shared_secret()) + 1 << std::endl;
}

TEST(DHTests, ConstructorFromGroupFfdhe4096) {
    DH alice(DH::Group::ffdhe8192);
    DH bob(DH::Group::ffdhe8192);

    bob.compute_shared_secret(alice.get_public_key());
    alice.compute_shared_secret(bob.get_public_key());;

    EXPECT_EQ(alice.get_shared_secret(), bob.get_shared_secret());
    std::cout << "(ffdhe8192) shared bit len: " << mp::msb(alice.get_shared_secret()) + 1 << std::endl;
}

TEST(DHTests, ConstructorWithGandP1024) {
    auto [p, g] = DH::generate_prime_and_g(1024);
    DH alice(g, p);
    DH bob(g, p);

    bob.compute_shared_secret(alice.get_public_key());
    alice.compute_shared_secret(bob.get_public_key());;

    EXPECT_EQ(alice.get_shared_secret(), bob.get_shared_secret());
    std::cout << "(P1024) shared bit len: " << mp::msb(alice.get_shared_secret()) + 1 << std::endl;
}

TEST(DHTests, ConstructorWithGandP2048) {
    auto [p, g] = DH::generate_prime_and_g(1024);
    DH alice(g, p);
    DH bob(g, p);

    bob.compute_shared_secret(alice.get_public_key());
    alice.compute_shared_secret(bob.get_public_key());;

    EXPECT_EQ(alice.get_shared_secret(), bob.get_shared_secret());
    std::cout << "(P2048) shared bit len: " << mp::msb(alice.get_shared_secret()) + 1 << std::endl;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
