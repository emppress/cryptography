#ifndef RC4_H
#define RC4_H

#include <cstdint>
#include <array>
#include <future>
#include <span>
#include <vector>
#include <filesystem>

namespace crypto {
    class RC4 final {
        class Gen final {
            std::array<uint8_t, 256> _s_box{};
            uint8_t _i{}, _j{};

        public:
            Gen() = default;

            Gen(const Gen &) = delete;

            Gen(Gen &&) noexcept = default;

            Gen &operator=(const Gen &) = delete;

            Gen &operator=(Gen &&) noexcept = default;

            void reset(std::span<const uint8_t> key);

            uint8_t operator()() noexcept;
        };

        std::array<uint8_t, 256> _s_box{};
        std::vector<uint8_t> _key{};
        Gen _gen{};

    public:
        RC4() = default;

        RC4(const RC4 &) = delete;

        RC4 &operator=(const RC4 &) = delete;

        RC4(RC4 &&) noexcept = default;

        RC4 &operator=(RC4 &&) noexcept = default;

        ~RC4() = default;

        void set_key(std::span<const uint8_t> key);

        std::vector<uint8_t> encrypt(
            std::span<const uint8_t> input_data
        );

        std::vector<uint8_t> decrypt(
            std::span<const uint8_t> input_data
        );

        std::future<std::filesystem::path> encrypt_async(
            const std::filesystem::path &input_file, const std::filesystem::path &output_file = {}
        );

        std::future<std::filesystem::path> decrypt_async(
            const std::filesystem::path &input_file, const std::filesystem::path &output_file = {}
        );

    private:
    };
}


#endif //RC4_H
