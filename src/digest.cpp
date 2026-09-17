#include "rc/digest.hpp"

#include <cstring>

#include "rc/bytes.hpp"
#include "rc/identity.hpp"

namespace rc {
namespace {

constexpr std::array<std::uint32_t, 64> kRoundConstants = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

[[nodiscard]] constexpr std::uint32_t rotate_right(std::uint32_t value, unsigned count) noexcept {
  return (value >> count) | (value << (32u - count));
}

[[nodiscard]] constexpr std::uint32_t big_sigma0(std::uint32_t value) noexcept {
  return rotate_right(value, 2) ^ rotate_right(value, 13) ^ rotate_right(value, 22);
}

[[nodiscard]] constexpr std::uint32_t big_sigma1(std::uint32_t value) noexcept {
  return rotate_right(value, 6) ^ rotate_right(value, 11) ^ rotate_right(value, 25);
}

[[nodiscard]] constexpr std::uint32_t small_sigma0(std::uint32_t value) noexcept {
  return rotate_right(value, 7) ^ rotate_right(value, 18) ^ (value >> 3);
}

[[nodiscard]] constexpr std::uint32_t small_sigma1(std::uint32_t value) noexcept {
  return rotate_right(value, 17) ^ rotate_right(value, 19) ^ (value >> 10);
}

[[nodiscard]] constexpr std::uint32_t choose(std::uint32_t x, std::uint32_t y,
                                             std::uint32_t z) noexcept {
  return (x & y) ^ (~x & z);
}

[[nodiscard]] constexpr std::uint32_t majority(std::uint32_t x, std::uint32_t y,
                                               std::uint32_t z) noexcept {
  return (x & y) ^ (x & z) ^ (y & z);
}

}  // namespace

Sha256::Sha256() noexcept
    : state_{0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
             0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u} {}

void Sha256::compress(const std::uint8_t* block) noexcept {
  std::array<std::uint32_t, 64> schedule{};
  for (std::size_t index = 0; index < 16; ++index) {
    schedule[index] = (static_cast<std::uint32_t>(block[index * 4]) << 24) |
                      (static_cast<std::uint32_t>(block[(index * 4) + 1]) << 16) |
                      (static_cast<std::uint32_t>(block[(index * 4) + 2]) << 8) |
                      static_cast<std::uint32_t>(block[(index * 4) + 3]);
  }
  for (std::size_t index = 16; index < 64; ++index) {
    schedule[index] = small_sigma1(schedule[index - 2]) + schedule[index - 7] +
                      small_sigma0(schedule[index - 15]) + schedule[index - 16];
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t index = 0; index < 64; ++index) {
    const std::uint32_t temp1 =
        h + big_sigma1(e) + choose(e, f, g) + kRoundConstants[index] + schedule[index];
    const std::uint32_t temp2 = big_sigma0(a) + majority(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(std::span<const std::uint8_t> data) noexcept {
  if (finished_) {
    return;
  }
  total_bytes_ += data.size();
  std::size_t offset = 0;
  while (offset < data.size()) {
    const std::size_t take = (data.size() - offset) < (64 - buffer_length_)
                                 ? (data.size() - offset)
                                 : (64 - buffer_length_);
    std::memcpy(buffer_.data() + buffer_length_, data.data() + offset, take);
    buffer_length_ += take;
    offset += take;
    if (buffer_length_ == 64) {
      compress(buffer_.data());
      buffer_length_ = 0;
    }
  }
}

void Sha256::update(std::string_view data) noexcept {
  update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(data.data()),
                                       data.size()));
}

Sha256::Value Sha256::finish() noexcept {
  if (!finished_) {
    const std::uint64_t total_bits = total_bytes_ * 8u;
    std::array<std::uint8_t, 8> length_bytes{};
    for (std::size_t index = 0; index < 8; ++index) {
      length_bytes[index] = static_cast<std::uint8_t>((total_bits >> (8u * (7u - index))) & 0xFFu);
    }
    std::array<std::uint8_t, 72> padding{};
    padding[0] = 0x80u;
    const std::size_t pad_length =
        (buffer_length_ < 56) ? (56 - buffer_length_) : (120 - buffer_length_);
    update(std::span<const std::uint8_t>(padding.data(), pad_length));
    update(std::span<const std::uint8_t>(length_bytes.data(), length_bytes.size()));
    finished_ = true;
  }

  Value out{};
  for (std::size_t index = 0; index < 8; ++index) {
    out[index * 4] = static_cast<std::uint8_t>((state_[index] >> 24) & 0xFFu);
    out[(index * 4) + 1] = static_cast<std::uint8_t>((state_[index] >> 16) & 0xFFu);
    out[(index * 4) + 2] = static_cast<std::uint8_t>((state_[index] >> 8) & 0xFFu);
    out[(index * 4) + 3] = static_cast<std::uint8_t>(state_[index] & 0xFFu);
  }
  return out;
}

Sha256::Value Sha256::hash(std::span<const std::uint8_t> data) noexcept {
  Sha256 hasher;
  hasher.update(data);
  return hasher.finish();
}

std::optional<Digest> Digest::parse(std::string_view text) noexcept {
  if (text.size() != kTextLength) {
    return std::nullopt;
  }
  std::array<std::uint8_t, kByteCount> raw{};
  for (std::size_t index = 0; index < kByteCount; ++index) {
    const std::uint8_t high = detail::hex_nibble(text[2 * index]);
    const std::uint8_t low = detail::hex_nibble(text[(2 * index) + 1]);
    if (high == 0xFFu || low == 0xFFu) {
      return std::nullopt;
    }
    raw[index] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return from_bytes(raw);
}

std::string Digest::to_text() const {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out(kTextLength, '0');
  for (std::size_t index = 0; index < kByteCount; ++index) {
    out[2 * index] = kHex[bytes_[index] >> 4];
    out[(2 * index) + 1] = kHex[bytes_[index] & 0x0Fu];
  }
  return out;
}

Digest domain_digest(std::string_view domain, std::span<const std::uint8_t> payload) {
  Encoder encoder;
  encoder.u32(static_cast<std::uint32_t>(domain.size()));
  encoder.raw(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(domain.data()), domain.size()));
  encoder.raw(payload);
  const std::vector<std::uint8_t>& framed = encoder.bytes();
  return Digest::from_bytes(Sha256::hash(framed));
}

}  // namespace rc
