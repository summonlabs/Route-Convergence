#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "rc/identity.hpp"

namespace rc {

// SHA-256 (FIPS 180-4).  Used for semantic digests, plan digests, persistence
// integrity and wire integrity.  No cryptographic authentication claim is made
// anywhere in Route Convergence 1.0.0: the digest detects corruption and
// accidental divergence, it is not a MAC and it does not authenticate peers.
class Sha256 {
 public:
  static constexpr std::size_t kDigestBytes = 32;
  using Value = std::array<std::uint8_t, kDigestBytes>;

  Sha256() noexcept;

  void update(std::span<const std::uint8_t> data) noexcept;
  void update(std::string_view data) noexcept;
  [[nodiscard]] Value finish() noexcept;
  [[nodiscard]] static Value hash(std::span<const std::uint8_t> data) noexcept;

 private:
  void compress(const std::uint8_t* block) noexcept;

  std::array<std::uint32_t, 8> state_;
  std::array<std::uint8_t, 64> buffer_{};
  std::size_t buffer_length_ = 0;
  std::uint64_t total_bytes_ = 0;
  bool finished_ = false;
};

class Digest {
 public:
  static constexpr std::size_t kByteCount = 32;
  static constexpr std::size_t kTextLength = 64;

  constexpr Digest() noexcept = default;

  [[nodiscard]] static constexpr Digest from_bytes(
      const std::array<std::uint8_t, kByteCount>& raw) noexcept {
    Digest digest;
    digest.bytes_ = raw;
    return digest;
  }

  [[nodiscard]] static std::optional<Digest> parse(std::string_view text) noexcept;

  [[nodiscard]] constexpr const std::array<std::uint8_t, kByteCount>& bytes() const noexcept {
    return bytes_;
  }

  [[nodiscard]] std::string to_text() const;

  [[nodiscard]] constexpr bool is_nil() const noexcept {
    for (const std::uint8_t byte : bytes_) {
      if (byte != 0) {
        return false;
      }
    }
    return true;
  }

  friend constexpr auto operator<=>(const Digest&, const Digest&) noexcept = default;
  friend constexpr bool operator==(const Digest&, const Digest&) noexcept = default;

 private:
  std::array<std::uint8_t, kByteCount> bytes_{};
};

// Domain-separated digest: SHA-256(len(domain) as u32 LE || domain || payload).
// The domain string is part of the hashed pre-image, so two different semantic
// encodings can never produce the same digest by accident.
[[nodiscard]] Digest domain_digest(std::string_view domain, std::span<const std::uint8_t> payload);

// Deterministic identity derivation.  Used for reproducible deployments and for
// the SYNTHETIC fixtures that the examples, benchmarks and proofs build.  It is a
// naming helper only: nothing in Route Convergence ever treats a derived identity
// as proof of anything.
template <class Id>
[[nodiscard]] Id derive_id(std::string_view domain, std::uint64_t seed) {
  std::uint8_t framed[8];
  for (std::size_t index = 0; index < 8; ++index) {
    framed[index] = static_cast<std::uint8_t>((seed >> (8u * index)) & 0xFFu);
  }
  const Digest digest = domain_digest(domain, std::span<const std::uint8_t>(framed, sizeof(framed)));
  std::array<std::uint8_t, Id::kByteCount> raw{};
  for (std::size_t index = 0; index < Id::kByteCount; ++index) {
    raw[index] = digest.bytes()[index];
  }
  return Id::from_bytes(raw);
}

}  // namespace rc
