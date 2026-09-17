#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include "rc/digest.hpp"
#include "rc/limits.hpp"
#include "rc/outcome.hpp"

namespace rc {

// Versioned, integrity-checked store file.
//
// Layout (little-endian, deterministic, no padding):
//   magic[8]                    "RCONVGOV"
//   format_version u32          == kPersistenceFormatVersion
//   reserved u32                must be 0
//   coordinator_epoch u64       epoch the store was written under
//   convergence_generation u64  governor-wide convergence generation
//   payload_bytes u32           bounded by ConvergenceLimits::max_persistence_record_bytes
//   payload[payload_bytes]
//   tag[32]                     SHA-256 over everything preceding
//
// Files are replaced atomically: the new content is written to a temporary file
// next to the target, flushed, and then moved over the target.  A crash can
// therefore leave either the old complete file or the new complete file, never a
// mixture, and a leftover temporary file carries no authority.
inline constexpr std::size_t kStoreMagicBytes = 8;
inline constexpr std::size_t kStoreTagBytes = 32;
inline constexpr std::size_t kStoreHeaderBytes = 8 + 4 + 4 + 8 + 8 + 4;

struct StoreFileInfo {
  std::uint32_t format_version = 0;
  std::uint64_t coordinator_epoch = 0;
  std::uint64_t convergence_generation = 0;
  std::uint32_t payload_bytes = 0;
};

enum class StoreDefect : std::uint32_t {
  NONE = 0,
  IO_ERROR = 1,
  EMPTY = 2,
  BAD_MAGIC = 3,
  BAD_VERSION = 4,
  RESERVED_NOT_ZERO = 5,
  TRUNCATED = 6,
  TRAILING_BYTES = 7,
  INTEGRITY_FAILURE = 8,
  PAYLOAD_TOO_LARGE = 9,
  STRUCTURE = 10,
};

[[nodiscard]] std::string_view to_string(StoreDefect defect) noexcept;
[[nodiscard]] ConditionCode condition_for(StoreDefect defect) noexcept;

[[nodiscard]] std::vector<std::uint8_t> encode_store_file(std::uint64_t coordinator_epoch,
                                                          std::uint64_t convergence_generation,
                                                          std::span<const std::uint8_t> payload);

// Decodes a complete store file image.  Every structural defect is reported as a
// distinct, stable code.
[[nodiscard]] StoreDefect decode_store_file(std::span<const std::uint8_t> bytes,
                                            const ConvergenceLimits& limits, StoreFileInfo& info,
                                            std::vector<std::uint8_t>& payload);

// Writes the image to `path` atomically.  On success no temporary file remains.
[[nodiscard]] StoreDefect write_store_file_atomic(const std::filesystem::path& path,
                                                  std::span<const std::uint8_t> image,
                                                  std::string& error);

[[nodiscard]] StoreDefect read_store_file(const std::filesystem::path& path,
                                          std::vector<std::uint8_t>& bytes, std::string& error);

}  // namespace rc
