#include "rc/persistence.hpp"

#include <cstdio>
#include <fstream>
#include <system_error>

#include "rc/bytes.hpp"
#include "rc/version.hpp"

namespace rc {
namespace {

constexpr char kMagic[kStoreMagicBytes] = {'R', 'C', 'O', 'N', 'V', 'G', 'O', 'V'};

}  // namespace

std::string_view to_string(StoreDefect defect) noexcept {
  switch (defect) {
    case StoreDefect::NONE: return "NONE";
    case StoreDefect::IO_ERROR: return "IO_ERROR";
    case StoreDefect::EMPTY: return "EMPTY";
    case StoreDefect::BAD_MAGIC: return "BAD_MAGIC";
    case StoreDefect::BAD_VERSION: return "BAD_VERSION";
    case StoreDefect::RESERVED_NOT_ZERO: return "RESERVED_NOT_ZERO";
    case StoreDefect::TRUNCATED: return "TRUNCATED";
    case StoreDefect::TRAILING_BYTES: return "TRAILING_BYTES";
    case StoreDefect::INTEGRITY_FAILURE: return "INTEGRITY_FAILURE";
    case StoreDefect::PAYLOAD_TOO_LARGE: return "PAYLOAD_TOO_LARGE";
    case StoreDefect::STRUCTURE: return "STRUCTURE";
  }
  return "IO_ERROR";
}

ConditionCode condition_for(StoreDefect defect) noexcept {
  switch (defect) {
    case StoreDefect::NONE: return ConditionCode::NONE;
    case StoreDefect::IO_ERROR: return ConditionCode::STORE_IO;
    case StoreDefect::EMPTY: return ConditionCode::STORE_STRUCTURE;
    case StoreDefect::BAD_MAGIC: return ConditionCode::STORE_MAGIC;
    case StoreDefect::BAD_VERSION: return ConditionCode::STORE_VERSION;
    case StoreDefect::RESERVED_NOT_ZERO: return ConditionCode::STORE_STRUCTURE;
    case StoreDefect::TRUNCATED: return ConditionCode::STORE_STRUCTURE;
    case StoreDefect::TRAILING_BYTES: return ConditionCode::STORE_TRAILING_BYTES;
    case StoreDefect::INTEGRITY_FAILURE: return ConditionCode::STORE_INTEGRITY;
    case StoreDefect::PAYLOAD_TOO_LARGE: return ConditionCode::STORE_RECORD_LIMIT;
    case StoreDefect::STRUCTURE: return ConditionCode::STORE_STRUCTURE;
  }
  return ConditionCode::STORE_IO;
}

std::vector<std::uint8_t> encode_store_file(std::uint64_t coordinator_epoch,
                                            std::uint64_t convergence_generation,
                                            std::span<const std::uint8_t> payload) {
  Encoder encoder;
  encoder.raw(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(kMagic), kStoreMagicBytes));
  encoder.u32(kPersistenceFormatVersion);
  encoder.u32(0);
  encoder.u64(coordinator_epoch);
  encoder.u64(convergence_generation);
  encoder.u32(static_cast<std::uint32_t>(payload.size()));
  encoder.raw(payload);
  const std::vector<std::uint8_t>& header_and_payload = encoder.bytes();
  const Sha256::Value tag = Sha256::hash(header_and_payload);
  std::vector<std::uint8_t> image = header_and_payload;
  image.insert(image.end(), tag.begin(), tag.end());
  return image;
}

StoreDefect decode_store_file(std::span<const std::uint8_t> bytes,
                              const ConvergenceLimits& limits, StoreFileInfo& info,
                              std::vector<std::uint8_t>& payload) {
  info = StoreFileInfo{};
  payload.clear();
  if (bytes.empty()) {
    return StoreDefect::EMPTY;
  }
  if (bytes.size() < kStoreHeaderBytes + kStoreTagBytes) {
    return StoreDefect::TRUNCATED;
  }
  for (std::size_t index = 0; index < kStoreMagicBytes; ++index) {
    if (bytes[index] != static_cast<std::uint8_t>(kMagic[index])) {
      return StoreDefect::BAD_MAGIC;
    }
  }
  Decoder decoder(bytes);
  if (!decoder.skip(kStoreMagicBytes)) {
    return StoreDefect::TRUNCATED;
  }
  std::uint32_t version = 0;
  std::uint32_t reserved = 0;
  std::uint64_t epoch = 0;
  std::uint64_t generation = 0;
  std::uint32_t payload_bytes = 0;
  if (!decoder.u32(version) || !decoder.u32(reserved) || !decoder.u64(epoch) ||
      !decoder.u64(generation) || !decoder.u32(payload_bytes)) {
    return StoreDefect::TRUNCATED;
  }
  if (version != kPersistenceFormatVersion) {
    return StoreDefect::BAD_VERSION;
  }
  if (reserved != 0) {
    return StoreDefect::RESERVED_NOT_ZERO;
  }
  if (payload_bytes > limits.max_persistence_record_bytes) {
    return StoreDefect::PAYLOAD_TOO_LARGE;
  }
  const std::size_t expected = kStoreHeaderBytes + payload_bytes + kStoreTagBytes;
  if (bytes.size() < expected) {
    return StoreDefect::TRUNCATED;
  }
  if (bytes.size() > expected) {
    return StoreDefect::TRAILING_BYTES;
  }
  const Sha256::Value tag = Sha256::hash(bytes.subspan(0, kStoreHeaderBytes + payload_bytes));
  for (std::size_t index = 0; index < kStoreTagBytes; ++index) {
    if (tag[index] != bytes[kStoreHeaderBytes + payload_bytes + index]) {
      return StoreDefect::INTEGRITY_FAILURE;
    }
  }
  payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(kStoreHeaderBytes),
                 bytes.begin() + static_cast<std::ptrdiff_t>(kStoreHeaderBytes + payload_bytes));
  info.format_version = version;
  info.coordinator_epoch = epoch;
  info.convergence_generation = generation;
  info.payload_bytes = payload_bytes;
  return StoreDefect::NONE;
}

StoreDefect read_store_file(const std::filesystem::path& path, std::vector<std::uint8_t>& bytes,
                            std::string& error) {
  std::error_code code;
  if (!std::filesystem::exists(path, code)) {
    error = "store file does not exist";
    return StoreDefect::IO_ERROR;
  }
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    error = "store file could not be opened";
    return StoreDefect::IO_ERROR;
  }
  stream.seekg(0, std::ios::end);
  const std::streamoff size = stream.tellg();
  if (size < 0) {
    error = "store file size could not be determined";
    return StoreDefect::IO_ERROR;
  }
  stream.seekg(0, std::ios::beg);
  bytes.assign(static_cast<std::size_t>(size), 0);
  if (size > 0) {
    stream.read(reinterpret_cast<char*>(bytes.data()), size);
    if (!stream) {
      error = "store file could not be read completely";
      return StoreDefect::IO_ERROR;
    }
  }
  error.clear();
  return StoreDefect::NONE;
}

StoreDefect write_store_file_atomic(const std::filesystem::path& path,
                                    std::span<const std::uint8_t> image, std::string& error) {
  std::error_code code;
  const std::filesystem::path directory = path.has_parent_path() ? path.parent_path() : ".";
  std::filesystem::create_directories(directory, code);
  std::filesystem::path temporary = path;
  temporary += ".tmp";

  {
    std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
    if (!stream) {
      error = "store temporary file could not be created";
      return StoreDefect::IO_ERROR;
    }
    if (!image.empty()) {
      stream.write(reinterpret_cast<const char*>(image.data()),
                   static_cast<std::streamsize>(image.size()));
    }
    stream.flush();
    if (!stream) {
      error = "store temporary file could not be written";
      return StoreDefect::IO_ERROR;
    }
  }

  std::filesystem::rename(temporary, path, code);
  if (code) {
    std::filesystem::remove(path, code);
    code.clear();
    std::filesystem::rename(temporary, path, code);
    if (code) {
      std::filesystem::remove(temporary, code);
      error = "store file could not be replaced atomically";
      return StoreDefect::IO_ERROR;
    }
  }
  error.clear();
  return StoreDefect::NONE;
}

}  // namespace rc
