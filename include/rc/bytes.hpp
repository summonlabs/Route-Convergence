#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rc {

// Deterministic little-endian encoder.  Multi-byte integers are fixed width, no
// padding, no alignment, no implementation-defined layout, no length ambiguity:
// every variable-length field carries an explicit bound-checked prefix.
class Encoder {
 public:
  explicit Encoder(std::size_t max_blob_bytes = 65536) noexcept;

  void u8(std::uint8_t value);
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void boolean(bool value);
  void raw(std::span<const std::uint8_t> bytes);
  void blob(std::span<const std::uint8_t> bytes);
  void text(std::string_view value);
  void fixed16(std::span<const std::uint8_t, 16> bytes);

  [[nodiscard]] bool ok() const noexcept { return !failed_; }
  [[nodiscard]] const std::vector<std::uint8_t>& bytes() const noexcept { return data_; }
  [[nodiscard]] std::vector<std::uint8_t> take();
  [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }

 private:
  std::vector<std::uint8_t> data_;
  std::size_t max_blob_bytes_ = 65536;
  bool failed_ = false;
};

// Deterministic strict decoder.  Once any read fails the decoder is latched into
// a failed state and every later read fails, so a partially decoded message can
// never be mistaken for a valid one.  at_end() is the trailing-byte check.
class Decoder {
 public:
  explicit Decoder(std::span<const std::uint8_t> data, std::size_t max_blob_bytes = 65536) noexcept;

  bool u8(std::uint8_t& out);
  bool u16(std::uint16_t& out);
  bool u32(std::uint32_t& out);
  bool u64(std::uint64_t& out);
  bool boolean(bool& out);
  bool raw(std::span<std::uint8_t> out);
  bool blob(std::vector<std::uint8_t>& out, std::size_t limit);
  bool text(std::string& out, std::size_t limit);
  bool fixed16(std::span<std::uint8_t, 16> out);
  bool skip(std::size_t count);

  [[nodiscard]] bool failed() const noexcept { return failed_; }
  [[nodiscard]] std::size_t remaining() const noexcept { return data_.size() - position_; }
  [[nodiscard]] bool at_end() const noexcept { return position_ == data_.size(); }
  [[nodiscard]] std::size_t position() const noexcept { return position_; }

 private:
  bool require(std::size_t count);

  std::span<const std::uint8_t> data_;
  std::size_t position_ = 0;
  std::size_t max_blob_bytes_ = 65536;
  bool failed_ = false;
};

}  // namespace rc
