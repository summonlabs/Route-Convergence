#include "rc/identity.hpp"

namespace rc {

std::optional<SubjectToken> SubjectToken::make(std::string_view text) noexcept {
  if (text.empty() || text.size() > kAbsoluteMaxSubjectBytes) {
    return std::nullopt;
  }
  for (const char raw : text) {
    const unsigned char value = static_cast<unsigned char>(raw);
    if (value < 0x21u || value > 0x7Eu) {
      // Printable ASCII without spaces only: a subject is a token, not prose.
      return std::nullopt;
    }
  }
  SubjectToken token;
  token.text_.assign(text);
  return token;
}

}  // namespace rc
