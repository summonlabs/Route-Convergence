#include "rc/policy.hpp"

#include "rc/bytes.hpp"

namespace rc {

std::string_view to_string(OrderingMode mode) noexcept {
  switch (mode) {
    case OrderingMode::MAKE_BEFORE_BREAK: return "MAKE_BEFORE_BREAK";
    case OrderingMode::BREAK_BEFORE_MAKE: return "BREAK_BEFORE_MAKE";
  }
  return "UNKNOWN";
}

std::string_view to_string(VerificationMode mode) noexcept {
  switch (mode) {
    case VerificationMode::REQUIRED: return "REQUIRED";
    case VerificationMode::NONE: return "NONE";
  }
  return "UNKNOWN";
}

bool ConvergencePolicy::is_well_formed() const noexcept {
  return !id.is_nil() && generation.value() >= 1;
}

bool ConvergencePolicy::is_coherent(std::string& reason) const {
  if (!is_well_formed()) {
    reason = "policy identity or generation is malformed";
    return false;
  }
  if (ordering == OrderingMode::MAKE_BEFORE_BREAK) {
    if (!allow_overlap) {
      reason = "MAKE_BEFORE_BREAK requires allow_overlap";
      return false;
    }
  } else {
    if (!allow_break_before_make) {
      reason = "BREAK_BEFORE_MAKE was selected but the policy does not allow it";
      return false;
    }
    if (allow_overlap) {
      reason = "BREAK_BEFORE_MAKE requires allow_overlap to be false";
      return false;
    }
  }
  if (max_parallel_steps == 0 || max_parallel_steps > kAbsoluteMaxParallelSteps) {
    reason = "max_parallel_steps must be in [1, kAbsoluteMaxParallelSteps]";
    return false;
  }
  if (max_retries_per_step > kAbsoluteMaxRetriesPerStep) {
    reason = "max_retries_per_step exceeds kAbsoluteMaxRetriesPerStep";
    return false;
  }
  reason.clear();
  return true;
}

Digest ConvergencePolicy::content_digest() const {
  Encoder encoder;
  encoder.fixed16(id.bytes());
  encoder.u64(generation.value());
  encoder.u32(static_cast<std::uint32_t>(ordering));
  encoder.u32(static_cast<std::uint32_t>(verification));
  encoder.boolean(allow_overlap);
  encoder.boolean(allow_break_before_make);
  encoder.u32(max_parallel_steps);
  encoder.u32(max_retries_per_step);
  encoder.boolean(require_rollback_capability);
  encoder.boolean(supersede_predecessor_on_success);
  return domain_digest("rc.policy.v1", encoder.bytes());
}

std::string ConvergencePolicy::render() const {
  std::string out = "policy id=";
  out += id.to_text();
  out += " generation=" + std::to_string(generation.value());
  out += " ordering=";
  out += to_string(ordering);
  out += " verification=";
  out += to_string(verification);
  out += " overlap=" + std::to_string(allow_overlap ? 1 : 0);
  out += " break_before_make_allowed=" + std::to_string(allow_break_before_make ? 1 : 0);
  out += " max_parallel_steps=" + std::to_string(max_parallel_steps);
  out += " max_retries_per_step=" + std::to_string(max_retries_per_step);
  out += " require_rollback_capability=" +
         std::to_string(require_rollback_capability ? 1 : 0);
  out += " supersede_predecessor_on_success=" +
         std::to_string(supersede_predecessor_on_success ? 1 : 0);
  return out;
}

}  // namespace rc
