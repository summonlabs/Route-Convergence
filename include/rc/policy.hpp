#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "rc/digest.hpp"
#include "rc/identity.hpp"

namespace rc {

// How old and new state are ordered.  Nothing in Route Convergence ever picks
// one silently: the mode is an explicit field of an explicitly identified and
// generation-stamped policy object.
enum class OrderingMode : std::uint32_t {
  // New state is validated, prepared, installed, activated and verified before
  // old state is deactivated or withdrawn.
  MAKE_BEFORE_BREAK = 1,
  // Old state is removed first.  Permitted only when the bound policy explicitly
  // allows it; it is never inferred and never a fallback.
  BREAK_BEFORE_MAKE = 2,
};

[[nodiscard]] std::string_view to_string(OrderingMode mode) noexcept;

// Whether explicit verification steps are part of the plan.  Independently of
// this setting, the governor always re-checks target currentness, dependency
// generations, epoch, worker fencing and invalidation watermarks at completion
// time; NONE removes the explicit verification *steps*, not the checks.
enum class VerificationMode : std::uint32_t {
  REQUIRED = 1,
  NONE = 2,
};

[[nodiscard]] std::string_view to_string(VerificationMode mode) noexcept;

struct ConvergencePolicy {
  ConvergencePolicyId id;
  ConvergencePolicyGeneration generation;
  OrderingMode ordering = OrderingMode::MAKE_BEFORE_BREAK;
  VerificationMode verification = VerificationMode::REQUIRED;
  // Whether old and new state may coexist for a bounded part of the transition.
  // MAKE_BEFORE_BREAK requires it; BREAK_BEFORE_MAKE forbids it.
  bool allow_overlap = true;
  // Whether BREAK_BEFORE_MAKE may be selected at all under this policy.
  bool allow_break_before_make = false;
  std::uint32_t max_parallel_steps = 1;
  std::uint32_t max_retries_per_step = 2;
  // When set, a plan under this policy refuses to exist if any of its steps is
  // classified IRREVERSIBLE.
  bool require_rollback_capability = false;
  // When set, successfully completing a plan supersedes the previous plan for
  // the same route.
  bool supersede_predecessor_on_success = true;

  [[nodiscard]] bool is_well_formed() const noexcept;
  [[nodiscard]] bool is_coherent(std::string& reason) const;
  [[nodiscard]] Digest content_digest() const;
  [[nodiscard]] std::string render() const;

  friend bool operator==(const ConvergencePolicy&, const ConvergencePolicy&) = default;
};


}  // namespace rc
