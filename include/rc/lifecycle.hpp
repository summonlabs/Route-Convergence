#pragma once

#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rc {

// Convergence plan lifecycle.  This is the smallest model that keeps every real
// distinction: an administratively ended lineage (SUPERSEDED / REVOKED /
// RETIRED) behaves differently from a plan that merely lost its live
// currentness (REVALIDATION_REQUIRED) or is waiting for a dependency to return
// (PAUSED).  There is deliberately no separate ROLLED_BACK state: a forward plan
// whose rollback completed is SUPERSEDED by its own rollback plan, and the
// lineage records exactly that.
enum class PlanLifecycle : std::uint32_t {
  DECLARED = 1,
  VALIDATING = 2,
  READY = 3,
  EXECUTING = 4,
  PAUSED = 5,
  REVALIDATION_REQUIRED = 6,
  ROLLBACK_REQUIRED = 7,
  ROLLING_BACK = 8,
  COMPLETED = 9,
  SUPERSEDED = 10,
  REVOKED = 11,
  RETIRED = 12,
};

inline constexpr std::uint32_t kPlanLifecycleCount = 12;

[[nodiscard]] std::string_view to_string(PlanLifecycle lifecycle) noexcept;

// True for lifecycles that no longer accept ordinary forward progress.
[[nodiscard]] bool is_terminal_lifecycle(PlanLifecycle lifecycle) noexcept;

// True for the single lifecycle that can never be left.
[[nodiscard]] bool is_absolutely_terminal(PlanLifecycle lifecycle) noexcept;

// True when the lifecycle may be moved to RETIRED.
[[nodiscard]] bool is_retirable(PlanLifecycle lifecycle) noexcept;

enum class PlanEvent : std::uint32_t {
  DECLARE = 1,
  VALIDATE_OK = 2,
  VALIDATE_FAIL = 3,
  MARK_READY = 4,
  DISPATCH = 5,
  STEP_COMPLETED = 6,
  STEP_FAILED = 7,
  STEP_AMBIGUOUS = 8,
  ALL_STEPS_TERMINAL = 9,
  PAUSE = 10,
  RESUME = 11,
  INVALIDATE = 12,
  REVALIDATE_OK = 13,
  REVALIDATE_FAIL = 14,
  REQUIRE_ROLLBACK = 15,
  BEGIN_ROLLBACK = 16,
  ROLLBACK_STEP_COMPLETED = 17,
  ROLLBACK_FAILED = 18,
  ROLLBACK_COMPLETED = 19,
  SUPERSEDE = 20,
  REVOKE = 21,
  RETIRE = 22,
  RECOVER = 23,
};

inline constexpr std::uint32_t kPlanEventCount = 23;

[[nodiscard]] std::string_view to_string(PlanEvent event) noexcept;

// One legal plan transition.  The complete set of these entries *is* the plan
// transition table: any (lifecycle, event) pair that does not appear here is
// denied, so a caller can never reach an unspecified state.
struct PlanTransitionRule {
  PlanLifecycle from;
  PlanEvent event;
  PlanLifecycle to;
};

[[nodiscard]] const std::vector<PlanTransitionRule>& plan_transition_table();

// Inputs of the derived (non sticky) plan lifecycle computation.  The result
// depends on nothing else: no timestamps, no arrival order, no process state.
struct PlanTransitionInputs {
  bool target_current = true;
  bool dependency_current = true;
  bool policy_current = true;
  bool rollback_required = false;
  bool mandatory_steps_terminal = false;
};

// Full transition.  Returns the successor lifecycle when the event is legal in
// this state, and std::nullopt when it is denied.
[[nodiscard]] std::optional<PlanLifecycle> apply_plan_event(PlanLifecycle state, PlanEvent event,
                                                            const PlanTransitionInputs& inputs) noexcept;

// Static legality: is this event legal at all in this state?
[[nodiscard]] bool plan_lifecycle_allows(PlanLifecycle state, PlanEvent event) noexcept;

// Step lifecycle.  RECONCILIATION_REQUIRED exists because an ambiguous external
// side effect is a real, distinct condition: the operation may or may not have
// happened, and neither COMPLETED nor FAILED would be truthful.
enum class StepLifecycle : std::uint32_t {
  PENDING = 1,
  READY = 2,
  DISPATCHED = 3,
  COMPLETED = 4,
  FAILED = 5,
  STALE = 6,
  SKIPPED = 7,
  ROLLBACK_PENDING = 8,
  ROLLED_BACK = 9,
  RECONCILIATION_REQUIRED = 10,
  RETIRED = 11,
};

inline constexpr std::uint32_t kStepLifecycleCount = 11;

[[nodiscard]] std::string_view to_string(StepLifecycle state) noexcept;

// True when no further forward progress is possible for this step.
[[nodiscard]] bool is_step_terminal(StepLifecycle state) noexcept;

// True when the step counts as satisfied for plan completion purposes.
[[nodiscard]] bool is_step_satisfied(StepLifecycle state) noexcept;

enum class StepEvent : std::uint32_t {
  DECLARE = 1,
  MARK_READY = 2,
  DISPATCH = 3,
  COMPLETE = 4,
  FAIL_RETRYABLE = 5,
  FAIL_PERMANENT = 6,
  MARK_AMBIGUOUS = 7,
  RECONCILE_APPLIED = 8,
  RECONCILE_NOT_APPLIED = 9,
  MARK_STALE = 10,
  SKIP = 11,
  BEGIN_ROLLBACK = 12,
  ROLLBACK_COMPLETE = 13,
  ROLLBACK_FAIL = 14,
  RETIRE = 15,
  RECOVER = 16,
};

inline constexpr std::uint32_t kStepEventCount = 16;

[[nodiscard]] std::string_view to_string(StepEvent event) noexcept;

struct StepTransitionRule {
  StepLifecycle from;
  StepEvent event;
  StepLifecycle to;
};

[[nodiscard]] const std::vector<StepTransitionRule>& step_transition_table();
[[nodiscard]] bool step_lifecycle_allows(StepLifecycle state, StepEvent event) noexcept;
[[nodiscard]] std::optional<StepLifecycle> apply_step_event(StepLifecycle state,
                                                            StepEvent event) noexcept;

// Currentness causes are never collapsed into one "stale" flag: an operator must
// be able to tell a superseded target route generation from a fenced publisher.
enum class CurrentnessCause : std::uint32_t {
  STALE_TARGET_ROUTE = 1,
  STALE_SOURCE_ROUTE = 2,
  STALE_PATH_AUTHORITY = 3,
  STALE_MULTIPATH_SET = 4,
  STALE_ECMP_GENERATION = 5,
  STALE_ASSIGNMENT_GENERATION = 6,
  STALE_WEIGHT_POLICY = 7,
  STALE_EPOCH = 8,
  STALE_POLICY_GENERATION = 9,
  FENCED_PUBLISHER = 10,
  SUPERSEDED_BY_SUCCESSOR = 11,
  REVALIDATION_REQUIRED = 12,
};

inline constexpr std::uint32_t kCurrentnessCauseCount = 12;

[[nodiscard]] std::string_view to_string(CurrentnessCause cause) noexcept;

class Currentness {
 public:
  constexpr Currentness() noexcept = default;

  [[nodiscard]] static constexpr Currentness from_bits(std::uint32_t bits) noexcept {
    Currentness value;
    value.bits_ = bits;
    return value;
  }
  [[nodiscard]] static constexpr Currentness current() noexcept { return Currentness{}; }

  void add(CurrentnessCause cause) noexcept;
  void remove(CurrentnessCause cause) noexcept;
  void clear() noexcept { bits_ = 0; }

  [[nodiscard]] constexpr bool is_current() const noexcept { return bits_ == 0; }
  [[nodiscard]] constexpr bool has(CurrentnessCause cause) const noexcept {
    return (bits_ & mask_of(cause)) != 0;
  }
  [[nodiscard]] constexpr std::uint32_t bits() const noexcept { return bits_; }
  [[nodiscard]] std::vector<CurrentnessCause> causes() const;
  [[nodiscard]] std::string render() const;

  // A plan keeps live authority while none of the causes that end live authority
  // are present.  A stale source route prevents *planning* but does not by
  // itself revoke an already running plan, so it is deliberately excluded here.
  [[nodiscard]] bool authority_current() const noexcept;

  friend constexpr bool operator==(const Currentness&, const Currentness&) noexcept = default;
  friend constexpr auto operator<=>(const Currentness&, const Currentness&) noexcept = default;

 private:
  [[nodiscard]] static constexpr std::uint32_t mask_of(CurrentnessCause cause) noexcept {
    return 1u << (static_cast<std::uint32_t>(cause) - 1u);
  }

  std::uint32_t bits_ = 0;
};

// Why a recorded change happened.  Bounded, stable, persisted.
enum class ChangeReason : std::uint32_t {
  CREATE = 1,
  VALIDATE = 2,
  DISPATCH_STEP = 3,
  COMPLETE_STEP = 4,
  FAIL_STEP = 5,
  AMBIGUOUS_STEP = 6,
  RECONCILE_STEP = 7,
  PAUSE = 8,
  RESUME = 9,
  INVALIDATE = 10,
  REVALIDATE = 11,
  SUPERSEDE = 12,
  ROLLBACK_REQUESTED = 13,
  ROLLBACK_STEP = 14,
  ROLLBACK_COMPLETED = 15,
  REVOKE = 16,
  RETIRE = 17,
  RECOVERY = 18,
  EPOCH_ADVANCE = 19,
  WORKER_FENCE = 20,
  STEP_READY = 21,
};

inline constexpr std::uint32_t kChangeReasonCount = 21;

[[nodiscard]] std::string_view to_string(ChangeReason reason) noexcept;

}  // namespace rc
