#include "rc/lifecycle.hpp"

#include <algorithm>

namespace rc {
namespace {

using Rule = PlanTransitionRule;
using SRule = StepTransitionRule;

// The complete plan transition table.  Any pair that is absent is denied.
const std::vector<Rule>& plan_rules() {
  static const std::vector<Rule> rules = {
      {PlanLifecycle::DECLARED, PlanEvent::DECLARE, PlanLifecycle::VALIDATING},
      {PlanLifecycle::VALIDATING, PlanEvent::VALIDATE_OK, PlanLifecycle::READY},
      {PlanLifecycle::VALIDATING, PlanEvent::VALIDATE_FAIL, PlanLifecycle::REVOKED},
      {PlanLifecycle::VALIDATING, PlanEvent::MARK_READY, PlanLifecycle::READY},
      {PlanLifecycle::PAUSED, PlanEvent::MARK_READY, PlanLifecycle::READY},
      {PlanLifecycle::READY, PlanEvent::DISPATCH, PlanLifecycle::EXECUTING},
      {PlanLifecycle::EXECUTING, PlanEvent::DISPATCH, PlanLifecycle::EXECUTING},
      {PlanLifecycle::EXECUTING, PlanEvent::STEP_COMPLETED, PlanLifecycle::EXECUTING},
      {PlanLifecycle::EXECUTING, PlanEvent::STEP_FAILED, PlanLifecycle::PAUSED},
      {PlanLifecycle::EXECUTING, PlanEvent::STEP_FAILED, PlanLifecycle::ROLLBACK_REQUIRED},
      {PlanLifecycle::EXECUTING, PlanEvent::STEP_AMBIGUOUS, PlanLifecycle::PAUSED},
      {PlanLifecycle::EXECUTING, PlanEvent::ALL_STEPS_TERMINAL, PlanLifecycle::COMPLETED},
      {PlanLifecycle::VALIDATING, PlanEvent::PAUSE, PlanLifecycle::PAUSED},
      {PlanLifecycle::READY, PlanEvent::PAUSE, PlanLifecycle::PAUSED},
      {PlanLifecycle::EXECUTING, PlanEvent::PAUSE, PlanLifecycle::PAUSED},
      {PlanLifecycle::PAUSED, PlanEvent::RESUME, PlanLifecycle::READY},
      {PlanLifecycle::VALIDATING, PlanEvent::INVALIDATE, PlanLifecycle::REVALIDATION_REQUIRED},
      {PlanLifecycle::READY, PlanEvent::INVALIDATE, PlanLifecycle::REVALIDATION_REQUIRED},
      {PlanLifecycle::EXECUTING, PlanEvent::INVALIDATE, PlanLifecycle::REVALIDATION_REQUIRED},
      {PlanLifecycle::PAUSED, PlanEvent::INVALIDATE, PlanLifecycle::REVALIDATION_REQUIRED},
      {PlanLifecycle::VALIDATING, PlanEvent::REVALIDATE_OK, PlanLifecycle::READY},
      {PlanLifecycle::REVALIDATION_REQUIRED, PlanEvent::REVALIDATE_OK, PlanLifecycle::READY},
      {PlanLifecycle::PAUSED, PlanEvent::REVALIDATE_OK, PlanLifecycle::READY},
      {PlanLifecycle::REVALIDATION_REQUIRED, PlanEvent::REVALIDATE_FAIL,
       PlanLifecycle::REVALIDATION_REQUIRED},
      {PlanLifecycle::PAUSED, PlanEvent::REVALIDATE_FAIL, PlanLifecycle::PAUSED},
      {PlanLifecycle::VALIDATING, PlanEvent::REQUIRE_ROLLBACK, PlanLifecycle::ROLLBACK_REQUIRED},
      {PlanLifecycle::READY, PlanEvent::REQUIRE_ROLLBACK, PlanLifecycle::ROLLBACK_REQUIRED},
      {PlanLifecycle::EXECUTING, PlanEvent::REQUIRE_ROLLBACK, PlanLifecycle::ROLLBACK_REQUIRED},
      {PlanLifecycle::PAUSED, PlanEvent::REQUIRE_ROLLBACK, PlanLifecycle::ROLLBACK_REQUIRED},
      {PlanLifecycle::REVALIDATION_REQUIRED, PlanEvent::REQUIRE_ROLLBACK,
       PlanLifecycle::ROLLBACK_REQUIRED},
      {PlanLifecycle::ROLLBACK_REQUIRED, PlanEvent::BEGIN_ROLLBACK, PlanLifecycle::ROLLING_BACK},
      {PlanLifecycle::ROLLING_BACK, PlanEvent::ROLLBACK_STEP_COMPLETED,
       PlanLifecycle::ROLLING_BACK},
      {PlanLifecycle::ROLLING_BACK, PlanEvent::ROLLBACK_FAILED, PlanLifecycle::PAUSED},
      {PlanLifecycle::ROLLING_BACK, PlanEvent::ROLLBACK_COMPLETED, PlanLifecycle::SUPERSEDED},
      {PlanLifecycle::DECLARED, PlanEvent::SUPERSEDE, PlanLifecycle::SUPERSEDED},
      {PlanLifecycle::VALIDATING, PlanEvent::SUPERSEDE, PlanLifecycle::SUPERSEDED},
      {PlanLifecycle::READY, PlanEvent::SUPERSEDE, PlanLifecycle::SUPERSEDED},
      {PlanLifecycle::EXECUTING, PlanEvent::SUPERSEDE, PlanLifecycle::SUPERSEDED},
      {PlanLifecycle::PAUSED, PlanEvent::SUPERSEDE, PlanLifecycle::SUPERSEDED},
      {PlanLifecycle::REVALIDATION_REQUIRED, PlanEvent::SUPERSEDE, PlanLifecycle::SUPERSEDED},
      {PlanLifecycle::ROLLBACK_REQUIRED, PlanEvent::SUPERSEDE, PlanLifecycle::SUPERSEDED},
      {PlanLifecycle::ROLLING_BACK, PlanEvent::SUPERSEDE, PlanLifecycle::SUPERSEDED},
      {PlanLifecycle::DECLARED, PlanEvent::REVOKE, PlanLifecycle::REVOKED},
      {PlanLifecycle::VALIDATING, PlanEvent::REVOKE, PlanLifecycle::REVOKED},
      {PlanLifecycle::READY, PlanEvent::REVOKE, PlanLifecycle::REVOKED},
      {PlanLifecycle::EXECUTING, PlanEvent::REVOKE, PlanLifecycle::REVOKED},
      {PlanLifecycle::PAUSED, PlanEvent::REVOKE, PlanLifecycle::REVOKED},
      {PlanLifecycle::REVALIDATION_REQUIRED, PlanEvent::REVOKE, PlanLifecycle::REVOKED},
      {PlanLifecycle::ROLLBACK_REQUIRED, PlanEvent::REVOKE, PlanLifecycle::REVOKED},
      {PlanLifecycle::DECLARED, PlanEvent::RETIRE, PlanLifecycle::RETIRED},
      {PlanLifecycle::PAUSED, PlanEvent::RETIRE, PlanLifecycle::RETIRED},
      {PlanLifecycle::REVALIDATION_REQUIRED, PlanEvent::RETIRE, PlanLifecycle::RETIRED},
      {PlanLifecycle::ROLLBACK_REQUIRED, PlanEvent::RETIRE, PlanLifecycle::RETIRED},
      {PlanLifecycle::COMPLETED, PlanEvent::RETIRE, PlanLifecycle::RETIRED},
      {PlanLifecycle::SUPERSEDED, PlanEvent::RETIRE, PlanLifecycle::RETIRED},
      {PlanLifecycle::REVOKED, PlanEvent::RETIRE, PlanLifecycle::RETIRED},
      {PlanLifecycle::DECLARED, PlanEvent::RECOVER, PlanLifecycle::VALIDATING},
      {PlanLifecycle::VALIDATING, PlanEvent::RECOVER, PlanLifecycle::VALIDATING},
      {PlanLifecycle::READY, PlanEvent::RECOVER, PlanLifecycle::REVALIDATION_REQUIRED},
      {PlanLifecycle::EXECUTING, PlanEvent::RECOVER, PlanLifecycle::REVALIDATION_REQUIRED},
      {PlanLifecycle::PAUSED, PlanEvent::RECOVER, PlanLifecycle::PAUSED},
      {PlanLifecycle::REVALIDATION_REQUIRED, PlanEvent::RECOVER,
       PlanLifecycle::REVALIDATION_REQUIRED},
      {PlanLifecycle::ROLLBACK_REQUIRED, PlanEvent::RECOVER, PlanLifecycle::ROLLBACK_REQUIRED},
      // A governed rollback that was interrupted resumes as a rollback: its
      // rollback plan is durable and is revalidated before any of its steps run.
      {PlanLifecycle::ROLLING_BACK, PlanEvent::RECOVER, PlanLifecycle::ROLLING_BACK},
  };
  return rules;
}

// The complete step transition table.  Any pair that is absent is denied.
const std::vector<SRule>& step_rules() {
  static const std::vector<SRule> rules = {
      {StepLifecycle::PENDING, StepEvent::DECLARE, StepLifecycle::PENDING},
      {StepLifecycle::PENDING, StepEvent::MARK_READY, StepLifecycle::READY},
      {StepLifecycle::FAILED, StepEvent::MARK_READY, StepLifecycle::READY},
      {StepLifecycle::READY, StepEvent::DISPATCH, StepLifecycle::DISPATCHED},
      {StepLifecycle::DISPATCHED, StepEvent::COMPLETE, StepLifecycle::COMPLETED},
      {StepLifecycle::DISPATCHED, StepEvent::FAIL_RETRYABLE, StepLifecycle::FAILED},
      {StepLifecycle::DISPATCHED, StepEvent::FAIL_PERMANENT, StepLifecycle::FAILED},
      {StepLifecycle::DISPATCHED, StepEvent::MARK_AMBIGUOUS,
       StepLifecycle::RECONCILIATION_REQUIRED},
      {StepLifecycle::RECONCILIATION_REQUIRED, StepEvent::RECONCILE_APPLIED,
       StepLifecycle::COMPLETED},
      {StepLifecycle::RECONCILIATION_REQUIRED, StepEvent::RECONCILE_NOT_APPLIED,
       StepLifecycle::READY},
      {StepLifecycle::PENDING, StepEvent::MARK_STALE, StepLifecycle::STALE},
      {StepLifecycle::READY, StepEvent::MARK_STALE, StepLifecycle::STALE},
      {StepLifecycle::DISPATCHED, StepEvent::MARK_STALE, StepLifecycle::STALE},
      {StepLifecycle::FAILED, StepEvent::MARK_STALE, StepLifecycle::STALE},
      {StepLifecycle::RECONCILIATION_REQUIRED, StepEvent::MARK_STALE, StepLifecycle::STALE},
      {StepLifecycle::PENDING, StepEvent::SKIP, StepLifecycle::SKIPPED},
      {StepLifecycle::READY, StepEvent::SKIP, StepLifecycle::SKIPPED},
      {StepLifecycle::FAILED, StepEvent::SKIP, StepLifecycle::SKIPPED},
      {StepLifecycle::COMPLETED, StepEvent::BEGIN_ROLLBACK, StepLifecycle::ROLLBACK_PENDING},
      {StepLifecycle::ROLLBACK_PENDING, StepEvent::ROLLBACK_COMPLETE, StepLifecycle::ROLLED_BACK},
      {StepLifecycle::ROLLBACK_PENDING, StepEvent::ROLLBACK_FAIL, StepLifecycle::FAILED},
      {StepLifecycle::COMPLETED, StepEvent::RETIRE, StepLifecycle::RETIRED},
      {StepLifecycle::SKIPPED, StepEvent::RETIRE, StepLifecycle::RETIRED},
      {StepLifecycle::ROLLED_BACK, StepEvent::RETIRE, StepLifecycle::RETIRED},
      {StepLifecycle::STALE, StepEvent::RETIRE, StepLifecycle::RETIRED},
      {StepLifecycle::FAILED, StepEvent::RETIRE, StepLifecycle::RETIRED},
      // Recovery never turns an in-flight step into a completed one.
      {StepLifecycle::DISPATCHED, StepEvent::RECOVER, StepLifecycle::RECONCILIATION_REQUIRED},
      {StepLifecycle::PENDING, StepEvent::RECOVER, StepLifecycle::PENDING},
      {StepLifecycle::READY, StepEvent::RECOVER, StepLifecycle::READY},
      {StepLifecycle::COMPLETED, StepEvent::RECOVER, StepLifecycle::COMPLETED},
      {StepLifecycle::FAILED, StepEvent::RECOVER, StepLifecycle::FAILED},
      {StepLifecycle::SKIPPED, StepEvent::RECOVER, StepLifecycle::SKIPPED},
      // Recovery re-arms a stale step: it never completed, so it may run again
      // once the plan's authority has been re-established.
      {StepLifecycle::STALE, StepEvent::RECOVER, StepLifecycle::PENDING},
      {StepLifecycle::ROLLED_BACK, StepEvent::RECOVER, StepLifecycle::ROLLED_BACK},
      {StepLifecycle::ROLLBACK_PENDING, StepEvent::RECOVER, StepLifecycle::ROLLBACK_PENDING},
      {StepLifecycle::RECONCILIATION_REQUIRED, StepEvent::RECOVER,
       StepLifecycle::RECONCILIATION_REQUIRED},
      {StepLifecycle::RETIRED, StepEvent::RECOVER, StepLifecycle::RETIRED},
  };
  return rules;
}

}  // namespace

std::string_view to_string(PlanLifecycle lifecycle) noexcept {
  switch (lifecycle) {
    case PlanLifecycle::DECLARED: return "DECLARED";
    case PlanLifecycle::VALIDATING: return "VALIDATING";
    case PlanLifecycle::READY: return "READY";
    case PlanLifecycle::EXECUTING: return "EXECUTING";
    case PlanLifecycle::PAUSED: return "PAUSED";
    case PlanLifecycle::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
    case PlanLifecycle::ROLLBACK_REQUIRED: return "ROLLBACK_REQUIRED";
    case PlanLifecycle::ROLLING_BACK: return "ROLLING_BACK";
    case PlanLifecycle::COMPLETED: return "COMPLETED";
    case PlanLifecycle::SUPERSEDED: return "SUPERSEDED";
    case PlanLifecycle::REVOKED: return "REVOKED";
    case PlanLifecycle::RETIRED: return "RETIRED";
  }
  return "UNKNOWN";
}

bool is_terminal_lifecycle(PlanLifecycle lifecycle) noexcept {
  return lifecycle == PlanLifecycle::COMPLETED || lifecycle == PlanLifecycle::SUPERSEDED ||
         lifecycle == PlanLifecycle::REVOKED || lifecycle == PlanLifecycle::RETIRED;
}

bool is_absolutely_terminal(PlanLifecycle lifecycle) noexcept {
  return lifecycle == PlanLifecycle::RETIRED;
}

bool is_retirable(PlanLifecycle lifecycle) noexcept {
  for (const Rule& rule : plan_rules()) {
    if (rule.from == lifecycle && rule.event == PlanEvent::RETIRE) {
      return true;
    }
  }
  return false;
}

std::string_view to_string(PlanEvent event) noexcept {
  switch (event) {
    case PlanEvent::DECLARE: return "DECLARE";
    case PlanEvent::VALIDATE_OK: return "VALIDATE_OK";
    case PlanEvent::VALIDATE_FAIL: return "VALIDATE_FAIL";
    case PlanEvent::MARK_READY: return "MARK_READY";
    case PlanEvent::DISPATCH: return "DISPATCH";
    case PlanEvent::STEP_COMPLETED: return "STEP_COMPLETED";
    case PlanEvent::STEP_FAILED: return "STEP_FAILED";
    case PlanEvent::STEP_AMBIGUOUS: return "STEP_AMBIGUOUS";
    case PlanEvent::ALL_STEPS_TERMINAL: return "ALL_STEPS_TERMINAL";
    case PlanEvent::PAUSE: return "PAUSE";
    case PlanEvent::RESUME: return "RESUME";
    case PlanEvent::INVALIDATE: return "INVALIDATE";
    case PlanEvent::REVALIDATE_OK: return "REVALIDATE_OK";
    case PlanEvent::REVALIDATE_FAIL: return "REVALIDATE_FAIL";
    case PlanEvent::REQUIRE_ROLLBACK: return "REQUIRE_ROLLBACK";
    case PlanEvent::BEGIN_ROLLBACK: return "BEGIN_ROLLBACK";
    case PlanEvent::ROLLBACK_STEP_COMPLETED: return "ROLLBACK_STEP_COMPLETED";
    case PlanEvent::ROLLBACK_FAILED: return "ROLLBACK_FAILED";
    case PlanEvent::ROLLBACK_COMPLETED: return "ROLLBACK_COMPLETED";
    case PlanEvent::SUPERSEDE: return "SUPERSEDE";
    case PlanEvent::REVOKE: return "REVOKE";
    case PlanEvent::RETIRE: return "RETIRE";
    case PlanEvent::RECOVER: return "RECOVER";
  }
  return "UNKNOWN";
}

const std::vector<PlanTransitionRule>& plan_transition_table() { return plan_rules(); }

bool plan_lifecycle_allows(PlanLifecycle state, PlanEvent event) noexcept {
  // Static table legality only: an event that is legal at all in this state is
  // allowed here, independently of the transition inputs, which the caller
  // supplies separately to apply_plan_event.
  for (const Rule& rule : plan_rules()) {
    if (rule.from == state && rule.event == event) {
      return true;
    }
  }
  return false;
}

std::optional<PlanLifecycle> apply_plan_event(PlanLifecycle state, PlanEvent event,
                                              const PlanTransitionInputs& inputs) noexcept {
  std::optional<PlanLifecycle> found;
  for (const Rule& rule : plan_rules()) {
    if (rule.from != state || rule.event != event) {
      continue;
    }
    found = rule.to;
    break;
  }
  if (!found.has_value()) {
    return std::nullopt;
  }
  switch (event) {
    case PlanEvent::STEP_FAILED:
      // A permanent failure under a policy that requires rollback moves the plan
      // to ROLLBACK_REQUIRED instead of merely pausing it.
      return inputs.rollback_required ? PlanLifecycle::ROLLBACK_REQUIRED : PlanLifecycle::PAUSED;
    case PlanEvent::ALL_STEPS_TERMINAL:
      return inputs.mandatory_steps_terminal ? found : std::nullopt;
    case PlanEvent::REVALIDATE_OK:
      if (!inputs.target_current || !inputs.dependency_current || !inputs.policy_current) {
        return std::nullopt;
      }
      return found;
    default:
      return found;
  }
}

std::string_view to_string(StepLifecycle state) noexcept {
  switch (state) {
    case StepLifecycle::PENDING: return "PENDING";
    case StepLifecycle::READY: return "READY";
    case StepLifecycle::DISPATCHED: return "DISPATCHED";
    case StepLifecycle::COMPLETED: return "COMPLETED";
    case StepLifecycle::FAILED: return "FAILED";
    case StepLifecycle::STALE: return "STALE";
    case StepLifecycle::SKIPPED: return "SKIPPED";
    case StepLifecycle::ROLLBACK_PENDING: return "ROLLBACK_PENDING";
    case StepLifecycle::ROLLED_BACK: return "ROLLED_BACK";
    case StepLifecycle::RECONCILIATION_REQUIRED: return "RECONCILIATION_REQUIRED";
    case StepLifecycle::RETIRED: return "RETIRED";
  }
  return "UNKNOWN";
}

bool is_step_terminal(StepLifecycle state) noexcept {
  switch (state) {
    case StepLifecycle::COMPLETED:
    case StepLifecycle::FAILED:
    case StepLifecycle::STALE:
    case StepLifecycle::SKIPPED:
    case StepLifecycle::ROLLED_BACK:
    case StepLifecycle::RETIRED:
      return true;
    default:
      return false;
  }
}

bool is_step_satisfied(StepLifecycle state) noexcept {
  return state == StepLifecycle::COMPLETED || state == StepLifecycle::SKIPPED;
}

std::string_view to_string(StepEvent event) noexcept {
  switch (event) {
    case StepEvent::DECLARE: return "DECLARE";
    case StepEvent::MARK_READY: return "MARK_READY";
    case StepEvent::DISPATCH: return "DISPATCH";
    case StepEvent::COMPLETE: return "COMPLETE";
    case StepEvent::FAIL_RETRYABLE: return "FAIL_RETRYABLE";
    case StepEvent::FAIL_PERMANENT: return "FAIL_PERMANENT";
    case StepEvent::MARK_AMBIGUOUS: return "MARK_AMBIGUOUS";
    case StepEvent::RECONCILE_APPLIED: return "RECONCILE_APPLIED";
    case StepEvent::RECONCILE_NOT_APPLIED: return "RECONCILE_NOT_APPLIED";
    case StepEvent::MARK_STALE: return "MARK_STALE";
    case StepEvent::SKIP: return "SKIP";
    case StepEvent::BEGIN_ROLLBACK: return "BEGIN_ROLLBACK";
    case StepEvent::ROLLBACK_COMPLETE: return "ROLLBACK_COMPLETE";
    case StepEvent::ROLLBACK_FAIL: return "ROLLBACK_FAIL";
    case StepEvent::RETIRE: return "RETIRE";
    case StepEvent::RECOVER: return "RECOVER";
  }
  return "UNKNOWN";
}

const std::vector<StepTransitionRule>& step_transition_table() { return step_rules(); }

bool step_lifecycle_allows(StepLifecycle state, StepEvent event) noexcept {
  for (const SRule& rule : step_rules()) {
    if (rule.from == state && rule.event == event) {
      return true;
    }
  }
  return false;
}

std::optional<StepLifecycle> apply_step_event(StepLifecycle state, StepEvent event) noexcept {
  for (const SRule& rule : step_rules()) {
    if (rule.from == state && rule.event == event) {
      return rule.to;
    }
  }
  return std::nullopt;
}

std::string_view to_string(CurrentnessCause cause) noexcept {
  switch (cause) {
    case CurrentnessCause::STALE_TARGET_ROUTE: return "STALE_TARGET_ROUTE";
    case CurrentnessCause::STALE_SOURCE_ROUTE: return "STALE_SOURCE_ROUTE";
    case CurrentnessCause::STALE_PATH_AUTHORITY: return "STALE_PATH_AUTHORITY";
    case CurrentnessCause::STALE_MULTIPATH_SET: return "STALE_MULTIPATH_SET";
    case CurrentnessCause::STALE_ECMP_GENERATION: return "STALE_ECMP_GENERATION";
    case CurrentnessCause::STALE_ASSIGNMENT_GENERATION: return "STALE_ASSIGNMENT_GENERATION";
    case CurrentnessCause::STALE_WEIGHT_POLICY: return "STALE_WEIGHT_POLICY";
    case CurrentnessCause::STALE_EPOCH: return "STALE_EPOCH";
    case CurrentnessCause::STALE_POLICY_GENERATION: return "STALE_POLICY_GENERATION";
    case CurrentnessCause::FENCED_PUBLISHER: return "FENCED_PUBLISHER";
    case CurrentnessCause::SUPERSEDED_BY_SUCCESSOR: return "SUPERSEDED_BY_SUCCESSOR";
    case CurrentnessCause::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
  }
  return "UNKNOWN";
}

void Currentness::add(CurrentnessCause cause) noexcept { bits_ |= mask_of(cause); }

void Currentness::remove(CurrentnessCause cause) noexcept { bits_ &= ~mask_of(cause); }

std::vector<CurrentnessCause> Currentness::causes() const {
  std::vector<CurrentnessCause> out;
  for (std::uint32_t index = 1; index <= kCurrentnessCauseCount; ++index) {
    const auto cause = static_cast<CurrentnessCause>(index);
    if (has(cause)) {
      out.push_back(cause);
    }
  }
  return out;
}

std::string Currentness::render() const {
  if (bits_ == 0) {
    return "current";
  }
  std::string out;
  for (const CurrentnessCause cause : causes()) {
    if (!out.empty()) {
      out += ',';
    }
    out += to_string(cause);
  }
  return out;
}

bool Currentness::authority_current() const noexcept {
  static const std::uint32_t kAuthorityEnding =
      mask_of(CurrentnessCause::STALE_TARGET_ROUTE) |
      mask_of(CurrentnessCause::STALE_PATH_AUTHORITY) |
      mask_of(CurrentnessCause::STALE_MULTIPATH_SET) |
      mask_of(CurrentnessCause::STALE_ECMP_GENERATION) |
      mask_of(CurrentnessCause::STALE_ASSIGNMENT_GENERATION) |
      mask_of(CurrentnessCause::STALE_WEIGHT_POLICY) |
      mask_of(CurrentnessCause::STALE_EPOCH) |
      mask_of(CurrentnessCause::STALE_POLICY_GENERATION) |
      mask_of(CurrentnessCause::FENCED_PUBLISHER) |
      mask_of(CurrentnessCause::SUPERSEDED_BY_SUCCESSOR);
  return (bits_ & kAuthorityEnding) == 0;
}

std::string_view to_string(ChangeReason reason) noexcept {
  switch (reason) {
    case ChangeReason::CREATE: return "CREATE";
    case ChangeReason::VALIDATE: return "VALIDATE";
    case ChangeReason::DISPATCH_STEP: return "DISPATCH_STEP";
    case ChangeReason::COMPLETE_STEP: return "COMPLETE_STEP";
    case ChangeReason::FAIL_STEP: return "FAIL_STEP";
    case ChangeReason::AMBIGUOUS_STEP: return "AMBIGUOUS_STEP";
    case ChangeReason::RECONCILE_STEP: return "RECONCILE_STEP";
    case ChangeReason::PAUSE: return "PAUSE";
    case ChangeReason::RESUME: return "RESUME";
    case ChangeReason::INVALIDATE: return "INVALIDATE";
    case ChangeReason::REVALIDATE: return "REVALIDATE";
    case ChangeReason::SUPERSEDE: return "SUPERSEDE";
    case ChangeReason::ROLLBACK_REQUESTED: return "ROLLBACK_REQUESTED";
    case ChangeReason::ROLLBACK_STEP: return "ROLLBACK_STEP";
    case ChangeReason::ROLLBACK_COMPLETED: return "ROLLBACK_COMPLETED";
    case ChangeReason::REVOKE: return "REVOKE";
    case ChangeReason::RETIRE: return "RETIRE";
    case ChangeReason::RECOVERY: return "RECOVERY";
    case ChangeReason::EPOCH_ADVANCE: return "EPOCH_ADVANCE";
    case ChangeReason::WORKER_FENCE: return "WORKER_FENCE";
    case ChangeReason::STEP_READY: return "STEP_READY";
  }
  return "UNKNOWN";
}

}  // namespace rc
