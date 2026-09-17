#pragma once

// Internal state of the Route Convergence governor.  Not installed: this header
// is private to the library implementation.

#include <deque>
#include <map>
#include <memory>
#include <set>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

#include "rc/convergence.hpp"

namespace rc {

struct AttemptRecord {
  Digest payload;
  Outcome outcome = Outcome::INTERNAL_ERROR;
  ConvergencePlanId plan;
  TransitionStepId step;
  ConvergencePlanGeneration plan_generation;
  TransitionStepGeneration step_generation;
  ConvergenceGeneration convergence_generation;
  Digest digest;
  std::string conditions;
};

struct WorkerRecord {
  PublisherRegistration registration;
  bool live = false;
};

struct GovernorState {
  RouteFabricView& routes;
  PathAuthorityView& paths;
  FabricEpochView& epochs;
  GovernorOptions options;

  mutable std::shared_mutex mutex;

  CoordinatorEpoch epoch;
  ConvergenceGeneration convergence;
  AuthorityGeneration authority_generation = AuthorityGeneration::from_value(1);
  std::filesystem::path store_path;

  std::map<ConvergencePlanId, ConvergencePlan> plans;
  std::map<PlanKey, ConvergencePlanId> by_key;
  std::map<RouteId, std::vector<ConvergencePlanId>> by_route;
  std::map<PathId, std::vector<ConvergencePlanId>> by_path;
  std::map<WorkerBootId, std::vector<std::pair<ConvergencePlanId, TransitionStepId>>> by_boot;
  std::map<PlanLifecycle, std::set<ConvergencePlanId>> by_lifecycle;
  std::map<ConvergencePolicyId, ConvergencePolicy> policies;
  std::map<PublisherId, WorkerRecord> workers;
  // Permanent fences: an administrative fence, or a boot superseded by a newer
  // boot of the same publisher.
  std::set<WorkerBootId> fenced_boots;
  std::map<MutationAttemptId, AttemptRecord> attempts;
  std::deque<MutationAttemptId> attempt_order;
  GovernorStats stats;
  bool coherent = true;
  std::string incoherence_reason;

  GovernorState(RouteFabricView& routes_view, PathAuthorityView& paths_view,
                FabricEpochView& epochs_view, GovernorOptions governor_options)
      : routes(routes_view),
        paths(paths_view),
        epochs(epochs_view),
        options(std::move(governor_options)),
        epoch(options.initial_epoch),
        store_path(options.store_path) {}
};

// --- internal helpers (implemented across the governor translation units) ----

// Advances the governor-wide convergence generation.  Returns false when the
// counter is exhausted, which is a hard failure rather than a wrap.
[[nodiscard]] bool advance_convergence(GovernorState& state);

// Advances a plan's authority generation.  Returns false on exhaustion.
[[nodiscard]] bool advance_authority(GovernorState& state, ConvergencePlan& plan);

// Recomputes plan currentness against the upstream observations.  Returns true
// when the plan still holds live convergence authority.
[[nodiscard]] bool recompute_currentness(GovernorState& state, ConvergencePlan& plan,
                                         ConditionList& conditions);

// Marks a plan as needing revalidation because an authority-ending cause is
// present.
void invalidate_plan(GovernorState& state, ConvergencePlan& plan, CurrentnessCause cause,
                     ChangeReason reason);

// Records one bounded history entry and advances the plan generation when the
// semantic content of the plan changed.  Returns false when the plan generation
// counter is exhausted, which is reported and never wrapped.
[[nodiscard]] bool touch_plan(GovernorState& state, ConvergencePlan& plan, ChangeReason reason,
                              ConditionCode condition, const TransitionStepId& step);

// Recomputes PENDING to READY for every step whose prerequisites are satisfied.
void refresh_ready_steps(GovernorState& state, ConvergencePlan& plan);

// Marks every DISPATCHED step of the plan as stale.
void stale_in_flight_steps(GovernorState& state, ConvergencePlan& plan);

// Marks every step dispatched by one worker boot as stale and requires fresh
// revalidation of exactly the plans that had such work in flight.  Plans the boot
// merely owned are untouched: a plan's currentness does not depend on which
// process acted on it last.
void stale_in_flight_steps_of_boot(GovernorState& state, const WorkerBootId& boot,
                                   ChangeReason reason);

void index_plan(GovernorState& state, const ConvergencePlan& plan);
void reindex_plan(GovernorState& state, const ConvergencePlan& plan);
void deindex_plan(GovernorState& state, const ConvergencePlan& plan);

// Records the outcome of an attempt so that an exact replay is recognised and a
// conflicting replay is refused.
void record_attempt(GovernorState& state, const AuthorityContext& authority, const Digest& payload,
                    const PlanMutationResult& result);

enum class AttemptCheck : std::uint32_t { FRESH = 0, REPLAY = 1, CONFLICT = 2 };

[[nodiscard]] AttemptCheck check_attempt(GovernorState& state, const AuthorityContext& authority,
                                         const Digest& payload, PlanMutationResult& replay_result);

// Authority verification.  Fills `condition` and returns false when the claim is
// not authorized for the exact route and plan.
[[nodiscard]] bool authorize(GovernorState& state, const AuthorityContext& authority,
                             Capability capability, const RouteId& route,
                             const ConvergencePlanId& plan, Condition& condition);

// Worker fencing.  A fenced boot is fenced permanently for the life of the store.
void fence_boot(GovernorState& state, const WorkerBootId& boot, ChangeReason reason);

// Epoch application.  Used by the explicit notice path and by the defensive
// re-observation performed at the start of every mutation.
void apply_epoch(GovernorState& state, CoordinatorEpoch next, ChangeReason reason,
                 ProvenanceId provenance);

[[nodiscard]] PlanMutationResult make_result(const GovernorState& state, Outcome outcome,
                                             const ConvergencePlan& plan);
[[nodiscard]] PlanMutationResult make_result(const GovernorState& state, Outcome outcome,
                                             const ConvergencePlan& plan, ConditionCode code,
                                             std::string_view subject,
                                             std::uint64_t observed = 0,
                                             std::uint64_t expected = 0);
[[nodiscard]] PlanMutationResult rejection(Outcome outcome, ConditionCode code,
                                           std::string_view subject,
                                           std::uint64_t observed = 0,
                                           std::uint64_t expected = 0);

[[nodiscard]] ConvergenceSnapshot build_snapshot(const GovernorState& state,
                                                 const ConvergencePlan& plan);

[[nodiscard]] Digest request_digest(std::string_view domain, const PlanKey& key,
                                    const std::string& extra);

// Domain-separated digest of an operation payload that is not a plan request.
[[nodiscard]] Digest text_digest(std::string_view domain, std::string_view text);

// Attempt gate shared by every mutating entry point.  Returns true when the
// caller must return \`early\` immediately: a replay of the same attempt with the
// same payload is IDEMPOTENT and a reuse with a different payload is a conflict.
[[nodiscard]] bool attempt_gate(GovernorState& state, const AuthorityContext& authority,
                                const Digest& payload, PlanMutationResult& early);

[[nodiscard]] ProvenanceId epoch_provenance(CoordinatorEpoch epoch);

// The route generation a plan must still observe to be executing against reality.
// A forward plan targets the new generation; a rollback plan compensates a state
// that is still the current one even though its target is an older generation.
[[nodiscard]] inline RouteGeneration expected_observation(const ConvergencePlan& plan) {
  return plan.is_rollback ? plan.key.source_generation : plan.key.target_generation;
}

// True when this publisher/boot pair is registered, live and not fenced.
[[nodiscard]] bool worker_live_locked(const GovernorState& state, const PublisherId& publisher,
                                      const WorkerBootId& boot);

// Moves one plan to SUPERSEDED, recording the lineage.  Does nothing when the
// transition is not legal in the plan's current lifecycle.
void supersede_entry(GovernorState& state, const ConvergencePlanId& id, ChangeReason reason,
                     const ConvergencePlanId& successor);

}  // namespace rc

// The governor holds its state through one private implementation object so that
// the public header stays free of the internal state layout.
struct rc::ConvergenceGovernor::Impl {
  std::unique_ptr<GovernorState> state;
};
