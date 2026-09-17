#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "rc/authority.hpp"
#include "rc/graph.hpp"
#include "rc/persistence.hpp"
#include "rc/plan.hpp"
#include "rc/upstream.hpp"

namespace rc {

struct GovernorOptions {
  ConvergenceLimits limits;
  CoordinatorEpoch initial_epoch = CoordinatorEpoch::from_value(1);
  // The coordinator's own fabric and namespace identity.  A nil field means the
  // identity is not asserted, and a scope that asserts it is then accepted.
  FabricId fabric;
  RoutingNamespaceId routing_namespace;
  std::filesystem::path store_path;  // empty disables durable autosave
  bool autosave = true;
  bool provenance_stamp = true;
};

// Diagnostic counters.  They are observations about this process, never
// authority: they are excluded from every semantic digest, they are never
// persisted and they never decide an outcome.
struct GovernorStats {
  std::uint64_t plans_created = 0;
  std::uint64_t plans_completed = 0;
  std::uint64_t plans_superseded = 0;
  std::uint64_t plans_revoked = 0;
  std::uint64_t plans_retired = 0;
  std::uint64_t plans_invalidated = 0;
  std::uint64_t steps_dispatched = 0;
  std::uint64_t steps_completed = 0;
  std::uint64_t steps_failed = 0;
  std::uint64_t steps_staled = 0;
  std::uint64_t stale_completions_rejected = 0;
  std::uint64_t ambiguous_steps = 0;
  std::uint64_t reconciliations = 0;
  std::uint64_t rollbacks_started = 0;
  std::uint64_t rollbacks_rejected = 0;
  std::uint64_t rollback_steps = 0;
  std::uint64_t epoch_advances = 0;
  std::uint64_t worker_fences = 0;
  std::uint64_t recoveries = 0;
  std::uint64_t policies_defined = 0;
  std::uint64_t workers_registered = 0;
  std::uint64_t attempt_replays = 0;
  std::uint64_t attempt_conflicts = 0;
  std::uint64_t autonomous_progress_loops = 0;
};

// Result of applying an upstream notice.  A notice may affect many plans, so the
// result reports what actually happened rather than collapsing it into one plan.
struct NoticeResult {
  Outcome outcome = Outcome::INTERNAL_ERROR;
  CoordinatorEpoch epoch;
  ConvergenceGeneration convergence_generation;
  std::uint32_t plans_examined = 0;
  std::uint32_t plans_invalidated = 0;
  std::uint32_t plans_superseded = 0;
  std::uint32_t steps_staled = 0;
  ConditionList conditions;

  [[nodiscard]] bool accepted() const noexcept { return is_acceptance(outcome); }
};

// --- deterministic step generation -----------------------------------------

// Deterministic step generation.  Same source state, same target state, same
// policy and same limits always produce the same step list in the same canonical
// order, and the resulting plan digest is identical.
[[nodiscard]] std::optional<std::vector<StepSpec>> generate_steps(
    const RouteBinding& source, const RouteBinding& target, const ConvergencePolicy& policy,
    const ConvergenceLimits& limits, std::string& reason);

// Policy conformance of a step graph: under MAKE_BEFORE_BREAK every break-side
// step must be a transitive successor of the required make-side and verification
// steps; under BREAK_BEFORE_MAKE the reverse holds.
[[nodiscard]] GraphValidation validate_policy_conformance(const std::vector<StepSpec>& steps,
                                                          const ConvergencePolicy& policy,
                                                          const ConvergenceLimits& limits);

// The single authoritative convergence coordinator.
//
// Concurrency: every public method is thread safe.  Queries take a shared lock;
// mutations take an exclusive lock.  The upstream views are read while a lock is
// held, so an implementation must be a pure in-memory observation and must never
// call back into the governor.  No external I/O ever happens under the lock: a
// worker performs the external operation in its own process, and persistence
// encoding happens under the lock while the file write happens outside it.
//
// Authority: Route Convergence 1.0.0 has exactly one authoritative coordinator
// per durable store.  It is not a consensus system, there is no leader election
// and no split-brain prevention is claimed.
class ConvergenceGovernor {
 public:
  ConvergenceGovernor(RouteFabricView& routes, PathAuthorityView& paths, FabricEpochView& epochs,
                      GovernorOptions options = {});
  ~ConvergenceGovernor();
  ConvergenceGovernor(const ConvergenceGovernor&) = delete;
  ConvergenceGovernor& operator=(const ConvergenceGovernor&) = delete;
  ConvergenceGovernor(ConvergenceGovernor&&) = delete;
  ConvergenceGovernor& operator=(ConvergenceGovernor&&) = delete;

  // Validates a governor configuration before it is used.  An incoherent limit
  // set is refused: a governor built from one rejects every mutation with
  // INTERNAL_INVARIANT instead of silently ignoring a limit.
  [[nodiscard]] static bool validate_options(const GovernorOptions& options, std::string& reason);
  [[nodiscard]] bool coherent() const;

  // --- configuration and observation ---
  [[nodiscard]] const ConvergenceLimits& limits() const noexcept;
  [[nodiscard]] CoordinatorEpoch epoch() const;
  [[nodiscard]] ConvergenceGeneration convergence_generation() const;
  [[nodiscard]] GovernorStats stats() const;
  [[nodiscard]] std::size_t plan_count() const;
  [[nodiscard]] std::size_t worker_count() const;
  [[nodiscard]] const std::filesystem::path& store_path() const;

  // --- convergence policy registry ---
  PlanMutationResult define_policy(const ConvergencePolicy& policy,
                                   const AuthorityContext& authority);
  [[nodiscard]] std::optional<ConvergencePolicy> current_policy(
      const ConvergencePolicyId& id) const;
  [[nodiscard]] std::vector<ConvergencePolicy> list_policies() const;

  // --- worker registry and fencing ---
  PlanMutationResult register_worker(const PublisherRegistration& registration,
                                     const AuthorityContext& authority);
  PlanMutationResult fence_worker(const WorkerBootId& boot, const AuthorityContext& authority);
  // Session loss.  The coordinator calls this when a worker session ends without
  // an administrative fence, so a disconnected worker can never complete work it
  // already had in flight.  It is deliberately not reachable from the wire: a
  // client cannot fence another worker by claiming a session ended, and it only
  // fences the boot that is currently registered for that publisher.
  PlanMutationResult fence_session_loss(const PublisherId& publisher, const WorkerBootId& boot);

  [[nodiscard]] bool is_worker_fenced(const WorkerBootId& boot) const;
  [[nodiscard]] bool is_worker_live(const PublisherId& publisher, const WorkerBootId& boot) const;
  [[nodiscard]] std::vector<PublisherRegistration> list_workers() const;

  // --- plans ---
  PlanMutationResult create_plan(const PlanRequest& request, const AuthorityContext& authority);
  [[nodiscard]] std::optional<PlanSummary> query_plan(const ConvergencePlanId& plan) const;
  [[nodiscard]] PlanList list_plans() const;
  [[nodiscard]] std::optional<ConvergenceSnapshot> snapshot(const ConvergencePlanId& plan) const;
  [[nodiscard]] std::optional<ConvergenceDiff> diff(const ConvergencePlanId& plan,
                                                    ConvergencePlanGeneration from) const;
  [[nodiscard]] ExplainResponse explain(const ExplainRequest& request) const;
  [[nodiscard]] std::optional<PlanKey> plan_key(const ConvergencePlanId& plan) const;

  // --- execution ---
  // Operator view: every ready step the coordinator holds.
  [[nodiscard]] ReadyStepList ready_steps(std::uint32_t max_steps) const;
  // Scoped view: only ready steps inside the presented authority scope.  A
  // worker must never be offered work it is not authorized to dispatch.
  [[nodiscard]] ReadyStepList ready_steps_for(std::uint32_t max_steps,
                                              const AuthorityScope& scope) const;
  [[nodiscard]] std::optional<PublisherRegistration> worker_registration(
      const PublisherId& publisher) const;
  [[nodiscard]] StepDispatch dispatch_step(const ConvergencePlanId& plan,
                                           const TransitionStepId& step,
                                           const AuthorityContext& authority);
  PlanMutationResult complete_step(const CompletionEvidence& evidence,
                                   const AuthorityContext& authority);
  PlanMutationResult fail_step(const ConvergencePlanId& plan, const TransitionStepId& step,
                               BackendOutcome outcome, std::string detail,
                               const AuthorityContext& authority);
  PlanMutationResult reconcile_step(const ConvergencePlanId& plan, const TransitionStepId& step,
                                    bool applied, std::string detail,
                                    const AuthorityContext& authority);
  PlanMutationResult revalidate_plan(const ConvergencePlanId& plan,
                                     const AuthorityContext& authority);
  PlanMutationResult pause_plan(const ConvergencePlanId& plan, ConditionCode cause,
                                const AuthorityContext& authority);
  PlanMutationResult begin_rollback(const ConvergencePlanId& plan,
                                    const AuthorityContext& authority);
  PlanMutationResult retire_plan(const ConvergencePlanId& plan,
                                 const AuthorityContext& authority);
  PlanMutationResult revoke_plan(const ConvergencePlanId& plan, const AuthorityContext& authority);

  // --- upstream notices ---
  NoticeResult note_route_change(const RouteChangeNotice& notice,
                                 const AuthorityContext& authority);
  NoticeResult note_path_change(const PathChangeNotice& notice, const AuthorityContext& authority);
  NoticeResult note_epoch_change(const EpochChangeNotice& notice,
                                 const AuthorityContext& authority);

  // Re-reads the upstream epoch and applies any advance it observes.  Safe to
  // call at any time; the coordinator calls it when it learns of an epoch
  // change, and every mutation performs the same re-observation defensively.
  [[nodiscard]] NoticeResult sync_epoch();

  // --- persistence ---
  PlanMutationResult save(const std::filesystem::path& path);
  PlanMutationResult load(const std::filesystem::path& path);
  [[nodiscard]] std::vector<std::uint8_t> encode_state() const;
  PlanMutationResult decode_state(std::span<const std::uint8_t> payload);

  // --- semantic digests ---
  // Semantic state only: identity, bindings, generations, canonical step DAG,
  // step states, lifecycle, currentness and policy generation.  No timestamp, no
  // thread identifier, no socket, no memory address, no arrival order and no
  // process-local counter participates.
  [[nodiscard]] static Digest plan_content_digest(const ConvergencePlan& plan);
  [[nodiscard]] static Digest snapshot_digest(const ConvergenceSnapshot& snapshot);
  [[nodiscard]] static Digest policy_digest(const ConvergencePolicy& policy);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// Convenience: derive a deterministic publisher/boot pair for fixtures.
[[nodiscard]] PublisherId derive_publisher_id(std::uint64_t seed);
[[nodiscard]] WorkerBootId derive_worker_boot_id(std::uint64_t seed);
[[nodiscard]] ProvenanceId derive_provenance_id(std::uint64_t seed);

}  // namespace rc
