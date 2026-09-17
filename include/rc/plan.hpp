#pragma once

#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "rc/digest.hpp"
#include "rc/identity.hpp"
#include "rc/lifecycle.hpp"
#include "rc/outcome.hpp"
#include "rc/policy.hpp"
#include "rc/step.hpp"
#include "rc/upstream.hpp"

namespace rc {

// Semantic uniqueness of a convergence plan.  Two requests with the same key are
// the same *semantic* plan; a request whose content differs while the key is
// unchanged produces a different plan identity and supersedes the earlier one.
// Exact replay of the same semantic plan is idempotent and advances nothing.
struct PlanKey {
  RouteId route;
  RouteGeneration source_generation;
  RouteGeneration target_generation;
  ConvergencePolicyGeneration policy_generation;

  [[nodiscard]] bool is_well_formed() const noexcept;
  [[nodiscard]] Digest content_digest() const;
  [[nodiscard]] std::string render() const;

  friend bool operator==(const PlanKey&, const PlanKey&) = default;
  friend auto operator<=>(const PlanKey&, const PlanKey&) = default;
};

enum class PlanMode : std::uint32_t {
  // Steps are generated deterministically from the bindings and the policy.
  GENERATED = 1,
  // Steps are supplied by the caller and validated by the governor: DAG
  // legality, conflict domains, resource limits and policy conformance.
  EXPLICIT = 2,
};

[[nodiscard]] std::string_view to_string(PlanMode mode) noexcept;

struct PlanRequest {
  PlanMode mode = PlanMode::GENERATED;
  RouteBinding source;
  RouteBinding target;
  // The policy is bound by identity *and* generation, and the generation must be
  // the one the governor currently holds for that policy identity.
  ConvergencePolicy policy;
  CoordinatorEpoch epoch;
  ProvenanceId provenance;
  // Planning from an old source generation is refused unless the caller states
  // explicitly that the source is historical.  Ambiguous currentness is never
  // planned from.
  bool accept_historical_source = false;
  // EXPLICIT mode: complete step list, including prerequisites.
  std::vector<StepSpec> explicit_steps;

  [[nodiscard]] bool is_well_formed() const noexcept;
};

// One bounded history entry.  History is a semantic audit trail, not a log: it
// contains no timestamps, no thread identifiers and no process-local counters.
struct PlanChange {
  ChangeReason reason = ChangeReason::CREATE;
  ConvergencePlanGeneration plan_generation;
  ConvergenceGeneration convergence_generation;
  ConditionCode condition = ConditionCode::NONE;
  TransitionStepId step;
  StepLifecycle step_state = StepLifecycle::PENDING;
  std::uint64_t observed = 0;
  std::uint64_t expected = 0;
};

// A convergence plan is a first-class governed object.  Its identity is derived
// from its semantic content, so it does not depend on memory address, insertion
// order or arrival order.
struct ConvergencePlan {
  ConvergencePlanId id;
  PlanKey key;
  ConvergencePlanGeneration generation;
  PlanLifecycle lifecycle = PlanLifecycle::DECLARED;
  Currentness currentness;
  ConvergencePolicy policy;
  RouteBinding source;
  RouteBinding target;
  PlanMode mode = PlanMode::GENERATED;
  CoordinatorEpoch created_epoch;
  CoordinatorEpoch bound_epoch;
  ProvenanceId provenance;
  // The publisher and worker boot that most recently acted on this plan.  It is
  // what "which publisher/epoch owns this transition" answers, and it is how a
  // fenced publisher is detected without scanning the step records.
  PublisherId owner_publisher;
  WorkerBootId owner_boot;
  AuthorityGeneration authority_generation;
  std::vector<TransitionStep> steps;  // canonical order
  std::vector<std::vector<TransitionStepId>> layers;
  Digest digest;
  // Plan invalidation watermark.  It advances on every event that invalidates
  // in-flight work for this plan and records the governor-wide convergence
  // generation at that moment, so a completion dispatched before the event can
  // never be mistaken for a completion after it.
  ConvergenceGeneration watermark;
  // Lineage.  Supersession is never silent.
  ConvergencePlanId predecessor;
  ConvergencePlanId successor;
  ChangeReason supersession_reason = ChangeReason::CREATE;
  ConvergencePlanId rollback_plan;
  bool rollback_required = false;
  bool is_rollback = false;
  // Last condition recorded for this plan.  It is diagnostic provenance, not
  // semantic state, so it is deliberately excluded from the plan digest.
  ConditionCode last_condition = ConditionCode::NONE;
  std::vector<PlanChange> history;

  [[nodiscard]] bool is_well_formed() const noexcept;
  [[nodiscard]] const TransitionStep* find_step(const TransitionStepId& step) const noexcept;
  [[nodiscard]] TransitionStep* find_step(const TransitionStepId& step) noexcept;
  [[nodiscard]] std::optional<ConvergencePlanGeneration> next_generation() const noexcept;
};

// Immutable structural digest over the plan identity, its exact bindings, its
// policy generation and its canonical step DAG.  It excludes mutable lifecycle
// and step state, which is why it can be the basis of a stable plan identity: the
// digest is computed from the canonical topological order of the DAG, so two
// equivalent graphs built in different insertion orders hash identically.
[[nodiscard]] Digest plan_structure_digest(const PlanKey& key, const RouteBinding& source,
                                           const RouteBinding& target,
                                           const ConvergencePolicy& policy, PlanMode mode,
                                           const std::vector<StepSpec>& steps);

// --- snapshots --------------------------------------------------------------

struct StepSnapshot {
  TransitionStepId id;
  StepKey key;
  TransitionStepGeneration generation;
  StepLifecycle state = StepLifecycle::PENDING;
  std::uint32_t attempts = 0;
  bool mandatory = true;
  bool idempotent = true;
  bool verification = false;
  Reversibility reversibility = Reversibility::COMPENSATABLE;
  std::uint32_t conflict_domains = 0;
  CompletionEvidenceId last_evidence;
  BackendOutcome last_outcome = BackendOutcome::APPLIED;
  MutationAttemptId last_attempt;
  ConvergenceGeneration dispatch_watermark;
  CoordinatorEpoch dispatch_epoch;
  PublisherId dispatch_publisher;
  WorkerBootId dispatch_boot;
  std::vector<StepKey> depends_on;
  bool prerequisites_satisfied = false;
  bool executable = false;
};

// Immutable convergence snapshot.  Once produced it is never mutated; producing
// a second snapshot of the same convergence state yields the same snapshot digest.
struct ConvergenceSnapshot {
  SnapshotId id;
  ConvergencePlanId plan;
  ConvergencePlanGeneration plan_generation;
  PlanLifecycle lifecycle = PlanLifecycle::DECLARED;
  Currentness currentness;
  ConvergencePolicy policy;
  RouteBinding source;
  RouteBinding target;
  PlanMode mode = PlanMode::GENERATED;
  CoordinatorEpoch epoch;
  CoordinatorEpoch created_epoch;
  PublisherId owner_publisher;
  WorkerBootId owner_boot;
  AuthorityGeneration authority_generation;
  ProvenanceId provenance;
  ConvergenceGeneration convergence_generation;
  ConvergenceGeneration watermark;
  ConvergencePlanId predecessor;
  ConvergencePlanId successor;
  ChangeReason supersession_reason = ChangeReason::CREATE;
  ConvergencePlanId rollback_plan;
  bool is_rollback = false;
  std::vector<StepSnapshot> steps;  // canonical order
  std::vector<std::vector<TransitionStepId>> layers;
  Digest digest;
};

// Compact listing entry.
struct PlanSummary {
  ConvergencePlanId id;
  PlanKey key;
  ConvergencePlanGeneration generation;
  PlanLifecycle lifecycle = PlanLifecycle::DECLARED;
  Currentness currentness;
  std::uint32_t total_steps = 0;
  std::uint32_t completed_steps = 0;
  std::uint32_t ready_steps = 0;
  Digest digest;
};

// Bounded plan listing.  A listing that hit the configured batch limit says so
// rather than silently returning a prefix.
struct PlanList {
  std::vector<PlanSummary> plans;
  bool truncated = false;
};

// --- deterministic diffs ----------------------------------------------------

enum class DiffKind : std::uint32_t {
  PLAN_CREATED = 1,
  LIFECYCLE_CHANGED = 2,
  CURRENTNESS_CHANGED = 3,
  STEP_STATE_CHANGED = 4,
  PREREQUISITE_SATISFIED = 5,
  TARGET_SUPERSEDED = 6,
  PATH_DEPENDENCY_STALE = 7,
  ROLLBACK_ENTERED = 8,
  CONVERGENCE_COMPLETED = 9,
  AUTHORITY_CHANGED = 10,
  EPOCH_CHANGED = 11,
  LINEAGE_CHANGED = 12,
};

[[nodiscard]] std::string_view to_string(DiffKind kind) noexcept;

struct DiffEntry {
  DiffKind kind = DiffKind::PLAN_CREATED;
  ConvergencePlanGeneration plan_generation;
  ConvergenceGeneration convergence_generation;
  TransitionStepId step;
  std::string subject;
  std::uint64_t observed = 0;
  std::uint64_t expected = 0;

  [[nodiscard]] std::string render() const;
};

struct ConvergenceDiff {
  ConvergencePlanId plan;
  ConvergencePlanGeneration from_generation;
  ConvergencePlanGeneration to_generation;
  std::vector<DiffEntry> entries;

  [[nodiscard]] std::string render() const;
};

// --- operator explanations --------------------------------------------------

enum class ExplainKind : std::uint32_t {
  PLAN = 1,
  STEP = 2,
  READINESS = 3,
  PREREQUISITE = 4,
  OLD_STATE_RETENTION = 5,
  TARGET_ACTIVATION = 6,
  ROLLBACK = 7,
  STALENESS = 8,
  COMPLETION = 9,
  AUTHORITY = 10,
};

[[nodiscard]] std::string_view to_string(ExplainKind kind) noexcept;

struct ExplainRequest {
  ConvergencePlanId plan;
  TransitionStepId step;
  ExplainKind kind = ExplainKind::PLAN;
};

struct ExplainResponse {
  bool found = false;
  Explanation explanation;
  [[nodiscard]] std::string render() const { return explanation.render(); }
};

// --- results ----------------------------------------------------------------

struct PlanMutationResult {
  Outcome outcome = Outcome::INTERNAL_ERROR;
  ConvergencePlanId plan;
  TransitionStepId step;
  ConvergencePlanGeneration plan_generation;
  TransitionStepGeneration step_generation;
  ConvergenceGeneration convergence_generation;
  Digest digest;
  ConditionList conditions;

  [[nodiscard]] bool accepted() const noexcept { return is_acceptance(outcome); }
  [[nodiscard]] std::string render() const;
};

struct StepDispatch {
  Outcome outcome = Outcome::INTERNAL_ERROR;
  ConvergencePlanId plan;
  TransitionStepId step;
  TransitionStepGeneration step_generation;
  ConvergenceGeneration watermark;
  CoordinatorEpoch epoch;
  StepSpec spec;
  ConditionList conditions;

  [[nodiscard]] bool accepted() const noexcept { return is_acceptance(outcome); }
};

struct ReadyStep {
  ConvergencePlanId plan;
  TransitionStepId step;
  StepKey key;
  TransitionStepGeneration generation;
  ConvergenceGeneration watermark;
  RouteId route;
  StepSpec spec;
};

struct ReadyStepList {
  std::vector<ReadyStep> steps;
  bool truncated = false;

  [[nodiscard]] std::string render() const;
};

}  // namespace rc
