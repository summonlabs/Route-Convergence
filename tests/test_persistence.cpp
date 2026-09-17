// Durable-state proofs for Route Convergence: the store file and the durable
// state payload are exercised byte by byte, and every recovery claim is checked
// against the governor's own conservative transition rules.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <process.h>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "fixture.hpp"
#include "test_framework.hpp"

using namespace rc;  // NOLINT(google-build-using-namespace): a test translation unit.

namespace {

using Bytes = std::vector<std::uint8_t>;

// No fixed path is used anywhere: the directory is derived from this process
// id, so two test processes can never collide over a store file.
[[nodiscard]] std::filesystem::path temp_root() {
  std::filesystem::path root = std::filesystem::temp_directory_path();
  root /= "rc-persistence-" + std::to_string(::_getpid());
  return root;
}

class TempStore {
 public:
  explicit TempStore(std::string_view name) : directory_(temp_root() / std::string(name)) {
    std::error_code code;
    const bool created = std::filesystem::create_directories(directory_, code);
    (void)created;
  }
  TempStore(const TempStore&) = delete;
  TempStore& operator=(const TempStore&) = delete;
  ~TempStore() {
    std::error_code code;
    const std::uintmax_t removed = std::filesystem::remove_all(directory_, code);
    (void)removed;
  }
  [[nodiscard]] std::filesystem::path path(std::string_view name) const {
    return directory_ / std::string(name);
  }
 private:
  std::filesystem::path directory_;
};

[[nodiscard]] const ReadyStep* first_ready_step(const ReadyStepList& ready,
                                                const ConvergencePlanId& plan) {
  for (const ReadyStep& step : ready.steps) {
    if (step.plan == plan) {
      return &step;
    }
  }
  return nullptr;
}

[[nodiscard]] const StepSnapshot* find_step(const ConvergenceSnapshot& snapshot,
                                            const TransitionStepId& id) {
  for (const StepSnapshot& step : snapshot.steps) {
    if (step.id == id) {
      return &step;
    }
  }
  return nullptr;
}

// Drives every ready step of one plan to completion.  Every dispatch and every
// completion carries its own fresh mutation attempt: the governor records an
// attempt against the payload it authorized and refuses to let one attempt
// authorize two different mutations.
[[nodiscard]] PlanMutationResult drive_to_completion(rc::test::Fixture& fixture,
                                                     const ConvergencePlanId& plan,
                                                     std::uint64_t attempt_base) {
  PlanMutationResult last;
  for (std::uint32_t index = 0; index < 64; ++index) {
    const ReadyStepList ready = fixture.governor().ready_steps(fixture.governor().limits().max_parallel_steps);
    const ReadyStep* candidate = first_ready_step(ready, plan);
    if (candidate == nullptr) {
      break;
    }
    const std::uint64_t dispatch_seed = attempt_base + (2ull * index);
    const StepDispatch dispatch = fixture.governor().dispatch_step(candidate->plan, candidate->step,
                                                                   fixture.authority(dispatch_seed));
    RC_REQUIRE(dispatch.accepted());
    CompletionEvidence evidence;
    evidence.plan = candidate->plan;
    evidence.step = candidate->step;
    evidence.step_generation = dispatch.step_generation;
    evidence.attempt = fixture.authority(dispatch_seed).attempt;
    evidence.epoch = dispatch.epoch;
    evidence.publisher = fixture.publisher();
    evidence.worker_boot = fixture.boot();
    evidence.outcome = BackendOutcome::APPLIED;
    evidence.dispatch_watermark = dispatch.watermark;
    evidence.applied_route_generation = dispatch.spec.route_generation;
    evidence.observed_path_authority_generation = dispatch.spec.path_authority_generation;
    evidence.id = derive_evidence_id(evidence);
    last = fixture.governor().complete_step(evidence, fixture.authority(dispatch_seed + 1ull));
    RC_REQUIRE(last.accepted());
  }
  return last;
}

void put_u32_le(Bytes& bytes, std::size_t offset, std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    bytes[offset + index] = static_cast<std::uint8_t>((value >> (8u * index)) & 0xFFu);
  }
}

[[nodiscard]] std::uint32_t get_u32_le(const Bytes& bytes, std::size_t offset) {
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(bytes[offset + index]) << (8u * index);
  }
  return value;
}

[[nodiscard]] bool is_store_condition(ConditionCode code) {
  switch (code) {
    case ConditionCode::STORE_MAGIC:
    case ConditionCode::STORE_VERSION:
    case ConditionCode::STORE_INTEGRITY:
    case ConditionCode::STORE_STRUCTURE:
    case ConditionCode::STORE_IO:
    case ConditionCode::STORE_TRAILING_BYTES:
    case ConditionCode::STORE_RECORD_LIMIT:
      return true;
    default:
      return false;
  }
}

[[nodiscard]] bool rejected_with_store_condition(const PlanMutationResult& result) {
  if (result.outcome != Outcome::STORE_ERROR || result.conditions.empty()) {
    return false;
  }
  for (const Condition& condition : result.conditions.entries()) {
    if (!is_store_condition(condition.code)) {
      return false;
    }
  }
  return true;
}

// The defect a single flipped bit must produce, derived from the documented
// store layout and the documented order in which the fields are checked.
[[nodiscard]] StoreDefect expected_store_defect_for_flip(const Bytes& image, std::size_t offset,
                                                         const ConvergenceLimits& limits) {
  constexpr std::size_t kVersionOffset = kStoreMagicBytes;
  constexpr std::size_t kReservedOffset = kVersionOffset + 4;
  constexpr std::size_t kEpochOffset = kReservedOffset + 4;
  constexpr std::size_t kPayloadBytesOffset = kEpochOffset + 16;
  if (offset < kVersionOffset) {
    return StoreDefect::BAD_MAGIC;
  }
  if (offset < kReservedOffset) {
    return StoreDefect::BAD_VERSION;
  }
  if (offset < kEpochOffset) {
    return StoreDefect::RESERVED_NOT_ZERO;
  }
  if (offset < kPayloadBytesOffset) {
    return StoreDefect::INTEGRITY_FAILURE;
  }
  if (offset < kStoreHeaderBytes) {
    const std::uint32_t declared = get_u32_le(image, kPayloadBytesOffset);
    if (declared > limits.max_persistence_record_bytes) {
      return StoreDefect::PAYLOAD_TOO_LARGE;
    }
    const std::size_t expected = kStoreHeaderBytes + declared + kStoreTagBytes;
    if (image.size() < expected) {
      return StoreDefect::TRUNCATED;
    }
    if (image.size() > expected) {
      return StoreDefect::TRAILING_BYTES;
    }
    return StoreDefect::INTEGRITY_FAILURE;
  }
  return StoreDefect::INTEGRITY_FAILURE;
}

// Writes the exact image, reads it back, decodes it in memory and asks a real
// governor to load it: every path must report the same defect.
void expect_store_defect(rc::test::Fixture& fixture, const std::filesystem::path& path,
                         const Bytes& image, StoreDefect expected,
                         const ConvergenceLimits& limits) {
  std::string error;
  RC_CHECK_EQ(write_store_file_atomic(path, image, error), StoreDefect::NONE);
  Bytes read_back;
  RC_CHECK_EQ(read_store_file(path, read_back, error), StoreDefect::NONE);
  RC_CHECK(read_back == image);
  StoreFileInfo info;
  Bytes payload;
  RC_CHECK_EQ(decode_store_file(read_back, limits, info, payload), expected);
  if (expected != StoreDefect::NONE) {
    RC_CHECK(payload.empty());
    RC_CHECK_EQ(info.payload_bytes, 0u);
  }
  const PlanMutationResult result = fixture.governor().load(path);
  RC_CHECK(!result.accepted());
  RC_CHECK_EQ(result.outcome, Outcome::STORE_ERROR);
  RC_CHECK(rc::test::has_condition(result.conditions, condition_for(expected)));
  RC_CHECK(is_store_condition(condition_for(expected)));
}

[[nodiscard]] PlanMutationResult decode_state_into_fresh_governor(const Bytes& payload) {
  rc::test::Fixture fresh(83u);
  return fresh.governor().decode_state(payload);
}

}  // namespace

// A complete governor round-trips: plan lifecycle, step states, digests, the
// policy registry and lineage all survive load() into a different governor.
RC_TEST(persistence_round_trip_preserves_semantic_state) {
  TempStore store("round-trip");
  rc::test::Fixture source(11u);
  RC_REQUIRE(source.define_policy(25u).accepted());
  const RouteBinding first = rc::test::Fixture::binding(31u, 1u, 41u, 1u);
  const RouteBinding second = rc::test::Fixture::binding(31u, 2u, 41u, 1u);
  const RouteBinding third = rc::test::Fixture::binding(31u, 3u, 41u, 1u);

  // Plan A is declared against the generation that is current at the time, but
  // it is never executed.  Plan B records plan A as its predecessor, and
  // completing plan B supersedes it.
  source.publish(second);
  const PlanMutationResult created_first = source.create(first, second, 25u, 101u, true);
  RC_REQUIRE(created_first.accepted());
  RC_CHECK_EQ(created_first.outcome, Outcome::PLAN_CREATED);
  source.publish(third);
  const PlanMutationResult created_second = source.create(second, third, 25u, 211u, true);
  RC_REQUIRE(created_second.accepted());
  RC_CHECK_EQ(created_second.outcome, Outcome::PLAN_CREATED);
  RC_CHECK_EQ(drive_to_completion(source, created_second.plan, 5000u).outcome, Outcome::PLAN_COMPLETED);

  const std::optional<ConvergenceSnapshot> snapshot_first = source.governor().snapshot(created_first.plan);
  const std::optional<ConvergenceSnapshot> snapshot_second = source.governor().snapshot(created_second.plan);
  const std::optional<PlanSummary> summary_first = source.governor().query_plan(created_first.plan);
  const std::optional<PlanSummary> summary_second = source.governor().query_plan(created_second.plan);
  RC_REQUIRE(snapshot_first.has_value() && snapshot_second.has_value());
  RC_REQUIRE(summary_first.has_value() && summary_second.has_value());
  RC_CHECK_EQ(snapshot_first->lifecycle, PlanLifecycle::SUPERSEDED);
  RC_CHECK_EQ(snapshot_second->lifecycle, PlanLifecycle::COMPLETED);
  RC_CHECK_EQ(snapshot_first->successor, created_second.plan);
  RC_CHECK_EQ(snapshot_second->predecessor, created_first.plan);
  RC_CHECK_EQ(snapshot_first->supersession_reason, ChangeReason::SUPERSEDE);
  RC_CHECK(snapshot_first->currentness.has(CurrentnessCause::SUPERSEDED_BY_SUCCESSOR));
  RC_CHECK_EQ(summary_second->completed_steps, summary_second->total_steps);

  const std::vector<ConvergencePolicy> policies_before = source.governor().list_policies();
  RC_REQUIRE(policies_before.size() == 1);
  const std::filesystem::path path = store.path("round-trip.store");
  const PlanMutationResult saved = source.governor().save(path);
  RC_REQUIRE(saved.accepted());
  RC_CHECK_EQ(saved.outcome, Outcome::PLAN_UPDATED);

  rc::test::Fixture restored(12u);
  const PlanMutationResult loaded = restored.governor().load(path);
  RC_REQUIRE(loaded.accepted());
  RC_CHECK_EQ(loaded.outcome, Outcome::PLAN_UPDATED);
  RC_CHECK_EQ(restored.governor().store_path(), path);
  RC_CHECK_EQ(restored.governor().plan_count(), std::size_t{2});
  RC_CHECK_EQ(restored.governor().worker_count(), std::size_t{0});

  const std::optional<ConvergenceSnapshot> recovered_first = restored.governor().snapshot(created_first.plan);
  const std::optional<ConvergenceSnapshot> recovered_second = restored.governor().snapshot(created_second.plan);
  RC_REQUIRE(recovered_first.has_value() && recovered_second.has_value());

  // Neither a superseded plan nor a completed plan has a RECOVER transition,
  // so both keep the lifecycle they were saved with.
  RC_CHECK(!apply_plan_event(PlanLifecycle::SUPERSEDED, PlanEvent::RECOVER, PlanTransitionInputs{}).has_value());
  RC_CHECK(!apply_plan_event(PlanLifecycle::COMPLETED, PlanEvent::RECOVER, PlanTransitionInputs{}).has_value());
  RC_CHECK_EQ(recovered_first->lifecycle, snapshot_first->lifecycle);
  RC_CHECK_EQ(recovered_second->lifecycle, snapshot_second->lifecycle);
  RC_CHECK_EQ(recovered_first->successor, created_second.plan);
  RC_CHECK_EQ(recovered_second->predecessor, created_first.plan);
  RC_CHECK_EQ(recovered_first->supersession_reason, ChangeReason::SUPERSEDE);
  RC_CHECK(recovered_first->currentness.has(CurrentnessCause::SUPERSEDED_BY_SUCCESSOR));
  RC_CHECK(recovered_first->convergence_generation.value() > snapshot_first->convergence_generation.value());

  // Every step record, layer, binding and lineage field round-trips exactly;
  // only the governor-wide convergence generation and the plan watermark it
  // re-stamps move, and recovery is the reason they move.
  ConvergenceSnapshot expected_first = *snapshot_first;
  expected_first.convergence_generation = recovered_first->convergence_generation;
  expected_first.watermark = recovered_first->watermark;
  ConvergenceSnapshot expected_second = *snapshot_second;
  expected_second.convergence_generation = recovered_second->convergence_generation;
  expected_second.watermark = recovered_second->watermark;
  RC_CHECK_EQ(ConvergenceGovernor::snapshot_digest(*recovered_first), ConvergenceGovernor::snapshot_digest(expected_first));
  RC_CHECK_EQ(ConvergenceGovernor::snapshot_digest(*recovered_second), ConvergenceGovernor::snapshot_digest(expected_second));
  for (const StepSnapshot& step : recovered_second->steps) {
    RC_CHECK(is_step_satisfied(step.state));
  }

  const std::optional<PlanSummary> recovered_summary_first = restored.governor().query_plan(created_first.plan);
  const std::optional<PlanSummary> recovered_summary_second = restored.governor().query_plan(created_second.plan);
  RC_REQUIRE(recovered_summary_first.has_value() && recovered_summary_second.has_value());
  RC_CHECK_EQ(recovered_summary_first->id, summary_first->id);
  RC_CHECK_EQ(recovered_summary_first->digest, summary_first->digest);
  RC_CHECK_EQ(recovered_summary_first->generation, summary_first->generation);
  RC_CHECK_EQ(recovered_summary_first->lifecycle, summary_first->lifecycle);
  RC_CHECK_EQ(recovered_summary_first->currentness.bits(), summary_first->currentness.bits());
  RC_CHECK_EQ(recovered_summary_first->total_steps, summary_first->total_steps);
  RC_CHECK_EQ(recovered_summary_first->completed_steps, summary_first->completed_steps);
  RC_CHECK_EQ(recovered_summary_first->ready_steps, summary_first->ready_steps);
  RC_CHECK_EQ(recovered_summary_first->key.content_digest(), summary_first->key.content_digest());
  RC_CHECK_EQ(recovered_summary_second->digest, summary_second->digest);
  RC_CHECK_EQ(recovered_summary_second->generation, summary_second->generation);
  RC_CHECK_EQ(recovered_summary_second->completed_steps, summary_second->completed_steps);
  RC_CHECK_EQ(recovered_summary_second->key.content_digest(), summary_second->key.content_digest());

  const std::optional<PlanKey> key_before = source.governor().plan_key(created_second.plan);
  const std::optional<PlanKey> key_after = restored.governor().plan_key(created_second.plan);
  RC_REQUIRE(key_before.has_value() && key_after.has_value());
  RC_CHECK(*key_before == *key_after);
  const std::vector<ConvergencePolicy> policies_after = restored.governor().list_policies();
  RC_REQUIRE(policies_after.size() == policies_before.size());
  RC_CHECK(policies_after.front() == policies_before.front());
  RC_CHECK_EQ(policies_after.front().id, policies_before.front().id);
  RC_CHECK_EQ(policies_after.front().generation, policies_before.front().generation);
  RC_CHECK_EQ(ConvergenceGovernor::policy_digest(policies_after.front()), ConvergenceGovernor::policy_digest(policies_before.front()));
}

// Recovery is conservative: a DISPATCHED step is never COMPLETED by a load; it
// becomes RECONCILIATION_REQUIRED and its plan becomes REVALIDATION_REQUIRED.
RC_TEST(persistence_recovery_never_completes_in_flight_work) {
  TempStore store("in-flight");
  rc::test::Fixture source(13u);
  RC_REQUIRE(source.define_policy(27u).accepted());
  const RouteBinding first = rc::test::Fixture::binding(33u, 1u, 43u, 1u);
  const RouteBinding second = rc::test::Fixture::binding(33u, 2u, 43u, 1u);
  source.publish(second);
  const PlanMutationResult created = source.create(first, second, 27u, 301u, true);
  RC_REQUIRE(created.accepted());

  const ReadyStepList ready = source.governor().ready_steps(source.governor().limits().max_parallel_steps);
  const ReadyStep* candidate = first_ready_step(ready, created.plan);
  RC_REQUIRE(candidate != nullptr);
  const StepDispatch dispatch = source.governor().dispatch_step(candidate->plan, candidate->step, source.authority(3301u));
  RC_REQUIRE(dispatch.accepted());
  RC_CHECK_EQ(dispatch.outcome, Outcome::STEP_DISPATCHED);

  const std::optional<ConvergenceSnapshot> before = source.governor().snapshot(created.plan);
  RC_REQUIRE(before.has_value());
  RC_CHECK_EQ(before->lifecycle, PlanLifecycle::EXECUTING);
  const StepSnapshot* dispatched_before = find_step(*before, dispatch.step);
  RC_REQUIRE(dispatched_before != nullptr);
  RC_CHECK_EQ(dispatched_before->state, StepLifecycle::DISPATCHED);

  const std::optional<StepLifecycle> recovered_dispatched = apply_step_event(StepLifecycle::DISPATCHED, StepEvent::RECOVER);
  const std::optional<PlanLifecycle> recovered_executing = apply_plan_event(PlanLifecycle::EXECUTING, PlanEvent::RECOVER, PlanTransitionInputs{});
  RC_REQUIRE(recovered_dispatched.has_value());
  RC_REQUIRE(recovered_executing.has_value());
  RC_CHECK_EQ(*recovered_dispatched, StepLifecycle::RECONCILIATION_REQUIRED);
  RC_CHECK_EQ(*recovered_executing, PlanLifecycle::REVALIDATION_REQUIRED);

  const std::filesystem::path path = store.path("in-flight.store");
  RC_REQUIRE(source.governor().save(path).accepted());
  rc::test::Fixture restored(14u);
  RC_REQUIRE(restored.governor().load(path).accepted());
  const std::optional<ConvergenceSnapshot> after = restored.governor().snapshot(created.plan);
  RC_REQUIRE(after.has_value());
  RC_CHECK_EQ(after->lifecycle, PlanLifecycle::REVALIDATION_REQUIRED);
  const StepSnapshot* dispatched_after = find_step(*after, dispatch.step);
  RC_REQUIRE(dispatched_after != nullptr);
  RC_CHECK_EQ(dispatched_after->state, StepLifecycle::RECONCILIATION_REQUIRED);
  RC_CHECK(dispatched_after->state != StepLifecycle::COMPLETED);
  RC_CHECK(!is_step_satisfied(dispatched_after->state));
  RC_CHECK(!is_step_terminal(dispatched_after->state));
  RC_CHECK_EQ(dispatched_after->last_attempt, dispatched_before->last_attempt);
  RC_CHECK_EQ(dispatched_after->attempts, dispatched_before->attempts);

  const std::optional<PlanSummary> summary = restored.governor().query_plan(created.plan);
  RC_REQUIRE(summary.has_value());
  RC_CHECK_EQ(summary->completed_steps, 0u);
  RC_CHECK_EQ(summary->lifecycle, PlanLifecycle::REVALIDATION_REQUIRED);

  // The whole recovered snapshot is exactly the documented recovery of the
  // saved one: only step states, the plan lifecycle and the governor-wide
  // convergence bookkeeping may differ.
  RC_CHECK(after->plan_generation.value() > before->plan_generation.value());
  ConvergenceSnapshot expected = *before;
  expected.lifecycle = *recovered_executing;
  for (std::size_t index = 0; index < expected.steps.size(); ++index) {
      const std::optional<StepLifecycle> recovered = apply_step_event(before->steps[index].state, StepEvent::RECOVER);
    expected.steps[index].state = recovered.value_or(before->steps[index].state);
  }
  expected.plan_generation = after->plan_generation;
  expected.convergence_generation = after->convergence_generation;
  expected.watermark = after->watermark;
  RC_CHECK_EQ(ConvergenceGovernor::snapshot_digest(*after), ConvergenceGovernor::snapshot_digest(expected));
}

// Completed step history survives recovery, and recovery appends its own entry.
RC_TEST(persistence_recovery_preserves_completed_step_history) {
  TempStore store("history");
  rc::test::Fixture source(15u);
  RC_REQUIRE(source.define_policy(28u).accepted());
  const RouteBinding first = rc::test::Fixture::binding(35u, 1u, 45u, 1u);
  const RouteBinding second = rc::test::Fixture::binding(35u, 2u, 45u, 1u);
  source.publish(second);
  const PlanMutationResult created = source.create(first, second, 28u, 401u, true);
  RC_REQUIRE(created.accepted());
  RC_CHECK_EQ(drive_to_completion(source, created.plan, 7000u).outcome, Outcome::PLAN_COMPLETED);

  const std::optional<ConvergenceSnapshot> before = source.governor().snapshot(created.plan);
  const std::optional<ConvergenceDiff> history_before = source.governor().diff(created.plan, ConvergencePlanGeneration::from_value(0));
  RC_REQUIRE(before.has_value() && history_before.has_value());
  RC_REQUIRE(history_before->entries.size() >= 2);
  std::uint32_t completed_before = 0;
  for (const StepSnapshot& step : before->steps) {
    if (step.state == StepLifecycle::COMPLETED) {
      ++completed_before;
    }
  }
  RC_CHECK(completed_before >= 1);
  RC_CHECK_EQ(history_before->entries.back().kind, DiffKind::CONVERGENCE_COMPLETED);

  const std::filesystem::path path = store.path("history.store");
  RC_REQUIRE(source.governor().save(path).accepted());
  rc::test::Fixture restored(16u);
  RC_REQUIRE(restored.governor().load(path).accepted());

  const std::optional<ConvergenceSnapshot> after = restored.governor().snapshot(created.plan);
  const std::optional<ConvergenceDiff> history_after = restored.governor().diff(created.plan, ConvergencePlanGeneration::from_value(0));
  RC_REQUIRE(after.has_value() && history_after.has_value());
  RC_CHECK_EQ(after->lifecycle, PlanLifecycle::COMPLETED);
  RC_CHECK_EQ(after->steps.size(), before->steps.size());
  std::uint32_t completed_after = 0;
  for (std::size_t index = 0; index < before->steps.size(); ++index) {
    const StepSnapshot& saved_step = before->steps[index];
    const StepSnapshot& recovered_step = after->steps[index];
    RC_CHECK_EQ(recovered_step.id, saved_step.id);
    RC_CHECK_EQ(recovered_step.state, saved_step.state);
    RC_CHECK_EQ(recovered_step.generation, saved_step.generation);
    RC_CHECK_EQ(recovered_step.attempts, saved_step.attempts);
    RC_CHECK_EQ(recovered_step.last_evidence, saved_step.last_evidence);
    RC_CHECK_EQ(recovered_step.last_attempt, saved_step.last_attempt);
    RC_CHECK_EQ(recovered_step.last_outcome, saved_step.last_outcome);
    RC_CHECK_EQ(recovered_step.dispatch_watermark, saved_step.dispatch_watermark);
    RC_CHECK_EQ(recovered_step.dispatch_epoch, saved_step.dispatch_epoch);
    RC_CHECK_EQ(recovered_step.dispatch_publisher, saved_step.dispatch_publisher);
    RC_CHECK_EQ(recovered_step.dispatch_boot, saved_step.dispatch_boot);
    if (recovered_step.state == StepLifecycle::COMPLETED) {
      ++completed_after;
    }
  }
  RC_CHECK_EQ(completed_after, completed_before);

  // Recovery appends exactly one history entry; every entry recorded before the
  // load is still present, in order, with the same generations and step
  // references.  Only the kind of the final pre-load entry can change, because
  // that entry is no longer the final one.
  RC_CHECK_EQ(history_after->entries.size(), history_before->entries.size() + 1);
  const std::size_t last_saved = history_before->entries.size() - 1;
  for (std::size_t index = 0; index <= last_saved; ++index) {
    const DiffEntry& saved_entry = history_before->entries[index];
    const DiffEntry& recovered_entry = history_after->entries[index];
    RC_CHECK_EQ(recovered_entry.plan_generation, saved_entry.plan_generation);
    RC_CHECK_EQ(recovered_entry.convergence_generation, saved_entry.convergence_generation);
    RC_CHECK_EQ(recovered_entry.step, saved_entry.step);
    RC_CHECK_EQ(recovered_entry.subject, saved_entry.subject);
    RC_CHECK_EQ(recovered_entry.observed, saved_entry.observed);
    RC_CHECK_EQ(recovered_entry.expected, saved_entry.expected);
    if (index != last_saved) {
      RC_CHECK_EQ(recovered_entry.kind, saved_entry.kind);
    }
  }
  RC_CHECK_EQ(history_after->entries.back().kind, DiffKind::CURRENTNESS_CHANGED);
  RC_CHECK_EQ(history_after->entries.back().subject, std::string("RECOVERED_CONSERVATIVE"));
}

// Live worker authority is never restored: after a load even a fully formed
// completion from the pre-crash publisher and boot is rejected.
RC_TEST(persistence_recovery_does_not_restore_worker_authority) {
  TempStore store("authority");
  rc::test::Fixture source(17u);
  RC_REQUIRE(source.define_policy(29u).accepted());
  const RouteBinding first = rc::test::Fixture::binding(37u, 1u, 47u, 1u);
  const RouteBinding second = rc::test::Fixture::binding(37u, 2u, 47u, 1u);
  source.publish(second);
  const PlanMutationResult created = source.create(first, second, 29u, 501u, true);
  RC_REQUIRE(created.accepted());

  const ReadyStepList ready = source.governor().ready_steps(source.governor().limits().max_parallel_steps);
  const ReadyStep* candidate = first_ready_step(ready, created.plan);
  RC_REQUIRE(candidate != nullptr);
  const std::uint64_t dispatch_seed = 9100u;
  const StepDispatch dispatch = source.governor().dispatch_step(candidate->plan, candidate->step, source.authority(dispatch_seed));
  RC_REQUIRE(dispatch.accepted());
  RC_CHECK(source.governor().is_worker_live(source.publisher(), source.boot()));

  CompletionEvidence evidence;
  evidence.plan = created.plan;
  evidence.step = dispatch.step;
  evidence.step_generation = dispatch.step_generation;
  evidence.attempt = source.authority(dispatch_seed).attempt;
  evidence.epoch = dispatch.epoch;
  evidence.publisher = source.publisher();
  evidence.worker_boot = source.boot();
  evidence.outcome = BackendOutcome::APPLIED;
  evidence.dispatch_watermark = dispatch.watermark;
  evidence.applied_route_generation = dispatch.spec.route_generation;
  evidence.observed_path_authority_generation = dispatch.spec.path_authority_generation;
  evidence.id = derive_evidence_id(evidence);
  RC_REQUIRE(evidence.is_well_formed());

  const std::filesystem::path path = store.path("authority.store");
  RC_REQUIRE(source.governor().save(path).accepted());
  rc::test::Fixture restored(18u);
  RC_REQUIRE(restored.governor().load(path).accepted());
  RC_CHECK_EQ(restored.governor().worker_count(), std::size_t{0});
  RC_CHECK(restored.governor().list_workers().empty());
  RC_CHECK(!restored.governor().worker_registration(source.publisher()).has_value());
  RC_CHECK(!restored.governor().is_worker_live(source.publisher(), source.boot()));
  RC_CHECK(!restored.governor().is_worker_fenced(source.boot()));

  const PlanMutationResult pre_crash = restored.governor().complete_step(evidence, source.authority(dispatch_seed));
  RC_CHECK(!pre_crash.accepted());
  RC_CHECK_EQ(pre_crash.outcome, Outcome::UNAUTHORIZED);
  RC_CHECK(rc::test::has_condition(pre_crash.conditions, ConditionCode::PUBLISHER_UNKNOWN));

  // The same publisher identity returning with a new boot is a new worker; the
  // old boot still carries no authority.
  RC_REQUIRE(restored.register_worker(17u, 19u, rc::test::kAllCapabilities).accepted());
  RC_CHECK_EQ(restored.governor().worker_count(), std::size_t{1});
  RC_CHECK(!restored.governor().is_worker_live(source.publisher(), source.boot()));
  const PlanMutationResult old_boot = restored.governor().complete_step(evidence, source.authority(dispatch_seed));
  RC_CHECK(!old_boot.accepted());
  RC_CHECK_EQ(old_boot.outcome, Outcome::UNAUTHORIZED);
  RC_CHECK(rc::test::has_condition(old_boot.conditions, ConditionCode::WORKER_FENCED));

  // The interrupted step must be reconciled before it can complete, so even the
  // freshly registered authority cannot report it as completed.
  const PlanMutationResult fresh_boot = restored.governor().complete_step(evidence, restored.authority(dispatch_seed));
  RC_CHECK(!fresh_boot.accepted());
  RC_CHECK(rc::test::has_condition(fresh_boot.conditions, ConditionCode::STEP_STALE));
}

// The store file defect matrix: every structural defect has exactly one stable
// code, in memory and through a real governor load.
RC_TEST(persistence_store_defect_matrix_is_exact) {
  TempStore store("store-matrix");
  const ConvergenceLimits limits;
  rc::test::Fixture fixture(19u);
  Bytes payload;
  for (std::uint32_t index = 0; index < 24u; ++index) {
    payload.push_back(static_cast<std::uint8_t>(((index * 7u) + 3u) & 0xFFu));
  }
  const Bytes image = encode_store_file(3u, 9u, payload);
  RC_CHECK_EQ(image.size(), kStoreHeaderBytes + payload.size() + kStoreTagBytes);

  StoreFileInfo info;
  Bytes decoded;
  RC_CHECK_EQ(decode_store_file(image, limits, info, decoded), StoreDefect::NONE);
  RC_CHECK_EQ(info.format_version, kPersistenceFormatVersion);
  RC_CHECK_EQ(info.coordinator_epoch, 3u);
  RC_CHECK_EQ(info.convergence_generation, 9u);
  RC_CHECK_EQ(info.payload_bytes, 24u);
  RC_CHECK(decoded == payload);

  const std::filesystem::path path = store.path("matrix.store");
  std::string error;
  RC_CHECK_EQ(write_store_file_atomic(path, image, error), StoreDefect::NONE);
  std::filesystem::path temporary = path;
  temporary += ".tmp";
  RC_CHECK(!std::filesystem::exists(temporary));
  Bytes read_back;
  RC_CHECK_EQ(read_store_file(path, read_back, error), StoreDefect::NONE);
  RC_CHECK(read_back == image);
  RC_CHECK_EQ(decode_store_file(read_back, limits, info, decoded), StoreDefect::NONE);
  RC_CHECK(decoded == payload);

  expect_store_defect(fixture, path, Bytes{}, StoreDefect::EMPTY, limits);
  for (std::size_t index = 0; index < kStoreMagicBytes; ++index) {
    Bytes bad = image;
    bad[index] = static_cast<std::uint8_t>(bad[index] ^ 0x20u);
    expect_store_defect(fixture, path, bad, StoreDefect::BAD_MAGIC, limits);
  }
  Bytes unsupported = image;
  put_u32_le(unsupported, kStoreMagicBytes, kPersistenceFormatVersion + 1u);
  expect_store_defect(fixture, path, unsupported, StoreDefect::BAD_VERSION, limits);
  Bytes reserved = image;
  put_u32_le(reserved, kStoreMagicBytes + 4u, 1u);
  expect_store_defect(fixture, path, reserved, StoreDefect::RESERVED_NOT_ZERO, limits);

  // Every truncation length of a complete image.
  for (std::size_t length = 0; length < image.size(); ++length) {
    const Bytes truncated(image.begin(), image.begin() + static_cast<std::ptrdiff_t>(length));
    const StoreDefect cut_defect = length == 0 ? StoreDefect::EMPTY : StoreDefect::TRUNCATED;
    expect_store_defect(fixture, path, truncated, cut_defect, limits);
  }
  Bytes trailing = image;
  trailing.push_back(0x00u);
  expect_store_defect(fixture, path, trailing, StoreDefect::TRAILING_BYTES, limits);

  Bytes oversized = image;
  put_u32_le(oversized, kStoreHeaderBytes - 4u, limits.max_persistence_record_bytes + 1u);
  RC_CHECK_EQ(expected_store_defect_for_flip(oversized, kStoreHeaderBytes - 4u, limits),
              StoreDefect::PAYLOAD_TOO_LARGE);
  expect_store_defect(fixture, path, oversized, StoreDefect::PAYLOAD_TOO_LARGE, limits);

  // Every single bit flip in the header, the payload and the integrity tag.
  for (std::size_t offset = 0; offset < image.size(); ++offset) {
    Bytes bad = image;
    bad[offset] = static_cast<std::uint8_t>(bad[offset] ^ 0x01u);
    expect_store_defect(fixture, path, bad, expected_store_defect_for_flip(bad, offset, limits), limits);
  }

  // Not one of these loads was allowed to touch live state.
  RC_CHECK_EQ(fixture.governor().plan_count(), std::size_t{0});
  RC_CHECK_EQ(fixture.governor().worker_count(), std::size_t{1});
}

// Payload-level corruption: a payload is accepted only when it is exactly the
// byte string a governor produced.  A governor holding two plans round-trips;
// truncation, a trailing byte and a changed byte are rejected.
RC_TEST(persistence_payload_defects_are_rejected_at_the_state_layer) {
  rc::test::Fixture source(21u);
  RC_REQUIRE(source.define_policy(30u).accepted());
  const RouteBinding first = rc::test::Fixture::binding(39u, 1u, 49u, 1u);
  const RouteBinding second = rc::test::Fixture::binding(39u, 2u, 49u, 1u);
  const RouteBinding third = rc::test::Fixture::binding(39u, 3u, 49u, 1u);
  source.publish(second);
  const PlanMutationResult created_first = source.create(first, second, 30u, 601u, true);
  RC_REQUIRE(created_first.accepted());
  RC_CHECK_EQ(drive_to_completion(source, created_first.plan, 11000u).outcome, Outcome::PLAN_COMPLETED);
  source.publish(third);
  const PlanMutationResult created_second = source.create(second, third, 30u, 611u, true);
  RC_REQUIRE(created_second.accepted());
  RC_CHECK_EQ(drive_to_completion(source, created_second.plan, 13000u).outcome, Outcome::PLAN_COMPLETED);
  RC_CHECK_EQ(source.governor().plan_count(), std::size_t{2});

  const Bytes payload = source.governor().encode_state();
  RC_REQUIRE(!payload.empty());
  const std::optional<PlanSummary> summary_first = source.governor().query_plan(created_first.plan);
  const std::optional<PlanSummary> summary_second = source.governor().query_plan(created_second.plan);
  RC_REQUIRE(summary_first.has_value() && summary_second.has_value());

  rc::test::Fixture restored(22u);
  const PlanMutationResult decoded = restored.governor().decode_state(payload);
  RC_REQUIRE(decoded.accepted());
  RC_CHECK_EQ(decoded.outcome, Outcome::PLAN_UPDATED);
  RC_CHECK(rc::test::has_condition(decoded.conditions, ConditionCode::RECOVERED_CONSERVATIVE));
  RC_CHECK_EQ(restored.governor().plan_count(), std::size_t{2});
  RC_CHECK_EQ(restored.governor().list_policies().size(), std::size_t{1});

  const std::optional<PlanSummary> recovered_first =
      restored.governor().query_plan(created_first.plan);
  const std::optional<PlanSummary> recovered_second =
      restored.governor().query_plan(created_second.plan);
  RC_REQUIRE(recovered_first.has_value() && recovered_second.has_value());
  RC_CHECK_EQ(recovered_first->digest, summary_first->digest);
  RC_CHECK_EQ(recovered_first->lifecycle, summary_first->lifecycle);
  RC_CHECK_EQ(recovered_first->completed_steps, summary_first->completed_steps);
  RC_CHECK_EQ(recovered_second->digest, summary_second->digest);
  RC_CHECK_EQ(recovered_second->lifecycle, summary_second->lifecycle);
  RC_CHECK_EQ(recovered_second->completed_steps, summary_second->completed_steps);

  // A governor that already holds durable state refuses a second payload.
  const PlanMutationResult second_decode = restored.governor().decode_state(payload);
  RC_CHECK(!second_decode.accepted());
  RC_CHECK(rc::test::has_condition(second_decode.conditions, ConditionCode::STORE_STRUCTURE));

  const std::size_t cuts[] = {0u, 12u, payload.size() / 2u, payload.size() - 1u};
  for (const std::size_t cut : cuts) {
    const Bytes truncated(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(cut));
    RC_CHECK(rejected_with_store_condition(decode_state_into_fresh_governor(truncated)));
  }
  Bytes trailing = payload;
  trailing.push_back(0x00u);
  const PlanMutationResult trailing_result = decode_state_into_fresh_governor(trailing);
  RC_CHECK(rejected_with_store_condition(trailing_result));
  RC_CHECK(rc::test::has_condition(trailing_result.conditions, ConditionCode::STORE_TRAILING_BYTES));

  const auto digest_at = std::search(payload.begin(), payload.end(), summary_first->digest.bytes().begin(), summary_first->digest.bytes().end());
  RC_REQUIRE(digest_at != payload.end());
  Bytes changed_digest = payload;
  const std::size_t digest_offset = static_cast<std::size_t>(digest_at - payload.begin());
  changed_digest[digest_offset] = static_cast<std::uint8_t>(changed_digest[digest_offset] ^ 0x40u);
  const PlanMutationResult digest_result = decode_state_into_fresh_governor(changed_digest);
  RC_CHECK(rejected_with_store_condition(digest_result));
  RC_CHECK(rc::test::has_condition(digest_result.conditions, ConditionCode::STORE_STRUCTURE));

  const auto plan_at = std::search(payload.begin(), payload.end(), created_second.plan.bytes().begin(), created_second.plan.bytes().end());
  RC_REQUIRE(plan_at != payload.end());
  Bytes changed_plan = payload;
  const std::size_t plan_offset = static_cast<std::size_t>(plan_at - payload.begin());
  changed_plan[plan_offset] = static_cast<std::uint8_t>(changed_plan[plan_offset] ^ 0x01u);
  const PlanMutationResult plan_result = decode_state_into_fresh_governor(changed_plan);
  RC_CHECK(rejected_with_store_condition(plan_result));
  RC_CHECK(rc::test::has_condition(plan_result.conditions, ConditionCode::STORE_STRUCTURE));
}