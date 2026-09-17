// Convergence governance tests: plan identity, dependency-ordered execution,
// dispatch authority, completion evidence, stale-completion defence,
// supersession, rollback, ambiguity and retirement.
//
// The upstream observation source is the SYNTHETIC control-plane fixture.  These
// tests prove ordering and governance behaviour; they are not a physical
// convergence claim.

#include <algorithm>
#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include "fixture.hpp"
#include "test_framework.hpp"

using namespace rc;
using rc::test::Fixture;
using rc::test::has_condition;

namespace {

// Finds the runtime step identifier for one step kind through the ready-step and
// snapshot views.
[[nodiscard]] std::optional<TransitionStepId> find_step(const ConvergenceGovernor& governor,
                                                        const ConvergencePlanId& plan,
                                                        StepKind kind) {
  const ReadyStepList ready = governor.ready_steps(256);
  for (const ReadyStep& step : ready.steps) {
    if (step.plan == plan && step.key.kind == kind) {
      return step.step;
    }
  }
  const std::optional<ConvergenceSnapshot> snapshot = governor.snapshot(plan);
  if (!snapshot.has_value()) {
    return std::nullopt;
  }
  for (const StepSnapshot& step : snapshot->steps) {
    if (step.key.kind == kind) {
      return step.id;
    }
  }
  return std::nullopt;
}

struct DriveResult {
  Outcome outcome = Outcome::INTERNAL_ERROR;
  std::uint32_t completed = 0;
};

// Executes ready steps of one plan until nothing is executable.
DriveResult drive(ConvergenceGovernor& governor, const ConvergencePlanId& plan,
                  const AuthorityContext& base, std::uint64_t& attempt_seed,
                  std::uint32_t limit = 64) {
  DriveResult result;
  for (std::uint32_t index = 0; index < limit; ++index) {
    const ReadyStepList ready = governor.ready_steps(64);
    const ReadyStep* candidate = nullptr;
    for (const ReadyStep& step : ready.steps) {
      if (step.plan == plan) {
        candidate = &step;
        break;
      }
    }
    if (candidate == nullptr) {
      break;
    }
    AuthorityContext dispatch_authority = base;
    dispatch_authority.attempt = Fixture::attempt_for(attempt_seed);
    AuthorityContext completion_authority = base;
    completion_authority.attempt = Fixture::attempt_for(attempt_seed + 1);
    attempt_seed += 2;
    const StepDispatch dispatch =
        governor.dispatch_step(candidate->plan, candidate->step, dispatch_authority);
    result.outcome = dispatch.outcome;
    if (!dispatch.accepted()) {
      return result;
    }
    CompletionEvidence evidence;
    evidence.plan = candidate->plan;
    evidence.step = candidate->step;
    evidence.step_generation = dispatch.step_generation;
    evidence.attempt = dispatch_authority.attempt;
    evidence.epoch = dispatch.epoch;
    evidence.publisher = base.publisher;
    evidence.worker_boot = base.worker_boot;
    evidence.outcome = BackendOutcome::APPLIED;
    evidence.dispatch_watermark = dispatch.watermark;
    evidence.applied_route_generation = dispatch.spec.route_generation;
    evidence.observed_path_authority_generation = dispatch.spec.path_authority_generation;
    evidence.id = derive_evidence_id(evidence);
    const PlanMutationResult completed = governor.complete_step(evidence, completion_authority);
    result.outcome = completed.outcome;
    if (!completed.accepted() && completed.outcome != Outcome::PLAN_COMPLETED) {
      return result;
    }
    ++result.completed;
  }
  return result;
}

}  // namespace

RC_TEST(plan_creation_is_deterministic_and_idempotent) {
  Fixture fixture(1);
  const PlanMutationResult policy = fixture.define_policy(1);
  RC_CHECK(policy.accepted());
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  const RouteBinding target = Fixture::binding(1, 2, 2, 1);
  fixture.publish(target);

  const PlanMutationResult first = fixture.create(source, target, 1, 11);
  RC_CHECK_EQ(first.outcome, Outcome::PLAN_CREATED);
  RC_CHECK_EQ(first.plan_generation.value(), std::uint64_t{1});
  RC_CHECK(!first.digest.is_nil());

  // An exact replay is idempotent and advances nothing.
  const PlanMutationResult replay = fixture.create(source, target, 1, 12);
  RC_CHECK_EQ(replay.outcome, Outcome::IDEMPOTENT);
  RC_CHECK_EQ(replay.plan, first.plan);
  RC_CHECK_EQ(replay.plan_generation.value(), first.plan_generation.value());
  RC_CHECK_EQ(fixture.governor().plan_count(), std::size_t{1});

  // The same semantic request in an independent governor yields the same plan
  // identity and the same digest.
  Fixture other(1);
  (void)other.define_policy(1);
  other.publish(target);
  const PlanMutationResult same = other.create(source, target, 1, 11);
  RC_CHECK_EQ(same.plan, first.plan);
  RC_CHECK_EQ(same.digest, first.digest);

  // A conflicting replay of one attempt identifier is refused.
  AuthorityContext authority = fixture.authority(11);
  PlanMutationResult conflict = fixture.governor().create_plan(
      [&] {
        PlanRequest request;
        request.mode = PlanMode::GENERATED;
        request.source = source;
        request.target = Fixture::binding(1, 2, 3, 1);
        request.policy = Fixture::policy(1);
        request.epoch = fixture.governor().epoch();
        request.provenance = Fixture::provenance_for(11);
        return request;
      }(),
      authority);
  RC_CHECK_EQ(conflict.outcome, Outcome::ATTEMPT_CONFLICT);
}

RC_TEST(make_before_break_retains_old_state_until_target_is_verified) {
  Fixture fixture(1);
  (void)fixture.define_policy(1);
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  const RouteBinding target = Fixture::binding(1, 2, 2, 1);
  fixture.publish(target);
  const PlanMutationResult plan = fixture.create(source, target, 1, 11);
  RC_REQUIRE(plan.outcome == Outcome::PLAN_CREATED);

  std::uint64_t attempt_seed = 100;
  const AuthorityContext base = fixture.authority(1);

  // Step through one step at a time and assert the withdrawal never becomes
  // ready before the target has been verified.
  for (std::uint32_t index = 0; index < 32; ++index) {
    const ReadyStepList ready = fixture.governor().ready_steps(1);
    if (ready.steps.empty()) {
      break;
    }
    const ReadyStep& step = ready.steps.front();
    if (step.key.kind == StepKind::WITHDRAW_OLD_ROUTE) {
      const std::optional<ConvergenceSnapshot> snapshot = fixture.governor().snapshot(plan.plan);
      RC_REQUIRE(snapshot.has_value());
      bool verified = false;
      for (const StepSnapshot& candidate : snapshot->steps) {
        if (candidate.key.kind == StepKind::VERIFY_NEW_STATE &&
            candidate.state == StepLifecycle::COMPLETED) {
          verified = true;
        }
      }
      RC_CHECK(verified);
    }
    AuthorityContext dispatch_authority = base;
    dispatch_authority.attempt = Fixture::attempt_for(attempt_seed);
    AuthorityContext completion_authority = base;
    completion_authority.attempt = Fixture::attempt_for(attempt_seed + 1);
    attempt_seed += 2;
    const StepDispatch dispatch =
        fixture.governor().dispatch_step(step.plan, step.step, dispatch_authority);
    RC_REQUIRE(dispatch.accepted());
    CompletionEvidence evidence;
    evidence.plan = step.plan;
    evidence.step = step.step;
    evidence.step_generation = dispatch.step_generation;
    evidence.attempt = dispatch_authority.attempt;
    evidence.epoch = dispatch.epoch;
    evidence.publisher = base.publisher;
    evidence.worker_boot = base.worker_boot;
    evidence.outcome = BackendOutcome::APPLIED;
    evidence.dispatch_watermark = dispatch.watermark;
    evidence.id = derive_evidence_id(evidence);
    const PlanMutationResult completed =
        fixture.governor().complete_step(evidence, completion_authority);
    RC_CHECK(completed.accepted() || completed.outcome == Outcome::PLAN_COMPLETED);
  }

  const std::optional<PlanSummary> summary = fixture.governor().query_plan(plan.plan);
  RC_REQUIRE(summary.has_value());
  RC_CHECK_EQ(summary->lifecycle, PlanLifecycle::COMPLETED);
  RC_CHECK_EQ(summary->completed_steps, summary->total_steps);
}

RC_TEST(source_currentness_rules_are_explicit) {
  Fixture fixture(1);
  (void)fixture.define_policy(1);
  // Route Fabric publishes generation 3 for this route.
  const RouteBinding observed = Fixture::binding(1, 3, 3, 1);
  fixture.publish(observed);

  // A source two generations behind is not the immediate predecessor, so it is
  // refused unless the caller explicitly declares it historical.
  const RouteBinding ancient = Fixture::binding(1, 1, 1, 1);
  const PlanMutationResult refused = fixture.create(ancient, observed, 1, 161);
  RC_CHECK_EQ(refused.outcome, Outcome::STALE_ROUTE);
  RC_CHECK(has_condition(refused.conditions, ConditionCode::SOURCE_ROUTE_STALE));
  const PlanMutationResult historical = fixture.create(ancient, observed, 1, 162, true);
  RC_CHECK_EQ(historical.outcome, Outcome::PLAN_CREATED);

  // The immediately preceding desired generation is the normal source.
  const RouteBinding predecessor = Fixture::binding(1, 2, 2, 1);
  fixture.publish_pair(predecessor, observed);
  const PlanMutationResult normal = fixture.create(predecessor, observed, 1, 163);
  RC_CHECK_EQ(normal.outcome, Outcome::PLAN_CREATED);

  // A target that is not the observed generation at all is stale.
  const RouteBinding future = Fixture::binding(1, 5, 5, 1);
  const PlanMutationResult ahead = fixture.create(predecessor, future, 1, 164, true);
  RC_CHECK_EQ(ahead.outcome, Outcome::STALE_ROUTE);
  RC_CHECK(has_condition(ahead.conditions, ConditionCode::TARGET_ROUTE_STALE));
}

RC_TEST(step_lookup_reports_only_generated_steps) {
  Fixture fixture(1);
  (void)fixture.define_policy(1);
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  const RouteBinding target = Fixture::binding(1, 2, 2, 1);
  fixture.publish(target);
  const PlanMutationResult plan = fixture.create(source, target, 1, 11);
  RC_REQUIRE(plan.outcome == Outcome::PLAN_CREATED);
  RC_CHECK(find_step(fixture.governor(), plan.plan, StepKind::VALIDATE_TARGET).has_value());
  // No group is involved, so no group step exists in the canonical plan.
  RC_CHECK(!find_step(fixture.governor(), plan.plan, StepKind::INSTALL_NEW_GROUP).has_value());
}

RC_TEST(dispatch_requires_prerequisites_and_authority) {
  Fixture fixture(1);
  (void)fixture.define_policy(1);
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  const RouteBinding target = Fixture::binding(1, 2, 2, 1);
  fixture.publish(target);
  const PlanMutationResult plan = fixture.create(source, target, 1, 11);
  RC_REQUIRE(plan.outcome == Outcome::PLAN_CREATED);

  const std::optional<ConvergenceSnapshot> snapshot = fixture.governor().snapshot(plan.plan);
  RC_REQUIRE(snapshot.has_value());
  std::optional<TransitionStepId> withdraw;
  std::optional<TransitionStepId> validate;
  for (const StepSnapshot& step : snapshot->steps) {
    if (step.key.kind == StepKind::WITHDRAW_OLD_ROUTE) {
      withdraw = step.id;
    }
    if (step.key.kind == StepKind::VALIDATE_TARGET) {
      validate = step.id;
    }
  }
  RC_REQUIRE(withdraw.has_value());
  RC_REQUIRE(validate.has_value());

  // A step whose prerequisites are not satisfied cannot execute.
  const StepDispatch blocked = fixture.governor().dispatch_step(plan.plan, *withdraw,
                                                                fixture.authority(21));
  RC_CHECK_EQ(blocked.outcome, Outcome::PREREQUISITE_INCOMPLETE);
  RC_CHECK(has_condition(blocked.conditions, ConditionCode::STEP_NOT_READY));

  // An unauthorized publisher cannot dispatch at all.
  AuthorityContext rogue = fixture.authority(22);
  rogue.publisher = Fixture::publisher_for(77);
  rogue.worker_boot = Fixture::boot_for(77);
  const StepDispatch unauthorized =
      fixture.governor().dispatch_step(plan.plan, *validate, rogue);
  RC_CHECK_EQ(unauthorized.outcome, Outcome::UNAUTHORIZED);
  RC_CHECK(has_condition(unauthorized.conditions, ConditionCode::PUBLISHER_UNKNOWN));

  // A stale epoch cannot dispatch.
  AuthorityContext stale_epoch = fixture.authority(23);
  stale_epoch.epoch = CoordinatorEpoch::from_value(99);
  const StepDispatch epoch_rejected =
      fixture.governor().dispatch_step(plan.plan, *validate, stale_epoch);
  RC_CHECK_EQ(epoch_rejected.outcome, Outcome::UNAUTHORIZED);
  RC_CHECK(has_condition(epoch_rejected.conditions, ConditionCode::AUTHORITY_EPOCH_STALE));

  // The correct authority succeeds.
  const StepDispatch accepted = fixture.governor().dispatch_step(plan.plan, *validate,
                                                                fixture.authority(24));
  RC_CHECK_EQ(accepted.outcome, Outcome::STEP_DISPATCHED);
  RC_CHECK_EQ(accepted.step_generation.value(), std::uint64_t{2});
}

RC_TEST(completion_requires_structured_evidence_and_replays_idempotently) {
  Fixture fixture(1);
  (void)fixture.define_policy(1);
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  const RouteBinding target = Fixture::binding(1, 2, 2, 1);
  fixture.publish(target);
  const PlanMutationResult plan = fixture.create(source, target, 1, 11);
  RC_REQUIRE(plan.outcome == Outcome::PLAN_CREATED);
  const std::optional<TransitionStepId> validate =
      find_step(fixture.governor(), plan.plan, StepKind::VALIDATE_TARGET);
  RC_REQUIRE(validate.has_value());

  const AuthorityContext dispatch_authority = fixture.authority(31);
  const StepDispatch dispatch =
      fixture.governor().dispatch_step(plan.plan, *validate, dispatch_authority);
  RC_REQUIRE(dispatch.outcome == Outcome::STEP_DISPATCHED);
  // A completion is a different request from the dispatch, so it carries its own
  // mutation attempt identifier while echoing the execution attempt it completes.
  const AuthorityContext completion_authority = fixture.authority(32);

  CompletionEvidence evidence;
  evidence.plan = plan.plan;
  evidence.step = *validate;
  evidence.step_generation = dispatch.step_generation;
  evidence.attempt = dispatch_authority.attempt;
  evidence.epoch = dispatch.epoch;
  evidence.publisher = fixture.publisher();
  evidence.worker_boot = fixture.boot();
  evidence.outcome = BackendOutcome::APPLIED;
  evidence.dispatch_watermark = dispatch.watermark;
  evidence.id = derive_evidence_id(evidence);

  // A malformed evidence record is refused before anything else.
  CompletionEvidence malformed = evidence;
  malformed.attempt = MutationAttemptId{};
  RC_CHECK_EQ(fixture.governor().complete_step(malformed, completion_authority).outcome,
              Outcome::MALFORMED_REQUEST);

  // The wrong step generation is refused.
  CompletionEvidence wrong_generation = evidence;
  wrong_generation.step_generation = TransitionStepGeneration::from_value(99);
  wrong_generation.id = derive_evidence_id(wrong_generation);
  RC_CHECK_EQ(fixture.governor().complete_step(wrong_generation, completion_authority).outcome,
              Outcome::STALE_STEP);

  // The wrong dispatch watermark is refused.
  CompletionEvidence wrong_watermark = evidence;
  wrong_watermark.dispatch_watermark = ConvergenceGeneration::from_value(4242);
  wrong_watermark.id = derive_evidence_id(wrong_watermark);
  RC_CHECK_EQ(fixture.governor().complete_step(wrong_watermark, completion_authority).outcome,
              Outcome::STALE_STEP);

  // The real completion succeeds and the exact replay is idempotent.
  const PlanMutationResult completed =
      fixture.governor().complete_step(evidence, completion_authority);
  RC_CHECK_EQ(completed.outcome, Outcome::STEP_COMPLETED);
  // The exact replay of the same completion under the same attempt identifier
  // advances nothing.
  const PlanMutationResult replay =
      fixture.governor().complete_step(evidence, completion_authority);
  RC_CHECK_EQ(replay.outcome, Outcome::IDEMPOTENT);
  RC_CHECK_EQ(replay.plan_generation.value(), completed.plan_generation.value());
}

RC_TEST(stale_target_route_generation_cannot_complete) {
  Fixture fixture(1);
  (void)fixture.define_policy(1);
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  const RouteBinding target = Fixture::binding(1, 2, 2, 1);
  fixture.publish(target);
  const PlanMutationResult plan = fixture.create(source, target, 1, 11);
  RC_REQUIRE(plan.outcome == Outcome::PLAN_CREATED);

  const std::optional<TransitionStepId> validate =
      find_step(fixture.governor(), plan.plan, StepKind::VALIDATE_TARGET);
  RC_REQUIRE(validate.has_value());
  const AuthorityContext authority = fixture.authority(41);
  const StepDispatch dispatch = fixture.governor().dispatch_step(plan.plan, *validate, authority);
  RC_REQUIRE(dispatch.outcome == Outcome::STEP_DISPATCHED);
  const AuthorityContext completion_authority = fixture.authority(42);

  const std::optional<PlanSummary> before = fixture.governor().query_plan(plan.plan);
  RC_REQUIRE(before.has_value());

  // Route Fabric publishes generation 3 while the step is in flight.
  const RouteBinding successor = Fixture::binding(1, 3, 3, 1);
  fixture.publish(successor);
  RouteChangeNotice notice;
  notice.binding = successor;
  notice.provenance = Fixture::provenance_for(42);
  const NoticeResult noticed = fixture.governor().note_route_change(notice, fixture.authority(43));
  RC_CHECK(noticed.accepted());
  RC_CHECK_EQ(noticed.plans_superseded, std::uint32_t{1});

  const std::optional<PlanSummary> after = fixture.governor().query_plan(plan.plan);
  RC_REQUIRE(after.has_value());
  RC_CHECK_EQ(after->lifecycle, PlanLifecycle::SUPERSEDED);
  RC_CHECK(after->generation.value() > before->generation.value());

  CompletionEvidence evidence;
  evidence.plan = plan.plan;
  evidence.step = *validate;
  evidence.step_generation = dispatch.step_generation;
  evidence.attempt = authority.attempt;
  evidence.epoch = dispatch.epoch;
  evidence.publisher = fixture.publisher();
  evidence.worker_boot = fixture.boot();
  evidence.outcome = BackendOutcome::APPLIED;
  evidence.dispatch_watermark = dispatch.watermark;
  evidence.id = derive_evidence_id(evidence);
  const PlanMutationResult late =
      fixture.governor().complete_step(evidence, completion_authority);
  RC_CHECK(!late.accepted());
  RC_CHECK(late.outcome == Outcome::STALE_STEP || late.outcome == Outcome::STALE_ROUTE ||
           late.outcome == Outcome::STALE_PLAN);

  const std::optional<PlanSummary> unchanged = fixture.governor().query_plan(plan.plan);
  RC_REQUIRE(unchanged.has_value());
  RC_CHECK_EQ(unchanged->generation.value(), after->generation.value());
  RC_CHECK_EQ(unchanged->lifecycle, PlanLifecycle::SUPERSEDED);
  RC_CHECK(fixture.governor().stats().stale_completions_rejected > 0);
}

RC_TEST(path_authority_race_rejects_stale_completion) {
  Fixture fixture(1);
  (void)fixture.define_policy(1);
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  const RouteBinding target = Fixture::binding(1, 2, 2, 1);
  fixture.publish(target);
  const PlanMutationResult plan = fixture.create(source, target, 1, 11);
  RC_REQUIRE(plan.outcome == Outcome::PLAN_CREATED);

  const std::optional<TransitionStepId> install =
      find_step(fixture.governor(), plan.plan, StepKind::INSTALL_NEW_ROUTE);
  RC_REQUIRE(install.has_value());

  // The step is only dispatchable once PREPARE_NEW_STATE has completed.
  std::uint64_t attempt_seed = 200;
  const AuthorityContext base = fixture.authority(1);
  const DriveResult partial = drive(fixture.governor(), plan.plan, base, attempt_seed, 2);
  RC_CHECK(partial.completed >= 2);

  const AuthorityContext authority = fixture.authority(51);
  const StepDispatch dispatch =
      fixture.governor().dispatch_step(plan.plan, *install, authority);
  RC_REQUIRE(dispatch.outcome == Outcome::STEP_DISPATCHED);
  const AuthorityContext completion_authority = fixture.authority(54);

  // Path Authority advances the generation of the target path.  The observation
  // source is updated first: a notice is an event, the governor reacts to the
  // observation.
  PathChangeNotice path_notice;
  path_notice.legality.path = target.path;
  path_notice.legality.generation = PathAuthorityGeneration::from_value(8);
  path_notice.legality.legal = true;
  path_notice.provenance = Fixture::provenance_for(52);
  fixture.upstream().set_path(path_notice.legality);
  const NoticeResult noticed =
      fixture.governor().note_path_change(path_notice, fixture.authority(53));
  RC_CHECK(noticed.accepted());
  RC_CHECK_EQ(noticed.plans_invalidated, std::uint32_t{1});

  CompletionEvidence evidence;
  evidence.plan = plan.plan;
  evidence.step = *install;
  evidence.step_generation = dispatch.step_generation;
  evidence.attempt = authority.attempt;
  evidence.epoch = dispatch.epoch;
  evidence.publisher = fixture.publisher();
  evidence.worker_boot = fixture.boot();
  evidence.outcome = BackendOutcome::APPLIED;
  evidence.dispatch_watermark = dispatch.watermark;
  evidence.id = derive_evidence_id(evidence);
  const PlanMutationResult late =
      fixture.governor().complete_step(evidence, completion_authority);
  RC_CHECK(!late.accepted());
  RC_CHECK(late.outcome == Outcome::REVALIDATION_REQUIRED || late.outcome == Outcome::STALE_STEP ||
           late.outcome == Outcome::STALE_PATH_AUTHORITY);

  const std::optional<PlanSummary> summary = fixture.governor().query_plan(plan.plan);
  RC_REQUIRE(summary.has_value());
  RC_CHECK(summary->lifecycle == PlanLifecycle::REVALIDATION_REQUIRED ||
           summary->lifecycle == PlanLifecycle::PAUSED);
  RC_CHECK(!summary->currentness.is_current());
  RC_CHECK(summary->currentness.has(CurrentnessCause::STALE_PATH_AUTHORITY));
}

RC_TEST(epoch_advance_and_worker_fence_reject_old_completions) {
  Fixture fixture(1);
  (void)fixture.define_policy(1);
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  const RouteBinding target = Fixture::binding(1, 2, 2, 1);
  fixture.publish(target);
  const PlanMutationResult plan = fixture.create(source, target, 1, 11);
  RC_REQUIRE(plan.outcome == Outcome::PLAN_CREATED);

  const std::optional<TransitionStepId> validate =
      find_step(fixture.governor(), plan.plan, StepKind::VALIDATE_TARGET);
  RC_REQUIRE(validate.has_value());
  const AuthorityContext authority = fixture.authority(61);
  const StepDispatch dispatch = fixture.governor().dispatch_step(plan.plan, *validate, authority);
  RC_REQUIRE(dispatch.outcome == Outcome::STEP_DISPATCHED);
  const AuthorityContext stale_epoch_authority = fixture.authority(67);

  // The fabric epoch advances while the step is in flight.
  fixture.upstream().set_epoch(CoordinatorEpoch::from_value(2));
  EpochChangeNotice notice;
  notice.previous = CoordinatorEpoch::from_value(1);
  notice.current = CoordinatorEpoch::from_value(2);
  notice.provenance = Fixture::provenance_for(62);
  const NoticeResult advanced =
      fixture.governor().note_epoch_change(notice, fixture.authority(63));
  RC_CHECK_EQ(advanced.outcome, Outcome::EPOCH_ADVANCED);
  RC_CHECK_EQ(fixture.governor().epoch().value(), std::uint64_t{2});

  CompletionEvidence evidence;
  evidence.plan = plan.plan;
  evidence.step = *validate;
  evidence.step_generation = dispatch.step_generation;
  evidence.attempt = authority.attempt;
  evidence.epoch = dispatch.epoch;
  evidence.publisher = fixture.publisher();
  evidence.worker_boot = fixture.boot();
  evidence.outcome = BackendOutcome::APPLIED;
  evidence.dispatch_watermark = dispatch.watermark;
  evidence.id = derive_evidence_id(evidence);
  // The late completion carries the old epoch, which is refused by the
  // authority stage before any generation check runs.
  const PlanMutationResult late =
      fixture.governor().complete_step(evidence, stale_epoch_authority);
  RC_CHECK(!late.accepted());
  RC_CHECK(late.outcome == Outcome::STALE_EPOCH || late.outcome == Outcome::STALE_STEP ||
           late.outcome == Outcome::REVALIDATION_REQUIRED || late.outcome == Outcome::UNAUTHORIZED);

  // Revalidation at the new epoch restores live authority.
  const PlanMutationResult revalidated =
      fixture.governor().revalidate_plan(plan.plan, fixture.authority(64));
  RC_CHECK_EQ(revalidated.outcome, Outcome::PLAN_REVALIDATED);
  const std::optional<PlanSummary> summary = fixture.governor().query_plan(plan.plan);
  RC_REQUIRE(summary.has_value());
  RC_CHECK_EQ(summary->lifecycle, PlanLifecycle::READY);
  RC_CHECK(summary->currentness.is_current());

  // A fenced worker boot can never complete anything again.
  const std::optional<TransitionStepId> ready_validate =
      find_step(fixture.governor(), plan.plan, StepKind::VALIDATE_TARGET);
  RC_REQUIRE(ready_validate.has_value());
  const AuthorityContext fence_authority = fixture.authority(65);
  const StepDispatch second =
      fixture.governor().dispatch_step(plan.plan, *ready_validate, fence_authority);
  RC_REQUIRE(second.outcome == Outcome::STEP_DISPATCHED);
  const AuthorityContext fenced_completion_authority = fixture.authority(68);
  RC_CHECK_EQ(fixture.governor().fence_worker(fixture.boot(), fixture.authority(66)).outcome,
              Outcome::WORKER_FENCED);
  RC_CHECK(fixture.governor().is_worker_fenced(fixture.boot()));
  CompletionEvidence fenced;
  fenced.plan = plan.plan;
  fenced.step = *ready_validate;
  fenced.step_generation = second.step_generation;
  fenced.attempt = fence_authority.attempt;
  fenced.epoch = second.epoch;
  fenced.publisher = fixture.publisher();
  fenced.worker_boot = fixture.boot();
  fenced.outcome = BackendOutcome::APPLIED;
  fenced.dispatch_watermark = second.watermark;
  fenced.id = derive_evidence_id(fenced);
  const PlanMutationResult rejected =
      fixture.governor().complete_step(fenced, fenced_completion_authority);
  RC_CHECK(!rejected.accepted());
  RC_CHECK(rejected.outcome == Outcome::STALE_WORKER || rejected.outcome == Outcome::UNAUTHORIZED);

  // A fresh boot for the same publisher is a reincarnation: the old boot stays
  // fenced forever and the new one is live.
  const PlanMutationResult reincarnated =
      fixture.register_worker(1, 999, rc::test::kAllCapabilities);
  RC_CHECK(reincarnated.accepted());
  RC_CHECK(fixture.governor().is_worker_fenced(Fixture::boot_for(1)));
  RC_CHECK(fixture.governor().is_worker_live(fixture.publisher(), fixture.boot()));
}

RC_TEST(supersession_preserves_lineage_and_rejects_late_steps) {
  Fixture fixture(1);
  (void)fixture.define_policy(1);
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  const RouteBinding target = Fixture::binding(1, 2, 2, 1);
  fixture.publish(target);
  const PlanMutationResult plan = fixture.create(source, target, 1, 11);
  RC_REQUIRE(plan.outcome == Outcome::PLAN_CREATED);

  std::uint64_t attempt_seed = 300;
  const AuthorityContext base = fixture.authority(1);
  (void)drive(fixture.governor(), plan.plan, base, attempt_seed, 2);

  const RouteBinding successor_target = Fixture::binding(1, 3, 4, 1);
  fixture.publish(successor_target);
  RouteChangeNotice notice;
  notice.binding = successor_target;
  notice.provenance = Fixture::provenance_for(71);
  (void)fixture.governor().note_route_change(notice, fixture.authority(72));

  // The successor moves from the previous desired generation to the new one, so
  // its source is an explicitly accepted historical source.
  const PlanMutationResult successor = fixture.create(target, successor_target, 1, 73, true);
  RC_CHECK_EQ(successor.outcome, Outcome::PLAN_CREATED);

  const std::optional<ConvergenceSnapshot> old_snapshot =
      fixture.governor().snapshot(plan.plan);
  RC_REQUIRE(old_snapshot.has_value());
  RC_CHECK_EQ(old_snapshot->lifecycle, PlanLifecycle::SUPERSEDED);
  RC_CHECK_EQ(old_snapshot->successor, successor.plan);
  RC_CHECK_EQ(old_snapshot->supersession_reason, ChangeReason::SUPERSEDE);

  const std::optional<ConvergenceSnapshot> new_snapshot =
      fixture.governor().snapshot(successor.plan);
  RC_REQUIRE(new_snapshot.has_value());
  RC_CHECK_EQ(new_snapshot->predecessor, plan.plan);
  RC_CHECK_EQ(new_snapshot->target.generation.value(), std::uint64_t{3});
  RC_CHECK(!(new_snapshot->digest == old_snapshot->digest));

  // Late work from the superseded plan cannot commit.
  const std::optional<TransitionStepId> any_step =
      find_step(fixture.governor(), plan.plan, StepKind::PREPARE_NEW_STATE);
  if (any_step.has_value()) {
    const StepDispatch rejected =
        fixture.governor().dispatch_step(plan.plan, *any_step, fixture.authority(74));
    RC_CHECK(!rejected.accepted());
  }
  const PlanMutationResult revalidate =
      fixture.governor().revalidate_plan(plan.plan, fixture.authority(75));
  RC_CHECK_EQ(revalidate.outcome, Outcome::SUPERSEDED);
}

RC_TEST(ambiguous_side_effect_requires_reconciliation) {
  Fixture fixture(1);
  (void)fixture.define_policy(1);
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  const RouteBinding target = Fixture::binding(1, 2, 2, 1);
  fixture.publish(target);
  const PlanMutationResult plan = fixture.create(source, target, 1, 11);
  RC_REQUIRE(plan.outcome == Outcome::PLAN_CREATED);

  const std::optional<TransitionStepId> validate =
      find_step(fixture.governor(), plan.plan, StepKind::VALIDATE_TARGET);
  RC_REQUIRE(validate.has_value());
  const AuthorityContext authority = fixture.authority(81);
  const StepDispatch dispatch = fixture.governor().dispatch_step(plan.plan, *validate, authority);
  RC_REQUIRE(dispatch.outcome == Outcome::STEP_DISPATCHED);
  const AuthorityContext completion_authority = fixture.authority(84);

  CompletionEvidence evidence;
  evidence.plan = plan.plan;
  evidence.step = *validate;
  evidence.step_generation = dispatch.step_generation;
  evidence.attempt = authority.attempt;
  evidence.epoch = dispatch.epoch;
  evidence.publisher = fixture.publisher();
  evidence.worker_boot = fixture.boot();
  evidence.outcome = BackendOutcome::AMBIGUOUS;
  evidence.dispatch_watermark = dispatch.watermark;
  evidence.detail = "acknowledgement lost";
  evidence.id = derive_evidence_id(evidence);
  const PlanMutationResult ambiguous =
      fixture.governor().complete_step(evidence, completion_authority);
  RC_CHECK_EQ(ambiguous.outcome, Outcome::AMBIGUOUS_SIDE_EFFECT);

  const std::optional<ConvergenceSnapshot> snapshot = fixture.governor().snapshot(plan.plan);
  RC_REQUIRE(snapshot.has_value());
  RC_CHECK_EQ(snapshot->lifecycle, PlanLifecycle::PAUSED);
  for (const StepSnapshot& step : snapshot->steps) {
    if (step.id == *validate) {
      RC_CHECK_EQ(step.state, StepLifecycle::RECONCILIATION_REQUIRED);
    }
  }

  // Nothing is re-applied blindly: reconciliation decides.
  const PlanMutationResult reconciled = fixture.governor().reconcile_step(
      plan.plan, *validate, true, "observed applied", fixture.authority(82));
  RC_CHECK_EQ(reconciled.outcome, Outcome::STEP_RECONCILED);
  const std::optional<ConvergenceSnapshot> after = fixture.governor().snapshot(plan.plan);
  RC_REQUIRE(after.has_value());
  for (const StepSnapshot& step : after->steps) {
    if (step.id == *validate) {
      RC_CHECK_EQ(step.state, StepLifecycle::COMPLETED);
    }
  }
  // Reconciling a step that is not awaiting reconciliation is refused.
  RC_CHECK_EQ(fixture.governor()
                  .reconcile_step(plan.plan, *validate, true, "again", fixture.authority(83))
                  .outcome,
              Outcome::STALE_STEP);
}

RC_TEST(retry_semantics_are_bounded_and_never_retry_permanent_failures) {
  Fixture fixture(1);
  (void)fixture.define_policy(1);
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  const RouteBinding target = Fixture::binding(1, 2, 2, 1);
  fixture.publish(target);
  const PlanMutationResult plan = fixture.create(source, target, 1, 11);
  RC_REQUIRE(plan.outcome == Outcome::PLAN_CREATED);
  const std::optional<TransitionStepId> validate =
      find_step(fixture.governor(), plan.plan, StepKind::VALIDATE_TARGET);
  RC_REQUIRE(validate.has_value());

  const AuthorityContext dispatch_authority = fixture.authority(91);
  const StepDispatch dispatch =
      fixture.governor().dispatch_step(plan.plan, *validate, dispatch_authority);
  RC_REQUIRE(dispatch.outcome == Outcome::STEP_DISPATCHED);
  const PlanMutationResult retryable = fixture.governor().fail_step(
      plan.plan, *validate, BackendOutcome::RETRYABLE_FAILURE, "transient",
      fixture.authority(94));
  RC_CHECK_EQ(retryable.outcome, Outcome::RETRYABLE_FAILURE);
  const std::optional<ConvergenceSnapshot> snapshot = fixture.governor().snapshot(plan.plan);
  RC_REQUIRE(snapshot.has_value());
  for (const StepSnapshot& step : snapshot->steps) {
    if (step.id == *validate) {
      RC_CHECK_EQ(step.state, StepLifecycle::READY);
      RC_CHECK_EQ(step.attempts, std::uint32_t{1});
    }
  }

  // A permanent failure is never retried and moves the plan to ROLLBACK_REQUIRED.
  const AuthorityContext second_authority = fixture.authority(92);
  const StepDispatch second =
      fixture.governor().dispatch_step(plan.plan, *validate, second_authority);
  RC_REQUIRE(second.outcome == Outcome::STEP_DISPATCHED);
  const PlanMutationResult permanent = fixture.governor().fail_step(
      plan.plan, *validate, BackendOutcome::PERMANENT_FAILURE, "permanent",
      fixture.authority(95));
  RC_CHECK_EQ(permanent.outcome, Outcome::PERMANENT_FAILURE);
  const std::optional<PlanSummary> summary = fixture.governor().query_plan(plan.plan);
  RC_REQUIRE(summary.has_value());
  RC_CHECK_EQ(summary->lifecycle, PlanLifecycle::ROLLBACK_REQUIRED);
  const std::optional<ConvergenceSnapshot> after = fixture.governor().snapshot(plan.plan);
  RC_REQUIRE(after.has_value());
  for (const StepSnapshot& step : after->steps) {
    if (step.id == *validate) {
      RC_CHECK_EQ(step.state, StepLifecycle::FAILED);
    }
  }
  // A plan that requires rollback accepts no further forward dispatch.
  RC_CHECK(!fixture.governor().dispatch_step(plan.plan, *validate, fixture.authority(93)).accepted());
}

RC_TEST(rollback_generates_an_explicit_compensating_plan) {
  Fixture fixture(1);
  (void)fixture.define_policy(1);
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  const RouteBinding target = Fixture::binding(1, 2, 2, 1);
  fixture.publish_pair(source, target);
  const PlanMutationResult plan = fixture.create(source, target, 1, 11);
  RC_REQUIRE(plan.outcome == Outcome::PLAN_CREATED);

  // Execute part of the make side of the transition.
  std::uint64_t attempt_seed = 400;
  const AuthorityContext base = fixture.authority(1);
  const DriveResult partial = drive(fixture.governor(), plan.plan, base, attempt_seed, 3);
  RC_CHECK(partial.completed >= 2);

  const PlanMutationResult rollback =
      fixture.governor().begin_rollback(plan.plan, fixture.authority(101));
  RC_CHECK_EQ(rollback.outcome, Outcome::ROLLBACK_PLAN_CREATED);
  RC_CHECK(!rollback.plan.is_nil());

  const std::optional<ConvergenceSnapshot> forward = fixture.governor().snapshot(plan.plan);
  RC_REQUIRE(forward.has_value());
  RC_CHECK_EQ(forward->lifecycle, PlanLifecycle::ROLLING_BACK);
  RC_CHECK_EQ(forward->rollback_plan, rollback.plan);
  RC_CHECK_EQ(forward->successor, rollback.plan);

  const std::optional<ConvergenceSnapshot> compensation =
      fixture.governor().snapshot(rollback.plan);
  RC_REQUIRE(compensation.has_value());
  RC_CHECK(compensation->is_rollback);
  RC_CHECK_EQ(compensation->predecessor, plan.plan);
  RC_CHECK_EQ(compensation->target.generation.value(), source.generation.value());
  RC_CHECK_EQ(compensation->source.generation.value(), target.generation.value());
  RC_CHECK(compensation->steps.size() <= forward->steps.size());

  // The compensating plan is itself dependency-safe and can be driven to the end.
  std::uint64_t rollback_attempt = 500;
  const DriveResult done =
      drive(fixture.governor(), rollback.plan, base, rollback_attempt);
  RC_CHECK_EQ(done.outcome, Outcome::PLAN_COMPLETED);

  const std::optional<PlanSummary> forward_after =
      fixture.governor().query_plan(plan.plan);
  RC_REQUIRE(forward_after.has_value());
  RC_CHECK_EQ(forward_after->lifecycle, PlanLifecycle::SUPERSEDED);
  RC_CHECK(fixture.governor().stats().rollbacks_started >= 1);
}

RC_TEST(unsafe_rollback_is_rejected_when_the_target_is_no_longer_authorized) {
  Fixture fixture(1);
  (void)fixture.define_policy(1);
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  const RouteBinding target = Fixture::binding(1, 2, 2, 1);
  fixture.publish(target);
  const PlanMutationResult plan = fixture.create(source, target, 1, 11);
  RC_REQUIRE(plan.outcome == Outcome::PLAN_CREATED);

  std::uint64_t attempt_seed = 600;
  const AuthorityContext base = fixture.authority(1);
  (void)drive(fixture.governor(), plan.plan, base, attempt_seed, 2);

  // Path Authority withdraws legality from the path the rollback would restore.
  PathChangeNotice notice;
  notice.legality.path = source.path;
  notice.legality.generation = source.path_authority_generation;
  notice.legality.legal = false;
  notice.provenance = Fixture::provenance_for(111);
  fixture.upstream().set_path(notice.legality);
  (void)fixture.governor().note_path_change(notice, fixture.authority(112));

  const PlanMutationResult rollback =
      fixture.governor().begin_rollback(plan.plan, fixture.authority(113));
  RC_CHECK_EQ(rollback.outcome, Outcome::UNSAFE_ROLLBACK);
  RC_CHECK(has_condition(rollback.conditions, ConditionCode::ROLLBACK_TARGET_UNAUTHORIZED));
  const std::optional<PlanSummary> summary = fixture.governor().query_plan(plan.plan);
  RC_REQUIRE(summary.has_value());
  RC_CHECK(summary->lifecycle != PlanLifecycle::ROLLING_BACK);
  RC_CHECK(fixture.governor().stats().rollbacks_rejected > 0);
}

RC_TEST(revoke_and_retire_are_terminal_and_fence_in_flight_work) {
  Fixture fixture(1);
  (void)fixture.define_policy(1);
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  const RouteBinding target = Fixture::binding(1, 2, 2, 1);
  fixture.publish(target);
  const PlanMutationResult plan = fixture.create(source, target, 1, 11);
  RC_REQUIRE(plan.outcome == Outcome::PLAN_CREATED);

  const std::optional<TransitionStepId> validate =
      find_step(fixture.governor(), plan.plan, StepKind::VALIDATE_TARGET);
  RC_REQUIRE(validate.has_value());
  const AuthorityContext authority = fixture.authority(121);
  const StepDispatch dispatch = fixture.governor().dispatch_step(plan.plan, *validate, authority);
  RC_REQUIRE(dispatch.outcome == Outcome::STEP_DISPATCHED);
  (void)authority;

  RC_CHECK_EQ(fixture.governor().revoke_plan(plan.plan, fixture.authority(122)).outcome,
              Outcome::PLAN_REVOKED);
  const std::optional<ConvergenceSnapshot> revoked = fixture.governor().snapshot(plan.plan);
  RC_REQUIRE(revoked.has_value());
  RC_CHECK_EQ(revoked->lifecycle, PlanLifecycle::REVOKED);
  for (const StepSnapshot& step : revoked->steps) {
    if (step.id == *validate) {
      RC_CHECK_EQ(step.state, StepLifecycle::STALE);
    }
  }
  // Revoking again is idempotent, and retirement is the only move left.
  RC_CHECK_EQ(fixture.governor().revoke_plan(plan.plan, fixture.authority(123)).outcome,
              Outcome::IDEMPOTENT);
  RC_CHECK_EQ(fixture.governor().retire_plan(plan.plan, fixture.authority(124)).outcome,
              Outcome::PLAN_RETIRED);
  const std::optional<PlanSummary> retired = fixture.governor().query_plan(plan.plan);
  RC_REQUIRE(retired.has_value());
  RC_CHECK_EQ(retired->lifecycle, PlanLifecycle::RETIRED);
  RC_CHECK_EQ(fixture.governor().retire_plan(plan.plan, fixture.authority(125)).outcome,
              Outcome::IDEMPOTENT);
  RC_CHECK_EQ(fixture.governor().revalidate_plan(plan.plan, fixture.authority(126)).outcome,
              Outcome::RETIRED);
}

RC_TEST(explicit_plans_are_validated_for_policy_conformance) {
  Fixture fixture(1);
  (void)fixture.define_policy(1);
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  const RouteBinding target = Fixture::binding(1, 2, 2, 1);
  fixture.publish(target);

  // A plan that removes the old route before the new one is installed violates
  // make-before-break and is refused.
  StepSpec validate;
  validate.kind = StepKind::VALIDATE_TARGET;
  validate.subject = *SubjectToken::make("target");
  validate.idempotent = true;
  StepSpec withdraw;
  withdraw.kind = StepKind::WITHDRAW_OLD_ROUTE;
  withdraw.subject = *SubjectToken::make(target.route.to_text());
  withdraw.idempotent = true;
  withdraw.depends_on.push_back(validate.key());
  StepSpec finalise;
  finalise.kind = StepKind::FINALIZE;
  finalise.subject = *SubjectToken::make("plan");
  finalise.idempotent = true;
  finalise.depends_on.push_back(validate.key());
  finalise.depends_on.push_back(withdraw.key());

  PlanRequest request;
  request.mode = PlanMode::EXPLICIT;
  request.source = source;
  request.target = target;
  request.policy = Fixture::policy(1);
  request.epoch = fixture.governor().epoch();
  request.provenance = Fixture::provenance_for(131);
  request.explicit_steps = {validate, withdraw, finalise};
  const PlanMutationResult rejected =
      fixture.governor().create_plan(request, fixture.authority(132));
  RC_CHECK_EQ(rejected.outcome, Outcome::GRAPH_INVALID);
  RC_CHECK(has_condition(rejected.conditions, ConditionCode::BREAK_BEFORE_MAKE_NOT_PERMITTED));

  // A cyclic explicit plan is refused.
  StepSpec first = validate;
  StepSpec second;
  second.kind = StepKind::INSTALL_NEW_ROUTE;
  second.subject = *SubjectToken::make(target.route.to_text());
  second.idempotent = true;
  second.depends_on.push_back(first.key());
  first.depends_on.push_back(second.key());
  PlanRequest cycle = request;
  cycle.explicit_steps = {first, second, finalise};
  cycle.provenance = Fixture::provenance_for(133);
  const PlanMutationResult cyclic =
      fixture.governor().create_plan(cycle, fixture.authority(134));
  RC_CHECK_EQ(cyclic.outcome, Outcome::GRAPH_INVALID);
  RC_CHECK(has_condition(cyclic.conditions, ConditionCode::DEPENDENCY_CYCLE));
}

RC_TEST(governor_enforces_plan_and_step_limits) {
  ConvergenceLimits limits;
  limits.max_plans = 1;
  limits.max_steps_per_plan = 4;
  limits.max_parallel_steps = 2;
  Fixture fixture(1, CoordinatorEpoch::from_value(1), limits);
  (void)fixture.define_policy(1);
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  const RouteBinding target = Fixture::binding(1, 2, 2, 1);
  fixture.publish(target);

  // The generated make-before-break plan is larger than four steps.
  const PlanMutationResult too_many_steps = fixture.create(source, target, 1, 141);
  RC_CHECK_EQ(too_many_steps.outcome, Outcome::RESOURCE_LIMIT);
  RC_CHECK(has_condition(too_many_steps.conditions, ConditionCode::STEP_LIMIT));

  ConvergenceLimits roomy;
  roomy.max_plans = 1;
  Fixture second(1, CoordinatorEpoch::from_value(1), roomy);
  (void)second.define_policy(1);
  second.publish(target);
  const PlanMutationResult first = second.create(source, target, 1, 142);
  RC_CHECK_EQ(first.outcome, Outcome::PLAN_CREATED);
  const RouteBinding other_source = Fixture::binding(2, 1, 3, 1);
  const RouteBinding other_target = Fixture::binding(2, 2, 4, 1);
  second.publish(other_target);
  const PlanMutationResult second_plan = second.create(other_source, other_target, 1, 143);
  RC_CHECK_EQ(second_plan.outcome, Outcome::RESOURCE_LIMIT);
  RC_CHECK(has_condition(second_plan.conditions, ConditionCode::PLAN_LIMIT));
}

RC_TEST(revalidation_pauses_and_resumes_a_plan) {
  Fixture fixture(1);
  (void)fixture.define_policy(1);
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  const RouteBinding target = Fixture::binding(1, 2, 2, 1);
  fixture.publish(target);
  const PlanMutationResult plan = fixture.create(source, target, 1, 11);
  RC_REQUIRE(plan.outcome == Outcome::PLAN_CREATED);

  RC_CHECK_EQ(fixture.governor()
                  .pause_plan(plan.plan, ConditionCode::REVALIDATION_REQUIRED,
                              fixture.authority(151))
                  .outcome,
              Outcome::PLAN_PAUSED);
  const std::optional<PlanSummary> paused = fixture.governor().query_plan(plan.plan);
  RC_REQUIRE(paused.has_value());
  RC_CHECK_EQ(paused->lifecycle, PlanLifecycle::PAUSED);
  // A paused plan cannot dispatch.
  const std::optional<TransitionStepId> validate =
      find_step(fixture.governor(), plan.plan, StepKind::VALIDATE_TARGET);
  RC_REQUIRE(validate.has_value());
  const StepDispatch blocked =
      fixture.governor().dispatch_step(plan.plan, *validate, fixture.authority(152));
  RC_CHECK(!blocked.accepted());

  RC_CHECK_EQ(fixture.governor().revalidate_plan(plan.plan, fixture.authority(153)).outcome,
              Outcome::PLAN_REVALIDATED);
  const std::optional<PlanSummary> resumed = fixture.governor().query_plan(plan.plan);
  RC_REQUIRE(resumed.has_value());
  RC_CHECK_EQ(resumed->lifecycle, PlanLifecycle::READY);
  RC_CHECK_EQ(fixture.governor().dispatch_step(plan.plan, *validate, fixture.authority(154)).outcome,
              Outcome::STEP_DISPATCHED);
}

RC_TEST(snapshots_diffs_and_explanations_are_deterministic) {
  Fixture fixture(1);
  (void)fixture.define_policy(1);
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  const RouteBinding target = Fixture::binding(1, 2, 2, 1);
  fixture.publish(target);
  const PlanMutationResult plan = fixture.create(source, target, 1, 11);
  RC_REQUIRE(plan.outcome == Outcome::PLAN_CREATED);

  const std::optional<ConvergenceSnapshot> first = fixture.governor().snapshot(plan.plan);
  const std::optional<ConvergenceSnapshot> second = fixture.governor().snapshot(plan.plan);
  RC_REQUIRE(first.has_value());
  RC_REQUIRE(second.has_value());
  RC_CHECK_EQ(first->digest, second->digest);
  RC_CHECK_EQ(first->id, second->id);

  std::uint64_t attempt_seed = 700;
  const AuthorityContext base = fixture.authority(1);
  (void)drive(fixture.governor(), plan.plan, base, attempt_seed, 2);
  const std::optional<ConvergenceSnapshot> third = fixture.governor().snapshot(plan.plan);
  RC_REQUIRE(third.has_value());
  RC_CHECK(!(third->digest == first->digest));

  const std::optional<ConvergenceDiff> diff =
      fixture.governor().diff(plan.plan, ConvergencePlanGeneration::from_value(0));
  RC_REQUIRE(diff.has_value());
  RC_CHECK(!diff->entries.empty());
  RC_CHECK(diff->entries.front().kind == DiffKind::PLAN_CREATED ||
           diff->entries.front().kind == DiffKind::LIFECYCLE_CHANGED);
  const std::optional<ConvergenceDiff> same =
      fixture.governor().diff(plan.plan, ConvergencePlanGeneration::from_value(0));
  RC_REQUIRE(same.has_value());
  RC_CHECK_EQ(diff->render(), same->render());
  // A diff from the current generation is empty.
  const std::optional<PlanSummary> current = fixture.governor().query_plan(plan.plan);
  RC_REQUIRE(current.has_value());
  const std::optional<ConvergenceDiff> empty =
      fixture.governor().diff(plan.plan, current->generation);
  RC_REQUIRE(empty.has_value());
  RC_CHECK(empty->entries.empty());

  for (const ExplainKind kind :
       {ExplainKind::PLAN, ExplainKind::READINESS, ExplainKind::OLD_STATE_RETENTION,
        ExplainKind::TARGET_ACTIVATION, ExplainKind::ROLLBACK, ExplainKind::STALENESS,
        ExplainKind::COMPLETION, ExplainKind::AUTHORITY}) {
    ExplainRequest request;
    request.plan = plan.plan;
    request.kind = kind;
    const ExplainResponse response = fixture.governor().explain(request);
    RC_CHECK(response.found);
    RC_CHECK(!response.render().empty());
  }
  ExplainRequest step_request;
  step_request.plan = plan.plan;
  step_request.kind = ExplainKind::STEP;
  const std::optional<TransitionStepId> validate =
      find_step(fixture.governor(), plan.plan, StepKind::VALIDATE_TARGET);
  RC_REQUIRE(validate.has_value());
  step_request.step = *validate;
  RC_CHECK(fixture.governor().explain(step_request).found);
}

RC_TEST(concurrent_independent_plans_and_completions_are_safe) {
  Fixture fixture(1);
  (void)fixture.define_policy(1);
  const AuthorityContext base = fixture.authority(1);

  std::vector<ConvergencePlanId> plans;
  for (std::uint64_t index = 0; index < 4; ++index) {
    const RouteBinding source = Fixture::binding(100 + index, 1, 200 + index, 1);
    const RouteBinding target = Fixture::binding(100 + index, 2, 300 + index, 1);
    fixture.publish(target);
    const PlanMutationResult created = fixture.create(source, target, 1, 800 + index);
    RC_REQUIRE(created.outcome == Outcome::PLAN_CREATED);
    plans.push_back(created.plan);
  }

  // Independent plans can be driven concurrently: the dispatch/complete pair for
  // one plan never blocks or corrupts another.
  std::atomic<int> completed{0};
  std::vector<Outcome> outcomes(plans.size(), Outcome::INTERNAL_ERROR);
  std::vector<std::thread> threads;
  threads.reserve(plans.size());
  for (std::size_t index = 0; index < plans.size(); ++index) {
    threads.emplace_back([&fixture, &completed, &outcomes, &plans, &base, index]() {
      std::uint64_t attempt_seed = 900 + (index * 1000);
      const DriveResult result =
          drive(fixture.governor(), plans[index], base, attempt_seed, 32);
      outcomes[index] = result.outcome;
      if (result.outcome == Outcome::PLAN_COMPLETED) {
        completed.fetch_add(1);
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
  for (std::size_t index = 0; index < plans.size(); ++index) {
    const std::optional<PlanSummary> summary = fixture.governor().query_plan(plans[index]);
    RC_REQUIRE(summary.has_value());
    if (summary->lifecycle != PlanLifecycle::COMPLETED) {
      ExplainRequest request;
      request.plan = plans[index];
      request.kind = ExplainKind::STALENESS;
      ::rc::test::report_failure(__FILE__, __LINE__,
                                 std::string("plan ") + plans[index].to_text() +
                                     " lifecycle=" + std::string(to_string(summary->lifecycle)) +
                                     " last_outcome=" + std::string(to_string(outcomes[index])) +
                                     " currentness=" + summary->currentness.render() + " :: " +
                                     fixture.governor().explain(request).render());
    }
  }
  RC_CHECK_EQ(completed.load(), 4);
  for (const ConvergencePlanId& plan : plans) {
    const std::optional<PlanSummary> summary = fixture.governor().query_plan(plan);
    RC_REQUIRE(summary.has_value());
    RC_CHECK_EQ(summary->lifecycle, PlanLifecycle::COMPLETED);
  }
}
