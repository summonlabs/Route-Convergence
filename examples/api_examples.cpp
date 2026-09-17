// Route Convergence in-process API examples.
//
// Every scenario drives the real public control-plane API in this process against
// rc::SyntheticUpstream, which is a SYNTHETIC control-plane fixture and not a
// physical fabric.  These examples prove ordering, governance, invalidation,
// supersession, rollback and stale-completion behaviour; they make no physical
// convergence claim.
//
// Exactly one deterministic "EXAMPLE <name> OK" line is printed per scenario, and
// the program stops at the first failed assertion with a non-zero exit status, so
// this file doubles as a scripted proof.

#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "fixture.hpp"
#include "rc/rc.hpp"

using namespace rc;
using rc::test::Fixture;
using rc::test::has_condition;

namespace {

// --- deterministic example identities ---------------------------------------

constexpr std::uint64_t kRouteSeed = 1;
constexpr std::uint64_t kSourcePathSeed = 1;
constexpr std::uint64_t kTargetPathSeed = 2;
constexpr std::uint64_t kThirdPathSeed = 3;
constexpr std::uint64_t kPolicySeed = 1;

constexpr std::uint64_t kRouteGenerationOne = 1;
constexpr std::uint64_t kRouteGenerationTwo = 2;
constexpr std::uint64_t kRouteGenerationThree = 3;
constexpr std::uint64_t kPathGenerationOne = 1;
constexpr std::uint64_t kPathGenerationTwo = 2;

// A failed assertion ends the scenario immediately: an "EXAMPLE <name> OK" line
// therefore means every assertion of that scenario held.
#define RC_EXAMPLE_REQUIRE(condition)                                                     \
  do {                                                                                    \
    if (!(condition)) {                                                                   \
      std::cout << "EXAMPLE " << kExample << " FAILED check=" #condition                  \
                << " line=" << __LINE__ << "\n";                                          \
      return 2;                                                                           \
    }                                                                                     \
  } while (false)

// --- shared fixture helpers -------------------------------------------------

struct TransitionSetup {
  RouteBinding source;
  RouteBinding target;
  PlanMutationResult plan;
};

[[nodiscard]] const StepSnapshot* find_step(const ConvergenceSnapshot& snapshot, StepKind kind) {
  for (const StepSnapshot& step : snapshot.steps) {
    if (step.key.kind == kind) {
      return &step;
    }
  }
  return nullptr;
}

void publish_path(SyntheticUpstream& upstream, const PathId& path, std::uint64_t generation,
                  bool legal) {
  PathLegality legality;
  legality.path = path;
  legality.generation = PathAuthorityGeneration::from_value(generation);
  legality.legal = legal;
  upstream.set_path(legality);
}

// Route Fabric asserts one exact route binding and Path Authority asserts the
// legality of the source path, so a transition can be planned against a coherent
// observation.  The plan is created against an older source generation, which must
// be declared historical because the fabric already publishes the target.
[[nodiscard]] TransitionSetup prepare_transition(Fixture& fixture, std::uint64_t attempt_seed) {
  TransitionSetup setup;
  setup.source = Fixture::binding(kRouteSeed, kRouteGenerationOne, kSourcePathSeed,
                                  kPathGenerationOne);
  setup.target = Fixture::binding(kRouteSeed, kRouteGenerationTwo, kTargetPathSeed,
                                  kPathGenerationOne);
  fixture.publish(setup.target);
  publish_path(fixture.upstream(), setup.source.path, kPathGenerationOne, true);
  setup.plan = fixture.create(setup.source, setup.target, kPolicySeed, attempt_seed, true);
  return setup;
}

[[nodiscard]] CompletionEvidence evidence_for(const Fixture& fixture, const StepDispatch& dispatch,
                                              const AuthorityContext& authority) {
  CompletionEvidence evidence;
  evidence.plan = dispatch.plan;
  evidence.step = dispatch.step;
  evidence.step_generation = dispatch.step_generation;
  evidence.attempt = authority.attempt;
  evidence.epoch = dispatch.epoch;
  evidence.publisher = fixture.publisher();
  evidence.worker_boot = fixture.boot();
  evidence.outcome = BackendOutcome::APPLIED;
  evidence.dispatch_watermark = dispatch.watermark;
  evidence.applied_route_generation = dispatch.spec.route_generation;
  evidence.observed_path_authority_generation = dispatch.spec.path_authority_generation;
  evidence.id = derive_evidence_id(evidence);
  return evidence;
}

struct StepExecution {
  bool dispatched = false;
  Outcome outcome = Outcome::INTERNAL_ERROR;
  ConditionList conditions;
};

// Dispatches and completes one ready step.  One MutationAttemptId binds the whole
// work item, which is exactly how the worker and the CLI bind a dispatch and its
// completion.
[[nodiscard]] StepExecution execute_ready_step(ConvergenceGovernor& governor,
                                               const Fixture& fixture, const ReadyStep& step,
                                               std::uint64_t& attempt_seed) {
  StepExecution execution;
  const AuthorityContext authority = fixture.authority(attempt_seed++);
  const StepDispatch dispatch = governor.dispatch_step(step.plan, step.step, authority);
  execution.outcome = dispatch.outcome;
  execution.conditions = dispatch.conditions;
  if (!dispatch.accepted()) {
    return execution;
  }
  execution.dispatched = true;
  const PlanMutationResult completed =
      governor.complete_step(evidence_for(fixture, dispatch, authority), authority);
  execution.outcome = completed.outcome;
  execution.conditions = completed.conditions;
  return execution;
}

struct ExecutionReport {
  Outcome outcome = Outcome::INTERNAL_ERROR;
  std::uint32_t completed = 0;
  std::uint32_t break_steps = 0;
  std::uint32_t break_steps_after_verification = 0;
  ConditionList conditions;
};

// Executes the ready steps of one plan in canonical order.  Before a break-side
// step is dispatched it asserts that the target state was already verified, which
// is the make-before-break guarantee stated in terms of the real step graph.
[[nodiscard]] ExecutionReport execute_plan(ConvergenceGovernor& governor, const Fixture& fixture,
                                           const ConvergencePlanId& plan,
                                           std::uint64_t& attempt_seed, std::uint32_t limit) {
  ExecutionReport report;
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
    if (is_break_step(candidate->key.kind)) {
      ++report.break_steps;
      const std::optional<ConvergenceSnapshot> snapshot = governor.snapshot(plan);
      if (snapshot.has_value()) {
        const StepSnapshot* verification = find_step(*snapshot, StepKind::VERIFY_NEW_STATE);
        if (verification != nullptr && verification->state == StepLifecycle::COMPLETED) {
          ++report.break_steps_after_verification;
        }
      }
    }
    const StepExecution execution = execute_ready_step(governor, fixture, *candidate, attempt_seed);
    report.outcome = execution.outcome;
    report.conditions = execution.conditions;
    if (!execution.dispatched) {
      return report;
    }
    if (!is_acceptance(execution.outcome)) {
      return report;
    }
    ++report.completed;
  }
  return report;
}

// Runs a plan up to the step that is ready next and dispatches exactly that step,
// leaving it in flight for the caller.  The returned authority is the one that
// binds the work item, so a later failure or completion report must present it.
[[nodiscard]] bool dispatch_next(ConvergenceGovernor& governor, const Fixture& fixture,
                                 const ConvergencePlanId& plan, std::uint64_t& attempt_seed,
                                 StepDispatch& dispatch, AuthorityContext& authority) {
  const ReadyStepList ready = governor.ready_steps(64);
  for (const ReadyStep& step : ready.steps) {
    if (step.plan != plan) {
      continue;
    }
    authority = fixture.authority(attempt_seed++);
    dispatch = governor.dispatch_step(step.plan, step.step, authority);
    return dispatch.accepted();
  }
  return false;
}

[[nodiscard]] std::uint32_t run_forward_to_failure(Fixture& fixture, const TransitionSetup& setup,
                                                   std::uint64_t& attempt_seed,
                                                   ConvergenceGovernor& governor) {
  const ExecutionReport first =
      execute_plan(governor, fixture, setup.plan.plan, attempt_seed, 3);
  if (first.completed != 3u) {
    return first.completed;
  }
  StepDispatch activation;
  AuthorityContext authority;
  if (!dispatch_next(governor, fixture, setup.plan.plan, attempt_seed, activation, authority)) {
    return first.completed;
  }
  // The failure report presents the attempt that dispatched the work item, which
  // is what binds a failure to the exact in-flight execution.
  const PlanMutationResult failed = governor.fail_step(
      setup.plan.plan, activation.step, BackendOutcome::PERMANENT_FAILURE,
      "the data plane refused the activation", authority);
  return failed.outcome == Outcome::PERMANENT_FAILURE ? first.completed : 0u;
}

// --- scenario 1: basic make-before-break ------------------------------------

int example_basic_make_before_break() {
  constexpr std::string_view kExample = "basic_make_before_break";
  Fixture fixture(1);
  RC_EXAMPLE_REQUIRE(fixture.define_policy(kPolicySeed).accepted());
  const TransitionSetup setup = prepare_transition(fixture, 11);
  RC_EXAMPLE_REQUIRE(setup.plan.outcome == Outcome::PLAN_CREATED);
  ConvergenceGovernor& governor = fixture.governor();

  // The canonical step order is generated deterministically from the bindings and
  // the policy; the plan must contain exactly that order.
  std::string reason;
  const std::optional<std::vector<StepSpec>> generated = generate_steps(
      setup.source, setup.target, Fixture::policy(kPolicySeed), governor.limits(), reason);
  RC_EXAMPLE_REQUIRE(generated.has_value());
  const std::optional<ConvergenceSnapshot> declared = governor.snapshot(setup.plan.plan);
  RC_EXAMPLE_REQUIRE(declared.has_value());
  const StepKind expected_order[] = {
      StepKind::VALIDATE_TARGET,   StepKind::PREPARE_NEW_STATE,  StepKind::INSTALL_NEW_ROUTE,
      StepKind::ACTIVATE_NEW_PATH, StepKind::VERIFY_NEW_STATE,   StepKind::DEACTIVATE_OLD_PATH,
      StepKind::WITHDRAW_OLD_ROUTE, StepKind::VERIFY_REMOVAL,    StepKind::FINALIZE};
  RC_EXAMPLE_REQUIRE(declared->steps.size() == generated->size());
  RC_EXAMPLE_REQUIRE(declared->steps.size() == std::size(expected_order));
  for (std::size_t index = 0; index < declared->steps.size(); ++index) {
    RC_EXAMPLE_REQUIRE(declared->steps[index].key.kind == expected_order[index]);
    RC_EXAMPLE_REQUIRE(declared->steps[index].key == (*generated)[index].key());
  }
  // Make-side subjects bind the target state, break-side subjects the source state.
  RC_EXAMPLE_REQUIRE(declared->steps[1].key.subject.text() == setup.target.path.to_text());
  RC_EXAMPLE_REQUIRE(declared->steps[2].key.subject.text() == setup.target.route.to_text());
  RC_EXAMPLE_REQUIRE(declared->steps[5].key.subject.text() == setup.source.path.to_text());
  RC_EXAMPLE_REQUIRE(declared->steps[6].key.subject.text() == setup.source.route.to_text());
  RC_EXAMPLE_REQUIRE(declared->lifecycle == PlanLifecycle::READY);
  RC_EXAMPLE_REQUIRE(declared->steps[0].state == StepLifecycle::READY);
  for (std::size_t index = 1; index < declared->steps.size(); ++index) {
    RC_EXAMPLE_REQUIRE(declared->steps[index].state == StepLifecycle::PENDING);
  }

  // Complete the prerequisites in canonical order: each one is the only ready step.
  std::uint64_t attempt_seed = 100;
  const StepKind prerequisites[] = {StepKind::VALIDATE_TARGET, StepKind::PREPARE_NEW_STATE,
                                    StepKind::INSTALL_NEW_ROUTE};
  for (const StepKind kind : prerequisites) {
    const ReadyStepList ready = governor.ready_steps(1);
    RC_EXAMPLE_REQUIRE(ready.steps.size() == 1u);
    RC_EXAMPLE_REQUIRE(ready.steps.front().plan == setup.plan.plan);
    RC_EXAMPLE_REQUIRE(ready.steps.front().key.kind == kind);
    const StepExecution execution =
        execute_ready_step(governor, fixture, ready.steps.front(), attempt_seed);
    RC_EXAMPLE_REQUIRE(execution.dispatched);
    RC_EXAMPLE_REQUIRE(execution.outcome == Outcome::STEP_COMPLETED);
  }

  // The new route is installed but not verified, so the old route state is still
  // untouched: no break-side step is ready and none has run.
  const std::optional<ConvergenceSnapshot> installed = governor.snapshot(setup.plan.plan);
  RC_EXAMPLE_REQUIRE(installed.has_value());
  RC_EXAMPLE_REQUIRE(installed->lifecycle == PlanLifecycle::EXECUTING);
  const StepSnapshot* activation = find_step(*installed, StepKind::ACTIVATE_NEW_PATH);
  RC_EXAMPLE_REQUIRE(activation != nullptr);
  RC_EXAMPLE_REQUIRE(activation->state == StepLifecycle::READY);
  const StepKind retained[] = {StepKind::VERIFY_NEW_STATE, StepKind::DEACTIVATE_OLD_PATH,
                               StepKind::WITHDRAW_OLD_ROUTE, StepKind::VERIFY_REMOVAL};
  for (const StepKind kind : retained) {
    const StepSnapshot* step = find_step(*installed, kind);
    RC_EXAMPLE_REQUIRE(step != nullptr);
    RC_EXAMPLE_REQUIRE(step->state == StepLifecycle::PENDING);
  }
  const ReadyStepList next = governor.ready_steps(8);
  RC_EXAMPLE_REQUIRE(next.steps.size() == 1u);
  RC_EXAMPLE_REQUIRE(next.steps.front().key.kind == StepKind::ACTIVATE_NEW_PATH);

  // The rest of the transition runs to completion, and neither break-side step is
  // ever dispatched before the new state was verified.
  const ExecutionReport rest = execute_plan(governor, fixture, setup.plan.plan, attempt_seed, 32);
  RC_EXAMPLE_REQUIRE(rest.outcome == Outcome::PLAN_COMPLETED);
  RC_EXAMPLE_REQUIRE(rest.completed == 6u);
  RC_EXAMPLE_REQUIRE(rest.break_steps == 2u);
  RC_EXAMPLE_REQUIRE(rest.break_steps_after_verification == rest.break_steps);
  const std::optional<ConvergenceSnapshot> completed = governor.snapshot(setup.plan.plan);
  RC_EXAMPLE_REQUIRE(completed.has_value());
  RC_EXAMPLE_REQUIRE(completed->lifecycle == PlanLifecycle::COMPLETED);
  for (const StepSnapshot& step : completed->steps) {
    RC_EXAMPLE_REQUIRE(step.state == StepLifecycle::COMPLETED);
  }
  std::cout << "EXAMPLE " << kExample << " OK\n";
  return 0;
}

// --- scenario 2: target invalidation before activation ----------------------

int example_target_invalidation() {
  constexpr std::string_view kExample = "target_invalidation";
  Fixture fixture(1);
  RC_EXAMPLE_REQUIRE(fixture.define_policy(kPolicySeed).accepted());
  const TransitionSetup setup = prepare_transition(fixture, 11);
  RC_EXAMPLE_REQUIRE(setup.plan.outcome == Outcome::PLAN_CREATED);
  ConvergenceGovernor& governor = fixture.governor();

  std::uint64_t attempt_seed = 200;
  const ExecutionReport first = execute_plan(governor, fixture, setup.plan.plan, attempt_seed, 3);
  RC_EXAMPLE_REQUIRE(first.completed == 3u);
  RC_EXAMPLE_REQUIRE(first.outcome == Outcome::STEP_COMPLETED);

  // The activation step is in flight when Path Authority moves the target path to
  // a newer generation.
  StepDispatch activation;
  AuthorityContext activation_authority;
  RC_EXAMPLE_REQUIRE(
      dispatch_next(governor, fixture, setup.plan.plan, attempt_seed, activation, activation_authority));
  RC_EXAMPLE_REQUIRE(activation.spec.key().kind == StepKind::ACTIVATE_NEW_PATH);
  publish_path(fixture.upstream(), setup.target.path, kPathGenerationTwo, true);
  PathChangeNotice notice;
  notice.legality.path = setup.target.path;
  notice.legality.generation = PathAuthorityGeneration::from_value(kPathGenerationTwo);
  notice.legality.legal = true;
  notice.provenance = Fixture::provenance_for(60);
  const NoticeResult noticed = governor.note_path_change(notice, fixture.authority(61));
  RC_EXAMPLE_REQUIRE(noticed.accepted());
  RC_EXAMPLE_REQUIRE(noticed.plans_invalidated == 1u);

  // The plan needs revalidation, the activation never happened, and the old route
  // state has not been touched.
  const std::optional<ConvergenceSnapshot> invalidated = governor.snapshot(setup.plan.plan);
  RC_EXAMPLE_REQUIRE(invalidated.has_value());
  RC_EXAMPLE_REQUIRE(invalidated->lifecycle == PlanLifecycle::REVALIDATION_REQUIRED);
  RC_EXAMPLE_REQUIRE(invalidated->currentness.has(CurrentnessCause::STALE_PATH_AUTHORITY));
  const StepSnapshot* in_flight = find_step(*invalidated, StepKind::ACTIVATE_NEW_PATH);
  RC_EXAMPLE_REQUIRE(in_flight != nullptr);
  RC_EXAMPLE_REQUIRE(in_flight->state == StepLifecycle::STALE);
  const StepKind retained[] = {StepKind::VERIFY_NEW_STATE, StepKind::DEACTIVATE_OLD_PATH,
                               StepKind::WITHDRAW_OLD_ROUTE, StepKind::VERIFY_REMOVAL};
  for (const StepKind kind : retained) {
    const StepSnapshot* step = find_step(*invalidated, kind);
    RC_EXAMPLE_REQUIRE(step != nullptr);
    RC_EXAMPLE_REQUIRE(step->state == StepLifecycle::PENDING);
  }

  // The completion of the in-flight activation arrives late and is refused.
  const PlanMutationResult late = governor.complete_step(
      evidence_for(fixture, activation, activation_authority), activation_authority);
  RC_EXAMPLE_REQUIRE(!late.accepted());
  RC_EXAMPLE_REQUIRE(late.outcome == Outcome::STALE_STEP);
  RC_EXAMPLE_REQUIRE(has_condition(late.conditions, ConditionCode::STEP_STALE));

  // Nothing can be dispatched from this plan until it is revalidated.
  const StepDispatch again = governor.dispatch_step(setup.plan.plan, activation.step,
                                                    fixture.authority(attempt_seed++));
  RC_EXAMPLE_REQUIRE(!again.accepted());
  RC_EXAMPLE_REQUIRE(again.outcome == Outcome::REVALIDATION_REQUIRED);
  std::cout << "EXAMPLE " << kExample << " OK\n";
  return 0;
}

// --- scenario 3: supersession and lineage -----------------------------------

int example_supersession_and_lineage() {
  constexpr std::string_view kExample = "supersession_and_lineage";
  Fixture fixture(1);
  RC_EXAMPLE_REQUIRE(fixture.define_policy(kPolicySeed).accepted());
  const TransitionSetup setup = prepare_transition(fixture, 11);
  RC_EXAMPLE_REQUIRE(setup.plan.outcome == Outcome::PLAN_CREATED);
  ConvergenceGovernor& governor = fixture.governor();

  std::uint64_t attempt_seed = 300;
  const ExecutionReport first = execute_plan(governor, fixture, setup.plan.plan, attempt_seed, 2);
  RC_EXAMPLE_REQUIRE(first.completed == 2u);

  StepDispatch in_flight;
  AuthorityContext in_flight_authority;
  RC_EXAMPLE_REQUIRE(
      dispatch_next(governor, fixture, setup.plan.plan, attempt_seed, in_flight, in_flight_authority));
  RC_EXAMPLE_REQUIRE(in_flight.spec.key().kind == StepKind::INSTALL_NEW_ROUTE);

  // Route Fabric publishes generation 3 while the R1 -> R2 plan is still running.
  const RouteBinding third =
      Fixture::binding(kRouteSeed, kRouteGenerationThree, kThirdPathSeed, kPathGenerationOne);
  fixture.publish(third);
  publish_path(fixture.upstream(), setup.source.path, kPathGenerationOne, true);
  RouteChangeNotice notice;
  notice.binding = third;
  notice.provenance = Fixture::provenance_for(70);
  const NoticeResult noticed = governor.note_route_change(notice, fixture.authority(71));
  RC_EXAMPLE_REQUIRE(noticed.outcome == Outcome::PLAN_SUPERSEDED);
  RC_EXAMPLE_REQUIRE(noticed.plans_superseded == 1u);

  const std::optional<ConvergenceSnapshot> superseded = governor.snapshot(setup.plan.plan);
  RC_EXAMPLE_REQUIRE(superseded.has_value());
  RC_EXAMPLE_REQUIRE(superseded->lifecycle == PlanLifecycle::SUPERSEDED);
  RC_EXAMPLE_REQUIRE(superseded->supersession_reason == ChangeReason::SUPERSEDE);
  RC_EXAMPLE_REQUIRE(superseded->currentness.has(CurrentnessCause::SUPERSEDED_BY_SUCCESSOR));
  const StepSnapshot* stale = find_step(*superseded, StepKind::INSTALL_NEW_ROUTE);
  RC_EXAMPLE_REQUIRE(stale != nullptr);
  RC_EXAMPLE_REQUIRE(stale->state == StepLifecycle::STALE);

  // Late work of the superseded plan is refused, both completions and dispatches.
  const PlanMutationResult late = governor.complete_step(
      evidence_for(fixture, in_flight, in_flight_authority), in_flight_authority);
  RC_EXAMPLE_REQUIRE(!late.accepted());
  RC_EXAMPLE_REQUIRE(late.outcome == Outcome::STALE_STEP);
  RC_EXAMPLE_REQUIRE(has_condition(late.conditions, ConditionCode::STEP_STALE));
  const StepDispatch rejected =
      governor.dispatch_step(setup.plan.plan, in_flight.step, fixture.authority(attempt_seed++));
  RC_EXAMPLE_REQUIRE(!rejected.accepted());
  RC_EXAMPLE_REQUIRE(rejected.outcome == Outcome::STALE_PLAN);
  RC_EXAMPLE_REQUIRE(has_condition(rejected.conditions, ConditionCode::PLAN_TERMINAL));

  // A successor plan for generation 3 can be created; it records its predecessor.
  const PlanMutationResult successor = fixture.create(setup.target, third, kPolicySeed, 72, true);
  RC_EXAMPLE_REQUIRE(successor.outcome == Outcome::PLAN_CREATED);
  const std::optional<ConvergenceSnapshot> successor_snapshot = governor.snapshot(successor.plan);
  RC_EXAMPLE_REQUIRE(successor_snapshot.has_value());
  RC_EXAMPLE_REQUIRE(successor_snapshot->predecessor == setup.plan.plan);
  RC_EXAMPLE_REQUIRE(successor_snapshot->target.generation == third.generation);

  // Lineage is preserved in both directions.  Path Authority refreshes the target
  // path generation, and the same semantic transition is planned again: the same
  // plan key with different content is a new plan identity that supersedes the
  // earlier one and records both links.
  publish_path(fixture.upstream(), third.path, kPathGenerationTwo, true);
  PathChangeNotice path_notice;
  path_notice.legality.path = third.path;
  path_notice.legality.generation = PathAuthorityGeneration::from_value(kPathGenerationTwo);
  path_notice.legality.legal = true;
  path_notice.provenance = Fixture::provenance_for(73);
  const NoticeResult path_result = governor.note_path_change(path_notice, fixture.authority(74));
  RC_EXAMPLE_REQUIRE(path_result.accepted());
  RC_EXAMPLE_REQUIRE(path_result.plans_invalidated == 1u);

  const RouteBinding refreshed = Fixture::binding(kRouteSeed, kRouteGenerationThree,
                                                  kThirdPathSeed, kPathGenerationTwo);
  const PlanMutationResult replanned = fixture.create(setup.target, refreshed, kPolicySeed, 75, true);
  RC_EXAMPLE_REQUIRE(replanned.outcome == Outcome::PLAN_CREATED);
  const std::optional<ConvergenceSnapshot> replanned_snapshot = governor.snapshot(replanned.plan);
  const std::optional<ConvergenceSnapshot> successor_after = governor.snapshot(successor.plan);
  RC_EXAMPLE_REQUIRE(replanned_snapshot.has_value());
  RC_EXAMPLE_REQUIRE(successor_after.has_value());
  RC_EXAMPLE_REQUIRE(replanned_snapshot->predecessor == successor.plan);
  RC_EXAMPLE_REQUIRE(successor_after->successor == replanned.plan);
  RC_EXAMPLE_REQUIRE(successor_after->lifecycle == PlanLifecycle::SUPERSEDED);
  RC_EXAMPLE_REQUIRE(successor_after->supersession_reason == ChangeReason::SUPERSEDE);
  std::cout << "EXAMPLE " << kExample << " OK\n";
  return 0;
}

// --- scenario 4: rollback ---------------------------------------------------

int example_rollback() {
  constexpr std::string_view kExample = "rollback";
  Fixture fixture(1);
  RC_EXAMPLE_REQUIRE(fixture.define_policy(kPolicySeed).accepted());
  const TransitionSetup setup = prepare_transition(fixture, 11);
  RC_EXAMPLE_REQUIRE(setup.plan.outcome == Outcome::PLAN_CREATED);
  ConvergenceGovernor& governor = fixture.governor();

  std::uint64_t attempt_seed = 400;
  RC_EXAMPLE_REQUIRE(run_forward_to_failure(fixture, setup, attempt_seed, governor) == 3u);
  const std::optional<ConvergenceSnapshot> failed = governor.snapshot(setup.plan.plan);
  RC_EXAMPLE_REQUIRE(failed.has_value());
  RC_EXAMPLE_REQUIRE(failed->lifecycle == PlanLifecycle::ROLLBACK_REQUIRED);
  const StepSnapshot* activation = find_step(*failed, StepKind::ACTIVATE_NEW_PATH);
  RC_EXAMPLE_REQUIRE(activation != nullptr);
  RC_EXAMPLE_REQUIRE(activation->state == StepLifecycle::FAILED);

  // The compensating work for the state that is still observed.
  std::string reason;
  const std::optional<std::vector<StepSpec>> compensation = generate_steps(
      setup.target, setup.source, Fixture::policy(kPolicySeed), governor.limits(), reason);
  RC_EXAMPLE_REQUIRE(compensation.has_value());

  const PlanMutationResult rollback =
      governor.begin_rollback(setup.plan.plan, fixture.authority(attempt_seed++));
  RC_EXAMPLE_REQUIRE(rollback.outcome == Outcome::ROLLBACK_PLAN_CREATED);
  RC_EXAMPLE_REQUIRE(!rollback.plan.is_nil());

  // The forward plan is fenced into ROLLING_BACK and names its compensating plan.
  const std::optional<ConvergenceSnapshot> forward = governor.snapshot(setup.plan.plan);
  RC_EXAMPLE_REQUIRE(forward.has_value());
  RC_EXAMPLE_REQUIRE(forward->lifecycle == PlanLifecycle::ROLLING_BACK);
  RC_EXAMPLE_REQUIRE(forward->rollback_plan == rollback.plan);
  RC_EXAMPLE_REQUIRE(forward->successor == rollback.plan);

  // The compensating plan is an ordinary governed plan whose steps are a subset of
  // the compensating work for the observed target state.
  const std::optional<ConvergenceSnapshot> compensating = governor.snapshot(rollback.plan);
  RC_EXAMPLE_REQUIRE(compensating.has_value());
  RC_EXAMPLE_REQUIRE(compensating->is_rollback);
  RC_EXAMPLE_REQUIRE(compensating->predecessor == setup.plan.plan);
  RC_EXAMPLE_REQUIRE(compensating->target.generation == setup.source.generation);
  RC_EXAMPLE_REQUIRE(compensating->source.generation == setup.target.generation);
  RC_EXAMPLE_REQUIRE(compensating->steps.size() <= compensation->size());
  for (const StepSnapshot& step : compensating->steps) {
    bool in_compensation = false;
    for (const StepSpec& spec : *compensation) {
      if (spec.key() == step.key) {
        in_compensation = true;
        break;
      }
    }
    RC_EXAMPLE_REQUIRE(in_compensation);
  }

  // It is a real dependency-safe plan and runs to completion.
  const ExecutionReport run =
      execute_plan(governor, fixture, rollback.plan, attempt_seed, 32);
  RC_EXAMPLE_REQUIRE(run.outcome == Outcome::PLAN_COMPLETED);
  RC_EXAMPLE_REQUIRE(run.completed == static_cast<std::uint32_t>(compensating->steps.size()));
  const std::optional<ConvergenceSnapshot> rollback_done = governor.snapshot(rollback.plan);
  RC_EXAMPLE_REQUIRE(rollback_done.has_value());
  RC_EXAMPLE_REQUIRE(rollback_done->lifecycle == PlanLifecycle::COMPLETED);

  // The forward plan ends superseded by its own rollback, with the reason recorded.
  const std::optional<ConvergenceSnapshot> forward_done = governor.snapshot(setup.plan.plan);
  RC_EXAMPLE_REQUIRE(forward_done.has_value());
  RC_EXAMPLE_REQUIRE(forward_done->lifecycle == PlanLifecycle::SUPERSEDED);
  RC_EXAMPLE_REQUIRE(forward_done->supersession_reason == ChangeReason::ROLLBACK_COMPLETED);
  RC_EXAMPLE_REQUIRE(forward_done->successor == rollback.plan);
  std::cout << "EXAMPLE " << kExample << " OK\n";
  return 0;
}

// --- scenario 5: unsafe rollback rejection ----------------------------------

int example_unsafe_rollback_rejection() {
  constexpr std::string_view kExample = "unsafe_rollback_rejection";
  Fixture fixture(1);
  RC_EXAMPLE_REQUIRE(fixture.define_policy(kPolicySeed).accepted());
  const TransitionSetup setup = prepare_transition(fixture, 11);
  RC_EXAMPLE_REQUIRE(setup.plan.outcome == Outcome::PLAN_CREATED);
  ConvergenceGovernor& governor = fixture.governor();

  std::uint64_t attempt_seed = 500;
  RC_EXAMPLE_REQUIRE(run_forward_to_failure(fixture, setup, attempt_seed, governor) == 3u);

  // Path Authority withdraws legality from the path the rollback would restore.
  publish_path(fixture.upstream(), setup.source.path, kPathGenerationOne, false);
  PathChangeNotice notice;
  notice.legality.path = setup.source.path;
  notice.legality.generation = PathAuthorityGeneration::from_value(kPathGenerationOne);
  notice.legality.legal = false;
  notice.provenance = Fixture::provenance_for(80);
  const NoticeResult noticed = governor.note_path_change(notice, fixture.authority(81));
  RC_EXAMPLE_REQUIRE(noticed.accepted());

  const std::size_t plans_before = governor.plan_count();
  const PlanMutationResult rollback =
      governor.begin_rollback(setup.plan.plan, fixture.authority(attempt_seed++));
  RC_EXAMPLE_REQUIRE(rollback.outcome == Outcome::UNSAFE_ROLLBACK);
  RC_EXAMPLE_REQUIRE(has_condition(rollback.conditions, ConditionCode::ROLLBACK_TARGET_UNAUTHORIZED));
  RC_EXAMPLE_REQUIRE(rollback.plan.is_nil());

  // No compensating plan was created and the forward plan did not start rolling back.
  RC_EXAMPLE_REQUIRE(governor.plan_count() == plans_before);
  const std::optional<ConvergenceSnapshot> forward = governor.snapshot(setup.plan.plan);
  RC_EXAMPLE_REQUIRE(forward.has_value());
  RC_EXAMPLE_REQUIRE(forward->lifecycle == PlanLifecycle::ROLLBACK_REQUIRED);
  RC_EXAMPLE_REQUIRE(forward->rollback_plan.is_nil());
  std::cout << "EXAMPLE " << kExample << " OK\n";
  return 0;
}

// --- scenario 6: stale completion -------------------------------------------

int example_stale_completion() {
  constexpr std::string_view kExample = "stale_completion";
  Fixture fixture(1);
  RC_EXAMPLE_REQUIRE(fixture.define_policy(kPolicySeed).accepted());
  const TransitionSetup setup = prepare_transition(fixture, 11);
  RC_EXAMPLE_REQUIRE(setup.plan.outcome == Outcome::PLAN_CREATED);
  ConvergenceGovernor& governor = fixture.governor();

  std::uint64_t attempt_seed = 600;
  StepDispatch dispatch;
  AuthorityContext authority;
  RC_EXAMPLE_REQUIRE(
      dispatch_next(governor, fixture, setup.plan.plan, attempt_seed, dispatch, authority));
  RC_EXAMPLE_REQUIRE(dispatch.spec.key().kind == StepKind::VALIDATE_TARGET);

  // The target route generation is superseded while the step is in flight.
  const RouteBinding third =
      Fixture::binding(kRouteSeed, kRouteGenerationThree, kThirdPathSeed, kPathGenerationOne);
  fixture.publish(third);
  RouteChangeNotice notice;
  notice.binding = third;
  notice.provenance = Fixture::provenance_for(90);
  const NoticeResult noticed = governor.note_route_change(notice, fixture.authority(91));
  RC_EXAMPLE_REQUIRE(noticed.outcome == Outcome::PLAN_SUPERSEDED);

  const std::optional<PlanSummary> before = governor.query_plan(setup.plan.plan);
  RC_EXAMPLE_REQUIRE(before.has_value());
  const std::uint64_t rejections_before = governor.stats().stale_completions_rejected;

  // The completion of the in-flight step arrives after the supersession.
  const PlanMutationResult late =
      governor.complete_step(evidence_for(fixture, dispatch, authority), authority);
  RC_EXAMPLE_REQUIRE(!late.accepted());
  RC_EXAMPLE_REQUIRE(late.outcome == Outcome::STALE_STEP);
  RC_EXAMPLE_REQUIRE(has_condition(late.conditions, ConditionCode::STEP_STALE));
  RC_EXAMPLE_REQUIRE(governor.stats().stale_completions_rejected == rejections_before + 1u);

  // The rejected completion advanced nothing at all.
  const std::optional<PlanSummary> after = governor.query_plan(setup.plan.plan);
  RC_EXAMPLE_REQUIRE(after.has_value());
  RC_EXAMPLE_REQUIRE(after->generation == before->generation);
  RC_EXAMPLE_REQUIRE(after->lifecycle == PlanLifecycle::SUPERSEDED);
  RC_EXAMPLE_REQUIRE(after->completed_steps == 0u);
  const std::optional<ConvergenceSnapshot> snapshot = governor.snapshot(setup.plan.plan);
  RC_EXAMPLE_REQUIRE(snapshot.has_value());
  const StepSnapshot* step = find_step(*snapshot, StepKind::VALIDATE_TARGET);
  RC_EXAMPLE_REQUIRE(step != nullptr);
  RC_EXAMPLE_REQUIRE(step->state == StepLifecycle::STALE);
  std::cout << "EXAMPLE " << kExample << " OK\n";
  return 0;
}

}  // namespace

int main() {
  if (const int status = example_basic_make_before_break(); status != 0) {
    return status;
  }
  if (const int status = example_target_invalidation(); status != 0) {
    return status;
  }
  if (const int status = example_supersession_and_lineage(); status != 0) {
    return status;
  }
  if (const int status = example_rollback(); status != 0) {
    return status;
  }
  if (const int status = example_unsafe_rollback_rejection(); status != 0) {
    return status;
  }
  if (const int status = example_stale_completion(); status != 0) {
    return status;
  }
  return 0;
}
