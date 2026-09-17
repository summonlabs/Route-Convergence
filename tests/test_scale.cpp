// tests/test_scale.cpp
//
// SYNTHETIC control-plane scale scenarios for Route Convergence.
//
// Every scenario in this file is labelled SYNTHETIC: the populations below are
// control-plane plan populations driven through rc::test::Fixture and its
// SyntheticUpstream observation source, NOT physical fabrics, NOT forwarding
// state and NOT packets.  No scenario claims physical convergence.
//
// Each scenario asserts an observable property of the real API: exact plan
// counts, the exact number of plans one upstream notice affects, plan identity
// and digest stability, and index consistency across a durable round trip.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <process.h>
#include <string>
#include <vector>

#include "fixture.hpp"
#include "rc/rc.hpp"
#include "test_framework.hpp"

namespace {

using rc::ConvergencePlanId;
using rc::CoordinatorEpoch;
using rc::PathAuthorityGeneration;
using rc::PlanMutationResult;
using rc::RouteBinding;
using rc::StepKey;
using rc::StepSpec;
using rc::TransitionStepId;

constexpr std::uint32_t kTargetState = static_cast<std::uint32_t>(rc::ConflictDomain::TARGET_STATE);

struct RoutePair {
  RouteBinding source;
  RouteBinding target;
};

[[nodiscard]] rc::SubjectToken token(const std::string& text) {
  const std::optional<rc::SubjectToken> value = rc::SubjectToken::make(text);
  RC_REQUIRE(value.has_value());
  return *value;
}

void set_path_legality(rc::test::Fixture& fixture, const rc::PathId& path, std::uint64_t generation,
                       bool legal) {
  rc::PathLegality legality;
  legality.path = path;
  legality.generation = PathAuthorityGeneration::from_value(generation);
  legality.legal = legal;
  fixture.upstream().set_path(legality);
}

// SYNTHETIC fixture helper: publishes the target route binding and the exact path
// legality the plan is built against.
[[nodiscard]] RoutePair publish_route(rc::test::Fixture& fixture, std::uint64_t route_seed,
                                      std::uint64_t target_generation, std::uint64_t source_path,
                                      std::uint64_t target_path) {
  RoutePair pair;
  pair.source = rc::test::Fixture::binding(route_seed, target_generation - 1, source_path, 1);
  pair.target = rc::test::Fixture::binding(route_seed, target_generation, target_path, 1);
  fixture.publish(pair.target);
  set_path_legality(fixture, pair.source.path, 1, true);
  return pair;
}

// A hand-built EXPLICIT DAG with exactly step_count steps: VALIDATE_TARGET first,
// FINALIZE last and step_count - 2 observation stages in a strict chain, so the
// step count is real and every execution layer is exactly one step wide.
[[nodiscard]] std::vector<StepSpec> chain_dag(std::size_t step_count, const RouteBinding& target) {
  RC_REQUIRE(step_count >= 2);
  std::vector<StepSpec> steps;
  steps.reserve(step_count);
  StepSpec validate;
  validate.kind = rc::StepKind::VALIDATE_TARGET;
  validate.subject = token("target");
  validate.reversibility = rc::Reversibility::OBSERVATION;
  validate.conflict_domains = kTargetState;
  validate.path = target.path;
  validate.path_authority_generation = target.path_authority_generation;
  steps.push_back(validate);
  for (std::size_t index = 1; index + 1 < step_count; ++index) {
    StepSpec stage;
    stage.kind = rc::StepKind::VERIFY_NEW_STATE;
    stage.subject = token("stage" + std::to_string(index));
    stage.reversibility = rc::Reversibility::OBSERVATION;
    stage.conflict_domains = 0;
    stage.verification = true;
    stage.depends_on = {steps.back().key()};
    steps.push_back(stage);
  }
  StepSpec finalise;
  finalise.kind = rc::StepKind::FINALIZE;
  finalise.subject = token("plan");
  finalise.reversibility = rc::Reversibility::OBSERVATION;
  finalise.conflict_domains = kTargetState;
  finalise.depends_on = {steps.back().key()};
  steps.push_back(finalise);
  for (StepSpec& spec : steps) {
    spec.route = target.route;
    spec.route_generation = target.generation;
  }
  return steps;
}

// Creates one EXPLICIT plan.  The governor validates the DAG, the conflict
// domains, the policy conformance and the resource limits.
[[nodiscard]] PlanMutationResult create_explicit(rc::test::Fixture& fixture,
                                                 const RouteBinding& source,
                                                 const RouteBinding& target,
                                                 const std::vector<StepSpec>& steps,
                                                 std::uint64_t attempt_seed) {
  rc::PlanRequest request;
  request.mode = rc::PlanMode::EXPLICIT;
  request.source = source;
  request.target = target;
  request.policy = rc::test::Fixture::policy(1);
  request.epoch = fixture.governor().epoch();
  request.provenance = rc::test::Fixture::provenance_for(attempt_seed);
  request.accept_historical_source = true;
  request.explicit_steps = steps;
  return fixture.governor().create_plan(request, fixture.authority(attempt_seed));
}

// Dispatches and completes every ready step of one plan until nothing is left.
[[nodiscard]] std::size_t drain_plan(rc::test::Fixture& fixture, const ConvergencePlanId& plan,
                                     std::uint64_t& attempt_seed) {
  std::size_t completed = 0;
  for (std::size_t round = 0; round < 256; ++round) {
    const rc::ReadyStepList ready = fixture.governor().ready_steps(64);
    const rc::ReadyStep* candidate = nullptr;
    for (const rc::ReadyStep& step : ready.steps) {
      if (step.plan == plan) {
        candidate = &step;
        break;
      }
    }
    if (candidate == nullptr) {
      break;
    }
    const rc::AuthorityContext dispatch_context = fixture.authority(attempt_seed++);
    const rc::StepDispatch dispatch =
        fixture.governor().dispatch_step(candidate->plan, candidate->step, dispatch_context);
    RC_REQUIRE(dispatch.accepted());
    rc::CompletionEvidence evidence;
    evidence.plan = candidate->plan;
    evidence.step = candidate->step;
    evidence.step_generation = dispatch.step_generation;
    evidence.attempt = dispatch_context.attempt;
    evidence.epoch = dispatch.epoch;
    evidence.publisher = fixture.publisher();
    evidence.worker_boot = fixture.boot();
    evidence.outcome = rc::BackendOutcome::APPLIED;
    evidence.dispatch_watermark = dispatch.watermark;
    evidence.applied_route_generation = dispatch.spec.route_generation;
    evidence.observed_path_authority_generation = dispatch.spec.path_authority_generation;
    evidence.id = rc::derive_evidence_id(evidence);
    const PlanMutationResult result =
        fixture.governor().complete_step(evidence, fixture.authority(attempt_seed++));
    RC_REQUIRE(result.accepted());
    ++completed;
  }
  return completed;
}

[[nodiscard]] std::filesystem::path per_process_store(const std::string& name) {
  return std::filesystem::temp_directory_path() /
         (name + "_" + std::to_string(static_cast<long long>(_getpid())) + ".store");
}

}  // namespace

// SYNTHETIC: one thousand control-plane plans in one governor.
RC_TEST(synthetic_thousand_plan_population_is_complete_and_reproducible) {
  rc::test::Fixture fixture(31);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  constexpr std::size_t kPlanTotal = 1000;
  std::vector<ConvergencePlanId> plans;
  plans.reserve(kPlanTotal);
  for (std::size_t index = 0; index < kPlanTotal; ++index) {
    const RoutePair pair = publish_route(fixture, 10000 + index, 2, 20000 + index, 30000 + index);
    const std::vector<StepSpec> steps = chain_dag(2, pair.target);
    const PlanMutationResult created =
        create_explicit(fixture, pair.source, pair.target, steps, 40000 + index);
    RC_REQUIRE(created.accepted());
    plans.push_back(created.plan);
  }
  RC_CHECK_EQ(fixture.governor().plan_count(), kPlanTotal);

  // The bounded listing reports truncation instead of silently returning a
  // prefix, and every entry it does return is internally consistent.
  const rc::PlanList listing = fixture.governor().list_plans();
  RC_CHECK_EQ(listing.plans.size(),
              static_cast<std::size_t>(fixture.governor().limits().max_batch_size));
  RC_CHECK(listing.truncated);
  for (const rc::PlanSummary& summary : listing.plans) {
    const std::optional<rc::ConvergenceSnapshot> snapshot = fixture.governor().snapshot(summary.id);
    RC_REQUIRE(snapshot.has_value());
    RC_CHECK_EQ(summary.total_steps, 2u);
    RC_CHECK(summary.key.route == snapshot->target.route);
    RC_CHECK(rc::ConvergenceGovernor::snapshot_digest(*snapshot) == snapshot->digest);
  }

  // A digest is a function of semantic content: the same explicit DAG, built
  // again in a second governor for the same route, is the same plan.
  rc::test::Fixture twin(31);
  RC_REQUIRE(twin.define_policy(1).accepted());
  const RoutePair pair = publish_route(twin, 10000, 2, 20000, 30000);
  const std::vector<StepSpec> steps = chain_dag(2, pair.target);
  const PlanMutationResult recreated = create_explicit(twin, pair.source, pair.target, steps, 40000);
  RC_REQUIRE(recreated.accepted());
  RC_CHECK(recreated.plan == plans.front());
  const std::optional<rc::PlanSummary> expected = fixture.governor().query_plan(plans.front());
  const std::optional<rc::PlanSummary> actual = twin.governor().query_plan(recreated.plan);
  RC_REQUIRE(expected.has_value());
  RC_REQUIRE(actual.has_value());
  RC_CHECK(expected->digest == actual->digest);
}

// SYNTHETIC: ten thousand control-plane plans in one governor, with a targeted
// route notice that must reach exactly one of them.
RC_TEST(synthetic_ten_thousand_plan_population_targets_one_route) {
  rc::test::Fixture fixture(32);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  constexpr std::size_t kPlanTotal = 10000;
  std::vector<ConvergencePlanId> plans;
  std::vector<RouteBinding> targets;
  plans.reserve(kPlanTotal);
  targets.reserve(kPlanTotal);
  for (std::size_t index = 0; index < kPlanTotal; ++index) {
    const RoutePair pair = publish_route(fixture, 50000 + index, 2, 60000 + index, 70000 + index);
    const std::vector<StepSpec> steps = chain_dag(2, pair.target);
    const PlanMutationResult created =
        create_explicit(fixture, pair.source, pair.target, steps, 80000 + index);
    RC_REQUIRE(created.accepted());
    plans.push_back(created.plan);
    targets.push_back(pair.target);
  }
  RC_CHECK_EQ(fixture.governor().plan_count(), kPlanTotal);

  // Every sampled plan is present and keyed exactly as it was created.
  for (std::size_t index = 0; index < kPlanTotal; index += 997) {
    const std::optional<rc::PlanKey> key = fixture.governor().plan_key(plans[index]);
    RC_REQUIRE(key.has_value());
    RC_CHECK(key->route == targets[index].route);
    RC_CHECK(key->target_generation == targets[index].generation);
  }

  // One route moves to its next generation: exactly the plan of that route is
  // superseded and the rest of the population is untouched.
  const std::size_t victim = 4321;
  RouteBinding advanced = targets[victim];
  advanced.generation = rc::RouteGeneration::from_value(3);
  fixture.upstream().set_route(advanced);
  rc::RouteChangeNotice notice;
  notice.binding = advanced;
  notice.provenance = rc::test::Fixture::provenance_for(1);
  const rc::NoticeResult observed =
      fixture.governor().note_route_change(notice, fixture.authority(900001));
  RC_CHECK_EQ(observed.plans_examined, 1u);
  RC_CHECK_EQ(observed.plans_superseded, 1u);
  RC_CHECK_EQ(observed.plans_invalidated, 0u);
  const std::optional<rc::PlanSummary> superseded = fixture.governor().query_plan(plans[victim]);
  RC_REQUIRE(superseded.has_value());
  RC_CHECK(superseded->lifecycle == rc::PlanLifecycle::SUPERSEDED);
  const std::optional<rc::PlanSummary> survivor = fixture.governor().query_plan(plans[victim + 1]);
  RC_REQUIRE(survivor.has_value());
  RC_CHECK(survivor->lifecycle != rc::PlanLifecycle::SUPERSEDED);
  RC_CHECK_EQ(fixture.governor().plan_count(), kPlanTotal);
}

// SYNTHETIC: one hundred thousand control-plane plans in one governor, bounded
// by the configured plan limit.
RC_TEST(synthetic_hundred_thousand_plan_population_respects_the_limit) {
  constexpr std::size_t kPlanTotal = 100000;
  rc::ConvergenceLimits limits;
  limits.max_plans = static_cast<std::uint32_t>(kPlanTotal);
  limits.max_history_per_plan = 1;
  rc::test::Fixture fixture(33, CoordinatorEpoch::from_value(1), limits);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  for (std::size_t index = 0; index < kPlanTotal; ++index) {
    const RoutePair pair =
        publish_route(fixture, 200000 + index, 2, 400000 + index, 600000 + index);
    const std::vector<StepSpec> steps = chain_dag(2, pair.target);
    const PlanMutationResult created =
        create_explicit(fixture, pair.source, pair.target, steps, 800000 + index);
    RC_REQUIRE(created.accepted());
  }
  RC_CHECK_EQ(fixture.governor().plan_count(), kPlanTotal);
  const rc::PlanList listing = fixture.governor().list_plans();
  RC_CHECK(listing.truncated);
  RC_CHECK_EQ(listing.plans.size(), static_cast<std::size_t>(limits.max_batch_size));

  // The plan limit is a live limit, not a suggestion.
  const RoutePair extra = publish_route(fixture, 999999, 2, 999998, 999997);
  const std::vector<StepSpec> steps = chain_dag(2, extra.target);
  const PlanMutationResult rejected =
      create_explicit(fixture, extra.source, extra.target, steps, 999996);
  RC_CHECK(rejected.outcome == rc::Outcome::RESOURCE_LIMIT);
  RC_CHECK(rc::test::has_condition(rejected.conditions, rc::ConditionCode::PLAN_LIMIT));
  RC_CHECK_EQ(fixture.governor().plan_count(), kPlanTotal);
}

// SYNTHETIC: hand-built EXPLICIT DAGs of 8, 16, 32 and 64 steps, so that the
// step count is real rather than promised.
RC_TEST(synthetic_explicit_dags_of_8_16_32_and_64_steps) {
  rc::test::Fixture fixture(34);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  const std::size_t sizes[4] = {8, 16, 32, 64};
  std::uint64_t attempt = 1;
  for (std::size_t index = 0; index < 4; ++index) {
    const std::size_t step_count = sizes[index];
    const RoutePair pair = publish_route(fixture, 300 + index, 2, 400 + index, 500 + index);
    const std::vector<StepSpec> steps = chain_dag(step_count, pair.target);
    RC_CHECK_EQ(steps.size(), step_count);
    const PlanMutationResult created =
        create_explicit(fixture, pair.source, pair.target, steps, attempt++);
    RC_REQUIRE(created.accepted());
    const std::optional<rc::PlanSummary> summary = fixture.governor().query_plan(created.plan);
    RC_REQUIRE(summary.has_value());
    RC_CHECK_EQ(summary->total_steps, static_cast<std::uint32_t>(step_count));
    const std::optional<rc::ConvergenceSnapshot> snapshot = fixture.governor().snapshot(created.plan);
    RC_REQUIRE(snapshot.has_value());
    RC_CHECK_EQ(snapshot->steps.size(), step_count);
    RC_CHECK_EQ(snapshot->layers.size(), step_count);
    std::size_t executable = 0;
    std::vector<StepSpec> rebuilt;
    for (const rc::StepSnapshot& step : snapshot->steps) {
      executable += step.executable ? 1 : 0;
      StepSpec spec;
      spec.kind = step.key.kind;
      spec.subject = step.key.subject;
      spec.conflict_domains = step.conflict_domains;
      spec.mandatory = step.mandatory;
      spec.idempotent = step.idempotent;
      spec.verification = step.verification;
      spec.depends_on = step.depends_on;
      rebuilt.push_back(std::move(spec));
    }
    RC_CHECK_EQ(executable, static_cast<std::size_t>(1));
    const std::optional<std::vector<std::vector<std::size_t>>> layers = rc::canonical_layers(rebuilt);
    RC_REQUIRE(layers.has_value());
    RC_CHECK_EQ(layers->size(), step_count);
    // The whole DAG really executes to completion.
    const std::size_t completed = drain_plan(fixture, created.plan, attempt);
    RC_CHECK_EQ(completed, step_count);
    const std::optional<rc::PlanSummary> finished = fixture.governor().query_plan(created.plan);
    RC_REQUIRE(finished.has_value());
    RC_CHECK(finished->lifecycle == rc::PlanLifecycle::COMPLETED);
    RC_CHECK_EQ(finished->completed_steps, static_cast<std::uint32_t>(step_count));
  }

  // One step beyond the configured ceiling is refused, not truncated.
  const RoutePair oversized = publish_route(fixture, 399, 2, 499, 599);
  const std::vector<StepSpec> too_many = chain_dag(65, oversized.target);
  RC_CHECK_EQ(too_many.size(), static_cast<std::size_t>(65));
  const PlanMutationResult rejected =
      create_explicit(fixture, oversized.source, oversized.target, too_many, attempt++);
  RC_CHECK(rejected.outcome == rc::Outcome::RESOURCE_LIMIT);
  RC_CHECK(rc::test::has_condition(rejected.conditions, rc::ConditionCode::STEP_LIMIT));
}

// SYNTHETIC: many control-plane plans sharing one PathId.  One targeted path
// notice must affect exactly the plans that reference that path.
RC_TEST(synthetic_shared_path_invalidation_counts_exact_targets) {
  rc::test::Fixture fixture(35);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  constexpr std::size_t kShared = 500;
  constexpr std::size_t kControl = 500;
  const rc::PathId shared_path = rc::test::Fixture::path_for(900001);
  const rc::PathId control_path = rc::test::Fixture::path_for(900002);
  std::vector<ConvergencePlanId> shared_plans;
  std::vector<ConvergencePlanId> control_plans;
  shared_plans.reserve(kShared);
  control_plans.reserve(kControl);
  for (std::size_t index = 0; index < kShared; ++index) {
    const RoutePair pair = publish_route(fixture, 1000000 + index, 2, 1100000 + index, 900001);
    RC_CHECK(pair.target.path == shared_path);
    const std::vector<StepSpec> steps = chain_dag(2, pair.target);
    const PlanMutationResult created =
        create_explicit(fixture, pair.source, pair.target, steps, 1200000 + index);
    RC_REQUIRE(created.accepted());
    shared_plans.push_back(created.plan);
  }
  for (std::size_t index = 0; index < kControl; ++index) {
    const RoutePair pair = publish_route(fixture, 1300000 + index, 2, 1400000 + index, 900002);
    RC_CHECK(pair.target.path == control_path);
    const std::vector<StepSpec> steps = chain_dag(2, pair.target);
    const PlanMutationResult created =
        create_explicit(fixture, pair.source, pair.target, steps, 1500000 + index);
    RC_REQUIRE(created.accepted());
    control_plans.push_back(created.plan);
  }
  RC_CHECK_EQ(fixture.governor().plan_count(), kShared + kControl);

  // The exact number of plans that reference the shared path is known by
  // construction; the notice must invalidate exactly those and nothing else.
  set_path_legality(fixture, shared_path, 2, true);
  rc::PathChangeNotice notice;
  notice.legality.path = shared_path;
  notice.legality.generation = PathAuthorityGeneration::from_value(2);
  notice.legality.legal = true;
  notice.provenance = rc::test::Fixture::provenance_for(2);
  const rc::NoticeResult observed =
      fixture.governor().note_path_change(notice, fixture.authority(1600001));
  RC_CHECK_EQ(observed.plans_examined, static_cast<std::uint32_t>(kShared));
  RC_CHECK_EQ(observed.plans_invalidated, static_cast<std::uint32_t>(kShared));
  RC_CHECK(observed.outcome == rc::Outcome::PLAN_REVALIDATION_REQUIRED);

  std::size_t invalidated = 0;
  for (const ConvergencePlanId& plan : shared_plans) {
    const std::optional<rc::PlanSummary> summary = fixture.governor().query_plan(plan);
    RC_REQUIRE(summary.has_value());
    invalidated += summary->lifecycle == rc::PlanLifecycle::REVALIDATION_REQUIRED ? 1 : 0;
  }
  RC_CHECK_EQ(invalidated, kShared);
  std::size_t control_invalidated = 0;
  for (const ConvergencePlanId& plan : control_plans) {
    const std::optional<rc::PlanSummary> summary = fixture.governor().query_plan(plan);
    RC_REQUIRE(summary.has_value());
    control_invalidated += summary->lifecycle == rc::PlanLifecycle::REVALIDATION_REQUIRED ? 1 : 0;
  }
  RC_CHECK_EQ(control_invalidated, static_cast<std::size_t>(0));

  // The control path is a separate index entry: invalidating it affects only the
  // control group.
  set_path_legality(fixture, control_path, 2, true);
  rc::PathChangeNotice control_notice = notice;
  control_notice.legality.path = control_path;
  control_notice.provenance = rc::test::Fixture::provenance_for(3);
  const rc::NoticeResult control_result =
      fixture.governor().note_path_change(control_notice, fixture.authority(1600002));
  RC_CHECK_EQ(control_result.plans_examined, static_cast<std::uint32_t>(kControl));
  RC_CHECK_EQ(control_result.plans_invalidated, static_cast<std::uint32_t>(kControl));
  RC_CHECK_EQ(fixture.governor().plan_count(), kShared + kControl);
}

// SYNTHETIC: mass target supersession over many plans and many routes.
RC_TEST(synthetic_mass_target_supersession_is_exact) {
  rc::test::Fixture fixture(36);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  constexpr std::size_t kRoutes = 200;
  constexpr std::uint64_t kPlansPerRoute = 5;
  std::vector<std::vector<ConvergencePlanId>> plans(kRoutes);
  std::vector<RouteBinding> latest(kRoutes);
  std::uint64_t attempt = 2000000;
  for (std::size_t route = 0; route < kRoutes; ++route) {
    for (std::uint64_t generation = 2; generation <= kPlansPerRoute + 1; ++generation) {
      const RoutePair pair =
          publish_route(fixture, 2100000 + route, generation, 2200000 + route, 2300000 + route);
      const std::vector<StepSpec> steps = chain_dag(2, pair.target);
      const PlanMutationResult created =
          create_explicit(fixture, pair.source, pair.target, steps, attempt++);
      RC_REQUIRE(created.accepted());
      plans[route].push_back(created.plan);
      latest[route] = pair.target;
    }
  }
  RC_CHECK_EQ(fixture.governor().plan_count(), kRoutes * kPlansPerRoute);

  // Each route advances to its newest generation once: every plan of the route
  // with an older target generation is superseded, the newest one stays live.
  std::uint32_t examined = 0;
  std::uint32_t superseded = 0;
  for (std::size_t route = 0; route < kRoutes; ++route) {
    rc::RouteChangeNotice notice;
    notice.binding = latest[route];
    notice.provenance = rc::test::Fixture::provenance_for(3000000 + route);
    const rc::NoticeResult observed =
        fixture.governor().note_route_change(notice, fixture.authority(attempt++));
    RC_CHECK_EQ(observed.plans_examined, static_cast<std::uint32_t>(kPlansPerRoute));
    RC_CHECK_EQ(observed.plans_superseded, static_cast<std::uint32_t>(kPlansPerRoute - 1));
    examined += observed.plans_examined;
    superseded += observed.plans_superseded;
  }
  RC_CHECK_EQ(examined, static_cast<std::uint32_t>(kRoutes * kPlansPerRoute));
  RC_CHECK_EQ(superseded, static_cast<std::uint32_t>(kRoutes * (kPlansPerRoute - 1)));
  RC_CHECK_EQ(fixture.governor().plan_count(), kRoutes * kPlansPerRoute);

  std::size_t live = 0;
  std::size_t retired = 0;
  for (const std::vector<ConvergencePlanId>& route_plans : plans) {
    for (std::size_t index = 0; index < route_plans.size(); ++index) {
      const std::optional<rc::PlanSummary> summary =
          fixture.governor().query_plan(route_plans[index]);
      RC_REQUIRE(summary.has_value());
      const bool newest = index + 1 == route_plans.size();
      if (newest) {
        live += summary->lifecycle != rc::PlanLifecycle::SUPERSEDED ? 1 : 0;
      } else {
        retired += summary->lifecycle == rc::PlanLifecycle::SUPERSEDED ? 1 : 0;
      }
    }
  }
  RC_CHECK_EQ(live, kRoutes);
  RC_CHECK_EQ(retired, kRoutes * (kPlansPerRoute - 1));
}

// SYNTHETIC: mass recovery of a durable population, including plans whose
// in-flight work is unknown after the restart.
RC_TEST(synthetic_mass_recovery_requires_reconciliation) {
  constexpr std::size_t kPlanTotal = 2000;
  constexpr std::size_t kInFlight = 200;
  const std::filesystem::path store = per_process_store("rc_scale_recovery");
  std::error_code remove_error;
  std::filesystem::remove(store, remove_error);
  rc::ConvergenceLimits limits;
  limits.max_history_per_plan = 8;
  std::vector<ConvergencePlanId> plans;
  std::vector<StepKey> head_keys;
  plans.reserve(kPlanTotal);
  head_keys.reserve(kPlanTotal);
  std::uint64_t attempt = 3000000;
  {
    rc::test::Fixture origin(37, CoordinatorEpoch::from_value(4), limits);
    RC_REQUIRE(origin.define_policy(1).accepted());
    for (std::size_t index = 0; index < kPlanTotal; ++index) {
      const RoutePair pair =
          publish_route(origin, 3100000 + index, 2, 3200000 + index, 3300000 + index);
      const std::vector<StepSpec> steps = chain_dag(2, pair.target);
      const PlanMutationResult created =
          create_explicit(origin, pair.source, pair.target, steps, attempt++);
      RC_REQUIRE(created.accepted());
      plans.push_back(created.plan);
      head_keys.push_back(steps.front().key());
    }
    RC_CHECK_EQ(origin.governor().plan_count(), kPlanTotal);
    // One in every ten plans is left with work in flight when the store is
    // written.
    std::size_t dispatched = 0;
    for (std::size_t index = 0; index < kPlanTotal; index += 10) {
      const TransitionStepId step = rc::derive_step_id(plans[index], head_keys[index]);
      const rc::StepDispatch dispatch =
          origin.governor().dispatch_step(plans[index], step, origin.authority(attempt++));
      RC_REQUIRE(dispatch.accepted());
      ++dispatched;
    }
    RC_CHECK_EQ(dispatched, kInFlight);
    RC_REQUIRE(origin.governor().save(store).accepted());
  }

  rc::test::Fixture restored(37, CoordinatorEpoch::from_value(4), limits);
  const PlanMutationResult loaded = restored.governor().load(store);
  RC_REQUIRE(loaded.accepted());
  RC_CHECK(rc::test::has_condition(loaded.conditions, rc::ConditionCode::RECOVERED_CONSERVATIVE));
  RC_CHECK_EQ(restored.governor().plan_count(), kPlanTotal);
  RC_CHECK_EQ(restored.governor().epoch().value(), static_cast<std::uint64_t>(4));

  // Every plan survived with its identity intact, and the recovered population
  // reports exactly the in-flight work as awaiting reconciliation.
  std::size_t reconciled = 0;
  std::size_t in_flight = 0;
  std::size_t completed = 0;
  for (std::size_t index = 0; index < kPlanTotal; ++index) {
    const std::optional<rc::ConvergenceSnapshot> snapshot =
        restored.governor().snapshot(plans[index]);
    RC_REQUIRE(snapshot.has_value());
    RC_CHECK_EQ(snapshot->steps.size(), static_cast<std::size_t>(2));
    bool awaiting = false;
    for (const rc::StepSnapshot& step : snapshot->steps) {
      awaiting = awaiting || step.state == rc::StepLifecycle::RECONCILIATION_REQUIRED;
      in_flight += step.state == rc::StepLifecycle::DISPATCHED ? 1 : 0;
      completed += step.state == rc::StepLifecycle::COMPLETED ? 1 : 0;
    }
    reconciled += awaiting ? 1 : 0;
  }
  RC_CHECK_EQ(reconciled, kInFlight);
  RC_CHECK_EQ(in_flight, static_cast<std::size_t>(0));
  RC_CHECK_EQ(completed, static_cast<std::size_t>(0));

  // The recovered population is queryable and keyed exactly as it was.
  const std::optional<rc::PlanKey> key = restored.governor().plan_key(plans.back());
  RC_REQUIRE(key.has_value());
  RC_CHECK(key->route == rc::test::Fixture::route_for(3100000 + kPlanTotal - 1));
  std::filesystem::remove(store, remove_error);
}
