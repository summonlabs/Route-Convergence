// tests/test_property.cpp
//
// Deterministic seeded randomised schedules over the real ConvergenceGovernor.
// Every schedule is driven by an explicit 64-bit LCG with a fixed seed, and every
// failing assertion names that seed.  Nothing retries, sleeps or reads a clock.
// The upstream observation source is the SYNTHETIC control-plane fixture.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <process.h>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "fixture.hpp"
#include "rc/rc.hpp"
#include "test_framework.hpp"

namespace {

using rc::BackendOutcome;
using rc::CompletionEvidence;
using rc::ConvergenceGeneration;
using rc::ConvergencePlanGeneration;
using rc::ConvergencePlanId;
using rc::CoordinatorEpoch;
using rc::MutationAttemptId;
using rc::PathAuthorityGeneration;
using rc::PlanLifecycle;
using rc::PlanMutationResult;
using rc::PublisherId;
using rc::RouteGeneration;
using rc::StepKey;
using rc::StepLifecycle;
using rc::TransitionStepGeneration;
using rc::TransitionStepId;
using rc::WorkerBootId;

class Lcg {
 public:
  explicit Lcg(std::uint64_t seed) noexcept
      : state_(seed * 6364136223846793005ull + 1442695040888963407ull) {}
  [[nodiscard]] std::uint64_t next() noexcept {
    state_ = (state_ * 6364136223846793005ull) + 1442695040888963407ull;
    return state_;
  }
  [[nodiscard]] std::uint32_t bounded(std::uint32_t bound) noexcept {
    return static_cast<std::uint32_t>((next() >> 33) % bound);
  }

 private:
  std::uint64_t state_ = 0;
};

[[nodiscard]] std::string seeded(std::uint64_t seed) { return "seed=" + std::to_string(seed); }

// Reports a failure with the schedule seed attached; the message is built only on
// the failing branch.
#define RC_PROPERTY_CHECK(condition, seed, detail)                                    \
  do {                                                                                \
    ++::rc::test::g_checks;                                                           \
    if (!(condition)) {                                                               \
      ::rc::test::report_failure(__FILE__, __LINE__, seeded((seed)) + " " + (detail)); \
    }                                                                                 \
  } while (false)

void set_path_legality(rc::test::Fixture& fixture, const rc::PathId& path, std::uint64_t generation,
                       bool legal) {
  rc::PathLegality legality;
  legality.path = path;
  legality.generation = PathAuthorityGeneration::from_value(generation);
  legality.legal = legal;
  fixture.upstream().set_path(legality);
}

[[nodiscard]] const rc::StepSnapshot* find_step(const rc::ConvergenceSnapshot& snapshot,
                                                const TransitionStepId& step) {
  for (const rc::StepSnapshot& candidate : snapshot.steps) {
    if (candidate.id == step) {
      return &candidate;
    }
  }
  return nullptr;
}

[[nodiscard]] const rc::StepSnapshot* find_step(const rc::ConvergenceSnapshot& snapshot,
                                                const StepKey& key) {
  for (const rc::StepSnapshot& candidate : snapshot.steps) {
    if (candidate.key == key) {
      return &candidate;
    }
  }
  return nullptr;
}

// The generational state a rejected mutation must leave untouched.
struct Generations {
  std::uint64_t plan_generation = 0;
  std::uint64_t convergence = 0;
};

[[nodiscard]] Generations generations_of(rc::test::Fixture& fixture,
                                         const ConvergencePlanId& plan) {
  const std::optional<rc::PlanSummary> summary = fixture.governor().query_plan(plan);
  RC_REQUIRE(summary.has_value());
  return Generations{summary->generation.value(),
                     fixture.governor().convergence_generation().value()};
}

// A rejected completion must not advance the plan, must not move the governor
// convergence generation and must not have completed the step it named.
void check_rejected(rc::test::Fixture& fixture, const ConvergencePlanId& plan,
                    const TransitionStepId& step, const PlanMutationResult& result,
                    const Generations& before, std::uint64_t seed, const char* what) {
  RC_PROPERTY_CHECK(!result.accepted(), seed, std::string(what) + ": the completion was accepted");
  const std::optional<rc::PlanSummary> after = fixture.governor().query_plan(plan);
  RC_REQUIRE(after.has_value());
  RC_PROPERTY_CHECK(after->generation.value() == before.plan_generation, seed,
                    std::string(what) + ": the rejected completion moved the plan generation");
  RC_PROPERTY_CHECK(fixture.governor().convergence_generation().value() == before.convergence, seed,
                    std::string(what) + ": the rejected completion moved the convergence");
  const std::optional<rc::ConvergenceSnapshot> snapshot = fixture.governor().snapshot(plan);
  RC_REQUIRE(snapshot.has_value());
  const rc::StepSnapshot* record = find_step(*snapshot, step);
  RC_REQUIRE(record != nullptr);
  RC_PROPERTY_CHECK(record->state != StepLifecycle::COMPLETED, seed,
                    std::string(what) + ": the rejected completion completed its step");
}

// Everything a worker needs to complete the step it just dispatched.  The
// dispatch authority attempt and the completion authority attempt are always
// distinct; the evidence binds the dispatch attempt.
class Schedule {
 public:
  Schedule(rc::test::Fixture& fixture, std::uint64_t seed) : fixture_(fixture), rng_(seed) {}

  struct RoutePair {
    rc::RouteBinding source;
    rc::RouteBinding target;
  };

  struct Ticket {
    ConvergencePlanId plan;
    TransitionStepId step;
    TransitionStepGeneration generation;
    MutationAttemptId attempt;
    ConvergenceGeneration watermark;
    CoordinatorEpoch epoch;
    RouteGeneration route_generation;
    PathAuthorityGeneration path_generation;
  };

  [[nodiscard]] Lcg& rng() noexcept { return rng_; }
  [[nodiscard]] rc::AuthorityContext authority() { return fixture_.authority(++attempt_serial_); }

  // Publishes a coherent route: the observed generation is the target and the
  // source is the immediately preceding generation.
  [[nodiscard]] RoutePair publish_route(std::uint64_t route_seed, std::uint64_t target_generation) {
    RoutePair pair;
    pair.source =
        rc::test::Fixture::binding(route_seed, target_generation - 1, (route_seed * 2) + 1, 1);
    pair.target =
        rc::test::Fixture::binding(route_seed, target_generation, (route_seed * 2) + 2, 1);
    fixture_.publish(pair.target);
    set_path_legality(fixture_, pair.source.path, 1, true);
    return pair;
  }

  [[nodiscard]] std::optional<rc::ReadyStep> any_ready(std::uint32_t budget = 8) {
    const rc::ReadyStepList list = fixture_.governor().ready_steps(budget);
    if (list.steps.empty()) {
      return std::nullopt;
    }
    return list.steps[rng_.bounded(static_cast<std::uint32_t>(list.steps.size()))];
  }

  [[nodiscard]] std::optional<Ticket> dispatch(const rc::ReadyStep& ready) {
    const rc::AuthorityContext context = authority();
    const rc::StepDispatch result =
        fixture_.governor().dispatch_step(ready.plan, ready.step, context);
    if (!result.accepted()) {
      return std::nullopt;
    }
    Ticket ticket;
    ticket.plan = ready.plan;
    ticket.step = ready.step;
    ticket.generation = result.step_generation;
    ticket.attempt = context.attempt;
    ticket.watermark = result.watermark;
    ticket.epoch = result.epoch;
    ticket.route_generation = result.spec.route_generation;
    ticket.path_generation = result.spec.path_authority_generation;
    return ticket;
  }

  [[nodiscard]] PlanMutationResult complete(const Ticket& ticket, BackendOutcome outcome) {
    return complete_as(ticket, outcome, fixture_.publisher(), fixture_.boot(), ticket.epoch,
                       authority());
  }

  [[nodiscard]] PlanMutationResult complete_as(const Ticket& ticket, BackendOutcome outcome,
                                               const PublisherId& publisher,
                                               const WorkerBootId& boot,
                                               CoordinatorEpoch evidence_epoch,
                                               const rc::AuthorityContext& context) {
    CompletionEvidence evidence;
    evidence.plan = ticket.plan;
    evidence.step = ticket.step;
    evidence.step_generation = ticket.generation;
    evidence.attempt = ticket.attempt;
    evidence.epoch = evidence_epoch;
    evidence.publisher = publisher;
    evidence.worker_boot = boot;
    evidence.outcome = outcome;
    evidence.dispatch_watermark = ticket.watermark;
    evidence.applied_route_generation = ticket.route_generation;
    evidence.observed_path_authority_generation = ticket.path_generation;
    evidence.id = rc::derive_evidence_id(evidence);
    return fixture_.governor().complete_step(evidence, context);
  }

 private:
  rc::test::Fixture& fixture_;
  Lcg rng_;
  std::uint64_t attempt_serial_ = 100000;
};

// Tracks every generation the governor exposes and reports the first decrease.
class GenerationWatch {
 public:
  void observe(const rc::ConvergenceGovernor& governor, std::uint64_t seed, const char* what) {
    const std::uint64_t convergence = governor.convergence_generation().value();
    RC_PROPERTY_CHECK(convergence >= convergence_, seed,
                      std::string(what) + ": convergence generation decreased");
    convergence_ = convergence;
    for (const rc::PlanSummary& summary : governor.list_plans().plans) {
      const auto entry = plans_.find(summary.id);
      if (entry != plans_.end()) {
        RC_PROPERTY_CHECK(summary.generation.value() >= entry->second, seed,
                          std::string(what) + ": plan generation decreased");
      }
      plans_[summary.id] = summary.generation.value();
      const std::optional<rc::ConvergenceSnapshot> snapshot = governor.snapshot(summary.id);
      if (!snapshot.has_value()) {
        continue;
      }
      for (const rc::StepSnapshot& step : snapshot->steps) {
        const auto key = std::make_pair(summary.id, step.id);
        const auto step_entry = steps_.find(key);
        if (step_entry != steps_.end()) {
          RC_PROPERTY_CHECK(step.generation.value() >= step_entry->second, seed,
                            std::string(what) + ": step generation decreased");
        }
        steps_[key] = step.generation.value();
      }
    }
  }

 private:
  std::uint64_t convergence_ = 0;
  std::map<ConvergencePlanId, std::uint64_t> plans_;
  std::map<std::pair<ConvergencePlanId, TransitionStepId>, std::uint64_t> steps_;
};

// A per-process store path: no fixed temporary name is shared between runs.
[[nodiscard]] std::filesystem::path per_process_store(const std::string& name) {
  return std::filesystem::temp_directory_path() /
         (name + "_" + std::to_string(static_cast<long long>(_getpid())) + ".store");
}

}  // namespace

// 1. No step is dispatched before all of its prerequisites are satisfied, and no
//    generation ever decreases across the schedule.
RC_TEST(seeded_schedules_never_dispatch_before_prerequisites) {
  const std::uint64_t seed = 0x5EED0001A5A5A5A5ull;
  rc::test::Fixture fixture(11);
  Schedule schedule(fixture, seed);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  std::vector<ConvergencePlanId> plans;
  for (std::uint64_t route = 1; route <= 3; ++route) {
    const Schedule::RoutePair pair = schedule.publish_route(route, 2);
    const PlanMutationResult created = fixture.create(pair.source, pair.target, 1, 100 + route, true);
    RC_REQUIRE(created.accepted());
    plans.push_back(created.plan);
  }
  GenerationWatch watch;
  std::size_t dispatched = 0;
  std::size_t completed = 0;
  for (std::size_t round = 0; round < 600; ++round) {
    const std::uint32_t choice = schedule.rng().bounded(100);
    const std::optional<rc::ReadyStep> ready = schedule.any_ready();
    if (choice < 80 && ready.has_value()) {
      const std::optional<rc::ConvergenceSnapshot> snapshot = fixture.governor().snapshot(ready->plan);
      RC_REQUIRE(snapshot.has_value());
      const rc::StepSnapshot* target = find_step(*snapshot, ready->step);
      RC_REQUIRE(target != nullptr);
      for (const StepKey& dependency : target->depends_on) {
        const rc::StepSnapshot* prerequisite = find_step(*snapshot, dependency);
        RC_PROPERTY_CHECK(prerequisite != nullptr && rc::is_step_satisfied(prerequisite->state), seed,
                          "a step with an unsatisfied prerequisite was offered for dispatch");
      }
      const std::optional<Schedule::Ticket> ticket = schedule.dispatch(*ready);
      if (ticket.has_value()) {
        ++dispatched;
        const PlanMutationResult result =
            schedule.complete(*ticket, choice < 74 ? BackendOutcome::APPLIED
                                                   : BackendOutcome::RETRYABLE_FAILURE);
        if (choice < 74) {
          RC_PROPERTY_CHECK(result.accepted(), seed, "a dispatchable step refused its completion");
          completed += result.accepted() ? 1 : 0;
        } else {
          RC_PROPERTY_CHECK(result.outcome == rc::Outcome::RETRYABLE_FAILURE, seed,
                            "a retryable failure was not reported as retryable");
        }
        (void)fixture.governor().revalidate_plan(ticket->plan, schedule.authority());
      }
    } else if (ready.has_value()) {
      (void)fixture.governor().revalidate_plan(ready->plan, schedule.authority());
    }
    if (round % 37 == 0) {
      fixture.upstream().set_epoch(CoordinatorEpoch::from_value(
          fixture.governor().epoch().value() + 1));
      (void)fixture.governor().sync_epoch();
      for (const ConvergencePlanId& plan : plans) {
        (void)fixture.governor().revalidate_plan(plan, schedule.authority());
      }
    }
    watch.observe(fixture.governor(), seed, "schedule");
  }
  RC_PROPERTY_CHECK(dispatched > 0, seed, "the schedule never dispatched a step");
  RC_PROPERTY_CHECK(completed > 0, seed, "the schedule never completed a step");
  RC_CHECK_EQ(fixture.governor().plan_count(), plans.size());
}

// 2. A COMPLETED plan has every mandatory step satisfied and nothing in flight.
RC_TEST(seeded_schedules_complete_only_with_mandatory_steps_satisfied) {
  const std::uint64_t seed = 0x5EED0002B6B6B6B6ull;
  rc::test::Fixture fixture(12);
  Schedule schedule(fixture, seed);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  std::vector<ConvergencePlanId> plans;
  for (std::uint64_t route = 1; route <= 4; ++route) {
    const Schedule::RoutePair pair = schedule.publish_route(route, 2);
    const PlanMutationResult created = fixture.create(pair.source, pair.target, 1, 200 + route, true);
    RC_REQUIRE(created.accepted());
    plans.push_back(created.plan);
  }
  std::size_t completions = 0;
  for (std::size_t round = 0; round < 400; ++round) {
    const std::optional<rc::ReadyStep> ready = schedule.any_ready();
    if (!ready.has_value()) {
      break;
    }
    const std::optional<Schedule::Ticket> ticket = schedule.dispatch(*ready);
    if (ticket.has_value() &&
        schedule.complete(*ticket, BackendOutcome::APPLIED).outcome == rc::Outcome::PLAN_COMPLETED) {
      ++completions;
    }
  }
  RC_PROPERTY_CHECK(completions > 0, seed, "no plan reached COMPLETED");
  std::size_t observed = 0;
  for (const ConvergencePlanId& plan : plans) {
    const std::optional<rc::ConvergenceSnapshot> snapshot = fixture.governor().snapshot(plan);
    RC_REQUIRE(snapshot.has_value());
    if (snapshot->lifecycle != PlanLifecycle::COMPLETED) {
      continue;
    }
    ++observed;
    for (const rc::StepSnapshot& step : snapshot->steps) {
      if (step.mandatory) {
        RC_PROPERTY_CHECK(rc::is_step_satisfied(step.state), seed,
                          "a COMPLETED plan has an unsatisfied mandatory step");
      }
      RC_PROPERTY_CHECK(step.state != StepLifecycle::DISPATCHED, seed,
                        "a COMPLETED plan still holds a DISPATCHED step");
    }
  }
  RC_CHECK_EQ(observed, completions);
}

// 3. A completion carrying a stale target route generation never advances.
RC_TEST(stale_target_route_generation_never_advances_plan) {
  const std::uint64_t seed = 0x5EED0003C7C7C7C7ull;
  rc::test::Fixture fixture(13);
  Schedule schedule(fixture, seed);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  const Schedule::RoutePair pair = schedule.publish_route(1, 2);
  const PlanMutationResult created = fixture.create(pair.source, pair.target, 1, 301, true);
  RC_REQUIRE(created.accepted());
  const std::optional<rc::ReadyStep> ready = schedule.any_ready();
  RC_REQUIRE(ready.has_value());
  const std::optional<Schedule::Ticket> ticket = schedule.dispatch(*ready);
  RC_REQUIRE(ticket.has_value());
  rc::RouteBinding advanced = pair.target;
  advanced.generation = RouteGeneration::from_value(3);
  fixture.upstream().set_route(advanced);
  rc::RouteChangeNotice notice;
  notice.binding = advanced;
  notice.provenance = rc::test::Fixture::provenance_for(77);
  const rc::NoticeResult observed = fixture.governor().note_route_change(notice, schedule.authority());
  RC_PROPERTY_CHECK(observed.plans_superseded == 1u, seed,
                    "the superseding route notice did not supersede the plan");
  const Generations before = generations_of(fixture, created.plan);
  const PlanMutationResult result = schedule.complete(*ticket, BackendOutcome::APPLIED);
  check_rejected(fixture, created.plan, ticket->step, result, before, seed,
                 "stale target route generation");
  const std::optional<rc::PlanSummary> after = fixture.governor().query_plan(created.plan);
  RC_REQUIRE(after.has_value());
  RC_PROPERTY_CHECK(after->lifecycle == PlanLifecycle::SUPERSEDED, seed,
                    "the plan with a superseded target generation is not SUPERSEDED");
}

// 4. A completion carrying a stale path authority generation never advances.
RC_TEST(stale_path_authority_generation_never_advances_plan) {
  const std::uint64_t seed = 0x5EED0004D8D8D8D8ull;
  rc::test::Fixture fixture(14);
  Schedule schedule(fixture, seed);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  const Schedule::RoutePair pair = schedule.publish_route(2, 2);
  const PlanMutationResult created = fixture.create(pair.source, pair.target, 1, 401, true);
  RC_REQUIRE(created.accepted());
  const std::optional<rc::ReadyStep> ready = schedule.any_ready();
  RC_REQUIRE(ready.has_value());
  const std::optional<Schedule::Ticket> ticket = schedule.dispatch(*ready);
  RC_REQUIRE(ticket.has_value());
  set_path_legality(fixture, pair.target.path, 2, true);
  rc::PathChangeNotice notice;
  notice.legality.path = pair.target.path;
  notice.legality.generation = PathAuthorityGeneration::from_value(2);
  notice.legality.legal = true;
  notice.provenance = rc::test::Fixture::provenance_for(78);
  const rc::NoticeResult observed = fixture.governor().note_path_change(notice, schedule.authority());
  RC_PROPERTY_CHECK(observed.plans_invalidated == 1u, seed,
                    "the stale path notice did not invalidate exactly the referencing plan");
  const Generations before = generations_of(fixture, created.plan);
  const PlanMutationResult result = schedule.complete(*ticket, BackendOutcome::APPLIED);
  check_rejected(fixture, created.plan, ticket->step, result, before, seed,
                 "stale path authority generation");
  const std::optional<rc::PlanSummary> after = fixture.governor().query_plan(created.plan);
  RC_REQUIRE(after.has_value());
  RC_PROPERTY_CHECK(after->lifecycle == PlanLifecycle::REVALIDATION_REQUIRED, seed,
                    "the plan with a stale path generation is not awaiting revalidation");
}

// 5. A completion carrying a stale coordinator epoch never advances.
RC_TEST(stale_coordinator_epoch_never_advances_plan) {
  const std::uint64_t seed = 0x5EED0005E9E9E9E9ull;
  rc::test::Fixture fixture(15);
  Schedule schedule(fixture, seed);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  const Schedule::RoutePair first_pair = schedule.publish_route(3, 2);
  const PlanMutationResult first_plan =
      fixture.create(first_pair.source, first_pair.target, 1, 501, true);
  RC_REQUIRE(first_plan.accepted());
  const std::optional<rc::ReadyStep> ready = schedule.any_ready();
  RC_REQUIRE(ready.has_value());
  const std::optional<Schedule::Ticket> ticket = schedule.dispatch(*ready);
  RC_REQUIRE(ticket.has_value());
  fixture.upstream().set_epoch(CoordinatorEpoch::from_value(2));
  rc::EpochChangeNotice notice;
  notice.previous = CoordinatorEpoch::from_value(1);
  notice.current = CoordinatorEpoch::from_value(2);
  notice.provenance = rc::test::Fixture::provenance_for(79);
  const rc::NoticeResult observed = fixture.governor().note_epoch_change(notice, schedule.authority());
  RC_PROPERTY_CHECK(observed.outcome == rc::Outcome::EPOCH_ADVANCED, seed,
                    "the epoch notice was not applied");
  RC_CHECK_EQ(fixture.governor().epoch().value(), static_cast<std::uint64_t>(2));
  const Generations before = generations_of(fixture, first_plan.plan);
  const PlanMutationResult result = schedule.complete(*ticket, BackendOutcome::APPLIED);
  check_rejected(fixture, first_plan.plan, ticket->step, result, before, seed,
                 "stale coordinator epoch");

  // A RETIRED plan keeps a genuinely in-flight step: a DISPATCHED step has no
  // RETIRE transition and an epoch advance skips terminal plans.  A completion
  // presented under the previous epoch is then refused by the epoch check.
  const Schedule::RoutePair second_pair = schedule.publish_route(4, 2);
  const PlanMutationResult second_plan =
      fixture.create(second_pair.source, second_pair.target, 1, 502, true);
  RC_REQUIRE(second_plan.accepted());
  const std::optional<rc::ReadyStep> second_ready = schedule.any_ready();
  RC_REQUIRE(second_ready.has_value());
  const std::optional<Schedule::Ticket> second_ticket = schedule.dispatch(*second_ready);
  RC_REQUIRE(second_ticket.has_value());
  RC_REQUIRE(fixture.governor()
                 .pause_plan(second_ticket->plan, rc::ConditionCode::NONE, schedule.authority())
                 .accepted());
  RC_REQUIRE(fixture.governor().retire_plan(second_ticket->plan, schedule.authority()).accepted());
  rc::EpochChangeNotice later;
  later.previous = CoordinatorEpoch::from_value(2);
  later.current = CoordinatorEpoch::from_value(3);
  later.provenance = rc::test::Fixture::provenance_for(80);
  fixture.upstream().set_epoch(CoordinatorEpoch::from_value(3));
  RC_REQUIRE(fixture.governor().note_epoch_change(later, schedule.authority()).accepted());
  const Generations retired_before = generations_of(fixture, second_ticket->plan);
  const PlanMutationResult refused =
      schedule.complete_as(*second_ticket, BackendOutcome::APPLIED, fixture.publisher(),
                           fixture.boot(), CoordinatorEpoch::from_value(2), schedule.authority());
  RC_PROPERTY_CHECK(refused.outcome == rc::Outcome::STALE_EPOCH, seed,
                    "a completion under the previous epoch was not refused as STALE_EPOCH");
  RC_PROPERTY_CHECK(
      rc::test::has_condition(refused.conditions, rc::ConditionCode::AUTHORITY_EPOCH_STALE), seed,
      "the previous-epoch completion did not report the stale epoch");
  check_rejected(fixture, second_ticket->plan, second_ticket->step, refused, retired_before, seed,
                 "previous epoch completion");
}

// 6. A completion from a fenced worker boot never advances the plan.
RC_TEST(fenced_worker_boot_completion_never_advances_plan) {
  const std::uint64_t seed = 0x5EED0006FAFAFAFAull;
  rc::test::Fixture fixture(16);
  Schedule schedule(fixture, seed);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  const Schedule::RoutePair pair = schedule.publish_route(5, 2);
  const PlanMutationResult created = fixture.create(pair.source, pair.target, 1, 601, true);
  RC_REQUIRE(created.accepted());
  const std::optional<rc::ReadyStep> ready = schedule.any_ready();
  RC_REQUIRE(ready.has_value());
  const std::optional<Schedule::Ticket> ticket = schedule.dispatch(*ready);
  RC_REQUIRE(ticket.has_value());
  const PublisherId owner_publisher = fixture.publisher();
  const WorkerBootId owner_boot = fixture.boot();

  // Variant one: the evidence names a boot that never dispatched this step.
  RC_REQUIRE(fixture.register_worker(2, 2, rc::test::kAllCapabilities).accepted());
  RC_PROPERTY_CHECK(fixture.governor().is_worker_live(fixture.publisher(), fixture.boot()), seed,
                    "the second worker is not live");
  const Generations mismatch_before = generations_of(fixture, created.plan);
  const PlanMutationResult mismatch = schedule.complete(*ticket, BackendOutcome::APPLIED);
  check_rejected(fixture, created.plan, ticket->step, mismatch, mismatch_before, seed,
                 "foreign worker boot");

  // Variant two: the dispatching boot is fenced permanently.
  RC_REQUIRE(fixture.governor().fence_worker(owner_boot, schedule.authority()).accepted());
  RC_PROPERTY_CHECK(fixture.governor().is_worker_fenced(owner_boot), seed,
                    "the fenced boot is not reported as fenced");
  RC_PROPERTY_CHECK(!fixture.governor().is_worker_live(owner_publisher, owner_boot), seed,
                    "a fenced boot is still reported live");
  const Generations fenced_before = generations_of(fixture, created.plan);
  rc::AuthorityContext fenced;
  fenced.epoch = fixture.governor().epoch();
  fenced.publisher = owner_publisher;
  fenced.worker_boot = owner_boot;
  fenced.attempt = rc::test::Fixture::attempt_for(4242);
  const PlanMutationResult result = schedule.complete_as(
      *ticket, BackendOutcome::APPLIED, owner_publisher, owner_boot, ticket->epoch, fenced);
  RC_PROPERTY_CHECK(result.outcome == rc::Outcome::UNAUTHORIZED, seed,
                    "a fenced-boot completion was refused for an unrelated reason");
  RC_PROPERTY_CHECK(rc::test::has_condition(result.conditions, rc::ConditionCode::WORKER_FENCED),
                    seed, "the fenced-boot completion did not report WORKER_FENCED");
  check_rejected(fixture, created.plan, ticket->step, result, fenced_before, seed,
                 "fenced worker boot");
}

// 7. A RETIRED plan never becomes non-RETIRED again.
RC_TEST(retired_plan_never_returns_to_a_live_lifecycle) {
  const std::uint64_t seed = 0x5EED00070B0B0B0Bull;
  rc::test::Fixture fixture(17);
  Schedule schedule(fixture, seed);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  const Schedule::RoutePair pair = schedule.publish_route(6, 2);
  const PlanMutationResult created = fixture.create(pair.source, pair.target, 1, 701, true);
  RC_REQUIRE(created.accepted());
  for (std::uint32_t value = 1; value <= rc::kPlanEventCount; ++value) {
    RC_PROPERTY_CHECK(!rc::apply_plan_event(PlanLifecycle::RETIRED, static_cast<rc::PlanEvent>(value),
                                            rc::PlanTransitionInputs{})
                           .has_value(),
                      seed, "a plan event is legal from RETIRED");
  }
  RC_PROPERTY_CHECK(rc::is_terminal_lifecycle(PlanLifecycle::RETIRED), seed,
                    "RETIRED is not classified terminal");
  RC_REQUIRE(fixture.governor()
                 .pause_plan(created.plan, rc::ConditionCode::NONE, schedule.authority())
                 .accepted());
  RC_REQUIRE(fixture.governor().retire_plan(created.plan, schedule.authority()).accepted());
  const auto lifecycle_now = [&fixture, &created]() {
    const std::optional<rc::PlanSummary> summary = fixture.governor().query_plan(created.plan);
    return summary.has_value() ? summary->lifecycle : PlanLifecycle::DECLARED;
  };
  const auto still_retired = [&](const char* what) {
    RC_PROPERTY_CHECK(lifecycle_now() == PlanLifecycle::RETIRED, seed,
                      std::string("a ") + what + " revived a RETIRED plan");
  };
  still_retired("retire");
  for (const rc::ReadyStep& step : fixture.governor().ready_steps(8).steps) {
    RC_PROPERTY_CHECK(!(step.plan == created.plan), seed, "a RETIRED plan was offered as ready");
  }
  const std::optional<rc::ConvergenceSnapshot> retired = fixture.governor().snapshot(created.plan);
  RC_REQUIRE(retired.has_value());
  const TransitionStepId first_step =
      retired->steps.empty() ? TransitionStepId{} : retired->steps.front().id;
  if (!first_step.is_nil()) {
    (void)fixture.governor().dispatch_step(created.plan, first_step, schedule.authority());
    still_retired("dispatch attempt");
  }
  (void)fixture.governor().pause_plan(created.plan, rc::ConditionCode::NONE, schedule.authority());
  still_retired("pause");
  (void)fixture.governor().revoke_plan(created.plan, schedule.authority());
  still_retired("revoke");
  (void)fixture.governor().revalidate_plan(created.plan, schedule.authority());
  still_retired("revalidation");
  (void)fixture.governor().begin_rollback(created.plan, schedule.authority());
  still_retired("rollback request");
  rc::RouteChangeNotice route_notice;
  route_notice.binding = pair.target;
  route_notice.binding.generation = RouteGeneration::from_value(9);
  route_notice.provenance = rc::test::Fixture::provenance_for(81);
  fixture.upstream().set_route(route_notice.binding);
  (void)fixture.governor().note_route_change(route_notice, schedule.authority());
  still_retired("superseding route notice");
  rc::PathChangeNotice path_notice;
  path_notice.legality.path = pair.target.path;
  path_notice.legality.generation = PathAuthorityGeneration::from_value(4);
  path_notice.legality.legal = true;
  path_notice.provenance = rc::test::Fixture::provenance_for(82);
  set_path_legality(fixture, pair.target.path, 4, true);
  (void)fixture.governor().note_path_change(path_notice, schedule.authority());
  still_retired("invalidating path notice");
  fixture.upstream().set_epoch(CoordinatorEpoch::from_value(5));
  rc::EpochChangeNotice epoch_notice;
  epoch_notice.previous = CoordinatorEpoch::from_value(1);
  epoch_notice.current = CoordinatorEpoch::from_value(5);
  epoch_notice.provenance = rc::test::Fixture::provenance_for(83);
  (void)fixture.governor().note_epoch_change(epoch_notice, schedule.authority());
  still_retired("epoch advance");
  RC_CHECK_EQ(fixture.governor().epoch().value(), static_cast<std::uint64_t>(5));
  RC_REQUIRE(fixture.governor().retire_plan(created.plan, schedule.authority()).outcome ==
             rc::Outcome::IDEMPOTENT);
  still_retired("second retire");
}

// 8. An exact replay of the same create request is IDEMPOTENT and advances nothing.
RC_TEST(exact_plan_replay_is_idempotent_and_advances_nothing) {
  const std::uint64_t seed = 0x5EED00081C1C1C1Cull;
  rc::test::Fixture fixture(18);
  Schedule schedule(fixture, seed);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  const Schedule::RoutePair pair = schedule.publish_route(7, 2);
  const PlanMutationResult created = fixture.create(pair.source, pair.target, 1, 801, true);
  RC_REQUIRE(created.outcome == rc::Outcome::PLAN_CREATED);
  const std::optional<rc::PlanSummary> before = fixture.governor().query_plan(created.plan);
  RC_REQUIRE(before.has_value());
  const Generations generations = generations_of(fixture, created.plan);
  const std::size_t plan_count = fixture.governor().plan_count();
  const std::uint64_t created_stat = fixture.governor().stats().plans_created;
  const PlanMutationResult replay = fixture.create(pair.source, pair.target, 1, 801, true);
  RC_PROPERTY_CHECK(replay.outcome == rc::Outcome::IDEMPOTENT, seed,
                    "an exact create replay was not reported IDEMPOTENT");
  RC_PROPERTY_CHECK(replay.plan == created.plan, seed, "the replay reported a different plan");
  RC_CHECK_EQ(fixture.governor().plan_count(), plan_count);
  RC_CHECK_EQ(fixture.governor().stats().plans_created, created_stat);
  const std::optional<rc::PlanSummary> after = fixture.governor().query_plan(created.plan);
  RC_REQUIRE(after.has_value());
  RC_PROPERTY_CHECK(after->generation.value() == generations.plan_generation, seed,
                    "the replay moved the plan generation");
  RC_PROPERTY_CHECK(after->digest == before->digest, seed, "the replay changed the plan digest");
  RC_PROPERTY_CHECK(fixture.governor().convergence_generation().value() == generations.convergence,
                    seed, "the replay moved the convergence generation");
  // The same attempt identity used for different content is a conflict, never a
  // silent second plan.
  const Schedule::RoutePair other = schedule.publish_route(8, 2);
  const PlanMutationResult conflict = fixture.create(other.source, other.target, 1, 801, true);
  RC_PROPERTY_CHECK(conflict.outcome == rc::Outcome::ATTEMPT_CONFLICT, seed,
                    "a conflicting reuse of one attempt identity was not refused");
  RC_CHECK_EQ(fixture.governor().plan_count(), plan_count);
}

// 9. Generation overflow is checked arithmetic, never a wrap.
RC_TEST(generation_overflow_is_checked_arithmetic) {
  const std::uint64_t seed = 0x5EED000A3E3E3E3Eull;
  const std::uint64_t maximum = ConvergencePlanGeneration::kMaximum;
  RC_PROPERTY_CHECK(!ConvergencePlanGeneration::from_value(maximum).next().has_value(), seed,
                    "plan generation next() at the maximum did not return nullopt");
  RC_PROPERTY_CHECK(!ConvergenceGeneration::from_value(maximum).next().has_value(), seed,
                    "convergence generation next() at the maximum did not return nullopt");
  RC_PROPERTY_CHECK(!TransitionStepGeneration::from_value(maximum).next().has_value(), seed,
                    "step generation next() at the maximum did not return nullopt");
  RC_PROPERTY_CHECK(!rc::AuthorityGeneration::from_value(maximum).next().has_value(), seed,
                    "authority generation next() at the maximum did not return nullopt");
  RC_PROPERTY_CHECK(!RouteGeneration::from_value(maximum).next().has_value(), seed,
                    "route generation next() at the maximum did not return nullopt");
  RC_PROPERTY_CHECK(!PathAuthorityGeneration::from_value(maximum).next().has_value(), seed,
                    "path generation next() at the maximum did not return nullopt");
  RC_PROPERTY_CHECK(!CoordinatorEpoch::from_value(maximum).next().has_value(), seed,
                    "coordinator epoch next() at the maximum did not return nullopt");
  const std::optional<ConvergencePlanGeneration> last =
      ConvergencePlanGeneration::from_value(maximum - 1).next();
  RC_REQUIRE(last.has_value());
  RC_CHECK_EQ(last->value(), maximum);
  RC_CHECK_EQ(ConvergencePlanGeneration::from_value(0).next().value().value(),
              static_cast<std::uint64_t>(1));
  rc::ConvergencePlan direct;
  direct.generation = ConvergencePlanGeneration::from_value(maximum);
  RC_PROPERTY_CHECK(!direct.next_generation().has_value(), seed,
                    "ConvergencePlan::next_generation() wrapped at the maximum");
  direct.generation = ConvergencePlanGeneration::from_value(maximum - 1);
  const std::optional<ConvergencePlanGeneration> successor = direct.next_generation();
  RC_REQUIRE(successor.has_value());
  RC_CHECK_EQ(successor->value(), maximum);
  direct.generation = ConvergencePlanGeneration::from_value(0);
  RC_CHECK_EQ(direct.next_generation().value().value(), static_cast<std::uint64_t>(1));

  rc::test::Fixture fixture(20);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  const rc::RouteBinding source = rc::test::Fixture::binding(9, 1, 21, 1);
  const rc::RouteBinding target = rc::test::Fixture::binding(9, 2, 22, 1);
  fixture.publish(target);
  set_path_legality(fixture, source.path, 1, true);
  const PlanMutationResult created = fixture.create(source, target, 1, 1001, true);
  RC_REQUIRE(created.accepted());
  RC_CHECK_EQ(created.plan_generation.value(), static_cast<std::uint64_t>(1));
  const std::optional<rc::ConvergenceSnapshot> snapshot = fixture.governor().snapshot(created.plan);
  RC_REQUIRE(snapshot.has_value());
  for (const rc::StepSnapshot& step : snapshot->steps) {
    RC_PROPERTY_CHECK(step.generation.value() >= 1, seed, "a step generation wrapped to zero");
  }
}

// 10. The dependency graph stays acyclic and closed over existing step keys.
RC_TEST(dependency_graph_stays_acyclic_and_names_existing_steps) {
  const std::uint64_t seed = 0x5EED000B4F4F4F4Full;
  rc::test::Fixture fixture(21);
  Schedule schedule(fixture, seed);
  const rc::ConvergenceLimits limits = fixture.governor().limits();
  RC_REQUIRE(fixture.define_policy(1).accepted());
  std::vector<ConvergencePlanId> plans;
  for (std::uint64_t route = 1; route <= 3; ++route) {
    const Schedule::RoutePair pair = schedule.publish_route(route, 2);
    const PlanMutationResult created = fixture.create(pair.source, pair.target, 1, 1100 + route, true);
    RC_REQUIRE(created.accepted());
    plans.push_back(created.plan);
  }
  for (std::size_t round = 0; round < 60; ++round) {
    const std::optional<rc::ReadyStep> ready = schedule.any_ready();
    if (!ready.has_value()) {
      break;
    }
    const std::optional<Schedule::Ticket> ticket = schedule.dispatch(*ready);
    if (ticket.has_value()) {
      (void)schedule.complete(*ticket, round % 5 == 0 ? BackendOutcome::RETRYABLE_FAILURE
                                                      : BackendOutcome::APPLIED);
      (void)fixture.governor().revalidate_plan(ticket->plan, schedule.authority());
    }
  }
  for (const ConvergencePlanId& plan : plans) {
    const std::optional<rc::ConvergenceSnapshot> snapshot = fixture.governor().snapshot(plan);
    RC_REQUIRE(snapshot.has_value());
    std::vector<rc::StepSpec> specs;
    std::set<StepKey> keys;
    for (const rc::StepSnapshot& step : snapshot->steps) {
      rc::StepSpec spec;
      spec.kind = step.key.kind;
      spec.subject = step.key.subject;
      spec.reversibility = step.reversibility;
      spec.conflict_domains = step.conflict_domains;
      spec.mandatory = step.mandatory;
      spec.idempotent = step.idempotent;
      spec.verification = step.verification;
      spec.depends_on = step.depends_on;
      specs.push_back(std::move(spec));
      RC_PROPERTY_CHECK(keys.insert(step.key).second, seed, "two steps share one semantic key");
      RC_PROPERTY_CHECK(!(std::find(step.depends_on.begin(), step.depends_on.end(), step.key) !=
                          step.depends_on.end()),
                        seed, "a step depends on itself");
    }
    for (const rc::StepSnapshot& step : snapshot->steps) {
      for (const StepKey& dependency : step.depends_on) {
        RC_PROPERTY_CHECK(keys.find(dependency) != keys.end(), seed,
                          "a step depends on a key that does not exist");
      }
    }
    const rc::GraphValidation validation = rc::validate_dependency_graph(specs, limits);
    RC_PROPERTY_CHECK(validation.ok, seed, "the plan dependency graph is not a legal DAG");
    const std::optional<std::vector<std::vector<std::size_t>>> layers = rc::canonical_layers(specs);
    RC_PROPERTY_CHECK(layers.has_value(), seed, "the plan dependency graph has a cycle");
    if (layers.has_value()) {
      RC_CHECK_EQ(layers->size(), snapshot->layers.size());
    }
  }
}

// 11. The governor's reverse indexes match the plan records.
RC_TEST(reverse_indexes_match_the_plan_records) {
  const std::uint64_t seed = 0x5EED000C5A5A5A5Aull;
  rc::test::Fixture fixture(22);
  Schedule schedule(fixture, seed);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  const rc::PathId shared_target_path = rc::test::Fixture::path_for(101);
  const rc::PathId first_source_path = rc::test::Fixture::path_for(102);
  const rc::PathId second_source_path = rc::test::Fixture::path_for(103);
  const rc::PathId private_path = rc::test::Fixture::path_for(104);
  const rc::RouteBinding sources[3] = {rc::test::Fixture::binding(201, 1, 102, 1),
                                       rc::test::Fixture::binding(202, 1, 103, 1),
                                       rc::test::Fixture::binding(203, 1, 104, 1)};
  const rc::RouteBinding targets[3] = {rc::test::Fixture::binding(201, 2, 101, 1),
                                       rc::test::Fixture::binding(202, 2, 101, 1),
                                       rc::test::Fixture::binding(203, 2, 104, 1)};
  RC_CHECK(targets[0].path == shared_target_path);
  RC_CHECK(sources[0].path == first_source_path);
  RC_CHECK(sources[1].path == second_source_path);
  RC_CHECK(sources[2].path == targets[2].path);
  RC_CHECK(sources[2].path == private_path);
  for (std::size_t index = 0; index < 3; ++index) {
    fixture.publish(targets[index]);
  }
  set_path_legality(fixture, first_source_path, 1, true);
  set_path_legality(fixture, second_source_path, 1, true);
  std::vector<ConvergencePlanId> plans;
  for (std::size_t index = 0; index < 3; ++index) {
    const PlanMutationResult created = fixture.create(
        sources[index], targets[index], 1, 1200 + static_cast<std::uint64_t>(index), true);
    RC_REQUIRE(created.accepted());
    plans.push_back(created.plan);
  }
  const rc::PlanList listing = fixture.governor().list_plans();
  RC_CHECK_EQ(listing.plans.size(), static_cast<std::size_t>(3));
  RC_CHECK(!listing.truncated);
  const rc::AuthorityContext publisher = schedule.authority();
  const auto notice_for = [&fixture](const rc::PathId& path, std::uint64_t generation,
                                     std::uint64_t provenance) {
    set_path_legality(fixture, path, generation, true);
    rc::PathChangeNotice notice;
    notice.legality.path = path;
    notice.legality.generation = PathAuthorityGeneration::from_value(generation);
    notice.legality.legal = true;
    notice.provenance = rc::test::Fixture::provenance_for(provenance);
    return notice;
  };
  // A path no plan references is absent from the index.
  const rc::NoticeResult absent = fixture.governor().note_path_change(
      notice_for(rc::test::Fixture::path_for(999), 2, 90), publisher);
  RC_PROPERTY_CHECK(absent.plans_examined == 0u, seed, "an unreferenced path notice examined plans");
  // A source-only path reaches its plan but does not invalidate it: currentness
  // follows the plan's target path.
  const rc::NoticeResult source_only =
      fixture.governor().note_path_change(notice_for(first_source_path, 2, 91), publisher);
  RC_PROPERTY_CHECK(source_only.plans_examined == 1u, seed,
                    "a source path is missing from the path index");
  RC_PROPERTY_CHECK(source_only.plans_invalidated == 0u, seed,
                    "a source-only path invalidated a plan");
  // The path two plans target: exactly those two plans, and no other route.
  const rc::NoticeResult shared =
      fixture.governor().note_path_change(notice_for(shared_target_path, 2, 92), publisher);
  RC_PROPERTY_CHECK(shared.plans_examined == 2u, seed,
                    "a shared target path does not index both plans");
  RC_PROPERTY_CHECK(shared.plans_invalidated == 2u, seed,
                    "a shared target path invalidated the wrong number of plans");
  const std::optional<rc::PlanSummary> untouched = fixture.governor().query_plan(plans[2]);
  RC_REQUIRE(untouched.has_value());
  RC_PROPERTY_CHECK(untouched->lifecycle != PlanLifecycle::REVALIDATION_REQUIRED, seed,
                    "invalidating a shared path invalidated a plan of another route");
  // A path that is both source and target of one plan is indexed exactly once.
  const rc::NoticeResult private_result =
      fixture.governor().note_path_change(notice_for(private_path, 2, 93), publisher);
  RC_PROPERTY_CHECK(private_result.plans_examined == 1u, seed,
                    "a path used as source and target was indexed twice");
  RC_PROPERTY_CHECK(private_result.plans_invalidated == 1u, seed,
                    "a private path invalidated the wrong number of plans");
  // Every route of every listed plan is reachable through the route index.
  const rc::RouteBinding fourth_source = rc::test::Fixture::binding(201, 2, 102, 1);
  const rc::RouteBinding fourth_target = rc::test::Fixture::binding(201, 3, 101, 1);
  fixture.publish(fourth_target);
  const PlanMutationResult fourth = fixture.create(fourth_source, fourth_target, 1, 1300, true);
  RC_REQUIRE(fourth.accepted());
  plans.push_back(fourth.plan);
  rc::RouteChangeNotice route_notice;
  route_notice.binding = fourth_target;
  route_notice.provenance = rc::test::Fixture::provenance_for(94);
  const rc::NoticeResult route_result =
      fixture.governor().note_route_change(route_notice, publisher);
  RC_PROPERTY_CHECK(route_result.plans_examined == 2u, seed,
                    "the route index does not hold every plan of the route");
  RC_PROPERTY_CHECK(route_result.plans_superseded == 1u, seed,
                    "the route notice did not supersede exactly the stale plan");
  for (std::size_t index = 1; index < plans.size(); ++index) {
    const std::optional<rc::PlanSummary> summary = fixture.governor().query_plan(plans[index]);
    RC_REQUIRE(summary.has_value());
    RC_PROPERTY_CHECK(summary->lifecycle != PlanLifecycle::SUPERSEDED, seed,
                      "the route notice superseded a plan of another route");
  }
}

// 12. Digests are deterministic across fixtures.
RC_TEST(plan_digests_are_deterministic_across_fixtures) {
  const std::uint64_t seed = 0x5EED000D6B6B6B6Bull;
  rc::test::Fixture first(23);
  rc::test::Fixture second(23);
  RC_REQUIRE(first.define_policy(1).accepted());
  RC_REQUIRE(second.define_policy(1).accepted());
  const rc::RouteBinding source = rc::test::Fixture::binding(11, 1, 31, 1);
  const rc::RouteBinding target = rc::test::Fixture::binding(11, 2, 32, 1);
  first.publish(target);
  second.publish(target);
  set_path_legality(first, source.path, 1, true);
  set_path_legality(second, source.path, 1, true);
  const PlanMutationResult created_first = first.create(source, target, 1, 1401, true);
  const PlanMutationResult created_second = second.create(source, target, 1, 1401, true);
  RC_REQUIRE(created_first.accepted());
  RC_REQUIRE(created_second.accepted());
  RC_PROPERTY_CHECK(created_first.plan == created_second.plan, seed,
                    "the same semantic plan produced two identities");
  RC_PROPERTY_CHECK(created_first.digest == created_second.digest, seed,
                    "the same semantic plan produced two digests");
  const std::optional<rc::PlanSummary> summary_first = first.governor().query_plan(created_first.plan);
  const std::optional<rc::PlanSummary> summary_second =
      second.governor().query_plan(created_second.plan);
  RC_REQUIRE(summary_first.has_value());
  RC_REQUIRE(summary_second.has_value());
  RC_PROPERTY_CHECK(summary_first->digest == summary_second->digest, seed,
                    "the two plan summaries disagree");
  RC_CHECK(summary_first->digest == created_first.digest);
  const std::optional<rc::ConvergenceSnapshot> snapshot_first =
      first.governor().snapshot(created_first.plan);
  const std::optional<rc::ConvergenceSnapshot> snapshot_second =
      second.governor().snapshot(created_second.plan);
  RC_REQUIRE(snapshot_first.has_value());
  RC_REQUIRE(snapshot_second.has_value());
  RC_PROPERTY_CHECK(snapshot_first->digest == snapshot_second->digest, seed,
                    "the same convergence state produced two snapshot digests");
  RC_PROPERTY_CHECK(rc::ConvergenceGovernor::snapshot_digest(*snapshot_first) ==
                        snapshot_first->digest,
                    seed, "the snapshot digest is not reproducible from its own content");
  // The structural digest and the canonical order ignore the declared step order.
  std::string reason;
  const std::optional<std::vector<rc::StepSpec>> generated = rc::generate_steps(
      source, target, rc::test::Fixture::policy(1), first.governor().limits(), reason);
  RC_REQUIRE(generated.has_value());
  const std::vector<rc::StepSpec> reversed(generated->rbegin(), generated->rend());
  const std::optional<rc::PlanKey> key = first.governor().plan_key(created_first.plan);
  RC_REQUIRE(key.has_value());
  RC_PROPERTY_CHECK(rc::plan_structure_digest(*key, source, target, rc::test::Fixture::policy(1),
                                              rc::PlanMode::GENERATED, *generated) ==
                        rc::plan_structure_digest(*key, source, target,
                                                  rc::test::Fixture::policy(1),
                                                  rc::PlanMode::GENERATED, reversed),
                    seed, "the structure digest depends on the declared order");
  // A different semantic plan has a different identity and digest.
  const rc::RouteBinding advanced_target = rc::test::Fixture::binding(11, 3, 32, 1);
  const rc::RouteBinding advanced_source = rc::test::Fixture::binding(11, 2, 31, 1);
  first.publish(advanced_target);
  const PlanMutationResult other = first.create(advanced_source, advanced_target, 1, 1402, true);
  RC_REQUIRE(other.accepted());
  RC_PROPERTY_CHECK(!(other.plan == created_first.plan), seed,
                    "two different semantic plans share one identity");
  RC_PROPERTY_CHECK(!(other.digest == created_first.digest), seed,
                    "two different semantic plans share one digest");
}

// 13. Recovery never turns unknown in-flight work into a completed step.
RC_TEST(recovery_never_completes_unknown_inflight_work) {
  const std::uint64_t seed = 0x5EED000E7C7C7C7Cull;
  const std::filesystem::path store = per_process_store("rc_property_recovery");
  std::error_code remove_error;
  std::filesystem::remove(store, remove_error);
  rc::test::Fixture origin(24);
  Schedule schedule(origin, seed);
  RC_REQUIRE(origin.define_policy(1).accepted());
  const Schedule::RoutePair pair = schedule.publish_route(12, 2);
  const PlanMutationResult created = origin.create(pair.source, pair.target, 1, 1501, true);
  RC_REQUIRE(created.accepted());
  const std::optional<rc::ReadyStep> ready = schedule.any_ready();
  RC_REQUIRE(ready.has_value());
  const std::optional<Schedule::Ticket> ticket = schedule.dispatch(*ready);
  RC_REQUIRE(ticket.has_value());
  const std::optional<rc::ConvergenceSnapshot> inflight = origin.governor().snapshot(created.plan);
  RC_REQUIRE(inflight.has_value());
  const rc::StepSnapshot* dispatched = find_step(*inflight, ticket->step);
  RC_REQUIRE(dispatched != nullptr);
  RC_REQUIRE(dispatched->state == StepLifecycle::DISPATCHED);
  RC_REQUIRE(origin.governor().save(store).accepted());
  // A governor that already holds state refuses a store image.
  RC_PROPERTY_CHECK(origin.governor().load(store).outcome == rc::Outcome::STORE_ERROR, seed,
                    "a populated governor accepted a loaded store image");
  rc::test::Fixture restored(24);
  const PlanMutationResult loaded = restored.governor().load(store);
  RC_REQUIRE(loaded.accepted());
  RC_PROPERTY_CHECK(rc::test::has_condition(loaded.conditions,
                                            rc::ConditionCode::RECOVERED_CONSERVATIVE),
                    seed, "the recovery did not report conservative recovery");
  RC_CHECK_EQ(restored.governor().plan_count(), static_cast<std::size_t>(1));
  const std::optional<rc::ConvergenceSnapshot> recovered = restored.governor().snapshot(created.plan);
  RC_REQUIRE(recovered.has_value());
  const rc::StepSnapshot* step = find_step(*recovered, ticket->step);
  RC_REQUIRE(step != nullptr);
  RC_PROPERTY_CHECK(step->state == StepLifecycle::RECONCILIATION_REQUIRED, seed,
                    "recovery did not mark unknown in-flight work for reconciliation");
  RC_PROPERTY_CHECK(!rc::is_step_satisfied(step->state), seed,
                    "recovery marked unknown in-flight work satisfied");
  RC_PROPERTY_CHECK(recovered->lifecycle != PlanLifecycle::COMPLETED, seed,
                    "a recovered plan with unknown in-flight work is COMPLETED");
  for (const rc::StepSnapshot& candidate : recovered->steps) {
    if (!(candidate.id == ticket->step)) {
      RC_PROPERTY_CHECK(candidate.state != StepLifecycle::DISPATCHED, seed,
                        "recovery left another step in flight");
    }
  }
  for (const rc::ReadyStep& candidate : restored.governor().ready_steps(8).steps) {
    RC_PROPERTY_CHECK(!(candidate.step == ticket->step), seed,
                      "a step awaiting reconciliation was offered as ready");
  }
  std::filesystem::remove(store, remove_error);
}
