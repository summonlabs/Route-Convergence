#pragma once

// Shared deterministic fixtures for the Route Convergence test suites.
//
// The upstream observation source is SyntheticUpstream: it is a control-plane
// fixture, not a physical fabric.  Every test that uses it says so.

#include <memory>
#include <string>
#include <vector>

#include "rc/rc.hpp"

namespace rc::test {

inline constexpr std::uint32_t kAllCapabilities =
    static_cast<std::uint32_t>(Capability::CREATE_PLAN) |
    static_cast<std::uint32_t>(Capability::DISPATCH_STEP) |
    static_cast<std::uint32_t>(Capability::COMPLETE_STEP) |
    static_cast<std::uint32_t>(Capability::REVALIDATE_PLAN) |
    static_cast<std::uint32_t>(Capability::ROLLBACK) |
    static_cast<std::uint32_t>(Capability::ADMIN) |
    static_cast<std::uint32_t>(Capability::PUBLISH_UPSTREAM);

// One isolated governor with its own synthetic upstream and its own limits.
class Fixture {
 public:
  explicit Fixture(std::uint64_t seed = 1,
                   CoordinatorEpoch epoch = CoordinatorEpoch::from_value(1),
                   ConvergenceLimits limits = ConvergenceLimits(),
                   bool with_admin = true)
      : upstream_(epoch), governor_(upstream_, upstream_, upstream_, make_options(limits, epoch)) {
    if (with_admin) {
      (void)register_worker(seed, seed, kAllCapabilities);
    }
  }

  Fixture(const Fixture&) = delete;
  Fixture& operator=(const Fixture&) = delete;

  [[nodiscard]] SyntheticUpstream& upstream() { return upstream_; }
  [[nodiscard]] ConvergenceGovernor& governor() { return governor_; }

  [[nodiscard]] static GovernorOptions make_options(const ConvergenceLimits& limits,
                                                    CoordinatorEpoch epoch) {
    GovernorOptions options;
    options.limits = limits;
    options.initial_epoch = epoch;
    options.fabric = fabric_for(1);
    options.routing_namespace = namespace_for(1);
    return options;
  }

  [[nodiscard]] static FabricId fabric_for(std::uint64_t seed) {
    return derive_id<FabricId>("rc.test.fabric", seed);
  }
  [[nodiscard]] static RoutingNamespaceId namespace_for(std::uint64_t seed) {
    return derive_id<RoutingNamespaceId>("rc.test.namespace", seed);
  }
  [[nodiscard]] static RouteId route_for(std::uint64_t seed) {
    return derive_id<RouteId>("rc.test.route", seed);
  }
  [[nodiscard]] static PathId path_for(std::uint64_t seed) {
    return derive_id<PathId>("rc.test.path", seed);
  }
  [[nodiscard]] static ECMPGroupId group_for(std::uint64_t seed) {
    return derive_id<ECMPGroupId>("rc.test.ecmp", seed);
  }
  [[nodiscard]] static WeightedPathSetId weighted_for(std::uint64_t seed) {
    return derive_id<WeightedPathSetId>("rc.test.weight", seed);
  }
  [[nodiscard]] static MultipathSetId multipath_for(std::uint64_t seed) {
    return derive_id<MultipathSetId>("rc.test.multipath", seed);
  }
  [[nodiscard]] static ConvergencePolicyId policy_for(std::uint64_t seed) {
    return derive_id<ConvergencePolicyId>("rc.test.policy", seed);
  }
  [[nodiscard]] static PublisherId publisher_for(std::uint64_t seed) {
    return derive_publisher_id(seed);
  }
  [[nodiscard]] static WorkerBootId boot_for(std::uint64_t seed) {
    return derive_worker_boot_id(seed);
  }
  [[nodiscard]] static ProvenanceId provenance_for(std::uint64_t seed) {
    return derive_provenance_id(seed);
  }
  [[nodiscard]] static MutationAttemptId attempt_for(std::uint64_t seed) {
    return derive_id<MutationAttemptId>("rc.test.attempt", seed);
  }

  [[nodiscard]] AuthorityContext authority(std::uint64_t attempt_seed = 1) const {
    AuthorityContext context;
    context.epoch = governor_.epoch();
    context.publisher = publisher_;
    context.worker_boot = boot_;
    context.attempt = attempt_for(attempt_seed);
    return context;
  }

  PlanMutationResult register_worker(std::uint64_t publisher_seed, std::uint64_t boot_seed,
                                     std::uint32_t capabilities,
                                     AuthorityScope scope = AuthorityScope{}) {
    publisher_ = publisher_for(publisher_seed);
    boot_ = boot_for(boot_seed);
    PublisherRegistration registration;
    registration.publisher = publisher_;
    registration.worker_boot = boot_;
    registration.scope = scope.kind == ScopeKind::DENY_ALL
                             ? AuthorityScope::for_fabric(fabric_for(1))
                             : scope;
    registration.capabilities = capabilities;
    registration.provenance = provenance_for(boot_seed);
    AuthorityContext context;
    context.epoch = governor_.epoch();
    context.publisher = publisher_;
    context.worker_boot = boot_;
    context.attempt = attempt_for(boot_seed * 7919ull + 1ull);
    return governor_.register_worker(registration, context);
  }

  [[nodiscard]] PublisherId publisher() const { return publisher_; }
  [[nodiscard]] WorkerBootId boot() const { return boot_; }

  // Deterministic fixture policy.
  static ConvergencePolicy policy(std::uint64_t seed, OrderingMode ordering = OrderingMode::MAKE_BEFORE_BREAK,
                                  bool allow_break_before_make = false, std::uint32_t parallel = 4,
                                  std::uint32_t retries = 2) {
    ConvergencePolicy value;
    value.id = policy_for(seed);
    value.generation = ConvergencePolicyGeneration::from_value(1);
    value.ordering = ordering;
    value.allow_break_before_make = allow_break_before_make;
    value.allow_overlap = ordering == OrderingMode::MAKE_BEFORE_BREAK;
    value.verification = VerificationMode::REQUIRED;
    value.max_parallel_steps = parallel;
    value.max_retries_per_step = retries;
    return value;
  }

  PlanMutationResult define_policy(std::uint64_t seed,
                                   OrderingMode ordering = OrderingMode::MAKE_BEFORE_BREAK,
                                   bool allow_break_before_make = false,
                                   std::uint32_t parallel = 4, std::uint32_t retries = 2) {
    return governor_.define_policy(
        policy(seed, ordering, allow_break_before_make, parallel, retries),
        authority(seed * 104729ull + 3ull));
  }

  static RouteBinding binding(std::uint64_t route_seed, std::uint64_t route_generation,
                              std::uint64_t path_seed, std::uint64_t path_generation,
                              bool legal = true) {
    RouteBinding value;
    value.route = route_for(route_seed);
    value.generation = RouteGeneration::from_value(route_generation);
    value.path = path_for(path_seed);
    value.path_authority_generation = PathAuthorityGeneration::from_value(path_generation);
    value.current = true;
    value.legal = legal;
    return value;
  }

  // Publishes an exact route binding and the exact path legality it references,
  // so the plan can be created against a coherent observation.
  void publish(const RouteBinding& value, bool path_legal = true) {
    upstream_.set_route(value);
    PathLegality legality;
    legality.path = value.path;
    legality.generation = value.path_authority_generation;
    legality.legal = path_legal;
    upstream_.set_path(legality);
  }

  // Publishes both the source and the target observation, which is what a real
  // transition needs: the rollback target must still be a legal observation.
  void publish_pair(const RouteBinding& source, const RouteBinding& target) {
    publish(source);
    publish(target);
  }

  PlanMutationResult create(const RouteBinding& source, const RouteBinding& target,
                            std::uint64_t policy_seed = 1, std::uint64_t attempt_seed = 99,
                            bool historical_source = false) {
    PlanRequest request;
    request.mode = PlanMode::GENERATED;
    request.source = source;
    request.target = target;
    request.policy = policy(policy_seed);
    request.epoch = governor_.epoch();
    request.provenance = provenance_for(attempt_seed);
    request.accept_historical_source = historical_source;
    return governor_.create_plan(request, authority(attempt_seed));
  }

  // Advances the plan by executing every step the governor currently reports as
  // ready, in canonical order, until nothing is executable.
  PlanMutationResult drain(const ConvergencePlanId& plan, std::uint32_t iterations = 64) {
    PlanMutationResult last;
    for (std::uint32_t index = 0; index < iterations; ++index) {
      const ReadyStepList ready = governor_.ready_steps(1);
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
      // One mutation attempt identifier per request: the dispatch and the
      // completion are different requests, so they never share one.
      const std::uint64_t attempt_seed = 1000ull + (index * 2ull);
      const AuthorityContext dispatch_authority = authority(attempt_seed);
      const StepDispatch dispatch =
          governor_.dispatch_step(candidate->plan, candidate->step, dispatch_authority);
      if (!dispatch.accepted()) {
        last.outcome = dispatch.outcome;
        return last;
      }
      CompletionEvidence evidence;
      evidence.plan = candidate->plan;
      evidence.step = candidate->step;
      evidence.step_generation = dispatch.step_generation;
      evidence.attempt = dispatch_authority.attempt;
      evidence.epoch = dispatch.epoch;
      evidence.publisher = publisher_;
      evidence.worker_boot = boot_;
      evidence.outcome = BackendOutcome::APPLIED;
      evidence.dispatch_watermark = dispatch.watermark;
      evidence.applied_route_generation = dispatch.spec.route_generation;
      evidence.observed_path_authority_generation = dispatch.spec.path_authority_generation;
      evidence.id = derive_evidence_id(evidence);
      last = governor_.complete_step(evidence, authority(attempt_seed + 1ull));
    }
    return last;
  }

 private:
  SyntheticUpstream upstream_;
  ConvergenceGovernor governor_;
  PublisherId publisher_;
  WorkerBootId boot_;
};

// True when the plan (or an explanation of it) mentions the given condition code.
[[nodiscard]] inline bool has_condition(const ConditionList& conditions, ConditionCode code) {
  for (const Condition& condition : conditions.entries()) {
    if (condition.code == code) {
      return true;
    }
  }
  return false;
}

}  // namespace rc::test
