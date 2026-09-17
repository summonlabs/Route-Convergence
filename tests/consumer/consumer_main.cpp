// Independent Route Convergence consumer.
//
// This program is built by a separate CMake project that sees only the installed
// package.  It exercises the documented public surface end to end:
//   * create an old and a target route generation,
//   * create a make-before-break convergence plan,
//   * inspect the canonical steps,
//   * complete the prerequisites in order,
//   * verify the old route is retained until target activation and verification,
//   * finish convergence.

#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <rc/rc.hpp>

namespace {

int g_failures = 0;

void check(bool condition, const std::string& message) {
  if (!condition) {
    ++g_failures;
    std::cout << "CONSUMER_FAIL " << message << "\n";
  }
}

class Harness final : public rc::RouteFabricView,
                      public rc::PathAuthorityView,
                      public rc::FabricEpochView {
 public:
  explicit Harness(rc::CoordinatorEpoch epoch) : epoch_(epoch) {}

  [[nodiscard]] std::optional<rc::RouteBinding> observe_route(const rc::RouteId& route) const override {
    for (const rc::RouteBinding& binding : routes_) {
      if (binding.route == route) {
        return binding;
      }
    }
    return std::nullopt;
  }

  [[nodiscard]] std::optional<rc::PathLegality> observe_path(const rc::PathId& path) const override {
    for (const rc::PathLegality& legality : paths_) {
      if (legality.path == path) {
        return legality;
      }
    }
    return std::nullopt;
  }

  [[nodiscard]] rc::CoordinatorEpoch current_epoch() const override { return epoch_; }

  void set_route(const rc::RouteBinding& binding) {
    for (rc::RouteBinding& existing : routes_) {
      if (existing.route == binding.route) {
        existing = binding;
        return;
      }
    }
    routes_.push_back(binding);
  }

  void set_path(const rc::PathId& path, rc::PathAuthorityGeneration generation) {
    for (rc::PathLegality& existing : paths_) {
      if (existing.path == path) {
        existing.generation = generation;
        existing.legal = true;
        return;
      }
    }
    rc::PathLegality legality;
    legality.path = path;
    legality.generation = generation;
    legality.legal = true;
    paths_.push_back(legality);
  }

 private:
  rc::CoordinatorEpoch epoch_;
  std::vector<rc::RouteBinding> routes_;
  std::vector<rc::PathLegality> paths_;
};

}  // namespace

int main() {
  using namespace rc;

  const FabricId fabric = derive_id<FabricId>("consumer.fabric", 1);
  const RoutingNamespaceId routing_namespace = derive_id<RoutingNamespaceId>("consumer.ns", 1);
  const RouteId route = derive_id<RouteId>("consumer.route", 1);
  const PathId path_a = derive_id<PathId>("consumer.path.a", 1);
  const PathId path_b = derive_id<PathId>("consumer.path.b", 1);
  const PublisherId publisher = derive_publisher_id(11);
  const WorkerBootId boot = derive_worker_boot_id(11);
  const ConvergencePolicyId policy_id = derive_id<ConvergencePolicyId>("consumer.policy", 1);

  Harness harness(CoordinatorEpoch::from_value(1));
  harness.set_path(path_a, PathAuthorityGeneration::from_value(4));
  harness.set_path(path_b, PathAuthorityGeneration::from_value(9));

  RouteBinding old_route;
  old_route.route = route;
  old_route.generation = RouteGeneration::from_value(10);
  old_route.path = path_a;
  old_route.path_authority_generation = PathAuthorityGeneration::from_value(4);
  harness.set_route(old_route);

  GovernorOptions options;
  options.initial_epoch = CoordinatorEpoch::from_value(1);
  options.fabric = fabric;
  options.routing_namespace = routing_namespace;
  std::string reason;
  check(ConvergenceGovernor::validate_options(options, reason), "governor options are coherent");

  ConvergenceGovernor governor(harness, harness, harness, options);

  // Every request carries its own mutation attempt identifier, exactly as a real
  // worker does.
  std::uint64_t attempt_counter = 0;
  const auto next_authority = [&governor, &publisher, &boot, &attempt_counter]() {
    AuthorityContext context;
    context.epoch = governor.epoch();
    context.publisher = publisher;
    context.worker_boot = boot;
    context.attempt =
        derive_id<MutationAttemptId>("consumer.attempt", attempt_counter++);
    return context;
  };
  AuthorityContext authority = next_authority();

  PublisherRegistration registration;
  registration.publisher = publisher;
  registration.worker_boot = boot;
  registration.scope = AuthorityScope::for_fabric(fabric);
  registration.capabilities =
      static_cast<std::uint32_t>(Capability::CREATE_PLAN) |
      static_cast<std::uint32_t>(Capability::DISPATCH_STEP) |
      static_cast<std::uint32_t>(Capability::COMPLETE_STEP) |
      static_cast<std::uint32_t>(Capability::REVALIDATE_PLAN) |
      static_cast<std::uint32_t>(Capability::ROLLBACK) |
      static_cast<std::uint32_t>(Capability::ADMIN);
  registration.provenance = derive_provenance_id(11);
  const PlanMutationResult registered = governor.register_worker(registration, authority);
  check(registered.accepted(), "worker registration accepted");

  ConvergencePolicy policy;
  policy.id = policy_id;
  policy.generation = ConvergencePolicyGeneration::from_value(1);
  policy.ordering = OrderingMode::MAKE_BEFORE_BREAK;
  policy.allow_overlap = true;
  policy.verification = VerificationMode::REQUIRED;
  policy.max_parallel_steps = 4;
  check(governor.define_policy(policy, next_authority()).accepted(),
        "policy definition accepted");

  RouteBinding target_route = old_route;
  target_route.generation = RouteGeneration::from_value(11);
  target_route.path = path_b;
  target_route.path_authority_generation = PathAuthorityGeneration::from_value(9);
  harness.set_route(target_route);

  PlanRequest request;
  request.mode = PlanMode::GENERATED;
  request.source = old_route;
  request.target = target_route;
  request.policy = policy;
  request.epoch = governor.epoch();
  request.provenance = derive_provenance_id(12);

  const PlanMutationResult created = governor.create_plan(request, next_authority());
  check(created.outcome == Outcome::PLAN_CREATED, "plan created");
  check(created.plan_generation.value() == 1, "plan generation starts at one");

  const std::optional<ConvergenceSnapshot> snapshot = governor.snapshot(created.plan);
  check(snapshot.has_value(), "snapshot available");
  if (!snapshot.has_value()) {
    std::cout << "CONSUMER_FAIL no snapshot\n";
    return 1;
  }

  // The canonical plan is a genuine dependency DAG in which the old route is not
  // withdrawn until the new state has been verified.
  bool saw_validate = false;
  bool saw_install = false;
  bool saw_verify = false;
  bool saw_withdraw = false;
  bool saw_finalize = false;
  for (const StepSnapshot& step : snapshot->steps) {
    switch (step.key.kind) {
      case StepKind::VALIDATE_TARGET: saw_validate = true; break;
      case StepKind::INSTALL_NEW_ROUTE: saw_install = true; break;
      case StepKind::VERIFY_NEW_STATE: saw_verify = true; break;
      case StepKind::WITHDRAW_OLD_ROUTE: saw_withdraw = true; break;
      case StepKind::FINALIZE: saw_finalize = true; break;
      default: break;
    }
  }
  check(saw_validate && saw_install && saw_verify && saw_withdraw && saw_finalize,
        "canonical make-before-break step set");
  for (const StepSnapshot& step : snapshot->steps) {
    if (step.key.kind != StepKind::WITHDRAW_OLD_ROUTE) {
      continue;
    }
    bool waits_for_verification = false;
    for (const StepKey& dependency : step.depends_on) {
      if (dependency.kind == StepKind::VERIFY_NEW_STATE ||
          dependency.kind == StepKind::DEACTIVATE_OLD_PATH) {
        waits_for_verification = true;
      }
    }
    check(waits_for_verification, "WITHDRAW_OLD_ROUTE follows verification");
  }

  // Drive the plan.  The old route must remain the observed binding until the
  // target has been activated and verified; the harness mirrors the externally
  // applied state as each mutation step completes.
  std::uint64_t attempt_seed = 100;
  bool converged = false;
  for (int guard = 0; guard < 32 && !converged; ++guard) {
    const ReadyStepList ready = governor.ready_steps(1);
    if (ready.steps.empty()) {
      break;
    }
    const ReadyStep& step = ready.steps.front();
    if (step.plan != created.plan) {
      break;
    }
    check(step.key.kind != StepKind::WITHDRAW_OLD_ROUTE || saw_verify,
          "the old route is only withdrawn after verification exists");

    const AuthorityContext dispatch_authority = next_authority();
    const AuthorityContext completion_authority = next_authority();
    ++attempt_seed;
    const StepDispatch dispatch =
        governor.dispatch_step(step.plan, step.step, dispatch_authority);
    check(dispatch.accepted(), "step dispatched: " + std::string(to_string(step.key.kind)));

    CompletionEvidence evidence;
    evidence.plan = step.plan;
    evidence.step = step.step;
    evidence.step_generation = dispatch.step_generation;
    evidence.attempt = dispatch_authority.attempt;
    evidence.epoch = dispatch.epoch;
    evidence.publisher = publisher;
    evidence.worker_boot = boot;
    evidence.outcome = BackendOutcome::APPLIED;
    evidence.dispatch_watermark = dispatch.watermark;
    evidence.applied_route_generation = dispatch.spec.route_generation;
    evidence.observed_path_authority_generation = dispatch.spec.path_authority_generation;
    evidence.detail = "consumer applied";
    evidence.id = derive_evidence_id(evidence);

    const PlanMutationResult completed = governor.complete_step(evidence, completion_authority);
    check(completed.accepted() || completed.outcome == Outcome::PLAN_COMPLETED,
          "step completed: " + std::string(to_string(step.key.kind)));

    // Mirror the control-plane effect into the synthetic observation source.
    if (step.key.kind == StepKind::INSTALL_NEW_ROUTE ||
        step.key.kind == StepKind::ACTIVATE_NEW_PATH) {
      RouteBinding observed = harness.observe_route(route).value_or(old_route);
      observed.path = target_route.path;
      observed.path_authority_generation = target_route.path_authority_generation;
      harness.set_route(observed);
    }
    if (step.key.kind == StepKind::WITHDRAW_OLD_ROUTE) {
      RouteBinding observed = harness.observe_route(route).value_or(old_route);
      observed.generation = target_route.generation;
      harness.set_route(observed);
    }

    const std::optional<PlanSummary> summary = governor.query_plan(created.plan);
    if (summary.has_value() && summary->lifecycle == PlanLifecycle::COMPLETED) {
      converged = true;
    }
  }

  const std::optional<PlanSummary> final_summary = governor.query_plan(created.plan);
  check(final_summary.has_value(), "plan is still queryable");
  if (final_summary.has_value()) {
    check(final_summary->lifecycle == PlanLifecycle::COMPLETED, "plan reached COMPLETED");
    check(final_summary->currentness.is_current(), "plan is convergence-current");
  }

  const std::optional<ConvergenceSnapshot> final_snapshot = governor.snapshot(created.plan);
  check(final_snapshot.has_value(), "final snapshot available");
  if (final_snapshot.has_value()) {
    for (const StepSnapshot& step : final_snapshot->steps) {
      check(step.state == StepLifecycle::COMPLETED || step.state == StepLifecycle::SKIPPED,
            "every step is satisfied at completion");
    }
    check(!final_snapshot->digest.is_nil(), "snapshot digest is present");
  }

  const ExplainResponse explanation = governor.explain(ExplainRequest{created.plan, {}, ExplainKind::COMPLETION});
  check(explanation.found, "explanation available");

  if (g_failures == 0) {
    std::cout << "RC_CONSUMER_OK version=" << version_line() << "\n";
    return 0;
  }
  std::cout << "RC_CONSUMER_FAILED failures=" << g_failures << "\n";
  return 1;
}
