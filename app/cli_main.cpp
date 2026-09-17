// Route Convergence command line interface.
//
// Every command emits deterministic key=value lines.  A rejection is reported as
// RC_CLI_ERROR code=<CONDITION_CODE>, never as free text, so the output is safe
// to script against.

#include <process.h>

#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "rc/client.hpp"
#include "rc/rc.hpp"
#include "support.hpp"

namespace {

using namespace rc;
using namespace rc::app;

int fail(ConditionCode code, std::string detail = {}) {
  std::cout << "RC_CLI_ERROR code=" << to_string(code);
  if (!detail.empty()) {
    std::cout << " detail=" << detail;
  }
  std::cout << '\n';
  std::cout.flush();
  return 1;
}

struct Session {
  RcClient client;
  bool connected = false;
  // True when the invocation presented a live authority identity.  A query needs
  // none; a mutation always does, and an operator is told so explicitly instead
  // of having a malformed authority rejected by the coordinator.
  bool authenticated = false;
};

// Every command that mutates authoritative convergence state.
[[nodiscard]] bool is_mutation(const std::vector<std::string>& positional) {
  if (positional.empty()) {
    return false;
  }
  const std::string& command = positional[0];
  const std::string sub = positional.size() > 1 ? positional[1] : std::string{};
  if (command == "notice") {
    return true;
  }
  if (command == "policy") {
    return sub == "define";
  }
  if (command == "worker") {
    return sub == "register" || sub == "fence";
  }
  if (command == "plan") {
    return sub == "create";
  }
  if (command == "step") {
    return sub == "dispatch" || sub == "complete" || sub == "run" || sub == "fail" ||
           sub == "reconcile";
  }
  return command == "revalidate" || command == "rollback" || command == "retire" ||
         command == "revoke" || command == "pause";
}

// A deterministic per-invocation seed: the exact command line and the process
// identifier, so two invocations of the same command are two distinct processes
// with two distinct worker boots.
[[nodiscard]] std::uint64_t invocation_seed(const CommandLine& line) {
  std::uint64_t digest = 1469598103934665603ull;
  for (const std::string& token : line.positional()) {
    for (const char character : token) {
      digest ^= static_cast<std::uint64_t>(static_cast<unsigned char>(character));
      digest *= 1099511628211ull;
    }
  }
  digest ^= static_cast<std::uint64_t>(_getpid()) * 2654435761ull;
  return digest;
}

int open_session(const CommandLine& line, Session& session) {
  const bool must_authenticate = is_mutation(line.positional());
  const std::uint16_t port = static_cast<std::uint16_t>(line.u64("port", 0));
  std::string error;
  std::optional<RcClient> client = RcClient::connect("127.0.0.1", port, 30000, error);
  if (!client.has_value()) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  HelloResponseBody hello;
  if (!client->hello(hello, error)) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  client->set_epoch(hello.epoch);
  const std::optional<std::string> publisher_text = line.value("publisher");
  const std::optional<std::string> boot_text = line.value("boot");
  if (must_authenticate && !publisher_text.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY,
                "--publisher is required for a mutation; --boot is optional and "
                "pins an identity instead of registering a fresh one");
  }
  if (publisher_text.has_value()) {
    const std::optional<PublisherId> publisher = parse_id<PublisherId>(*publisher_text);
    if (!publisher.has_value()) {
      return fail(ConditionCode::MALFORMED_IDENTITY, "publisher");
    }
    client->set_publisher(*publisher);
    if (boot_text.has_value()) {
      const std::optional<WorkerBootId> boot = parse_id<WorkerBootId>(*boot_text);
      if (!boot.has_value()) {
        return fail(ConditionCode::MALFORMED_IDENTITY, "boot");
      }
      client->set_worker_boot(*boot);
      session.authenticated = true;
    } else {
      // The CLI is a fresh process per invocation, so it is a fresh worker boot.
      // It registers itself with the full operator capability set and a fabric
      // scope; the previous invocation's boot is fenced by reincarnation.
      const WorkerBootId boot = derive_worker_boot_id(invocation_seed(line));
      client->set_worker_boot(boot);
      PublisherRegistration registration;
      registration.publisher = *publisher;
      registration.worker_boot = boot;
      registration.scope = AuthorityScope::for_fabric(derive_id<FabricId>("rc.fixture.fabric", 1));
      registration.capabilities =
          static_cast<std::uint32_t>(Capability::CREATE_PLAN) |
          static_cast<std::uint32_t>(Capability::DISPATCH_STEP) |
          static_cast<std::uint32_t>(Capability::COMPLETE_STEP) |
          static_cast<std::uint32_t>(Capability::REVALIDATE_PLAN) |
          static_cast<std::uint32_t>(Capability::ROLLBACK) |
          static_cast<std::uint32_t>(Capability::PUBLISH_UPSTREAM) |
          static_cast<std::uint32_t>(Capability::ADMIN);
      registration.provenance = derive_provenance_id(invocation_seed(line));
      PlanMutationResult registered;
      std::string register_error;
      if (!client->register_worker(registration, registered, register_error) ||
          !registered.accepted()) {
        return fail(registered.accepted() ? ConditionCode::TRANSPORT_FAILURE
                                          : registered.conditions.empty()
                                                ? ConditionCode::MALFORMED_IDENTITY
                                                : registered.conditions.entries().front().code,
                    register_error);
      }
      std::cout << "RC_CLI_REGISTER boot=" << boot.to_text() << '\n';
      session.authenticated = true;
    }
  }
  if (const std::optional<std::string> explicit_attempt = line.value("attempt");
      explicit_attempt.has_value()) {
    std::uint64_t parsed = 1;
    if (!parse_u64(*explicit_attempt, parsed)) {
      return fail(ConditionCode::MALFORMED_PAYLOAD, "attempt");
    }
    client->set_attempt(attempt_for(parsed));
  } else {
    client->set_attempt(attempt_for(invocation_seed(line)));
  }
  session.client = std::move(*client);
  session.connected = true;
  if (publisher_text.has_value() && boot_text.has_value()) {
    session.authenticated = true;
  }
  std::cout << "RC_CLI_HELLO epoch=" << hello.epoch.value()
            << " convergence_generation=" << hello.convergence_generation.value()
            << " wire_version=" << hello.wire_version << '\n';
  return 0;
}

[[nodiscard]] std::optional<ConvergencePlanId> require_plan(const CommandLine& line) {
  const std::optional<std::string> text = line.value("plan");
  if (!text.has_value()) {
    return std::nullopt;
  }
  return parse_id<ConvergencePlanId>(*text);
}

[[nodiscard]] std::optional<RouteBinding> require_binding(const CommandLine& line,
                                                          std::string_view prefix) {
  const std::optional<std::string> route_text = line.value(std::string(prefix) + "route");
  const std::optional<std::string> path_text = line.value(std::string(prefix) + "path");
  if (!route_text.has_value() || !path_text.has_value()) {
    return std::nullopt;
  }
  const std::optional<RouteId> route = parse_id<RouteId>(*route_text);
  const std::optional<PathId> path = parse_id<PathId>(*path_text);
  if (!route.has_value() || !path.has_value()) {
    return std::nullopt;
  }
  RouteBinding binding;
  binding.route = *route;
  binding.generation = RouteGeneration::from_value(line.u64(std::string(prefix) + "generation", 1));
  binding.path = *path;
  binding.path_authority_generation =
      PathAuthorityGeneration::from_value(line.u64(std::string(prefix) + "path-generation", 1));
  const std::uint64_t ecmp_generation = line.u64(std::string(prefix) + "ecmp-generation", 0);
  if (ecmp_generation != 0) {
    binding.ecmp_group = derive_id<ECMPGroupId>("rc.cli.ecmp", line.u64("ecmp-seed", 1));
    binding.ecmp_generation = ECMPGroupGeneration::from_value(ecmp_generation);
    binding.assignment_generation =
        AssignmentGeneration::from_value(line.u64(std::string(prefix) + "assignment-generation", 1));
  }
  const std::uint64_t weight_generation = line.u64(std::string(prefix) + "weight-generation", 0);
  if (weight_generation != 0) {
    binding.weighted_set = derive_id<WeightedPathSetId>("rc.cli.weight", line.u64("weight-seed", 1));
    binding.weight_policy_generation = WeightPolicyGeneration::from_value(weight_generation);
  }
  const std::uint64_t multipath_generation = line.u64(std::string(prefix) + "multipath-generation", 0);
  if (multipath_generation != 0) {
    binding.multipath_set = derive_id<MultipathSetId>("rc.cli.multipath", line.u64("multipath-seed", 1));
    binding.multipath_generation = MultipathSetGeneration::from_value(multipath_generation);
  }
  binding.current = true;
  binding.legal = true;
  return binding;
}

int command_version() {
  std::cout << version_report();
  std::cout.flush();
  return 0;
}

int command_plan_create(const CommandLine& line, Session& session) {
  const std::optional<RouteBinding> source = require_binding(line, "source-");
  const std::optional<RouteBinding> target = require_binding(line, "target-");
  if (!source.has_value() || !target.has_value()) {
    return fail(ConditionCode::MALFORMED_PAYLOAD, "source/target binding");
  }
  const std::optional<std::string> policy_text = line.value("policy");
  if (!policy_text.has_value()) {
    return fail(ConditionCode::MALFORMED_PAYLOAD, "policy");
  }
  const std::optional<ConvergencePolicyId> policy_id = parse_id<ConvergencePolicyId>(*policy_text);
  if (!policy_id.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "policy");
  }
  const std::optional<OrderingMode> ordering = parse_ordering(line.value_or("ordering", "mbb"));
  if (!ordering.has_value()) {
    return fail(ConditionCode::MALFORMED_PAYLOAD, "ordering");
  }

  PlanRequest request;
  request.mode = PlanMode::GENERATED;
  request.source = *source;
  request.target = *target;
  request.policy = make_policy(*policy_id, *ordering, line.has("allow-bbm"),
                               static_cast<std::uint32_t>(line.u64("parallel", 4)),
                               static_cast<std::uint32_t>(line.u64("retries", 2)));
  request.policy.generation =
      ConvergencePolicyGeneration::from_value(line.u64("policy-generation", 1));
  request.epoch = session.client.epoch();
  request.provenance = derive_provenance_id(line.u64("attempt", 1));
  request.accept_historical_source = line.has("historical-source");

  PlanMutationResult result;
  std::string error;
  if (!session.client.create_plan(request, result, error)) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  print_result(result, "RC_CLI_PLAN_CREATE");
  return result.accepted() ? 0 : 1;
}

int command_plan_show(const CommandLine& line, Session& session) {
  const std::optional<ConvergencePlanId> plan = require_plan(line);
  if (!plan.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "plan");
  }
  PlanQueryBody body;
  std::string error;
  if (!session.client.query_plan(*plan, body, error)) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  if (!body.found) {
    return fail(ConditionCode::PLAN_UNKNOWN, plan->to_text());
  }
  std::cout << "RC_CLI_PLAN plan=" << body.summary.id.to_text()
            << " lifecycle=" << to_string(body.summary.lifecycle)
            << " plan_generation=" << body.summary.generation.value()
            << " currentness=" << body.summary.currentness.render()
            << " steps=" << body.summary.total_steps
            << " completed=" << body.summary.completed_steps
            << " ready=" << body.summary.ready_steps
            << " digest=" << body.summary.digest.to_text() << '\n';
  std::cout << "RC_CLI_PLAN_KEY " << body.summary.key.render() << '\n';
  std::cout.flush();
  return 0;
}

int command_plan_list(Session& session) {
  PlanList list;
  std::string error;
  if (!session.client.list_plans(list, error)) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  for (const PlanSummary& summary : list.plans) {
    std::cout << "RC_CLI_PLAN plan=" << summary.id.to_text()
              << " lifecycle=" << to_string(summary.lifecycle)
              << " plan_generation=" << summary.generation.value()
              << " steps=" << summary.total_steps
              << " completed=" << summary.completed_steps
              << " ready=" << summary.ready_steps
              << " digest=" << summary.digest.to_text() << '\n';
  }
  std::cout << "RC_CLI_PLAN_LIST count=" << list.plans.size()
            << " truncated=" << (list.truncated ? 1 : 0) << '\n';
  std::cout.flush();
  return 0;
}

int command_step_ready(const CommandLine& line, Session& session) {
  ReadyStepList list;
  std::string error;
  if (!session.client.ready_steps(static_cast<std::uint32_t>(line.u64("max", 16)), list, error)) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  for (const ReadyStep& step : list.steps) {
    std::cout << "RC_CLI_STEP_READY plan=" << step.plan.to_text()
              << " step=" << step.step.to_text()
              << " key=" << step.key.render()
              << " generation=" << step.generation.value()
              << " watermark=" << step.watermark.value() << '\n';
  }
  std::cout << "RC_CLI_STEP_READY_LIST count=" << list.steps.size()
            << " truncated=" << (list.truncated ? 1 : 0) << '\n';
  std::cout.flush();
  return 0;
}

int command_step_dispatch(const CommandLine& line, Session& session) {
  const std::optional<ConvergencePlanId> plan = require_plan(line);
  const std::optional<std::string> step_text = line.value("step");
  if (!plan.has_value() || !step_text.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "plan/step");
  }
  const std::optional<TransitionStepId> step = parse_id<TransitionStepId>(*step_text);
  if (!step.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "step");
  }
  DispatchStepRequest request;
  request.plan = *plan;
  request.step = *step;
  StepDispatch dispatch;
  std::string error;
  if (!session.client.dispatch_step(request, dispatch, error)) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  std::cout << "RC_CLI_STEP_DISPATCH outcome=" << to_string(dispatch.outcome)
            << " plan=" << dispatch.plan.to_text()
            << " step=" << dispatch.step.to_text()
            << " key=" << dispatch.spec.key().render()
            << " generation=" << dispatch.step_generation.value()
            << " watermark=" << dispatch.watermark.value()
            << " epoch=" << dispatch.epoch.value() << '\n';
  std::cout.flush();
  return dispatch.accepted() ? 0 : 1;
}

int command_step_complete(const CommandLine& line, Session& session) {
  const std::optional<ConvergencePlanId> plan = require_plan(line);
  const std::optional<std::string> step_text = line.value("step");
  if (!plan.has_value() || !step_text.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "plan/step");
  }
  const std::optional<TransitionStepId> step = parse_id<TransitionStepId>(*step_text);
  if (!step.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "step");
  }
  const std::optional<BackendOutcome> outcome = parse_backend_outcome(line.value_or("outcome", "applied"));
  if (!outcome.has_value()) {
    return fail(ConditionCode::MALFORMED_PAYLOAD, "outcome");
  }
  CompletionEvidence evidence;
  evidence.plan = *plan;
  evidence.step = *step;
  evidence.step_generation =
      TransitionStepGeneration::from_value(line.u64("step-generation", 0));
  evidence.attempt = session.client.attempt();
  evidence.epoch = session.client.epoch();
  evidence.publisher = session.client.publisher();
  evidence.worker_boot = session.client.worker_boot();
  evidence.outcome = *outcome;
  evidence.dispatch_watermark =
      ConvergenceGeneration::from_value(line.u64("watermark", 0));
  evidence.detail = line.value_or("detail", std::string{});
  evidence.id = derive_evidence_id(evidence);
  PlanMutationResult result;
  std::string error;
  if (!session.client.complete_step(evidence, result, error)) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  print_result(result, "RC_CLI_STEP_COMPLETE");
  return result.accepted() ? 0 : 1;
}

// One invocation, one process, one worker boot: dispatch a step, perform the
// external control-plane operation through the local journal backend and commit
// the structured completion.  A dispatch and its completion cannot be split
// across two CLI invocations, because the completion must come from the boot that
// dispatched it.
int command_step_run(const CommandLine& line, Session& session) {
  const std::optional<ConvergencePlanId> plan = require_plan(line);
  const std::optional<std::string> step_text = line.value("step");
  if (!plan.has_value() || !step_text.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "plan/step");
  }
  const std::optional<TransitionStepId> step = parse_id<TransitionStepId>(*step_text);
  if (!step.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "step");
  }
  const std::optional<BackendOutcome> scripted =
      parse_backend_outcome(line.value_or("outcome", "applied"));
  if (!scripted.has_value()) {
    return fail(ConditionCode::MALFORMED_PAYLOAD, "outcome");
  }

  DispatchStepRequest request;
  request.plan = *plan;
  request.step = *step;
  StepDispatch dispatch;
  std::string error;
  if (!session.client.dispatch_step(request, dispatch, error)) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  std::cout << "RC_CLI_STEP_DISPATCH outcome=" << to_string(dispatch.outcome)
            << " plan=" << dispatch.plan.to_text() << " step=" << dispatch.step.to_text()
            << " generation=" << dispatch.step_generation.value()
            << " watermark=" << dispatch.watermark.value() << '\n';
  if (!dispatch.accepted()) {
    std::cout.flush();
    return 1;
  }

  JournalBackend backend;
  if (*scripted != BackendOutcome::APPLIED) {
    backend.script_outcome(dispatch.step, *scripted);
  }
  StepExecutionRequest execution;
  execution.plan = dispatch.plan;
  execution.step = dispatch.step;
  execution.step_generation = dispatch.step_generation;
  execution.spec = dispatch.spec;
  execution.watermark = dispatch.watermark;
  execution.epoch = dispatch.epoch;
  execution.target.route = dispatch.spec.route;
  execution.target.generation = dispatch.spec.route_generation;
  execution.target.path = dispatch.spec.path;
  execution.target.path_authority_generation = dispatch.spec.path_authority_generation;
  std::string detail;
  const BackendOutcome outcome = backend.apply(execution, detail);

  CompletionEvidence evidence;
  evidence.plan = dispatch.plan;
  evidence.step = dispatch.step;
  evidence.step_generation = dispatch.step_generation;
  evidence.attempt = session.client.attempt();
  evidence.epoch = dispatch.epoch;
  evidence.publisher = session.client.publisher();
  evidence.worker_boot = session.client.worker_boot();
  evidence.outcome = outcome;
  evidence.applied_route_generation = dispatch.spec.route_generation;
  evidence.observed_path_authority_generation = dispatch.spec.path_authority_generation;
  evidence.dispatch_watermark = dispatch.watermark;
  evidence.detail = detail;
  evidence.id = derive_evidence_id(evidence);

  // The completion is a separate request and therefore carries its own mutation
  // attempt identifier.
  session.client.set_attempt(attempt_for(line.u64("attempt", 1) + 1));
  PlanMutationResult result;
  if (!session.client.complete_step(evidence, result, error)) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  print_result(result, "RC_CLI_STEP_RUN");
  return result.accepted() ? 0 : 1;
}

int command_step_fail(const CommandLine& line, Session& session) {
  const std::optional<ConvergencePlanId> plan = require_plan(line);
  const std::optional<std::string> step_text = line.value("step");
  if (!plan.has_value() || !step_text.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "plan/step");
  }
  const std::optional<TransitionStepId> step = parse_id<TransitionStepId>(*step_text);
  const std::optional<BackendOutcome> outcome =
      parse_backend_outcome(line.value_or("outcome", "permanent"));
  if (!step.has_value() || !outcome.has_value()) {
    return fail(ConditionCode::MALFORMED_PAYLOAD, "step/outcome");
  }
  FailStepRequest request;
  request.plan = *plan;
  request.step = *step;
  request.step_generation = TransitionStepGeneration::from_value(line.u64("step-generation", 1));
  request.outcome = *outcome;
  request.detail = line.value_or("detail", std::string{});
  PlanMutationResult result;
  std::string error;
  if (!session.client.fail_step(request, result, error)) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  print_result(result, "RC_CLI_STEP_FAIL");
  return result.accepted() ? 0 : 1;
}

int command_step_reconcile(const CommandLine& line, Session& session) {
  const std::optional<ConvergencePlanId> plan = require_plan(line);
  const std::optional<std::string> step_text = line.value("step");
  if (!plan.has_value() || !step_text.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "plan/step");
  }
  const std::optional<TransitionStepId> step = parse_id<TransitionStepId>(*step_text);
  if (!step.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "step");
  }
  bool applied = false;
  if (!parse_bool(line.value_or("applied", "0"), applied)) {
    return fail(ConditionCode::MALFORMED_PAYLOAD, "applied");
  }
  ReconcileStepRequest request;
  request.plan = *plan;
  request.step = *step;
  request.applied = applied;
  request.detail = line.value_or("detail", std::string{});
  PlanMutationResult result;
  std::string error;
  if (!session.client.reconcile_step(request, result, error)) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  print_result(result, "RC_CLI_STEP_RECONCILE");
  return result.accepted() ? 0 : 1;
}

int command_plan_control(const CommandLine& line, Session& session, std::string_view what) {
  const std::optional<ConvergencePlanId> plan = require_plan(line);
  if (!plan.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "plan");
  }
  PlanMutationResult result;
  std::string error;
  bool ok = false;
  if (what == "revalidate") {
    ok = session.client.revalidate_plan(*plan, result, error);
  } else if (what == "rollback") {
    ok = session.client.begin_rollback(*plan, result, error);
  } else if (what == "retire") {
    ok = session.client.retire_plan(*plan, result, error);
  } else if (what == "revoke") {
    ok = session.client.revoke_plan(*plan, result, error);
  } else if (what == "pause") {
    PausePlanRequest request;
    request.plan = *plan;
    request.cause = ConditionCode::REVALIDATION_REQUIRED;
    ok = session.client.pause_plan(request, result, error);
  }
  if (!ok) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  print_result(result, "RC_CLI_PLAN");
  return result.accepted() ? 0 : 1;
}

int command_policy_define(const CommandLine& line, Session& session) {
  const std::optional<std::string> policy_text = line.value("policy");
  if (!policy_text.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "policy");
  }
  const std::optional<ConvergencePolicyId> id = parse_id<ConvergencePolicyId>(*policy_text);
  if (!id.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "policy");
  }
  const std::optional<OrderingMode> ordering = parse_ordering(line.value_or("ordering", "mbb"));
  if (!ordering.has_value()) {
    return fail(ConditionCode::MALFORMED_PAYLOAD, "ordering");
  }
  ConvergencePolicy policy = make_policy(*id, *ordering, line.has("allow-bbm"),
                                         static_cast<std::uint32_t>(line.u64("parallel", 4)),
                                         static_cast<std::uint32_t>(line.u64("retries", 2)));
  policy.generation = ConvergencePolicyGeneration::from_value(line.u64("generation", 1));
  policy.require_rollback_capability = line.has("require-rollback");
  bool verify = true;
  if (const std::optional<std::string> flag = line.value("verify"); flag.has_value()) {
    (void)parse_bool(*flag, verify);
  }
  policy.verification = verify ? VerificationMode::REQUIRED : VerificationMode::NONE;
  PlanMutationResult result;
  std::string error;
  if (!session.client.define_policy(policy, result, error)) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  print_result(result, "RC_CLI_POLICY_DEFINE");
  return result.accepted() ? 0 : 1;
}

int command_policy_list(Session& session) {
  PolicyListBody body;
  std::string error;
  if (!session.client.list_policies(body, error)) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  for (const ConvergencePolicy& policy : body.policies) {
    std::cout << "RC_CLI_POLICY " << policy.render() << '\n';
  }
  std::cout << "RC_CLI_POLICY_LIST count=" << body.policies.size() << '\n';
  std::cout.flush();
  return 0;
}

int command_explain(const CommandLine& line, Session& session) {
  const std::optional<ConvergencePlanId> plan = require_plan(line);
  if (!plan.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "plan");
  }
  const std::optional<ExplainKind> kind = parse_explain_kind(line.value_or("kind", "plan"));
  if (!kind.has_value()) {
    return fail(ConditionCode::MALFORMED_PAYLOAD, "kind");
  }
  ExplainRequest request;
  request.plan = *plan;
  request.kind = *kind;
  if (const std::optional<std::string> step = line.value("step"); step.has_value()) {
    const std::optional<TransitionStepId> parsed = parse_id<TransitionStepId>(*step);
    if (!parsed.has_value()) {
      return fail(ConditionCode::MALFORMED_IDENTITY, "step");
    }
    request.step = *parsed;
  }
  ExplainResponse response;
  std::string error;
  if (!session.client.explain(request, response, error)) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  std::cout << response.explanation.render();
  std::cout.flush();
  return response.found ? 0 : 1;
}

int command_snapshot(const CommandLine& line, Session& session) {
  const std::optional<ConvergencePlanId> plan = require_plan(line);
  if (!plan.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "plan");
  }
  SnapshotBody body;
  std::string error;
  if (!session.client.snapshot(*plan, body, error)) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  if (!body.found) {
    return fail(ConditionCode::PLAN_UNKNOWN, plan->to_text());
  }
  const ConvergenceSnapshot& snapshot = body.snapshot;
  std::cout << "RC_CLI_SNAPSHOT snapshot=" << snapshot.id.to_text()
            << " plan=" << snapshot.plan.to_text()
            << " lifecycle=" << to_string(snapshot.lifecycle)
            << " plan_generation=" << snapshot.plan_generation.value()
            << " currentness=" << snapshot.currentness.render()
            << " epoch=" << snapshot.epoch.value()
            << " convergence_generation=" << snapshot.convergence_generation.value()
            << " watermark=" << snapshot.watermark.value()
            << " digest=" << snapshot.digest.to_text() << '\n';
  for (const StepSnapshot& step : snapshot.steps) {
    std::cout << "RC_CLI_SNAPSHOT_STEP key=" << step.key.render()
              << " step=" << step.id.to_text()
              << " state=" << to_string(step.state)
              << " generation=" << step.generation.value()
              << " attempts=" << step.attempts
              << " executable=" << (step.executable ? 1 : 0) << '\n';
  }
  std::cout.flush();
  return 0;
}

int command_diff(const CommandLine& line, Session& session) {
  const std::optional<ConvergencePlanId> plan = require_plan(line);
  if (!plan.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "plan");
  }
  DiffBody body;
  std::string error;
  if (!session.client.diff(*plan, ConvergencePlanGeneration::from_value(line.u64("from", 0)), body,
                           error)) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  if (!body.found) {
    return fail(ConditionCode::PLAN_UNKNOWN, plan->to_text());
  }
  std::cout << body.diff.render() << '\n';
  std::cout.flush();
  return 0;
}

int command_notice(const CommandLine& line, Session& session, std::string_view what) {
  std::string error;
  if (what == "route") {
    const std::optional<RouteBinding> binding = require_binding(line, "");
    if (!binding.has_value()) {
      return fail(ConditionCode::MALFORMED_PAYLOAD, "route binding");
    }
    RouteChangeNotice notice;
    notice.binding = *binding;
    notice.provenance = derive_provenance_id(line.u64("attempt", 1));
    NoticeResult result;
    if (!session.client.publish_route_change(notice, result, error)) {
      return fail(ConditionCode::TRANSPORT_FAILURE, error);
    }
    std::cout << "RC_CLI_NOTICE outcome=" << to_string(result.outcome)
              << " examined=" << result.plans_examined
              << " invalidated=" << result.plans_invalidated
              << " superseded=" << result.plans_superseded
              << " staled_steps=" << result.steps_staled << '\n';
    std::cout.flush();
    return result.accepted() ? 0 : 1;
  }
  if (what == "path") {
    const std::optional<std::string> path_text = line.value("path");
    if (!path_text.has_value()) {
      return fail(ConditionCode::MALFORMED_IDENTITY, "path");
    }
    const std::optional<PathId> path = parse_id<PathId>(*path_text);
    if (!path.has_value()) {
      return fail(ConditionCode::MALFORMED_IDENTITY, "path");
    }
    bool legal = true;
    if (!parse_bool(line.value_or("legal", "1"), legal)) {
      return fail(ConditionCode::MALFORMED_PAYLOAD, "legal");
    }
    PathChangeNotice notice;
    notice.legality.path = *path;
    notice.legality.generation =
        PathAuthorityGeneration::from_value(line.u64("generation", 1));
    notice.legality.legal = legal;
    notice.provenance = derive_provenance_id(line.u64("attempt", 1));
    NoticeResult result;
    if (!session.client.publish_path_change(notice, result, error)) {
      return fail(ConditionCode::TRANSPORT_FAILURE, error);
    }
    std::cout << "RC_CLI_NOTICE outcome=" << to_string(result.outcome)
              << " examined=" << result.plans_examined
              << " invalidated=" << result.plans_invalidated << '\n';
    std::cout.flush();
    return result.accepted() ? 0 : 1;
  }
  const std::uint64_t current = line.u64("current", 0);
  if (current == 0) {
    return fail(ConditionCode::MALFORMED_PAYLOAD, "current");
  }
  EpochChangeNotice notice;
  notice.previous = CoordinatorEpoch::from_value(line.u64("previous", current - 1));
  notice.current = CoordinatorEpoch::from_value(current);
  notice.provenance = derive_provenance_id(line.u64("attempt", 1));
  NoticeResult result;
  if (!session.client.publish_epoch_change(notice, result, error)) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  std::cout << "RC_CLI_NOTICE outcome=" << to_string(result.outcome)
            << " epoch=" << result.epoch.value()
            << " examined=" << result.plans_examined
            << " invalidated=" << result.plans_invalidated << '\n';
  std::cout.flush();
  return result.accepted() ? 0 : 1;
}

int command_worker(const CommandLine& line, Session& session, std::string_view what) {
  std::string error;
  if (what == "register") {
    const std::optional<std::string> publisher_text = line.value("publisher");
    const std::optional<std::string> boot_text = line.value("boot");
    const std::optional<std::string> scope_text = line.value("scope");
    if (!publisher_text.has_value() || !boot_text.has_value() || !scope_text.has_value()) {
      return fail(ConditionCode::MALFORMED_PAYLOAD, "publisher/boot/scope");
    }
    const std::optional<PublisherId> publisher = parse_id<PublisherId>(*publisher_text);
    const std::optional<WorkerBootId> boot = parse_id<WorkerBootId>(*boot_text);
    const std::optional<ScopeKind> kind = parse_scope(*scope_text);
    if (!publisher.has_value() || !boot.has_value() || !kind.has_value()) {
      return fail(ConditionCode::MALFORMED_IDENTITY, "publisher/boot/scope");
    }
    PublisherRegistration registration;
    registration.publisher = *publisher;
    registration.worker_boot = *boot;
    registration.capabilities =
        static_cast<std::uint32_t>(Capability::CREATE_PLAN) |
        static_cast<std::uint32_t>(Capability::DISPATCH_STEP) |
        static_cast<std::uint32_t>(Capability::COMPLETE_STEP) |
        static_cast<std::uint32_t>(Capability::REVALIDATE_PLAN) |
        static_cast<std::uint32_t>(Capability::ROLLBACK) |
        static_cast<std::uint32_t>(Capability::PUBLISH_UPSTREAM) |
        static_cast<std::uint32_t>(Capability::ADMIN);
    registration.provenance = derive_provenance_id(line.u64("attempt", 1));
    if (*kind == ScopeKind::FABRIC) {
      registration.scope = AuthorityScope::for_fabric(fabric_for(1));
    } else if (*kind == ScopeKind::ROUTING_NAMESPACE) {
      registration.scope = AuthorityScope::for_routing_namespace(namespace_for(1), fabric_for(1));
    } else if (*kind == ScopeKind::ROUTE) {
      const std::optional<std::string> route_text = line.value("route");
      const std::optional<RouteId> route =
          route_text.has_value() ? parse_id<RouteId>(*route_text) : std::nullopt;
      if (!route.has_value()) {
        return fail(ConditionCode::MALFORMED_IDENTITY, "route");
      }
      registration.scope = AuthorityScope::for_route(*route, namespace_for(1), fabric_for(1));
    } else {
      return fail(ConditionCode::MALFORMED_PAYLOAD, "scope");
    }
    PlanMutationResult result;
    if (!session.client.register_worker(registration, result, error)) {
      return fail(ConditionCode::TRANSPORT_FAILURE, error);
    }
    print_result(result, "RC_CLI_WORKER_REGISTER");
    return result.accepted() ? 0 : 1;
  }
  const std::optional<std::string> boot_text = line.value("boot");
  if (!boot_text.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "boot");
  }
  const std::optional<WorkerBootId> boot = parse_id<WorkerBootId>(*boot_text);
  if (!boot.has_value()) {
    return fail(ConditionCode::MALFORMED_IDENTITY, "boot");
  }
  PlanMutationResult result;
  if (!session.client.fence_worker(*boot, result, error)) {
    return fail(ConditionCode::TRANSPORT_FAILURE, error);
  }
  print_result(result, "RC_CLI_WORKER_FENCE");
  return result.accepted() ? 0 : 1;
}

int command_store_inspect(const CommandLine& line) {
  const std::string path = line.value_or("store", std::string{});
  if (path.empty()) {
    return fail(ConditionCode::STORE_IO, "store path is required");
  }
  std::vector<std::uint8_t> bytes;
  std::string error;
  StoreDefect defect = read_store_file(path, bytes, error);
  if (defect != StoreDefect::NONE) {
    return fail(condition_for(defect), error);
  }
  StoreFileInfo info;
  std::vector<std::uint8_t> payload;
  ConvergenceLimits limits;
  defect = decode_store_file(bytes, limits, info, payload);
  std::cout << "RC_CLI_STORE file=" << path
            << " bytes=" << bytes.size()
            << " defect=" << to_string(defect);
  if (defect == StoreDefect::NONE) {
    std::cout << " format_version=" << info.format_version
              << " epoch=" << info.coordinator_epoch
              << " convergence_generation=" << info.convergence_generation
              << " payload_bytes=" << info.payload_bytes;
  }
  std::cout << '\n';
  std::cout.flush();
  return defect == StoreDefect::NONE ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  const CommandLine line = CommandLine::parse(argc, argv);
  const std::vector<std::string>& positional = line.positional();
  if (positional.empty()) {
    print_line("usage: rc_cli <command> [options]");
    print_line("commands: version, plan create|show|list,");
    print_line("          step ready|run|dispatch|complete|fail|reconcile,");
    print_line("          revalidate, rollback, retire, revoke, pause, policy define|list,");
    print_line("          explain, snapshot, diff, notice route|path|epoch,");
    print_line("          worker register|fence, store inspect");
    return 2;
  }
  if (positional[0] == "version" || line.has("version")) {
    return command_version();
  }
  if (positional[0] == "store") {
    return command_store_inspect(line);
  }

  Session session;
  const int opened = open_session(line, session);
  if (opened != 0) {
    return opened;
  }

  const std::string& command = positional[0];
  const std::string sub = positional.size() > 1 ? positional[1] : std::string{};

  if (command == "plan") {
    if (sub == "create") {
      return command_plan_create(line, session);
    }
    if (sub == "show") {
      return command_plan_show(line, session);
    }
    if (sub == "list") {
      return command_plan_list(session);
    }
  }
  if (command == "step") {
    if (sub == "ready") {
      return command_step_ready(line, session);
    }
    if (sub == "dispatch") {
      return command_step_dispatch(line, session);
    }
    if (sub == "complete") {
      return command_step_complete(line, session);
    }
    if (sub == "run") {
      return command_step_run(line, session);
    }
    if (sub == "fail") {
      return command_step_fail(line, session);
    }
    if (sub == "reconcile") {
      return command_step_reconcile(line, session);
    }
  }
  if (command == "policy") {
    if (sub == "define") {
      return command_policy_define(line, session);
    }
    if (sub == "list") {
      return command_policy_list(session);
    }
  }
  if (command == "notice") {
    if (sub != "route" && sub != "path" && sub != "epoch") {
      return fail(ConditionCode::MALFORMED_PAYLOAD, "notice kind");
    }
    return command_notice(line, session, sub);
  }
  if (command == "worker") {
    if (sub != "register" && sub != "fence") {
      return fail(ConditionCode::MALFORMED_PAYLOAD, "worker command");
    }
    return command_worker(line, session, sub);
  }
  if (command == "revalidate" || command == "rollback" || command == "retire" ||
      command == "revoke" || command == "pause") {
    return command_plan_control(line, session, command);
  }
  if (command == "explain") {
    return command_explain(line, session);
  }
  if (command == "snapshot") {
    return command_snapshot(line, session);
  }
  if (command == "diff") {
    return command_diff(line, session);
  }
  return fail(ConditionCode::MALFORMED_PAYLOAD, command);
}
