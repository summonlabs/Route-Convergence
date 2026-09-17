// Route Convergence worker / transition executor.
//
// A worker registers with a coordinator, pumps the steps it is authorized to
// execute, performs the external control-plane operation through its backend and
// commits structured completion evidence.  A fresh process is a fresh
// WorkerBootId: the previous boot of the same publisher is fenced permanently.

#include <cstdlib>
#include <optional>
#include <string>
#include <vector>

#include "rc/client.hpp"
#include "rc/rc.hpp"
#include "support.hpp"

namespace {

using namespace rc;

struct WorkerConfig {
  std::string host = "127.0.0.1";
  std::uint16_t port = 0;
  std::uint64_t publisher_seed = 1;
  std::uint64_t boot_seed = 1;
  ScopeKind scope = ScopeKind::FABRIC;
  std::uint32_t capabilities = 0;
  std::uint32_t max_steps = 64;
  std::uint32_t journal_entries = 4096;
  bool hold_after_dispatch = false;
  bool die_after_dispatch = false;
  bool wait_for_fence = false;
  bool exit_when_idle = true;
  BackendOutcome scripted = BackendOutcome::APPLIED;
  bool scripted_set = false;
  std::string scripted_step;
};

}  // namespace

int main(int argc, char** argv) {
  using namespace rc::app;

  const CommandLine line = CommandLine::parse(argc, argv);
  if (line.has("help")) {
    print_line("usage: rc_worker --port N --publisher-seed N --boot-seed N [--scope KIND]");
    print_line("                 [--route HEX] [--capabilities a,b,c] [--max-steps N]");
    print_line("                 [--hold] [--die-after-dispatch] [--wait-fence]");
    print_line("                 [--outcome applied|ambiguous|retryable|permanent|unsupported]");
    print_line("                 [--outcome-step HEX]");
    return 0;
  }

  WorkerConfig config;
  config.host = line.value_or("host", config.host);
  config.port = static_cast<std::uint16_t>(line.u64("port", 0));
  config.publisher_seed = line.u64("publisher-seed", 1);
  config.boot_seed = line.u64("boot-seed", 1);
  config.max_steps = static_cast<std::uint32_t>(line.u64("max-steps", 64));
  config.journal_entries = static_cast<std::uint32_t>(line.u64("journal-entries", 4096));
  config.hold_after_dispatch = line.has("hold");
  config.die_after_dispatch = line.has("die-after-dispatch");
  config.wait_for_fence = line.has("wait-fence");
  bool exit_when_idle = true;
  if (const std::optional<std::string> flag = line.value("exit-when-idle"); flag.has_value()) {
    (void)parse_bool(*flag, exit_when_idle);
  }
  config.exit_when_idle = exit_when_idle;

  if (const std::optional<std::string> scope = line.value("scope"); scope.has_value()) {
    const std::optional<ScopeKind> parsed = parse_scope(*scope);
    if (!parsed.has_value()) {
      print_line("RC_WORKER_ERROR code=MALFORMED_PAYLOAD detail=scope");
      return 2;
    }
    config.scope = *parsed;
  }
  std::vector<std::string> capability_names;
  if (const std::optional<std::string> capabilities = line.value("capabilities");
      capabilities.has_value()) {
    std::string current;
    for (const char character : *capabilities) {
      if (character == ',') {
        capability_names.push_back(current);
        current.clear();
        continue;
      }
      current.push_back(character);
    }
    if (!current.empty()) {
      capability_names.push_back(current);
    }
  }
  config.capabilities = capability_names.empty()
                            ? (static_cast<std::uint32_t>(Capability::DISPATCH_STEP) |
                               static_cast<std::uint32_t>(Capability::COMPLETE_STEP) |
                               static_cast<std::uint32_t>(Capability::CREATE_PLAN))
                            : parse_capabilities(capability_names);

  if (const std::optional<std::string> outcome = line.value("outcome"); outcome.has_value()) {
    const std::optional<BackendOutcome> parsed = parse_backend_outcome(*outcome);
    if (!parsed.has_value()) {
      print_line("RC_WORKER_ERROR code=MALFORMED_PAYLOAD detail=outcome");
      return 2;
    }
    config.scripted = *parsed;
    config.scripted_set = true;
  }
  config.scripted_step = line.value_or("outcome-step", std::string{});

  const PublisherId publisher = derive_publisher_id(config.publisher_seed);
  const WorkerBootId boot = derive_worker_boot_id(config.boot_seed);

  std::string error;
  std::optional<RcClient> client = RcClient::connect(config.host, config.port, 30000, error);
  if (!client.has_value()) {
    print_line("RC_WORKER_ERROR code=TRANSPORT_FAILURE detail=" + error);
    return 3;
  }

  HelloResponseBody hello;
  if (!client->hello(hello, error)) {
    print_line("RC_WORKER_ERROR code=" + error + " detail=hello");
    return 3;
  }
  client->set_epoch(hello.epoch);
  client->set_publisher(publisher);
  client->set_worker_boot(boot);
  // Registration, dispatch and completion are three different requests, so each
  // carries its own mutation attempt identifier.
  client->set_attempt(attempt_for(config.boot_seed * 1000003ull + 999983ull));

  AuthorityScope scope = AuthorityScope::deny_all();
  if (config.scope == ScopeKind::ROUTE) {
    const std::string route_text = line.value_or("route", std::string{});
    const std::optional<RouteId> route = parse_id<RouteId>(route_text);
    if (!route.has_value()) {
      print_line("RC_WORKER_ERROR code=MALFORMED_IDENTITY detail=route");
      return 2;
    }
    scope = AuthorityScope::for_route(*route, namespace_for(1), fabric_for(1));
  } else if (config.scope == ScopeKind::FABRIC) {
    scope = AuthorityScope::for_fabric(fabric_for(1));
  } else if (config.scope == ScopeKind::ROUTING_NAMESPACE) {
    scope = AuthorityScope::for_routing_namespace(namespace_for(1), fabric_for(1));
  } else if (config.scope == ScopeKind::PLAN) {
    const std::string plan_text = line.value_or("plan", std::string{});
    const std::optional<ConvergencePlanId> plan = parse_id<ConvergencePlanId>(plan_text);
    if (!plan.has_value()) {
      print_line("RC_WORKER_ERROR code=MALFORMED_IDENTITY detail=plan");
      return 2;
    }
    scope = AuthorityScope::for_plan(*plan);
  }
  client->set_scope(scope);

  PublisherRegistration registration;
  registration.publisher = publisher;
  registration.worker_boot = boot;
  registration.scope = scope;
  registration.capabilities = config.capabilities;
  registration.provenance = derive_provenance_id(config.boot_seed);

  PlanMutationResult registered;
  if (!client->register_worker(registration, registered, error)) {
    print_line("RC_WORKER_ERROR code=" + error + " detail=register");
    return 3;
  }
  print_line("RC_WORKER_REGISTERED outcome=" + std::string(to_string(registered.outcome)) +
             " boot=" + boot.to_text() + " publisher=" + publisher.to_text() +
             " epoch=" + std::to_string(hello.epoch.value()));
  if (!registered.accepted()) {
    return 4;
  }
  print_line("RC_WORKER_READY");

  if (config.wait_for_fence) {
    if (client->wait_for_fence(error)) {
      print_line("RC_WORKER_FENCED boot=" + boot.to_text());
      return 5;
    }
    print_line("RC_WORKER_EXIT code=0 detail=fence-wait-ended");
    return 0;
  }

  JournalBackend backend(config.journal_entries);
  std::uint32_t completed = 0;
  std::uint64_t attempt_counter = 0;

  while (completed < config.max_steps) {
    ReadyStepList ready;
    if (!client->ready_steps(config.max_steps, ready, error)) {
      print_line("RC_WORKER_ERROR code=" + error + " detail=ready");
      return 3;
    }
    if (ready.steps.empty()) {
      break;
    }
    const ReadyStep& candidate = ready.steps.front();
    attempt_counter += 1;
    const MutationAttemptId dispatch_attempt =
        attempt_for((config.boot_seed * 1000003ull) + attempt_counter);
    client->set_attempt(dispatch_attempt);
    AuthorityContext dispatch_authority;
    dispatch_authority.epoch = client->epoch();
    dispatch_authority.publisher = publisher;
    dispatch_authority.worker_boot = boot;
    dispatch_authority.attempt = dispatch_attempt;

    DispatchStepRequest dispatch_request;
    dispatch_request.plan = candidate.plan;
    dispatch_request.step = candidate.step;
    StepDispatch dispatch;
    if (!client->dispatch_step(dispatch_request, dispatch, error)) {
      print_line("RC_WORKER_ERROR code=" + error + " detail=dispatch");
      return 3;
    }
    print_line("RC_WORKER_DISPATCH plan=" + candidate.plan.to_text() +
               " step=" + candidate.step.to_text() +
               " key=" + candidate.key.render() +
               " generation=" + std::to_string(dispatch.step_generation.value()) +
               " watermark=" + std::to_string(dispatch.watermark.value()) +
               " epoch=" + std::to_string(dispatch.epoch.value()) +
               " attempt=" + dispatch_authority.attempt.to_text() +
               " outcome=" + std::string(to_string(dispatch.outcome)));
    if (!dispatch.accepted()) {
      print_line("RC_WORKER_ERROR code=DISPATCH_REJECTED detail=" +
                 std::string(to_string(dispatch.outcome)));
      return 4;
    }

    if (config.die_after_dispatch) {
      // A genuine immediate process death with no unwinding and no
      // acknowledgement: the coordinator must treat the in-flight step
      // conservatively.
      std::_Exit(9);
    }
    if (config.hold_after_dispatch) {
      if (client->wait_for_fence(error)) {
        print_line("RC_WORKER_FENCED boot=" + boot.to_text());
        return 5;
      }
      print_line("RC_WORKER_EXIT code=0 detail=hold-ended");
      return 0;
    }

    if (config.scripted_set) {
      if (config.scripted_step.empty() || config.scripted_step == candidate.step.to_text()) {
        TransitionStepId target = candidate.step;
        if (!config.scripted_step.empty()) {
          const std::optional<TransitionStepId> parsed = parse_id<TransitionStepId>(config.scripted_step);
          if (parsed.has_value()) {
            target = *parsed;
          }
        }
        backend.script_outcome(target, config.scripted);
      }
    }

    StepExecutionRequest execution;
    execution.plan = candidate.plan;
    execution.step = candidate.step;
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
    evidence.plan = candidate.plan;
    evidence.step = candidate.step;
    evidence.step_generation = dispatch.step_generation;
    evidence.attempt = dispatch_authority.attempt;
    // The completion is a distinct request, so it carries its own attempt id.
    client->set_attempt(attempt_for((config.boot_seed * 1000003ull) + attempt_counter + 500000ull));
    evidence.epoch = dispatch.epoch;
    evidence.publisher = publisher;
    evidence.worker_boot = boot;
    evidence.outcome = outcome;
    evidence.dispatch_watermark = dispatch.watermark;
    evidence.detail = detail;
    evidence.id = derive_evidence_id(evidence);

    PlanMutationResult result;
    if (!client->complete_step(evidence, result, error)) {
      print_line("RC_WORKER_ERROR code=" + error + " detail=complete");
      return 3;
    }
    print_line("RC_WORKER_COMPLETE plan=" + candidate.plan.to_text() +
               " step=" + candidate.step.to_text() +
               " backend=" + std::string(to_string(outcome)) +
               " outcome=" + std::string(to_string(result.outcome)));
    if (!result.accepted() && result.outcome != Outcome::RETRYABLE_FAILURE) {
      print_line("RC_WORKER_EXIT code=6 detail=completion-rejected");
      return 6;
    }
    completed += 1;
  }

  print_line("RC_WORKER_EXIT code=0 completed=" + std::to_string(completed));
  return 0;
}
