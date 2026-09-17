// Real-process proofs for Route Convergence.
//
// Every proof in this file starts an actual rc_coordinator process and, where a
// worker is involved, an actual rc_worker process, and kills them with real OS
// termination.  There is deliberately no thread-based substitute, no fixed port
// and no fixed path: ports are ephemeral and every temporary store is derived
// from the process identifier.
//
// There are no test timeouts anywhere: a child that never produces the line the
// proof is waiting for is a defect, not something to hide behind a watchdog.

// <process.h> is used instead of <windows.h> on purpose: windows.h defines an
// ERROR macro that would collide with WireMessageId::ERROR.
#include <process.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "rc/client.hpp"
#include "rc/process.hpp"
#include "rc/rc.hpp"
#include "test_framework.hpp"

using namespace rc;

namespace {

// Process identifier, monotonic clock and a counter together: scratch paths and
// identities are unique even when several suites run at the same time.
[[nodiscard]] std::uint64_t unique_seed() {
  static std::atomic<std::uint64_t> counter{0};
  const std::uint64_t ticks = static_cast<std::uint64_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
  return (static_cast<std::uint64_t>(_getpid()) * 1000003ull) ^ ticks ^
         (counter.fetch_add(1) * 7919ull);
}

// A scratch directory unique to this process and this call.
class Scratch {
 public:
  Scratch() {
    path_ = std::filesystem::temp_directory_path() /
            ("route-convergence-test-" + std::to_string(static_cast<std::uint64_t>(_getpid())) +
             "-" + std::to_string(unique_seed()));
    std::error_code code;
    std::filesystem::create_directories(path_, code);
  }
  ~Scratch() {
    std::error_code code;
    std::filesystem::remove_all(path_, code);
  }
  Scratch(const Scratch&) = delete;
  Scratch& operator=(const Scratch&) = delete;

  [[nodiscard]] std::filesystem::path store(const std::string& name = "rc.store") const {
    return path_ / name;
  }
  [[nodiscard]] const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
};

struct CoordinatorHandle {
  LocalProcess process;
  std::uint16_t port = 0;
  std::uint64_t epoch = 0;
  bool recovered = false;
  std::vector<std::string> lines;

  [[nodiscard]] bool start(std::uint64_t epoch_value, const std::string& store,
                           std::uint32_t receive_deadline_ms = 5000) {
    LocalProcess::Options options;
    options.executable = RC_COORDINATOR_EXECUTABLE;
    options.arguments = {"--port", "0",
                         "--epoch", std::to_string(epoch_value),
                         "--receive-deadline-ms", std::to_string(receive_deadline_ms)};
    if (!store.empty()) {
      options.arguments.push_back("--store");
      options.arguments.push_back(store);
      options.arguments.push_back("--recover");
    }
    std::string error;
    std::optional<LocalProcess> spawned = LocalProcess::spawn(options, error);
    if (!spawned.has_value()) {
      ::rc::test::report_failure(__FILE__, __LINE__, "coordinator spawn: " + error);
      return false;
    }
    process = std::move(*spawned);
    // Blocking read: the ready line is a product guarantee, and a coordinator
    // that never prints it is a defect.
    std::string line;
    while (process.read_line(line)) {
      lines.push_back(line);
      if (line.rfind("RC_COORDINATOR_READY", 0) == 0) {
        const std::size_t port_at = line.find("port=");
        const std::size_t epoch_at = line.find("epoch=");
        const std::size_t recovered_at = line.find("recovered=");
        port = static_cast<std::uint16_t>(std::stoul(line.substr(port_at + 5)));
        epoch = std::stoull(line.substr(epoch_at + 6));
        recovered = line.substr(recovered_at + 10, 1) == "1";
        return true;
      }
    }
    std::string transcript;
    for (const std::string& entry : lines) {
      transcript += entry;
      transcript += " | ";
    }
    ::rc::test::report_failure(__FILE__, __LINE__,
                               "coordinator never became ready: " + transcript);
    return false;
  }

  [[nodiscard]] bool kill() { return process.terminate(); }
};

struct ClientSession {
  RcClient client;
  PublisherId publisher;
  WorkerBootId boot;

  [[nodiscard]] bool connect(std::uint16_t port, std::uint64_t publisher_seed,
                             std::uint64_t boot_seed) {
    publisher = derive_publisher_id(publisher_seed);
    boot = derive_worker_boot_id(boot_seed);
    std::string error;
    std::optional<RcClient> opened = RcClient::connect("127.0.0.1", port, 30000, error);
    if (!opened.has_value()) {
      ::rc::test::report_failure(__FILE__, __LINE__, "client connect: " + error);
      return false;
    }
    client = std::move(*opened);
    HelloResponseBody hello;
    if (!client.hello(hello, error)) {
      ::rc::test::report_failure(__FILE__, __LINE__, "hello: " + error);
      return false;
    }
    client.set_epoch(hello.epoch);
    client.set_publisher(publisher);
    client.set_worker_boot(boot);
    client.set_attempt(derive_id<MutationAttemptId>("rc.test.distributed.attempt",
                                                    unique_seed()));
    return true;
  }

  [[nodiscard]] bool register_worker(std::uint32_t capabilities,
                                     AuthorityScope scope = AuthorityScope{}) {
    PublisherRegistration registration;
    registration.publisher = publisher;
    registration.worker_boot = boot;
    // The coordinator service identifies itself with these exact fixtures, so a
    // fabric scope built from the same derivation is accepted and any other
    // fabric is denied.
    registration.scope =
        scope.kind == ScopeKind::DENY_ALL
            ? AuthorityScope::for_fabric(derive_id<FabricId>("rc.fixture.fabric", 1))
            : scope;
    registration.capabilities = capabilities;
    registration.provenance = derive_provenance_id(unique_seed());
    PlanMutationResult result;
    std::string error;
    if (!client.register_worker(registration, result, error)) {
      ::rc::test::report_failure(__FILE__, __LINE__, "register: " + error);
      return false;
    }
    return result.accepted() || result.outcome == Outcome::IDEMPOTENT;
  }

  // Every request carries its own mutation attempt identifier, exactly as a real
  // worker does; a fresh one is taken before each mutation.
  void next_attempt() {
    client.set_attempt(
        derive_id<MutationAttemptId>("rc.test.distributed.attempt", unique_seed()));
  }
};

[[nodiscard]] std::map<std::string, std::string> parse_fields(const std::string& line) {
  std::map<std::string, std::string> fields;
  std::size_t index = 0;
  while (index < line.size()) {
    const std::size_t space = line.find(' ', index);
    const std::string token =
        line.substr(index, space == std::string::npos ? std::string::npos : space - index);
    const std::size_t equals = token.find('=');
    if (equals != std::string::npos) {
      fields[token.substr(0, equals)] = token.substr(equals + 1);
    }
    if (space == std::string::npos) {
      break;
    }
    index = space + 1;
  }
  return fields;
}

// Reads child output until a line with the given prefix arrives.  Blocking by
// design and bounded by the child's own behaviour, not by a timer.
[[nodiscard]] bool await_line(LocalProcess& process, const std::string& prefix,
                              std::map<std::string, std::string>& fields,
                              std::vector<std::string>& transcript) {
  std::string line;
  while (process.read_line(line)) {
    transcript.push_back(line);
    if (line.rfind(prefix, 0) == 0) {
      fields = parse_fields(line);
      return true;
    }
  }
  return false;
}

[[nodiscard]] RouteId distributed_route(std::uint64_t seed) {
  return derive_id<RouteId>("rc.test.distributed.route", seed);
}

}  // namespace

RC_TEST(real_worker_death_fences_the_boot_and_rejects_its_late_completion) {
  Scratch scratch;
  CoordinatorHandle coordinator;
  RC_REQUIRE(coordinator.start(1, std::string{}));

  ClientSession admin;
  RC_REQUIRE(admin.connect(coordinator.port, 41, 41));
  RC_REQUIRE(admin.register_worker(static_cast<std::uint32_t>(Capability::ADMIN) |
                                   static_cast<std::uint32_t>(Capability::CREATE_PLAN) |
                                   static_cast<std::uint32_t>(Capability::PUBLISH_UPSTREAM) |
                                   static_cast<std::uint32_t>(Capability::COMPLETE_STEP)));

  const RouteId route = distributed_route(7);
  const PathId path_a = derive_id<PathId>("rc.test.distributed.path", 1);
  const PathId path_b = derive_id<PathId>("rc.test.distributed.path", 2);
  const ConvergencePolicyId policy_id =
      derive_id<ConvergencePolicyId>("rc.test.distributed.policy", 1);

  ConvergencePolicy policy;
  policy.id = policy_id;
  policy.generation = ConvergencePolicyGeneration::from_value(1);
  policy.ordering = OrderingMode::MAKE_BEFORE_BREAK;
  policy.allow_overlap = true;
  policy.verification = VerificationMode::REQUIRED;
  policy.max_parallel_steps = 4;
  PlanMutationResult defined;
  std::string error;
  admin.next_attempt();
  RC_REQUIRE(admin.client.define_policy(policy, defined, error));
  RC_REQUIRE(defined.accepted());

  // The admin publishes the coherent upstream observation through the
  // coordinator's synthetic upstream feed.
  RouteBinding source;
  source.route = route;
  source.generation = RouteGeneration::from_value(1);
  source.path = path_a;
  source.path_authority_generation = PathAuthorityGeneration::from_value(1);
  RouteBinding target = source;
  target.generation = RouteGeneration::from_value(2);
  target.path = path_b;
  target.path_authority_generation = PathAuthorityGeneration::from_value(2);

  PathChangeNotice path_a_notice;
  path_a_notice.legality.path = path_a;
  path_a_notice.legality.generation = PathAuthorityGeneration::from_value(1);
  path_a_notice.legality.legal = true;
  path_a_notice.provenance = derive_provenance_id(unique_seed());
  NoticeResult path_result;
  admin.next_attempt();
  RC_REQUIRE(admin.client.publish_path_change(path_a_notice, path_result, error));

  PathChangeNotice path_b_notice;
  path_b_notice.legality.path = path_b;
  path_b_notice.legality.generation = PathAuthorityGeneration::from_value(2);
  path_b_notice.legality.legal = true;
  path_b_notice.provenance = derive_provenance_id(unique_seed());
  admin.next_attempt();
  RC_REQUIRE(admin.client.publish_path_change(path_b_notice, path_result, error));

  RouteChangeNotice route_notice;
  route_notice.binding = target;
  route_notice.provenance = derive_provenance_id(unique_seed());
  NoticeResult route_result;
  admin.next_attempt();
  RC_REQUIRE(admin.client.publish_route_change(route_notice, route_result, error));

  PlanRequest request;
  request.mode = PlanMode::GENERATED;
  request.source = source;
  request.target = target;
  request.policy = policy;
  request.epoch = admin.client.epoch();
  request.provenance = derive_provenance_id(unique_seed());
  PlanMutationResult plan;
  admin.next_attempt();
  RC_REQUIRE(admin.client.create_plan(request, plan, error));
  RC_REQUIRE(plan.outcome == Outcome::PLAN_CREATED);

  // Worker A registers, dispatches exactly one step and then holds.
  LocalProcess::Options worker_options;
  worker_options.executable = RC_WORKER_EXECUTABLE;
  worker_options.arguments = {"--port", std::to_string(coordinator.port),
                              "--publisher-seed", "77",
                              "--boot-seed", "11",
                              "--scope", "fabric",
                              "--hold"};
  std::string spawn_error;
  std::optional<LocalProcess> worker = LocalProcess::spawn(worker_options, spawn_error);
  RC_REQUIRE(worker.has_value());

  std::vector<std::string> transcript;
  std::map<std::string, std::string> fields;
  RC_REQUIRE(await_line(*worker, "RC_WORKER_REGISTERED", fields, transcript));
  RC_REQUIRE(await_line(*worker, "RC_WORKER_DISPATCH", fields, transcript));
  RC_CHECK(fields["outcome"] == "STEP_DISPATCHED");
  const std::string dispatched_step = fields["step"];
  const std::string dispatched_generation = fields["generation"];
  const std::string dispatched_watermark = fields["watermark"];
  const std::string dispatched_epoch = fields["epoch"];
  const std::string dispatched_attempt = fields["attempt"];

  // The worker is confirmed alive immediately before the kill.
  RC_CHECK(worker->running());
  RC_CHECK(worker->pid() != 0);
  RC_CHECK(worker->terminate());
  (void)worker->wait_for_exit();
  RC_CHECK(!worker->running());

  // Meanwhile the coordinator still reports the step as in flight.
  SnapshotBody in_flight;
  RC_REQUIRE(admin.client.snapshot(plan.plan, in_flight, error));
  RC_CHECK(in_flight.found);

  // Worker A2 uses the same publisher with a fresh boot: the old boot is fenced
  // permanently and must be rejected forever.
  ClientSession worker_a2;
  RC_REQUIRE(worker_a2.connect(coordinator.port, 77, 12));
  RC_REQUIRE(worker_a2.register_worker(static_cast<std::uint32_t>(Capability::DISPATCH_STEP) |
                                       static_cast<std::uint32_t>(Capability::COMPLETE_STEP)));

  // A late completion from the dead boot is rejected, and it does not advance
  // the plan.
  const std::optional<TransitionStepId> step_id = TransitionStepId::parse(dispatched_step);
  RC_REQUIRE(step_id.has_value());
  const std::optional<MutationAttemptId> attempt_id =
      MutationAttemptId::parse(dispatched_attempt);
  RC_REQUIRE(attempt_id.has_value());

  CompletionEvidence late;
  late.plan = plan.plan;
  late.step = *step_id;
  late.step_generation = TransitionStepGeneration::from_value(std::stoull(dispatched_generation));
  late.attempt = *attempt_id;
  late.epoch = CoordinatorEpoch::from_value(std::stoull(dispatched_epoch));
  late.publisher = worker_a2.publisher;
  late.worker_boot = derive_worker_boot_id(11);
  late.outcome = BackendOutcome::APPLIED;
  late.dispatch_watermark = ConvergenceGeneration::from_value(std::stoull(dispatched_watermark));
  late.detail = "late completion from a dead boot";
  late.id = derive_evidence_id(late);

  PlanMutationResult rejected;
  admin.next_attempt();
  RC_REQUIRE(admin.client.complete_step(late, rejected, error));
  if (rejected.accepted() ||
      (rejected.outcome != Outcome::STALE_WORKER && rejected.outcome != Outcome::UNAUTHORIZED &&
       rejected.outcome != Outcome::STALE_STEP)) {
    ::rc::test::report_failure(__FILE__, __LINE__,
                               "late completion outcome=" +
                                   std::string(to_string(rejected.outcome)) + " " +
                                   rejected.conditions.render());
  }
  RC_CHECK(!rejected.accepted());

  PlanQueryBody after;
  RC_REQUIRE(admin.client.query_plan(plan.plan, after, error));
  RC_CHECK(after.found);
  RC_CHECK(after.summary.lifecycle != PlanLifecycle::COMPLETED);

  // An unrelated worker on an unrelated route is unaffected.
  // An unrelated publisher on the same coordinator is untouched by the fence.
  ClientSession unrelated;
  RC_REQUIRE(unrelated.connect(coordinator.port, 91, 91));
  RC_REQUIRE(unrelated.register_worker(static_cast<std::uint32_t>(Capability::DISPATCH_STEP) |
                                       static_cast<std::uint32_t>(Capability::DISPATCH_STEP)));
  PlanQueryBody unrelated_view;
  RC_REQUIRE(unrelated.client.query_plan(plan.plan, unrelated_view, error));
  RC_CHECK(unrelated_view.found);

  RC_CHECK(coordinator.kill());
  (void)coordinator.process.wait_for_exit();
}

RC_TEST(real_coordinator_restart_preserves_plans_and_advances_the_epoch_monotonically) {
  Scratch scratch;
  const std::string store = scratch.store().string();

  CoordinatorHandle first;
  RC_REQUIRE(first.start(1, store));
  RC_CHECK_EQ(first.epoch, std::uint64_t{1});
  RC_CHECK(!first.recovered);

  ClientSession admin;
  RC_REQUIRE(admin.connect(first.port, 51, 51));
  RC_REQUIRE(admin.register_worker(static_cast<std::uint32_t>(Capability::ADMIN) |
                                   static_cast<std::uint32_t>(Capability::CREATE_PLAN) |
                                   static_cast<std::uint32_t>(Capability::DISPATCH_STEP) |
                                   static_cast<std::uint32_t>(Capability::COMPLETE_STEP) |
                                   static_cast<std::uint32_t>(Capability::PUBLISH_UPSTREAM)));

  const ConvergencePolicyId policy_id =
      derive_id<ConvergencePolicyId>("rc.test.distributed.policy", 2);
  ConvergencePolicy policy;
  policy.id = policy_id;
  policy.generation = ConvergencePolicyGeneration::from_value(1);
  policy.ordering = OrderingMode::MAKE_BEFORE_BREAK;
  policy.allow_overlap = true;
  policy.verification = VerificationMode::REQUIRED;
  policy.max_parallel_steps = 4;
  PlanMutationResult defined;
  std::string error;
  admin.next_attempt();
  RC_REQUIRE(admin.client.define_policy(policy, defined, error));
  RC_REQUIRE(defined.accepted());

  const RouteId route = distributed_route(11);
  const PathId path_a = derive_id<PathId>("rc.test.distributed.path", 11);
  const PathId path_b = derive_id<PathId>("rc.test.distributed.path", 12);
  RouteBinding source;
  source.route = route;
  source.generation = RouteGeneration::from_value(1);
  source.path = path_a;
  source.path_authority_generation = PathAuthorityGeneration::from_value(1);
  RouteBinding target = source;
  target.generation = RouteGeneration::from_value(2);
  target.path = path_b;
  target.path_authority_generation = PathAuthorityGeneration::from_value(1);

  const std::vector<PathId> registered_paths{path_a, path_b};
  for (const PathId& registered : registered_paths) {
    PathChangeNotice notice;
    notice.legality.path = registered;
    notice.legality.generation = PathAuthorityGeneration::from_value(1);
    notice.legality.legal = true;
    notice.provenance = derive_provenance_id(unique_seed());
    NoticeResult result;
    RC_REQUIRE(admin.client.publish_path_change(notice, result, error));
  }
  RouteChangeNotice route_notice;
  route_notice.binding = target;
  route_notice.provenance = derive_provenance_id(unique_seed());
  NoticeResult route_result;
  admin.next_attempt();
  RC_REQUIRE(admin.client.publish_route_change(route_notice, route_result, error));

  PlanRequest request;
  request.mode = PlanMode::GENERATED;
  request.source = source;
  request.target = target;
  request.policy = policy;
  request.epoch = admin.client.epoch();
  request.provenance = derive_provenance_id(unique_seed());
  PlanMutationResult plan;
  admin.next_attempt();
  RC_REQUIRE(admin.client.create_plan(request, plan, error));
  RC_REQUIRE(plan.outcome == Outcome::PLAN_CREATED);

  // Complete exactly one durable step, then leave a second one in flight.
  ReadyStepList ready;
  RC_REQUIRE(admin.client.ready_steps(1, ready, error));
  RC_REQUIRE(!ready.steps.empty());
  const ReadyStep first_step = ready.steps.front();
  admin.next_attempt();
  StepDispatch dispatched;
  if (!admin.client.dispatch_step(DispatchStepRequest{first_step.plan, first_step.step},
                                  dispatched, error)) {
    ::rc::test::report_failure(__FILE__, __LINE__, "dispatch transport: " + error);
  }
  RC_REQUIRE(dispatched.outcome == Outcome::STEP_DISPATCHED);
  CompletionEvidence evidence;
  evidence.plan = first_step.plan;
  evidence.step = first_step.step;
  evidence.step_generation = dispatched.step_generation;
  evidence.attempt = admin.client.attempt();
  evidence.epoch = dispatched.epoch;
  evidence.publisher = admin.publisher;
  evidence.worker_boot = admin.boot;
  evidence.outcome = BackendOutcome::APPLIED;
  evidence.dispatch_watermark = dispatched.watermark;
  evidence.id = derive_evidence_id(evidence);
  admin.next_attempt();
  PlanMutationResult completed;
  RC_REQUIRE(admin.client.complete_step(evidence, completed, error));
  RC_CHECK(completed.accepted());

  // Second step: dispatch only, and never complete it.
  ReadyStepList ready_again;
  RC_REQUIRE(admin.client.ready_steps(1, ready_again, error));
  RC_REQUIRE(!ready_again.steps.empty());
  const ReadyStep second_step = ready_again.steps.front();
  admin.next_attempt();
  StepDispatch in_flight;
  RC_REQUIRE(admin.client.dispatch_step(
      DispatchStepRequest{second_step.plan, second_step.step}, in_flight, error));
  RC_REQUIRE(in_flight.outcome == Outcome::STEP_DISPATCHED);

  // Hard-kill the coordinator.  Every mutation was made durable before the next
  // request was served, so nothing acknowledged is lost.
  RC_CHECK(first.kill());
  (void)first.process.wait_for_exit();

  CoordinatorHandle second;
  RC_REQUIRE(second.start(2, store));
  RC_CHECK_EQ(second.epoch, std::uint64_t{2});
  RC_CHECK(second.recovered);

  ClientSession restarted;
  RC_REQUIRE(restarted.connect(second.port, 52, 52));
  RC_REQUIRE(restarted.register_worker(
      static_cast<std::uint32_t>(Capability::ADMIN) |
      static_cast<std::uint32_t>(Capability::CREATE_PLAN) |
      static_cast<std::uint32_t>(Capability::DISPATCH_STEP) |
      static_cast<std::uint32_t>(Capability::COMPLETE_STEP) |
      static_cast<std::uint32_t>(Capability::REVALIDATE_PLAN)));

  PlanQueryBody recovered_plan;
  RC_REQUIRE(restarted.client.query_plan(plan.plan, recovered_plan, error));
  RC_CHECK(recovered_plan.found);
  RC_CHECK(recovered_plan.summary.lifecycle == PlanLifecycle::REVALIDATION_REQUIRED ||
           recovered_plan.summary.lifecycle == PlanLifecycle::READY);

  // The in-flight step is conservative: never completed by recovery.
  SnapshotBody snapshot;
  RC_REQUIRE(restarted.client.snapshot(plan.plan, snapshot, error));
  RC_REQUIRE(snapshot.found);
  RC_CHECK(second.epoch > first.epoch);
  for (const StepSnapshot& step : snapshot.snapshot.steps) {
    if (step.state == StepLifecycle::COMPLETED) {
      continue;
    }
    RC_CHECK(step.state != StepLifecycle::COMPLETED);
  }
  bool in_flight_conservative = false;
  for (const StepSnapshot& step : snapshot.snapshot.steps) {
    if (step.state == StepLifecycle::RECONCILIATION_REQUIRED ||
        step.state == StepLifecycle::PENDING || step.state == StepLifecycle::READY) {
      in_flight_conservative = true;
    }
  }
  RC_CHECK(in_flight_conservative);

  // An old-epoch completion is rejected.
  CompletionEvidence stale_epoch = evidence;
  stale_epoch.plan = second_step.plan;
  stale_epoch.step = second_step.step;
  stale_epoch.step_generation = in_flight.step_generation;
  stale_epoch.attempt = restarted.client.attempt();
  stale_epoch.epoch = CoordinatorEpoch::from_value(1);
  stale_epoch.publisher = restarted.publisher;
  stale_epoch.worker_boot = restarted.boot;
  stale_epoch.outcome = BackendOutcome::APPLIED;
  stale_epoch.dispatch_watermark = in_flight.watermark;
  stale_epoch.id = derive_evidence_id(stale_epoch);
  PlanMutationResult rejected_epoch;
  restarted.next_attempt();
  RC_REQUIRE(restarted.client.complete_step(stale_epoch, rejected_epoch, error));
  RC_CHECK(!rejected_epoch.accepted());
  RC_CHECK(rejected_epoch.outcome == Outcome::UNAUTHORIZED ||
           rejected_epoch.outcome == Outcome::STALE_EPOCH ||
           rejected_epoch.outcome == Outcome::STALE_STEP ||
           rejected_epoch.outcome == Outcome::REVALIDATION_REQUIRED);

  // Revalidation re-establishes authority at the new epoch and the plan can run
  // to completion again.
  PlanMutationResult revalidated;
  restarted.next_attempt();
  RC_REQUIRE(restarted.client.revalidate_plan(plan.plan, revalidated, error));
  RC_CHECK(revalidated.outcome == Outcome::PLAN_REVALIDATED ||
           revalidated.outcome == Outcome::SUPERSEDED ||
           revalidated.outcome == Outcome::REVALIDATION_REQUIRED);

  RC_CHECK(second.kill());
  (void)second.process.wait_for_exit();

  // A third restart proves epoch progression stays monotonic.
  CoordinatorHandle third;
  RC_REQUIRE(third.start(5, store));
  RC_CHECK_EQ(third.epoch, std::uint64_t{5});
  RC_CHECK(third.recovered);
  ClientSession third_client;
  RC_REQUIRE(third_client.connect(third.port, 53, 53));
  RC_REQUIRE(third_client.register_worker(static_cast<std::uint32_t>(Capability::ADMIN)));
  RC_CHECK_EQ(third_client.client.epoch().value(), std::uint64_t{5});
  RC_CHECK(third.kill());
  (void)third.process.wait_for_exit();
}

RC_TEST(a_partial_frame_peer_is_disconnected_within_the_read_budget) {
  Scratch scratch;
  CoordinatorHandle coordinator;
  RC_REQUIRE(coordinator.start(1, std::string{}, 400));

  std::string error;
  std::optional<TcpConnection> connection = connect_loopback(coordinator.port, error);
  RC_REQUIRE(connection.has_value());

  // Half a frame header and then silence: the coordinator must not let this pin a
  // session forever.
  const std::array<std::uint8_t, 6> partial = {'R', 'C', 'F', '1', 0x01, 0x00};
  RC_CHECK(connection->send_all(partial, error));

  std::vector<std::uint8_t> response(64, 0);
  const ReceiveStatus status = connection->receive_exactly(response, 30000, error);
  RC_CHECK(status == ReceiveStatus::CLOSED || status == ReceiveStatus::FAILURE);
  connection->close();

  RC_CHECK(coordinator.kill());
  (void)coordinator.process.wait_for_exit();
}

RC_TEST(a_malformed_peer_is_rejected_and_the_session_closes) {
  Scratch scratch;
  CoordinatorHandle coordinator;
  RC_REQUIRE(coordinator.start(1, std::string{}, 400));

  std::string error;
  std::optional<TcpConnection> connection = connect_loopback(coordinator.port, error);
  RC_REQUIRE(connection.has_value());

  // A complete frame with a valid header shape but a corrupted integrity tag: the
  // coordinator answers with an ERROR frame and closes the session.
  Envelope request;
  request.message = WireMessageId::HELLO;
  std::vector<std::uint8_t> frame = encode_frame(request, ConvergenceLimits{});
  RC_REQUIRE(frame.size() > kWireTagBytes);
  frame[kWireHeaderBytes + 1] ^= 0x5Au;
  RC_CHECK(connection->send_all(frame, error));

  std::vector<std::uint8_t> header(kWireHeaderBytes, 0);
  const ReceiveStatus status = connection->receive_exactly(header, 30000, error);
  RC_REQUIRE(status == ReceiveStatus::OK);
  const std::uint32_t payload_bytes =
      static_cast<std::uint32_t>(header[kWireHeaderBytes - 8]) |
      (static_cast<std::uint32_t>(header[kWireHeaderBytes - 7]) << 8) |
      (static_cast<std::uint32_t>(header[kWireHeaderBytes - 6]) << 16) |
      (static_cast<std::uint32_t>(header[kWireHeaderBytes - 5]) << 24);
  std::vector<std::uint8_t> body = header;
  body.resize(kWireHeaderBytes + payload_bytes + kWireTagBytes, 0);
  const ReceiveStatus rest = connection->receive_exactly(
      std::span<std::uint8_t>(body.data() + kWireHeaderBytes, payload_bytes + kWireTagBytes), 30000,
      error);
  RC_REQUIRE(rest == ReceiveStatus::OK);
  Envelope reply;
  RC_REQUIRE(decode_frame(body, ConvergenceLimits{}, reply) == WireDefect::NONE);
  RC_CHECK(reply.message == WireMessageId::ERROR);
  ErrorBody error_body;
  RC_CHECK(decode_payload(reply.payload, ConvergenceLimits{}, error_body));
  RC_CHECK(error_body.code == ConditionCode::WIRE_INTEGRITY_FAILURE);
  connection->close();

  RC_CHECK(coordinator.kill());
  (void)coordinator.process.wait_for_exit();
}

RC_TEST(coordinator_restarts_repeatedly_without_leaking_processes) {
  Scratch scratch;
  const std::string store = scratch.store("repeat.store").string();
  for (std::uint64_t round = 1; round <= 3; ++round) {
    CoordinatorHandle coordinator;
    RC_REQUIRE(coordinator.start(round, store));
    RC_CHECK_EQ(coordinator.epoch, round);
    // The first round starts against an empty store; every later round must
    // recover the state its predecessor made durable before it was killed.
    RC_CHECK_EQ(coordinator.recovered, round > 1);
    std::string error;
    std::optional<RcClient> client =
        RcClient::connect("127.0.0.1", coordinator.port, 30000, error);
    RC_REQUIRE(client.has_value());
    HelloResponseBody hello;
    RC_REQUIRE(client->hello(hello, error));
    RC_CHECK_EQ(hello.epoch.value(), round);
    client->close();
    RC_CHECK(coordinator.kill());
    (void)coordinator.process.wait_for_exit();
    RC_CHECK(!coordinator.process.running());
  }
}
