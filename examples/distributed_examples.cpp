// Route Convergence distributed examples: real OS processes.
//
// The coordinator and the worker are started as real child processes of this
// example, observed through their stdout and killed with real process
// termination.  Nothing here is a thread-based substitute: worker death and
// coordinator restart are proven against the actual binaries, and the durable
// store is a real file whose path is derived from this process id.
//
// Each scenario prints exactly one deterministic "EXAMPLE <name> OK" line, every
// child process is terminated before the example exits, and a failed assertion
// exits non-zero immediately.

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <optional>
#include <process.h>
#include <string>
#include <string_view>
#include <vector>

#include "rc/client.hpp"
#include "rc/process.hpp"
#include "rc/rc.hpp"

// The build supplies the exact target paths of the real applications.  The
// fallbacks below keep this translation unit compilable on its own (for a
// syntax-only check); a real build always defines both.
#ifndef RC_COORDINATOR_EXECUTABLE
#define RC_COORDINATOR_EXECUTABLE "rc_coordinator"
#endif
#ifndef RC_WORKER_EXECUTABLE
#define RC_WORKER_EXECUTABLE "rc_worker"
#endif

using namespace rc;

namespace {

constexpr std::uint64_t kSupervisorPublisherSeed = 1;
constexpr std::uint64_t kSupervisorBootSeed = 1;
constexpr std::uint64_t kWorkerPublisherSeed = 7;
constexpr std::uint64_t kWorkerBootSeed = 11;
constexpr std::uint64_t kReplacementBootSeed = 12;
constexpr std::uint32_t kAllCapabilities =
    static_cast<std::uint32_t>(Capability::CREATE_PLAN) |
    static_cast<std::uint32_t>(Capability::DISPATCH_STEP) |
    static_cast<std::uint32_t>(Capability::COMPLETE_STEP) |
    static_cast<std::uint32_t>(Capability::REVALIDATE_PLAN) |
    static_cast<std::uint32_t>(Capability::ROLLBACK) |
    static_cast<std::uint32_t>(Capability::ADMIN) |
    static_cast<std::uint32_t>(Capability::PUBLISH_UPSTREAM);

#define RC_EXAMPLE_CHECK(condition)                                            \
  do {                                                                         \
    if (!(condition)) {                                                        \
      std::cout << "EXAMPLE " << kExample << " FAILED check=" #condition       \
                << " line=" << __LINE__ << "\n";                               \
      return 2;                                                                \
    }                                                                          \
  } while (false)

[[nodiscard]] int fail(std::string_view example, const std::string& detail) {
  std::cout << "EXAMPLE " << example << " FAILED detail=" << detail << "\n";
  return 2;
}

// --- child process supervision ----------------------------------------------

// A child process that is always terminated before this example exits, on every
// path including an early failure.
class ChildGuard {
 public:
  ChildGuard() = default;
  ChildGuard(const ChildGuard&) = delete;
  ChildGuard& operator=(const ChildGuard&) = delete;
  ChildGuard(ChildGuard&& other) noexcept = default;
  ChildGuard& operator=(ChildGuard&& other) noexcept = default;
  ~ChildGuard() { stop(); }

  void adopt(std::optional<LocalProcess> process) {
    stop();
    process_ = std::move(process);
  }

  void stop() {
    if (process_.has_value()) {
      (void)process_->terminate();
      process_.reset();
    }
  }

  [[nodiscard]] bool valid() const { return process_.has_value(); }
  [[nodiscard]] LocalProcess& process() { return *process_; }

 private:
  std::optional<LocalProcess> process_;
};

[[nodiscard]] std::optional<std::string_view> field_value(std::string_view line,
                                                          std::string_view key) {
  std::size_t index = 0;
  while (index < line.size()) {
    const std::size_t space = line.find(' ', index);
    const std::size_t end = space == std::string_view::npos ? line.size() : space;
    const std::string_view token = line.substr(index, end - index);
    if (token.size() > key.size() && token.compare(0, key.size(), key) == 0 &&
        token[key.size()] == '=') {
      return token.substr(key.size() + 1);
    }
    if (space == std::string_view::npos) {
      break;
    }
    index = space + 1;
  }
  return std::nullopt;
}

[[nodiscard]] bool parse_u64_field(std::string_view line, std::string_view key,
                                   std::uint64_t& value) {
  const std::optional<std::string_view> text = field_value(line, key);
  if (!text.has_value() || text->empty()) {
    return false;
  }
  std::uint64_t parsed = 0;
  for (const char character : *text) {
    if (character < '0' || character > '9') {
      return false;
    }
    parsed = (parsed * 10u) + static_cast<std::uint64_t>(character - '0');
  }
  value = parsed;
  return true;
}

// Reads child output until one line carries the expected prefix.  A line that
// reports a child-side error, or the end of the child's output, fails the wait
// instead of blocking.
[[nodiscard]] bool read_until(LocalProcess& process, std::string_view prefix,
                              std::string_view error_prefix, std::string& line,
                              std::string& detail) {
  for (;;) {
    if (!process.read_line(line)) {
      detail = "child output ended before '" + std::string(prefix) + "'";
      return false;
    }
    if (line.rfind(prefix, 0) == 0) {
      return true;
    }
    if (line.rfind(error_prefix, 0) == 0) {
      detail = line;
      return false;
    }
  }
}

struct CoordinatorInfo {
  std::uint16_t port = 0;
  std::uint64_t epoch = 0;
  bool recovered = false;
};

[[nodiscard]] bool start_coordinator(ChildGuard& coordinator, const std::filesystem::path& store,
                                     std::uint64_t epoch, bool recover, CoordinatorInfo& info,
                                     std::string& detail) {
  LocalProcess::Options options;
  options.executable = RC_COORDINATOR_EXECUTABLE;
  options.arguments = {"--port", "0", "--store", store.string(), "--epoch",
                       std::to_string(epoch)};
  if (recover) {
    options.arguments.push_back("--recover");
  }
  std::string error;
  std::optional<LocalProcess> process = LocalProcess::spawn(options, error);
  if (!process.has_value()) {
    detail = "coordinator could not be started: " + error;
    return false;
  }
  coordinator.adopt(std::move(process));

  std::string line;
  if (!read_until(coordinator.process(), "RC_COORDINATOR_READY ", "RC_COORDINATOR_ERROR", line,
                  detail)) {
    return false;
  }
  std::uint64_t port = 0;
  std::uint64_t reported_epoch = 0;
  std::uint64_t recovered = 0;
  if (!parse_u64_field(line, "port", port) || !parse_u64_field(line, "epoch", reported_epoch) ||
      !parse_u64_field(line, "recovered", recovered)) {
    detail = "malformed readiness line: " + line;
    return false;
  }
  info.port = static_cast<std::uint16_t>(port);
  info.epoch = reported_epoch;
  info.recovered = recovered == 1;
  return true;
}

// --- coordinator session ----------------------------------------------------

// The coordinator service is configured with the deterministic fixture fabric
// identity (rc::app::fabric_for(1)), and rc_worker registers under a FABRIC scope
// over exactly that identity.  A ROUTE scope is not enough here: defining a policy
// is authorized against an empty route, which only a fabric or namespace scope
// covers.
[[nodiscard]] AuthorityScope coordinator_scope() {
  return AuthorityScope::for_fabric(derive_id<FabricId>("rc.fixture.fabric", 1));
}

struct Session {
  RcClient client;
  HelloResponseBody hello;
  RouteId route;
  std::uint64_t attempt_seed = 1;

  [[nodiscard]] MutationAttemptId next_attempt() {
    return derive_id<MutationAttemptId>("rc.examples.attempt", attempt_seed++);
  }
};

[[nodiscard]] bool open_session(std::uint16_t port, std::uint64_t publisher_seed,
                                std::uint64_t boot_seed, Session& session, std::string& detail) {
  std::string error;
  std::optional<RcClient> client = RcClient::connect("127.0.0.1", port, 30000, error);
  if (!client.has_value()) {
    detail = "client could not connect: " + error;
    return false;
  }
  if (!client->hello(session.hello, error)) {
    detail = "hello failed: " + error;
    return false;
  }
  const PublisherId publisher = derive_publisher_id(publisher_seed);
  const WorkerBootId boot = derive_worker_boot_id(boot_seed);
  client->set_epoch(session.hello.epoch);
  client->set_publisher(publisher);
  client->set_worker_boot(boot);
  client->set_scope(coordinator_scope());
  client->set_attempt(session.next_attempt());

  PublisherRegistration registration;
  registration.publisher = publisher;
  registration.worker_boot = boot;
  registration.scope = coordinator_scope();
  registration.capabilities = kAllCapabilities;
  registration.provenance = derive_id<ProvenanceId>("rc.examples.provenance", boot_seed);
  PlanMutationResult registered;
  if (!client->register_worker(registration, registered, error)) {
    detail = "register_worker failed: " + error;
    return false;
  }
  if (!registered.accepted()) {
    detail = std::string("registration refused: ") + std::string(to_string(registered.outcome));
    return false;
  }
  session.client = std::move(*client);
  return true;
}

[[nodiscard]] bool publish_route(Session& session, const RouteBinding& binding,
                                 std::uint64_t provenance_seed, std::string& detail) {
  RouteChangeNotice notice;
  notice.binding = binding;
  notice.provenance = derive_id<ProvenanceId>("rc.examples.provenance", provenance_seed);
  NoticeResult result;
  std::string error;
  session.client.set_attempt(session.next_attempt());
  if (!session.client.publish_route_change(notice, result, error)) {
    detail = "publish_route_change failed: " + error;
    return false;
  }
  if (!result.accepted()) {
    detail = std::string("route notice refused: ") + std::string(to_string(result.outcome));
    return false;
  }
  return true;
}

[[nodiscard]] bool publish_path(Session& session, const PathLegality& legality,
                                std::uint64_t provenance_seed, std::string& detail) {
  PathChangeNotice notice;
  notice.legality = legality;
  notice.provenance = derive_id<ProvenanceId>("rc.examples.provenance", provenance_seed);
  NoticeResult result;
  std::string error;
  session.client.set_attempt(session.next_attempt());
  if (!session.client.publish_path_change(notice, result, error)) {
    detail = "publish_path_change failed: " + error;
    return false;
  }
  if (!result.accepted()) {
    detail = std::string("path notice refused: ") + std::string(to_string(result.outcome));
    return false;
  }
  return true;
}

[[nodiscard]] PathLegality legality_of(const PathId& path, std::uint64_t generation, bool legal) {
  PathLegality legality;
  legality.path = path;
  legality.generation = PathAuthorityGeneration::from_value(generation);
  legality.legal = legal;
  return legality;
}

// --- shared scenario setup --------------------------------------------------

struct ScenarioData {
  RouteBinding source;
  RouteBinding target;
  ConvergencePolicy policy;
  ConvergencePlanId plan;
};

// One coordinator, one transition and one durable plan.  Route Fabric publishes
// generation 2 as the authoritative binding, so the plan is created against the
// older source generation, which the caller declares historical.
[[nodiscard]] bool prepare_scenario(std::uint16_t port, std::uint64_t publisher_seed,
                                    std::uint64_t boot_seed, const RouteId& route,
                                    const PathId& source_path, const PathId& target_path,
                                    Session& session, ScenarioData& data, std::string& detail) {
  session.route = route;
  if (!open_session(port, publisher_seed, boot_seed, session, detail)) {
    return false;
  }
  data.policy.id = derive_id<ConvergencePolicyId>("rc.examples.policy", 1);
  data.policy.generation = ConvergencePolicyGeneration::from_value(1);
  data.policy.ordering = OrderingMode::MAKE_BEFORE_BREAK;
  data.policy.verification = VerificationMode::REQUIRED;
  data.policy.allow_overlap = true;
  data.policy.max_parallel_steps = 4;
  data.policy.max_retries_per_step = 2;

  PlanMutationResult defined;
  std::string error;
  session.client.set_attempt(session.next_attempt());
  if (!session.client.define_policy(data.policy, defined, error)) {
    detail = "define_policy failed: " + error;
    return false;
  }
  if (!defined.accepted()) {
    detail = std::string("policy refused: ") + std::string(to_string(defined.outcome));
    return false;
  }

  data.source = make_route_binding(route, RouteGeneration::from_value(1), source_path,
                                   PathAuthorityGeneration::from_value(1));
  data.target = make_route_binding(route, RouteGeneration::from_value(2), target_path,
                                   PathAuthorityGeneration::from_value(1));
  if (!publish_route(session, data.target, 1, detail)) {
    return false;
  }
  if (!publish_path(session, legality_of(source_path, 1, true), 2, detail)) {
    return false;
  }
  if (!publish_path(session, legality_of(target_path, 1, true), 3, detail)) {
    return false;
  }

  PlanRequest request;
  request.mode = PlanMode::GENERATED;
  request.source = data.source;
  request.target = data.target;
  request.policy = data.policy;
  request.epoch = session.client.epoch();
  request.provenance = derive_id<ProvenanceId>("rc.examples.provenance", 4);
  request.accept_historical_source = true;
  PlanMutationResult created;
  session.client.set_attempt(session.next_attempt());
  if (!session.client.create_plan(request, created, error)) {
    detail = "create_plan failed: " + error;
    return false;
  }
  if (created.outcome != Outcome::PLAN_CREATED) {
    detail = std::string("plan not created: ") + std::string(to_string(created.outcome));
    return false;
  }
  data.plan = created.plan;
  return true;
}

// --- scenario 1: worker death ----------------------------------------------

int example_worker_death(const std::filesystem::path& directory) {
  constexpr std::string_view kExample = "distributed_worker_death";
  const RouteId route = derive_id<RouteId>("rc.examples.route", 1);
  const PathId source_path = derive_id<PathId>("rc.examples.path", 1);
  const PathId target_path = derive_id<PathId>("rc.examples.path", 2);
  const std::filesystem::path store = directory / "worker_death.store";

  ChildGuard coordinator;
  CoordinatorInfo info;
  std::string detail;
  if (!start_coordinator(coordinator, store, 1, false, info, detail)) {
    return fail(kExample, detail);
  }
  Session session;
  ScenarioData data;
  if (!prepare_scenario(info.port, kSupervisorPublisherSeed, kSupervisorBootSeed, route,
                        source_path, target_path, session, data, detail)) {
    return fail(kExample, detail);
  }
  RC_EXAMPLE_CHECK(info.epoch == std::uint64_t{1});

  // The worker registers, dispatches the first ready step of the plan and then
  // holds that work item, exactly like a worker that is executing a transition.
  LocalProcess::Options worker_options;
  worker_options.executable = RC_WORKER_EXECUTABLE;
  worker_options.arguments = {"--port",           std::to_string(info.port),
                              "--publisher-seed", std::to_string(kWorkerPublisherSeed),
                              "--boot-seed",      std::to_string(kWorkerBootSeed),
                              "--max-steps",      "1",
                              "--hold"};
  std::string error;
  std::optional<LocalProcess> worker = LocalProcess::spawn(worker_options, error);
  if (!worker.has_value()) {
    return fail(kExample, "worker could not be started: " + error);
  }
  ChildGuard worker_guard;
  worker_guard.adopt(std::move(worker));

  std::string dispatch_line;
  if (!read_until(worker_guard.process(), "RC_WORKER_DISPATCH ", "RC_WORKER_ERROR", dispatch_line,
                  detail)) {
    return fail(kExample, detail);
  }
  const std::optional<std::string_view> plan_text = field_value(dispatch_line, "plan");
  const std::optional<std::string_view> step_text = field_value(dispatch_line, "step");
  std::uint64_t step_generation = 0;
  std::uint64_t dispatch_watermark = 0;
  if (!plan_text.has_value() || !step_text.has_value() ||
      !parse_u64_field(dispatch_line, "generation", step_generation) ||
      !parse_u64_field(dispatch_line, "watermark", dispatch_watermark)) {
    return fail(kExample, "malformed dispatch line: " + dispatch_line);
  }
  const std::optional<ConvergencePlanId> dispatched_plan = ConvergencePlanId::parse(*plan_text);
  const std::optional<TransitionStepId> dispatched_step = TransitionStepId::parse(*step_text);
  RC_EXAMPLE_CHECK(dispatched_plan.has_value());
  RC_EXAMPLE_CHECK(dispatched_step.has_value());
  RC_EXAMPLE_CHECK(*dispatched_plan == data.plan);

  // Real process death: the worker is killed while its work item is in flight.
  worker_guard.stop();
  RC_EXAMPLE_CHECK(!worker_guard.valid());

  // A fresh process is a fresh WorkerBootId.  The replacement worker registers
  // under the same publisher, which fences the dead boot permanently.
  LocalProcess::Options replacement_options;
  replacement_options.executable = RC_WORKER_EXECUTABLE;
  replacement_options.arguments = {"--port",           std::to_string(info.port),
                                   "--publisher-seed", std::to_string(kWorkerPublisherSeed),
                                   "--boot-seed",      std::to_string(kReplacementBootSeed),
                                   "--max-steps",      "1"};
  std::optional<LocalProcess> replacement = LocalProcess::spawn(replacement_options, error);
  if (!replacement.has_value()) {
    return fail(kExample, "replacement worker could not be started: " + error);
  }
  ChildGuard replacement_guard;
  replacement_guard.adopt(std::move(replacement));
  std::string exit_line;
  if (!read_until(replacement_guard.process(), "RC_WORKER_EXIT ", "RC_WORKER_ERROR", exit_line,
                  detail)) {
    return fail(kExample, detail);
  }
  std::uint64_t replacement_code = 0;
  RC_EXAMPLE_CHECK(parse_u64_field(exit_line, "code", replacement_code));
  RC_EXAMPLE_CHECK(replacement_code == std::uint64_t{0});
  replacement_guard.stop();

  // The in-flight work of the dead boot is conservative: it is stale, never
  // completed, and the plan must be revalidated before anything else happens.
  PlanQueryBody query;
  RC_EXAMPLE_CHECK(session.client.query_plan(data.plan, query, error));
  RC_EXAMPLE_CHECK(query.found);
  RC_EXAMPLE_CHECK(query.summary.lifecycle == PlanLifecycle::REVALIDATION_REQUIRED);
  RC_EXAMPLE_CHECK(query.summary.completed_steps == 0u);
  SnapshotBody snapshot;
  RC_EXAMPLE_CHECK(session.client.snapshot(data.plan, snapshot, error));
  RC_EXAMPLE_CHECK(snapshot.found);
  bool found_stale_step = false;
  for (const StepSnapshot& step : snapshot.snapshot.steps) {
    if (step.id == *dispatched_step) {
      found_stale_step = true;
      RC_EXAMPLE_CHECK(step.state == StepLifecycle::STALE);
    }
  }
  RC_EXAMPLE_CHECK(found_stale_step);

  // A late completion presented for the dead boot is refused.  rc_worker binds
  // its first work item to an attempt derived from its boot seed.
  CompletionEvidence evidence;
  evidence.plan = *dispatched_plan;
  evidence.step = *dispatched_step;
  evidence.step_generation = TransitionStepGeneration::from_value(step_generation);
  evidence.attempt = derive_id<MutationAttemptId>("rc.fixture.attempt",
                                                  kWorkerBootSeed * 1000003ull + 1ull);
  evidence.epoch = session.hello.epoch;
  evidence.publisher = derive_publisher_id(kWorkerPublisherSeed);
  evidence.worker_boot = derive_worker_boot_id(kWorkerBootSeed);
  evidence.outcome = BackendOutcome::APPLIED;
  evidence.dispatch_watermark = ConvergenceGeneration::from_value(dispatch_watermark);
  evidence.id = derive_evidence_id(evidence);
  PlanMutationResult late;
  session.client.set_attempt(session.next_attempt());
  const bool answered = session.client.complete_step(evidence, late, error);
  RC_EXAMPLE_CHECK(!answered || !late.accepted());
  if (answered) {
    RC_EXAMPLE_CHECK(late.outcome == Outcome::STALE_STEP);
  }

  // Nothing advanced: the step is still conservative and no step ever completed.
  PlanQueryBody after;
  RC_EXAMPLE_CHECK(session.client.query_plan(data.plan, after, error));
  RC_EXAMPLE_CHECK(after.summary.completed_steps == 0u);
  RC_EXAMPLE_CHECK(after.summary.lifecycle == PlanLifecycle::REVALIDATION_REQUIRED);
  SnapshotBody after_snapshot;
  RC_EXAMPLE_CHECK(session.client.snapshot(data.plan, after_snapshot, error));
  for (const StepSnapshot& step : after_snapshot.snapshot.steps) {
    if (step.id == *dispatched_step) {
      RC_EXAMPLE_CHECK(step.state == StepLifecycle::STALE);
    }
  }

  // Every child process is killed before the scenario reports success.
  worker_guard.stop();
  coordinator.stop();
  std::cout << "EXAMPLE " << kExample << " OK\n";
  return 0;
}

// --- scenario 2: coordinator restart ---------------------------------------

int example_coordinator_restart(const std::filesystem::path& directory) {
  constexpr std::string_view kExample = "distributed_coordinator_restart";
  const RouteId route = derive_id<RouteId>("rc.examples.route", 2);
  const PathId source_path = derive_id<PathId>("rc.examples.path", 11);
  const PathId target_path = derive_id<PathId>("rc.examples.path", 12);
  const std::filesystem::path store = directory / "coordinator_restart.store";

  ConvergencePlanId plan;
  TransitionStepId dispatched_step;
  std::uint64_t step_generation = 0;
  std::uint64_t dispatch_watermark = 0;
  CoordinatorEpoch old_epoch;
  {
    ChildGuard coordinator;
    CoordinatorInfo info;
    std::string detail;
    if (!start_coordinator(coordinator, store, 1, false, info, detail)) {
      return fail(kExample, detail);
    }
    Session session;
    ScenarioData data;
    if (!prepare_scenario(info.port, kSupervisorPublisherSeed, kSupervisorBootSeed, route,
                          source_path, target_path, session, data, detail)) {
      return fail(kExample, detail);
    }
    // The first step is dispatched, so the durable store holds in-flight work.
    ReadyStepList ready;
    std::string error;
    if (!session.client.ready_steps(1, ready, error)) {
      return fail(kExample, "ready_steps failed: " + error);
    }
    if (ready.steps.empty()) {
      return fail(kExample, "no ready step was offered for the durable plan");
    }
    DispatchStepRequest dispatch_request;
    dispatch_request.plan = ready.steps.front().plan;
    dispatch_request.step = ready.steps.front().step;
    StepDispatch dispatch;
    session.client.set_attempt(session.next_attempt());
    if (!session.client.dispatch_step(dispatch_request, dispatch, error)) {
      return fail(kExample, "dispatch_step failed: " + error);
    }
    if (dispatch.outcome != Outcome::STEP_DISPATCHED) {
      return fail(kExample, std::string("step not dispatched: ") +
                                std::string(to_string(dispatch.outcome)));
    }
    plan = dispatch.plan;
    dispatched_step = dispatch.step;
    step_generation = dispatch.step_generation.value();
    dispatch_watermark = dispatch.watermark.value();
    old_epoch = session.hello.epoch;

    // Hard kill: no unwinding, no final save, no farewell.  The acknowledgement
    // of the dispatch was already durable when it was sent.
    coordinator.stop();
    RC_EXAMPLE_CHECK(!coordinator.valid());
  }

  // Restart against the same store at a higher epoch and recover.
  ChildGuard restarted;
  CoordinatorInfo recovered_info;
  std::string detail;
  if (!start_coordinator(restarted, store, 2, true, recovered_info, detail)) {
    return fail(kExample, detail);
  }
  RC_EXAMPLE_CHECK(recovered_info.recovered);
  RC_EXAMPLE_CHECK(recovered_info.epoch == std::uint64_t{2});

  Session session;
  session.route = route;
  if (!open_session(recovered_info.port, kSupervisorPublisherSeed, kSupervisorBootSeed, session,
                    detail)) {
    return fail(kExample, detail);
  }
  std::string error;
  RC_EXAMPLE_CHECK(session.hello.epoch == CoordinatorEpoch::from_value(2));

  // The durable plan survived the kill, and its in-flight work is conservative:
  // a dispatched step is recovered for reconciliation, never as completed work.
  PlanQueryBody query;
  RC_EXAMPLE_CHECK(session.client.query_plan(plan, query, error));
  RC_EXAMPLE_CHECK(query.found);
  RC_EXAMPLE_CHECK(query.summary.lifecycle == PlanLifecycle::REVALIDATION_REQUIRED);
  RC_EXAMPLE_CHECK(query.summary.completed_steps == 0u);
  SnapshotBody snapshot;
  RC_EXAMPLE_CHECK(session.client.snapshot(plan, snapshot, error));
  RC_EXAMPLE_CHECK(snapshot.found);
  bool recovered_conservatively = false;
  for (const StepSnapshot& step : snapshot.snapshot.steps) {
    if (step.id == dispatched_step) {
      recovered_conservatively = true;
      RC_EXAMPLE_CHECK(step.state == StepLifecycle::RECONCILIATION_REQUIRED);
    }
  }
  RC_EXAMPLE_CHECK(recovered_conservatively);

  // A completion presented under the old epoch is refused, and it advances
  // nothing.
  CompletionEvidence evidence;
  evidence.plan = plan;
  evidence.step = dispatched_step;
  evidence.step_generation = TransitionStepGeneration::from_value(step_generation);
  evidence.attempt = derive_id<MutationAttemptId>("rc.examples.attempt", 900);
  evidence.epoch = old_epoch;
  evidence.publisher = derive_publisher_id(kSupervisorPublisherSeed);
  evidence.worker_boot = derive_worker_boot_id(kSupervisorBootSeed);
  evidence.outcome = BackendOutcome::APPLIED;
  evidence.dispatch_watermark = ConvergenceGeneration::from_value(dispatch_watermark);
  evidence.id = derive_evidence_id(evidence);
  session.client.set_epoch(old_epoch);
  session.client.set_attempt(session.next_attempt());
  PlanMutationResult stale;
  const bool answered = session.client.complete_step(evidence, stale, error);
  RC_EXAMPLE_CHECK(!answered || !stale.accepted());

  session.client.set_epoch(session.hello.epoch);
  PlanQueryBody after;
  RC_EXAMPLE_CHECK(session.client.query_plan(plan, after, error));
  RC_EXAMPLE_CHECK(after.found);
  RC_EXAMPLE_CHECK(after.summary.completed_steps == 0u);
  RC_EXAMPLE_CHECK(after.summary.lifecycle == PlanLifecycle::REVALIDATION_REQUIRED);

  restarted.stop();
  std::cout << "EXAMPLE " << kExample << " OK\n";
  return 0;
}

[[nodiscard]] std::filesystem::path make_run_directory() {
  std::error_code error;
  const std::filesystem::path base = std::filesystem::temp_directory_path(error);
  if (error) {
    return {};
  }
  const std::filesystem::path directory =
      base / ("rc_examples_distributed_" + std::to_string(static_cast<unsigned long>(_getpid())));
  std::filesystem::remove_all(directory, error);
  error.clear();
  std::filesystem::create_directories(directory, error);
  if (error) {
    return {};
  }
  return directory;
}

}  // namespace

int main() {
  const std::filesystem::path directory = make_run_directory();
  if (directory.empty()) {
    std::cout << "EXAMPLE distributed FAILED detail=temporary directory is unavailable\n";
    return 2;
  }
  int status = example_worker_death(directory);
  if (status == 0) {
    status = example_coordinator_restart(directory);
  }
  std::error_code error;
  std::filesystem::remove_all(directory, error);
  return status;
}
