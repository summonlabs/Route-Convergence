// Route Convergence benchmarks.
//
// Only COMPLETED operations are measured: an operation that did not succeed ends
// the benchmark with a non-zero exit status instead of contributing a
// meaningless timing sample.  Timings use std::chrono::steady_clock, there are no
// sleeps and no retries, and the temp store path is derived from this process id.
//
// The plan population benchmark is labelled SYNTHETIC on purpose: it is a
// control-plane population of plan identities measured against
// rc::SyntheticUpstream, and it is not a physical convergence measurement.

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <process.h>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "rc/rc.hpp"

namespace {

using namespace rc;

constexpr std::uint32_t kAllCapabilities =
    static_cast<std::uint32_t>(Capability::CREATE_PLAN) |
    static_cast<std::uint32_t>(Capability::DISPATCH_STEP) |
    static_cast<std::uint32_t>(Capability::COMPLETE_STEP) |
    static_cast<std::uint32_t>(Capability::REVALIDATE_PLAN) |
    static_cast<std::uint32_t>(Capability::ROLLBACK) |
    static_cast<std::uint32_t>(Capability::ADMIN) |
    static_cast<std::uint32_t>(Capability::PUBLISH_UPSTREAM);

[[nodiscard]] GovernorOptions bench_options() {
  GovernorOptions options;
  options.initial_epoch = CoordinatorEpoch::from_value(1);
  options.fabric = derive_id<FabricId>("rc.bench.fabric", 1);
  options.routing_namespace = derive_id<RoutingNamespaceId>("rc.bench.namespace", 1);
  return options;
}

// One isolated governor with its own synthetic observation source.  The
// administrator is registered and the deterministic benchmark policy is defined
// unless the caller needs a governor that is still empty (a durable load target
// must hold no plans and no policies).
class BenchRig {
 public:
  explicit BenchRig(bool configure = true)
      : upstream_(CoordinatorEpoch::from_value(1)),
        governor_(upstream_, upstream_, upstream_, bench_options()),
        policy_(bench_policy()) {
    if (configure) {
      const PlanMutationResult registered = register_administrator();
      const PlanMutationResult defined = governor_.define_policy(policy_, authority(1));
      ready_ = registered.accepted() && defined.accepted();
    }
  }

  BenchRig(const BenchRig&) = delete;
  BenchRig& operator=(const BenchRig&) = delete;

  [[nodiscard]] bool ready() const { return ready_; }
  [[nodiscard]] SyntheticUpstream& upstream() { return upstream_; }
  [[nodiscard]] ConvergenceGovernor& governor() { return governor_; }
  [[nodiscard]] const ConvergencePolicy& policy() const { return policy_; }

  // Every request carries its own mutation attempt identifier, exactly as a real
  // worker does; the seed selects a family and the counter makes each request
  // inside it distinct.
  [[nodiscard]] AuthorityContext authority(std::uint64_t attempt_seed) {
    AuthorityContext context;
    context.epoch = governor_.epoch();
    context.publisher = publisher_;
    context.worker_boot = boot_;
    context.attempt = derive_id<MutationAttemptId>(
        "rc.bench.attempt", (attempt_seed * 4096ull) + attempt_counter_++);
    return context;
  }

  void set_path(const PathId& path, std::uint64_t generation, bool legal) {
    PathLegality legality;
    legality.path = path;
    legality.generation = PathAuthorityGeneration::from_value(generation);
    legality.legal = legal;
    upstream_.set_path(legality);
  }

  // Publishes the exact target binding and both path legalities, then creates one
  // generated plan for the transition.
  [[nodiscard]] PlanMutationResult create_transition(const RouteId& route,
                                                     const PathId& source_path,
                                                     const PathId& target_path,
                                                     std::uint64_t attempt_seed) {
    const RouteBinding source =
        make_route_binding(route, RouteGeneration::from_value(1), source_path,
                           PathAuthorityGeneration::from_value(1));
    const RouteBinding target =
        make_route_binding(route, RouteGeneration::from_value(2), target_path,
                           PathAuthorityGeneration::from_value(1));
    upstream_.set_route(target);
    set_path(source_path, 1, true);
    set_path(target_path, 1, true);
    PlanRequest request;
    request.mode = PlanMode::GENERATED;
    request.source = source;
    request.target = target;
    request.policy = policy_;
    request.epoch = governor_.epoch();
    request.provenance = derive_id<ProvenanceId>("rc.bench.provenance", attempt_seed);
    request.accept_historical_source = true;
    return governor_.create_plan(request, authority(attempt_seed));
  }

 private:
  [[nodiscard]] static ConvergencePolicy bench_policy() {
    ConvergencePolicy policy;
    policy.id = derive_id<ConvergencePolicyId>("rc.bench.policy", 1);
    policy.generation = ConvergencePolicyGeneration::from_value(1);
    policy.ordering = OrderingMode::MAKE_BEFORE_BREAK;
    policy.verification = VerificationMode::REQUIRED;
    policy.allow_overlap = true;
    policy.max_parallel_steps = 4;
    policy.max_retries_per_step = 2;
    return policy;
  }

  [[nodiscard]] PlanMutationResult register_administrator() {
    PublisherRegistration registration;
    registration.publisher = publisher_;
    registration.worker_boot = boot_;
    registration.scope = AuthorityScope::for_fabric(derive_id<FabricId>("rc.bench.fabric", 1));
    registration.capabilities = kAllCapabilities;
    registration.provenance = derive_id<ProvenanceId>("rc.bench.provenance", 2);
    return governor_.register_worker(registration, authority(2));
  }

  SyntheticUpstream upstream_;
  ConvergenceGovernor governor_;
  ConvergencePolicy policy_;
  std::uint64_t attempt_counter_ = 0;
  PublisherId publisher_ = derive_id<PublisherId>("rc.bench.publisher", 1);
  WorkerBootId boot_ = derive_id<WorkerBootId>("rc.bench.boot", 1);
  bool ready_ = false;
};

[[nodiscard]] std::string format_fixed(double value, int precision) {
  std::ostringstream stream;
  stream << std::fixed << std::setprecision(precision) << value;
  return stream.str();
}

void report(std::string_view name, std::uint64_t operations,
            std::chrono::steady_clock::duration elapsed) {
  const double nanoseconds = std::chrono::duration<double, std::nano>(elapsed).count();
  const double per_operation =
      operations == 0 ? 0.0 : nanoseconds / static_cast<double>(operations);
  std::cout << "bench " << name << " ops=" << operations
            << " total_ms=" << format_fixed(nanoseconds / 1000000.0, 3)
            << " ns_per_op=" << format_fixed(per_operation, 1) << "\n";
}

#define RC_BENCH_REQUIRE(condition)                                                     \
  do {                                                                                  \
    if (!(condition)) {                                                                 \
      std::cout << "bench " << kBench << " FAILED check=" #condition                    \
                << " line=" << __LINE__ << "\n";                                        \
      return false;                                                                     \
    }                                                                                   \
  } while (false)

constexpr std::uint64_t kPlanCreationOperations = 512;
constexpr std::uint64_t kGraphOperations = 20000;
constexpr std::uint64_t kQueryOperations = 20000;
constexpr std::uint64_t kCompletionOperations = 256;
constexpr std::uint64_t kSharedPathPlans = 256;
constexpr std::uint64_t kSnapshotOperations = 5000;
constexpr std::uint64_t kDigestOperations = 20000;
constexpr std::uint64_t kSaveOperations = 64;
constexpr std::uint64_t kLoadOperations = 16;
constexpr std::uint64_t kPopulationOperations = 100000;
constexpr std::uint64_t kPersistencePlans = 32;

// --- plan creation ----------------------------------------------------------

bool bench_plan_creation() {
  constexpr std::string_view kBench = "plan_creation";
  BenchRig rig;
  RC_BENCH_REQUIRE(rig.ready());
  const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
  for (std::uint64_t index = 0; index < kPlanCreationOperations; ++index) {
    const PlanMutationResult created =
        rig.create_transition(derive_id<RouteId>("rc.bench.creation.route", index),
                              derive_id<PathId>("rc.bench.creation.source", index),
                              derive_id<PathId>("rc.bench.creation.target", index), index + 1);
    RC_BENCH_REQUIRE(created.outcome == Outcome::PLAN_CREATED);
  }
  const std::chrono::steady_clock::duration elapsed = std::chrono::steady_clock::now() - start;
  RC_BENCH_REQUIRE(rig.governor().plan_count() == kPlanCreationOperations);
  report(kBench, kPlanCreationOperations, elapsed);
  return true;
}

// --- dependency graph validation -------------------------------------------

bool bench_dependency_graph_validation() {
  constexpr std::string_view kBench = "dependency_graph_validation";
  BenchRig rig;
  RC_BENCH_REQUIRE(rig.ready());
  const RouteId route = derive_id<RouteId>("rc.bench.sample.route", 1);
  const RouteBinding source = make_route_binding(route, RouteGeneration::from_value(1),
                                                 derive_id<PathId>("rc.bench.sample.source", 1),
                                                 PathAuthorityGeneration::from_value(1));
  const RouteBinding target = make_route_binding(route, RouteGeneration::from_value(2),
                                                 derive_id<PathId>("rc.bench.sample.target", 1),
                                                 PathAuthorityGeneration::from_value(1));
  std::string reason;
  const std::optional<std::vector<StepSpec>> steps =
      generate_steps(source, target, rig.policy(), rig.governor().limits(), reason);
  RC_BENCH_REQUIRE(steps.has_value());
  RC_BENCH_REQUIRE(!steps->empty());
  const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
  for (std::uint64_t index = 0; index < kGraphOperations; ++index) {
    const GraphValidation validation =
        validate_dependency_graph(*steps, rig.governor().limits());
    RC_BENCH_REQUIRE(validation.ok);
  }
  const std::chrono::steady_clock::duration elapsed = std::chrono::steady_clock::now() - start;
  report(kBench, kGraphOperations, elapsed);
  return true;
}

// --- canonical topological ordering ----------------------------------------

bool bench_canonical_topological_order() {
  constexpr std::string_view kBench = "canonical_topological_order";
  BenchRig rig;
  RC_BENCH_REQUIRE(rig.ready());
  const RouteId route = derive_id<RouteId>("rc.bench.sample.route", 1);
  const RouteBinding source = make_route_binding(route, RouteGeneration::from_value(1),
                                                 derive_id<PathId>("rc.bench.sample.source", 1),
                                                 PathAuthorityGeneration::from_value(1));
  const RouteBinding target = make_route_binding(route, RouteGeneration::from_value(2),
                                                 derive_id<PathId>("rc.bench.sample.target", 1),
                                                 PathAuthorityGeneration::from_value(1));
  std::string reason;
  const std::optional<std::vector<StepSpec>> steps =
      generate_steps(source, target, rig.policy(), rig.governor().limits(), reason);
  RC_BENCH_REQUIRE(steps.has_value());
  const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
  for (std::uint64_t index = 0; index < kGraphOperations; ++index) {
    const std::optional<std::vector<std::size_t>> order = canonical_topological_order(*steps);
    RC_BENCH_REQUIRE(order.has_value());
    RC_BENCH_REQUIRE(order->size() == steps->size());
  }
  const std::chrono::steady_clock::duration elapsed = std::chrono::steady_clock::now() - start;
  report(kBench, kGraphOperations, elapsed);
  return true;
}

// --- ready-step query -------------------------------------------------------

bool bench_ready_step_query() {
  constexpr std::string_view kBench = "ready_step_query";
  BenchRig rig;
  RC_BENCH_REQUIRE(rig.ready());
  const PlanMutationResult created =
      rig.create_transition(derive_id<RouteId>("rc.bench.ready.route", 1),
                            derive_id<PathId>("rc.bench.ready.source", 1),
                            derive_id<PathId>("rc.bench.ready.target", 1), 1);
  RC_BENCH_REQUIRE(created.outcome == Outcome::PLAN_CREATED);
  const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
  for (std::uint64_t index = 0; index < kQueryOperations; ++index) {
    const ReadyStepList ready = rig.governor().ready_steps(16);
    RC_BENCH_REQUIRE(!ready.steps.empty());
  }
  const std::chrono::steady_clock::duration elapsed = std::chrono::steady_clock::now() - start;
  report(kBench, kQueryOperations, elapsed);
  return true;
}

// --- completion commit ------------------------------------------------------

bool bench_completion_commit() {
  constexpr std::string_view kBench = "completion_commit";
  BenchRig rig;
  RC_BENCH_REQUIRE(rig.ready());
  struct Planned {
    ConvergencePlanId plan;
    TransitionStepId step;
    TransitionStepGeneration generation;
    ConvergenceGeneration watermark;
    CoordinatorEpoch epoch;
    AuthorityContext authority;
  };
  std::vector<Planned> prepared;
  prepared.reserve(kCompletionOperations);
  for (std::uint64_t index = 0; index < kCompletionOperations; ++index) {
    const PlanMutationResult created =
        rig.create_transition(derive_id<RouteId>("rc.bench.commit.route", index),
                              derive_id<PathId>("rc.bench.commit.source", index),
                              derive_id<PathId>("rc.bench.commit.target", index), index + 1);
    RC_BENCH_REQUIRE(created.outcome == Outcome::PLAN_CREATED);
    const ReadyStepList ready = rig.governor().ready_steps(1);
    RC_BENCH_REQUIRE(!ready.steps.empty());
    RC_BENCH_REQUIRE(ready.steps.front().plan == created.plan);
    const AuthorityContext authority = rig.authority(100000 + index);
    const StepDispatch dispatch =
        rig.governor().dispatch_step(created.plan, ready.steps.front().step, authority);
    RC_BENCH_REQUIRE(dispatch.outcome == Outcome::STEP_DISPATCHED);
    prepared.push_back(Planned{created.plan, dispatch.step, dispatch.step_generation,
                               dispatch.watermark, dispatch.epoch, authority});
  }
  const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
  for (const Planned& item : prepared) {
    CompletionEvidence evidence;
    evidence.plan = item.plan;
    evidence.step = item.step;
    evidence.step_generation = item.generation;
    evidence.attempt = item.authority.attempt;
    evidence.epoch = item.epoch;
    evidence.publisher = item.authority.publisher;
    evidence.worker_boot = item.authority.worker_boot;
    evidence.outcome = BackendOutcome::APPLIED;
    evidence.dispatch_watermark = item.watermark;
    evidence.id = derive_evidence_id(evidence);
    const PlanMutationResult completed =
        rig.governor().complete_step(evidence, item.authority);
    RC_BENCH_REQUIRE(completed.accepted());
  }
  const std::chrono::steady_clock::duration elapsed = std::chrono::steady_clock::now() - start;
  report(kBench, kCompletionOperations, elapsed);
  return true;
}

// --- targeted path invalidation --------------------------------------------

bool bench_path_invalidation() {
  constexpr std::string_view kBench = "targeted_path_invalidation";
  BenchRig rig;
  RC_BENCH_REQUIRE(rig.ready());
  const PathId shared_path = derive_id<PathId>("rc.bench.shared.path", 1);
  for (std::uint64_t index = 0; index < kSharedPathPlans; ++index) {
    const PlanMutationResult created =
        rig.create_transition(derive_id<RouteId>("rc.bench.invalidate.route", index), shared_path,
                              shared_path, index + 1);
    RC_BENCH_REQUIRE(created.outcome == Outcome::PLAN_CREATED);
  }
  RC_BENCH_REQUIRE(rig.governor().plan_count() == kSharedPathPlans);
  // Path Authority moves the shared path to a newer generation; the coordinator
  // must invalidate exactly the plans that depend on it.
  rig.set_path(shared_path, 2, true);
  PathChangeNotice notice;
  notice.legality.path = shared_path;
  notice.legality.generation = PathAuthorityGeneration::from_value(2);
  notice.legality.legal = true;
  notice.provenance = derive_id<ProvenanceId>("rc.bench.provenance", 900);
  const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
  const NoticeResult result = rig.governor().note_path_change(notice, rig.authority(901));
  const std::chrono::steady_clock::duration elapsed = std::chrono::steady_clock::now() - start;
  RC_BENCH_REQUIRE(result.accepted());
  RC_BENCH_REQUIRE(result.plans_examined == kSharedPathPlans);
  RC_BENCH_REQUIRE(result.plans_invalidated == kSharedPathPlans);
  report(kBench, kSharedPathPlans, elapsed);
  return true;
}

// --- snapshot ---------------------------------------------------------------

bool bench_snapshot() {
  constexpr std::string_view kBench = "snapshot";
  BenchRig rig;
  RC_BENCH_REQUIRE(rig.ready());
  const PlanMutationResult created =
      rig.create_transition(derive_id<RouteId>("rc.bench.snapshot.route", 1),
                            derive_id<PathId>("rc.bench.snapshot.source", 1),
                            derive_id<PathId>("rc.bench.snapshot.target", 1), 1);
  RC_BENCH_REQUIRE(created.outcome == Outcome::PLAN_CREATED);
  const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
  for (std::uint64_t index = 0; index < kSnapshotOperations; ++index) {
    const std::optional<ConvergenceSnapshot> snapshot = rig.governor().snapshot(created.plan);
    RC_BENCH_REQUIRE(snapshot.has_value());
    RC_BENCH_REQUIRE(snapshot->plan == created.plan);
  }
  const std::chrono::steady_clock::duration elapsed = std::chrono::steady_clock::now() - start;
  report(kBench, kSnapshotOperations, elapsed);
  return true;
}

// --- plan digest ------------------------------------------------------------

bool bench_plan_digest() {
  constexpr std::string_view kBench = "plan_structure_digest";
  BenchRig rig;
  RC_BENCH_REQUIRE(rig.ready());
  const RouteId route = derive_id<RouteId>("rc.bench.sample.route", 1);
  const RouteBinding source = make_route_binding(route, RouteGeneration::from_value(1),
                                                 derive_id<PathId>("rc.bench.sample.source", 1),
                                                 PathAuthorityGeneration::from_value(1));
  const RouteBinding target = make_route_binding(route, RouteGeneration::from_value(2),
                                                 derive_id<PathId>("rc.bench.sample.target", 1),
                                                 PathAuthorityGeneration::from_value(1));
  std::string reason;
  const std::optional<std::vector<StepSpec>> steps =
      generate_steps(source, target, rig.policy(), rig.governor().limits(), reason);
  RC_BENCH_REQUIRE(steps.has_value());
  PlanKey key;
  key.route = route;
  key.source_generation = RouteGeneration::from_value(1);
  key.target_generation = RouteGeneration::from_value(2);
  key.policy_generation = ConvergencePolicyGeneration::from_value(1);
  const Digest expected = plan_structure_digest(key, source, target, rig.policy(),
                                                PlanMode::GENERATED, *steps);
  RC_BENCH_REQUIRE(!expected.is_nil());
  const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
  for (std::uint64_t index = 0; index < kDigestOperations; ++index) {
    const Digest digest = plan_structure_digest(key, source, target, rig.policy(),
                                                PlanMode::GENERATED, *steps);
    RC_BENCH_REQUIRE(digest == expected);
  }
  const std::chrono::steady_clock::duration elapsed = std::chrono::steady_clock::now() - start;
  report(kBench, kDigestOperations, elapsed);
  return true;
}

// --- persistence ------------------------------------------------------------

bool bench_persistence_save(const std::filesystem::path& store) {
  constexpr std::string_view kBench = "persistence_save";
  BenchRig rig;
  RC_BENCH_REQUIRE(rig.ready());
  for (std::uint64_t index = 0; index < kPersistencePlans; ++index) {
    const PlanMutationResult created =
        rig.create_transition(derive_id<RouteId>("rc.bench.persist.route", index),
                              derive_id<PathId>("rc.bench.persist.source", index),
                              derive_id<PathId>("rc.bench.persist.target", index), index + 1);
    RC_BENCH_REQUIRE(created.outcome == Outcome::PLAN_CREATED);
  }
  const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
  for (std::uint64_t index = 0; index < kSaveOperations; ++index) {
    const PlanMutationResult saved = rig.governor().save(store);
    RC_BENCH_REQUIRE(saved.accepted());
  }
  const std::chrono::steady_clock::duration elapsed = std::chrono::steady_clock::now() - start;
  RC_BENCH_REQUIRE(std::filesystem::exists(store));
  report(kBench, kSaveOperations, elapsed);
  return true;
}

bool bench_persistence_load(const std::filesystem::path& store) {
  constexpr std::string_view kBench = "persistence_load";
  std::vector<std::unique_ptr<BenchRig>> rigs;
  rigs.reserve(kLoadOperations);
  for (std::uint64_t index = 0; index < kLoadOperations; ++index) {
    rigs.push_back(std::make_unique<BenchRig>(false));
  }
  const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
  for (const std::unique_ptr<BenchRig>& rig : rigs) {
    const PlanMutationResult loaded = rig->governor().load(store);
    RC_BENCH_REQUIRE(loaded.accepted());
    RC_BENCH_REQUIRE(rig->governor().plan_count() == kPersistencePlans);
  }
  const std::chrono::steady_clock::duration elapsed = std::chrono::steady_clock::now() - start;
  report(kBench, kLoadOperations, elapsed);
  return true;
}

// --- SYNTHETIC plan population ---------------------------------------------

bool bench_plan_population_synthetic() {
  constexpr std::string_view kBench = "plan_population_SYNTHETIC";
  std::cout << "# plan_population_SYNTHETIC: " << kPopulationOperations
            << " plan identities over rc::SyntheticUpstream (SYNTHETIC control plane, "
               "not physical convergence)\n";
  BenchRig rig;
  RC_BENCH_REQUIRE(rig.ready());
  const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
  for (std::uint64_t index = 0; index < kPopulationOperations; ++index) {
    const PathId path = derive_id<PathId>("rc.bench.population.path", index);
    const PlanMutationResult created =
        rig.create_transition(derive_id<RouteId>("rc.bench.population.route", index), path, path,
                              index + 1);
    RC_BENCH_REQUIRE(created.outcome == Outcome::PLAN_CREATED);
  }
  const std::chrono::steady_clock::duration elapsed = std::chrono::steady_clock::now() - start;
  RC_BENCH_REQUIRE(rig.governor().plan_count() == kPopulationOperations);
  report(kBench, kPopulationOperations, elapsed);
  return true;
}

[[nodiscard]] std::filesystem::path make_store_directory() {
  std::error_code error;
  const std::filesystem::path base = std::filesystem::temp_directory_path(error);
  if (error) {
    return {};
  }
  const std::filesystem::path directory =
      base / ("rc_benchmark_" + std::to_string(static_cast<unsigned long>(_getpid())));
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
  const std::filesystem::path directory = make_store_directory();
  if (directory.empty()) {
    std::cout << "bench setup FAILED detail=temporary directory is unavailable\n";
    return 1;
  }
  const std::filesystem::path store = directory / "benchmark.store";
  bool ok = bench_plan_creation();
  ok = ok && bench_dependency_graph_validation();
  ok = ok && bench_canonical_topological_order();
  ok = ok && bench_ready_step_query();
  ok = ok && bench_completion_commit();
  ok = ok && bench_path_invalidation();
  ok = ok && bench_snapshot();
  ok = ok && bench_plan_digest();
  ok = ok && bench_persistence_save(store);
  ok = ok && bench_persistence_load(store);
  ok = ok && bench_plan_population_synthetic();
  std::error_code error;
  std::filesystem::remove_all(directory, error);
  return ok ? 0 : 1;
}
