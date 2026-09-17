#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "rc/plan.hpp"
#include "rc/step.hpp"

namespace rc {

// Everything a worker needs in order to perform one transition step.  This is a
// value: it carries the exact plan, step generation, bindings and watermark the
// work was authorized under, and it becomes useless the moment any of those
// generations moves.
struct StepExecutionRequest {
  ConvergencePlanId plan;
  TransitionStepId step;
  TransitionStepGeneration step_generation;
  StepSpec spec;
  ConvergenceGeneration watermark;
  CoordinatorEpoch epoch;
  RouteBinding source;
  RouteBinding target;
};

// The external operation seam.  Route Convergence 1.0.0 ships exactly one
// backend: JournalBackend, a deterministic, idempotent control-plane journal
// applier.  No switch programming backend exists and none is claimed.
//
// A backend returns a *structured* outcome.  Returning "probably worked" is not
// expressible: the honest answer for a lost acknowledgement is AMBIGUOUS.
class TransitionBackend {
 public:
  TransitionBackend() = default;
  virtual ~TransitionBackend() = default;
  TransitionBackend(const TransitionBackend&) = delete;
  TransitionBackend& operator=(const TransitionBackend&) = delete;

  [[nodiscard]] virtual BackendOutcome apply(const StepExecutionRequest& request,
                                             std::string& detail) = 0;

  // Whether reapplying this step kind is provably idempotent for this backend.
  // Retry is only ever offered for a step whose backend says yes.
  [[nodiscard]] virtual bool is_idempotent(StepKind kind) const noexcept = 0;

  // Whether the backend can still observe that the effect of this step is
  // present.  Used by reconciliation after an AMBIGUOUS outcome: Route
  // Convergence never blindly reapplies a side-effecting operation.
  [[nodiscard]] virtual bool observes_applied(const StepExecutionRequest& request) const = 0;
};

// Deterministic control-plane journal backend.
//
// It records, by (plan, step) identity, which transition steps have been applied.
// Applying the same step identity twice returns IDEMPOTENT rather than APPLIED,
// which is exactly the property that makes bounded retry safe for the steps that
// declare themselves idempotent.
//
// The journal is control-plane bookkeeping.  It is not a forwarding table, it is
// not a switch, and nothing here claims to have moved a packet.
class JournalBackend : public TransitionBackend {
 public:
  explicit JournalBackend(std::uint32_t max_entries = 4096);

  [[nodiscard]] BackendOutcome apply(const StepExecutionRequest& request,
                                     std::string& detail) override;
  [[nodiscard]] bool is_idempotent(StepKind kind) const noexcept override;
  [[nodiscard]] bool observes_applied(const StepExecutionRequest& request) const override;

  // Test and example scripting.  A scripted outcome applies to the exact step
  // identity and is consumed once, so a scripted failure cannot silently leak
  // into an unrelated step.
  void script_outcome(const TransitionStepId& step, BackendOutcome outcome);
  void clear_script();
  [[nodiscard]] bool has_applied(const ConvergencePlanId& plan, const TransitionStepId& step) const;
  [[nodiscard]] std::size_t applied_count() const;
  [[nodiscard]] std::vector<std::string> journal_lines() const;

 private:
  struct Entry {
    ConvergencePlanId plan;
    TransitionStepId step;
    StepKind kind = StepKind::VALIDATE_TARGET;
    RouteGeneration route_generation;
    PathAuthorityGeneration path_generation;
  };

  mutable std::mutex mutex_;
  std::vector<Entry> entries_;
  std::map<std::string, BackendOutcome> scripted_;
  std::uint32_t max_entries_ = 4096;
  std::uint64_t applied_ = 0;
  std::uint64_t replayed_ = 0;
};

}  // namespace rc
