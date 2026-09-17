#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "rc/backend.hpp"
#include "rc/convergence.hpp"
#include "rc/net.hpp"
#include "rc/protocol.hpp"

namespace rc {

// Client session against one coordinator.  The session carries the live authority
// quadruple (epoch, publisher, worker boot, attempt) that every mutation binds.
class RcClient {
 public:
  RcClient();
  ~RcClient();
  RcClient(RcClient&& other) noexcept;
  RcClient& operator=(RcClient&& other) noexcept;
  RcClient(const RcClient&) = delete;
  RcClient& operator=(const RcClient&) = delete;

  [[nodiscard]] static std::optional<RcClient> connect(const std::string& host, std::uint16_t port,
                                                      std::uint32_t deadline_ms, std::string& error);

  [[nodiscard]] bool valid() const noexcept;
  [[nodiscard]] bool hello(HelloResponseBody& out, std::string& error);

  void set_epoch(CoordinatorEpoch epoch) noexcept;
  void set_publisher(PublisherId publisher) noexcept;
  void set_worker_boot(WorkerBootId boot) noexcept;
  void set_attempt(MutationAttemptId attempt) noexcept;
  void set_scope(AuthorityScope scope) noexcept;
  [[nodiscard]] CoordinatorEpoch epoch() const noexcept;
  [[nodiscard]] PublisherId publisher() const noexcept;
  [[nodiscard]] WorkerBootId worker_boot() const noexcept;
  [[nodiscard]] MutationAttemptId attempt() const noexcept;
  [[nodiscard]] const AuthorityScope& scope() const noexcept;

  [[nodiscard]] bool register_worker(const PublisherRegistration& registration,
                                     PlanMutationResult& out, std::string& error);
  [[nodiscard]] bool fence_worker(const WorkerBootId& boot, PlanMutationResult& out,
                                  std::string& error);
  [[nodiscard]] bool define_policy(const ConvergencePolicy& policy, PlanMutationResult& out,
                                   std::string& error);
  [[nodiscard]] bool list_policies(PolicyListBody& out, std::string& error);
  [[nodiscard]] bool create_plan(const PlanRequest& request, PlanMutationResult& out,
                                 std::string& error);
  [[nodiscard]] bool query_plan(const ConvergencePlanId& plan, PlanQueryBody& out,
                                std::string& error);
  [[nodiscard]] bool list_plans(PlanList& out, std::string& error);
  [[nodiscard]] bool ready_steps(std::uint32_t max_steps, ReadyStepList& out, std::string& error);
  [[nodiscard]] bool dispatch_step(const DispatchStepRequest& request, StepDispatch& out,
                                   std::string& error);
  [[nodiscard]] bool complete_step(const CompletionEvidence& evidence, PlanMutationResult& out,
                                   std::string& error);
  [[nodiscard]] bool fail_step(const FailStepRequest& request, PlanMutationResult& out,
                               std::string& error);
  [[nodiscard]] bool reconcile_step(const ReconcileStepRequest& request, PlanMutationResult& out,
                                    std::string& error);
  [[nodiscard]] bool revalidate_plan(const ConvergencePlanId& plan, PlanMutationResult& out,
                                     std::string& error);
  [[nodiscard]] bool pause_plan(const PausePlanRequest& request, PlanMutationResult& out,
                                std::string& error);
  [[nodiscard]] bool begin_rollback(const ConvergencePlanId& plan, PlanMutationResult& out,
                                    std::string& error);
  [[nodiscard]] bool retire_plan(const ConvergencePlanId& plan, PlanMutationResult& out,
                                 std::string& error);
  [[nodiscard]] bool revoke_plan(const ConvergencePlanId& plan, PlanMutationResult& out,
                                 std::string& error);
  [[nodiscard]] bool snapshot(const ConvergencePlanId& plan, SnapshotBody& out, std::string& error);
  [[nodiscard]] bool diff(const ConvergencePlanId& plan, ConvergencePlanGeneration from,
                          DiffBody& out, std::string& error);
  [[nodiscard]] bool explain(const ExplainRequest& request, ExplainResponse& out,
                             std::string& error);
  [[nodiscard]] bool publish_route_change(const RouteChangeNotice& notice, NoticeResult& out,
                                          std::string& error);
  [[nodiscard]] bool publish_path_change(const PathChangeNotice& notice, NoticeResult& out,
                                         std::string& error);
  [[nodiscard]] bool publish_epoch_change(const EpochChangeNotice& notice, NoticeResult& out,
                                          std::string& error);

  // Blocks until the coordinator fences this session or the connection ends.
  // Returns true when a FENCE_NOTICE was received.  The read budget is unlimited
  // by design: a worker waits for an authoritative fence, it does not guess.
  [[nodiscard]] bool wait_for_fence(std::string& error);

  void close();

 private:
  [[nodiscard]] bool round_trip(WireMessageId request_id, const std::vector<std::uint8_t>& payload,
                                WireMessageId expected, Envelope& response, std::string& error);

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace rc
