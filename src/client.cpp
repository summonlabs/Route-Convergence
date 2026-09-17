#include "rc/client.hpp"

#include <atomic>

namespace rc {

struct RcClient::Impl {
  TcpConnection connection;
  CoordinatorEpoch epoch;
  PublisherId publisher;
  WorkerBootId worker_boot;
  MutationAttemptId attempt;
  AuthorityScope scope;
  std::atomic<std::uint64_t> sequence{0};
};

RcClient::RcClient() = default;

RcClient::~RcClient() = default;

RcClient::RcClient(RcClient&& other) noexcept : impl_(std::move(other.impl_)) {}

RcClient& RcClient::operator=(RcClient&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
  }
  return *this;
}

std::optional<RcClient> RcClient::connect(const std::string& host, std::uint16_t port,
                                          std::uint32_t deadline_ms, std::string& error) {
  (void)host;
  (void)deadline_ms;
  std::optional<TcpConnection> connection = connect_loopback(port, error);
  if (!connection.has_value()) {
    return std::nullopt;
  }
  RcClient client;
  client.impl_ = std::make_unique<Impl>();
  client.impl_->connection = std::move(*connection);
  error.clear();
  return client;
}

bool RcClient::valid() const noexcept {
  return impl_ != nullptr && impl_->connection.valid();
}

void RcClient::set_epoch(CoordinatorEpoch epoch) noexcept {
  if (impl_ != nullptr) {
    impl_->epoch = epoch;
  }
}

void RcClient::set_publisher(PublisherId publisher) noexcept {
  if (impl_ != nullptr) {
    impl_->publisher = publisher;
  }
}

void RcClient::set_worker_boot(WorkerBootId boot) noexcept {
  if (impl_ != nullptr) {
    impl_->worker_boot = boot;
  }
}

void RcClient::set_attempt(MutationAttemptId attempt) noexcept {
  if (impl_ != nullptr) {
    impl_->attempt = attempt;
  }
}

void RcClient::set_scope(AuthorityScope scope) noexcept {
  if (impl_ != nullptr) {
    impl_->scope = scope;
  }
}

CoordinatorEpoch RcClient::epoch() const noexcept {
  return impl_ == nullptr ? CoordinatorEpoch{} : impl_->epoch;
}

PublisherId RcClient::publisher() const noexcept {
  return impl_ == nullptr ? PublisherId{} : impl_->publisher;
}

WorkerBootId RcClient::worker_boot() const noexcept {
  return impl_ == nullptr ? WorkerBootId{} : impl_->worker_boot;
}

MutationAttemptId RcClient::attempt() const noexcept {
  return impl_ == nullptr ? MutationAttemptId{} : impl_->attempt;
}

const AuthorityScope& RcClient::scope() const noexcept {
  static const AuthorityScope kDenyAll{};
  return impl_ == nullptr ? kDenyAll : impl_->scope;
}

bool RcClient::round_trip(WireMessageId request_id, const std::vector<std::uint8_t>& payload,
                          WireMessageId expected, Envelope& response, std::string& error) {
  if (!valid()) {
    error = "client is not connected";
    return false;
  }
  Envelope request;
  request.message = request_id;
  request.sequence = impl_->sequence.fetch_add(1) + 1;
  request.epoch = impl_->epoch;
  request.publisher = impl_->publisher;
  request.worker_boot = impl_->worker_boot;
  request.attempt = impl_->attempt;
  request.payload = payload;
  if (!write_frame(impl_->connection, request, ConvergenceLimits{}, error)) {
    return false;
  }
  Envelope reply;
  const WireDefect defect =
      read_frame(impl_->connection, ConvergenceLimits{}, 30000, reply, error);
  if (defect != WireDefect::NONE) {
    error = std::string(to_string(defect));
    return false;
  }
  if (reply.message == WireMessageId::FENCE_NOTICE) {
    error = "session was fenced by the coordinator";
    return false;
  }
  if (reply.message == WireMessageId::ERROR) {
    ErrorBody body;
    if (decode_payload(reply.payload, ConvergenceLimits{}, body)) {
      error = std::string(to_string(body.code));
    } else {
      error = "coordinator rejected the request";
    }
    return false;
  }
  if (reply.message != expected) {
    error = "unexpected response message";
    return false;
  }
  response = std::move(reply);
  return true;
}

bool RcClient::hello(HelloResponseBody& out, std::string& error) {
  Envelope response;
  if (!round_trip(WireMessageId::HELLO, {}, WireMessageId::HELLO_RESPONSE, response, error)) {
    return false;
  }
  if (!decode_payload(response.payload, ConvergenceLimits{}, out)) {
    error = "malformed hello response";
    return false;
  }
  impl_->epoch = out.epoch;
  return true;
}

#define RC_CLIENT_SIMPLE(name, message, expected, payload_type, out_type)             \
  bool RcClient::name(const payload_type& value, out_type& out, std::string& error) { \
    Envelope response;                                                                \
    if (!round_trip(message, encode_payload(value), expected, response, error)) {     \
      return false;                                                                   \
    }                                                                                 \
    if (!decode_payload(response.payload, ConvergenceLimits{}, out)) {                \
      error = "malformed " + std::string(to_string(expected)) + " payload (" +        \
              std::to_string(response.payload.size()) + " bytes)";                    \
      return false;                                                                   \
    }                                                                                 \
    return true;                                                                      \
  }

RC_CLIENT_SIMPLE(register_worker, WireMessageId::REGISTER_WORKER,
                 WireMessageId::REGISTER_WORKER_RESPONSE, PublisherRegistration,
                 PlanMutationResult)
RC_CLIENT_SIMPLE(fence_worker, WireMessageId::FENCE_WORKER,
                 WireMessageId::FENCE_WORKER_RESPONSE, WorkerBootId, PlanMutationResult)
RC_CLIENT_SIMPLE(define_policy, WireMessageId::DEFINE_POLICY,
                 WireMessageId::DEFINE_POLICY_RESPONSE, ConvergencePolicy, PlanMutationResult)
RC_CLIENT_SIMPLE(create_plan, WireMessageId::CREATE_PLAN, WireMessageId::CREATE_PLAN_RESPONSE,
                 PlanRequest, PlanMutationResult)
RC_CLIENT_SIMPLE(query_plan, WireMessageId::QUERY_PLAN, WireMessageId::QUERY_PLAN_RESPONSE,
                 ConvergencePlanId, PlanQueryBody)
RC_CLIENT_SIMPLE(dispatch_step, WireMessageId::DISPATCH_STEP,
                 WireMessageId::DISPATCH_STEP_RESPONSE, DispatchStepRequest, StepDispatch)
RC_CLIENT_SIMPLE(complete_step, WireMessageId::COMPLETE_STEP,
                 WireMessageId::COMPLETE_STEP_RESPONSE, CompletionEvidence, PlanMutationResult)
RC_CLIENT_SIMPLE(fail_step, WireMessageId::FAIL_STEP, WireMessageId::FAIL_STEP_RESPONSE,
                 FailStepRequest, PlanMutationResult)
RC_CLIENT_SIMPLE(reconcile_step, WireMessageId::RECONCILE_STEP,
                 WireMessageId::RECONCILE_STEP_RESPONSE, ReconcileStepRequest, PlanMutationResult)
RC_CLIENT_SIMPLE(revalidate_plan, WireMessageId::REVALIDATE_PLAN,
                 WireMessageId::REVALIDATE_PLAN_RESPONSE, ConvergencePlanId, PlanMutationResult)
RC_CLIENT_SIMPLE(begin_rollback, WireMessageId::BEGIN_ROLLBACK,
                 WireMessageId::BEGIN_ROLLBACK_RESPONSE, ConvergencePlanId, PlanMutationResult)
RC_CLIENT_SIMPLE(retire_plan, WireMessageId::RETIRE_PLAN, WireMessageId::RETIRE_PLAN_RESPONSE,
                 ConvergencePlanId, PlanMutationResult)
RC_CLIENT_SIMPLE(revoke_plan, WireMessageId::REVOKE_PLAN, WireMessageId::REVOKE_PLAN_RESPONSE,
                 ConvergencePlanId, PlanMutationResult)
RC_CLIENT_SIMPLE(pause_plan, WireMessageId::PAUSE_PLAN, WireMessageId::PAUSE_PLAN_RESPONSE,
                 PausePlanRequest, PlanMutationResult)
RC_CLIENT_SIMPLE(snapshot, WireMessageId::SNAPSHOT_REQUEST, WireMessageId::SNAPSHOT_RESPONSE,
                 ConvergencePlanId, SnapshotBody)
RC_CLIENT_SIMPLE(publish_route_change, WireMessageId::ROUTE_CHANGE,
                 WireMessageId::ROUTE_CHANGE_RESPONSE, RouteChangeNotice, NoticeResult)
RC_CLIENT_SIMPLE(publish_path_change, WireMessageId::PATH_CHANGE,
                 WireMessageId::PATH_CHANGE_RESPONSE, PathChangeNotice, NoticeResult)
RC_CLIENT_SIMPLE(publish_epoch_change, WireMessageId::EPOCH_CHANGE,
                 WireMessageId::EPOCH_CHANGE_RESPONSE, EpochChangeNotice, NoticeResult)

#undef RC_CLIENT_SIMPLE

bool RcClient::list_policies(PolicyListBody& out, std::string& error) {
  Envelope response;
  if (!round_trip(WireMessageId::LIST_POLICIES, {}, WireMessageId::LIST_POLICIES_RESPONSE,
                  response, error)) {
    return false;
  }
  if (!decode_payload(response.payload, ConvergenceLimits{}, out)) {
    error = "malformed policy list payload";
    return false;
  }
  return true;
}

bool RcClient::list_plans(PlanList& out, std::string& error) {
  Envelope response;
  if (!round_trip(WireMessageId::LIST_PLANS, {}, WireMessageId::LIST_PLANS_RESPONSE, response,
                  error)) {
    return false;
  }
  if (!decode_payload(response.payload, ConvergenceLimits{}, out)) {
    error = "malformed plan list payload";
    return false;
  }
  return true;
}

bool RcClient::ready_steps(std::uint32_t max_steps, ReadyStepList& out, std::string& error) {
  StepReadyRequest request;
  request.max_steps = max_steps;
  Envelope response;
  if (!round_trip(WireMessageId::STEP_READY, encode_payload(request),
                  WireMessageId::STEP_READY_RESPONSE, response, error)) {
    return false;
  }
  if (!decode_payload(response.payload, ConvergenceLimits{}, out)) {
    error = "malformed STEP_READY_RESPONSE payload (" +
            std::to_string(response.payload.size()) + " bytes)";
    return false;
  }
  return true;
}

bool RcClient::diff(const ConvergencePlanId& plan, ConvergencePlanGeneration from, DiffBody& out,
                    std::string& error) {
  DiffRequestBody request;
  request.plan = plan;
  request.from = from;
  Envelope response;
  if (!round_trip(WireMessageId::DIFF_REQUEST, encode_payload(request),
                  WireMessageId::DIFF_RESPONSE, response, error)) {
    return false;
  }
  if (!decode_payload(response.payload, ConvergenceLimits{}, out)) {
    error = "malformed diff payload";
    return false;
  }
  return true;
}

bool RcClient::explain(const ExplainRequest& request, ExplainResponse& out, std::string& error) {
  Envelope response;
  if (!round_trip(WireMessageId::EXPLAIN_REQUEST, encode_payload(request),
                  WireMessageId::EXPLAIN_RESPONSE, response, error)) {
    return false;
  }
  if (!decode_payload(response.payload, ConvergenceLimits{}, out)) {
    error = "malformed explanation payload";
    return false;
  }
  return true;
}

bool RcClient::wait_for_fence(std::string& error) {
  if (!valid()) {
    error = "client is not connected";
    return false;
  }
  for (;;) {
    Envelope reply;
    // The read budget is deliberately unlimited: a worker waits for an
    // authoritative fence, it does not guess and it does not poll.
    const WireDefect defect =
        read_frame(impl_->connection, ConvergenceLimits{}, 0xFFFFFFFFu, reply, error);
    if (defect != WireDefect::NONE) {
      error = std::string(to_string(defect));
      return false;
    }
    if (reply.message == WireMessageId::FENCE_NOTICE) {
      error.clear();
      return true;
    }
  }
}

void RcClient::close() {
  if (impl_ != nullptr) {
    impl_->connection.shutdown();
    impl_->connection.close();
  }
}

}  // namespace rc
