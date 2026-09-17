#include "rc/server.hpp"

#include <algorithm>

namespace rc {
namespace {

[[nodiscard]] AuthorityContext context_of(const Envelope& request, CoordinatorEpoch epoch) {
  AuthorityContext context;
  context.epoch = epoch;
  context.publisher = request.publisher;
  context.worker_boot = request.worker_boot;
  context.attempt = request.attempt;
  return context;
}

[[nodiscard]] Envelope error_response(const Envelope& request, CoordinatorEpoch epoch,
                                      ConditionCode code, Outcome outcome, std::string detail) {
  Envelope response;
  response.message = WireMessageId::ERROR;
  response.sequence = request.sequence;
  response.epoch = epoch;
  response.publisher = request.publisher;
  response.worker_boot = request.worker_boot;
  response.attempt = request.attempt;
  ErrorBody body;
  body.code = code;
  body.outcome = outcome;
  body.detail = std::move(detail);
  response.payload = encode_payload(body);
  return response;
}

}  // namespace

struct CoordinatorServer::Impl {
  ConvergenceGovernor& governor;
  CoordinatorServerOptions options;
  TcpListener listener;
  std::atomic<bool> stopping{false};
  std::atomic<std::uint32_t> sessions{0};
  std::atomic<std::uint64_t> handled{0};
  std::mutex mutex;
  struct Session {
    std::thread thread;
    std::shared_ptr<std::atomic<bool>> done;
  };
  std::vector<Session> workers;
  std::map<WorkerBootId, std::shared_ptr<TcpConnection>> by_boot;
  std::shared_ptr<TcpConnection> session_connection;

  Impl(ConvergenceGovernor& governor_reference, CoordinatorServerOptions server_options)
      : governor(governor_reference), options(std::move(server_options)) {}

  void notify_fence(const WorkerBootId& boot) {
    if (boot.is_nil()) {
      return;
    }
    std::shared_ptr<TcpConnection> connection;
    {
      const std::lock_guard<std::mutex> lock(mutex);
      const auto entry = by_boot.find(boot);
      if (entry == by_boot.end()) {
        return;
      }
      connection = entry->second;
      by_boot.erase(entry);
    }
    Envelope notice;
    notice.message = WireMessageId::FENCE_NOTICE;
    notice.epoch = governor.epoch();
    std::string error;
    (void)write_frame(*connection, notice, options.limits, error);
  }

  void forget(const WorkerBootId& boot, const std::shared_ptr<TcpConnection>& connection) {
    if (boot.is_nil()) {
      return;
    }
    const std::lock_guard<std::mutex> lock(mutex);
    const auto entry = by_boot.find(boot);
    if (entry != by_boot.end() && entry->second == connection) {
      by_boot.erase(entry);
    }
  }

  void remember(const WorkerBootId& boot, const std::shared_ptr<TcpConnection>& connection) {
    const std::lock_guard<std::mutex> lock(mutex);
    by_boot[boot] = connection;
  }

  [[nodiscard]] Envelope dispatch(const Envelope& request);
  void serve_connection(const std::shared_ptr<TcpConnection>& connection);

  // Joins only sessions that already finished, so the accept loop never blocks
  // on a live connection.
  void reap_finished() {
    const std::lock_guard<std::mutex> lock(mutex);
    std::vector<Session> keep;
    keep.reserve(workers.size());
    for (Session& session : workers) {
      if (session.done->load()) {
        if (session.thread.joinable()) {
          session.thread.join();
        }
      } else {
        keep.push_back(std::move(session));
      }
    }
    workers = std::move(keep);
  }
};

Envelope CoordinatorServer::Impl::dispatch(const Envelope& request) {
  Envelope response;
  const CoordinatorEpoch epoch = governor.epoch();
  response.sequence = request.sequence;
  response.epoch = epoch;
  response.publisher = request.publisher;
  response.worker_boot = request.worker_boot;
  response.attempt = request.attempt;
  const AuthorityContext context = context_of(request, epoch);
  const auto malformed = [&request, epoch](std::string detail) {
    return error_response(request, epoch, ConditionCode::MALFORMED_PAYLOAD,
                          Outcome::MALFORMED_REQUEST, std::move(detail));
  };

  switch (request.message) {
    case WireMessageId::HELLO: {
      HelloResponseBody body;
      body.wire_version = kWireVersion;
      body.epoch = epoch;
      body.product = std::string(kProductName);
      body.version = std::string(kVersionString);
      body.convergence_generation = governor.convergence_generation();
      response.message = WireMessageId::HELLO_RESPONSE;
      response.payload = encode_payload(body);
      return response;
    }
    case WireMessageId::REGISTER_WORKER: {
      PublisherRegistration registration;
      if (!decode_payload(request.payload, options.limits, registration)) {
        return malformed("register worker payload");
      }
      WorkerBootId previous;
      for (const PublisherRegistration& entry : governor.list_workers()) {
        if (entry.publisher == registration.publisher &&
            !(entry.worker_boot == registration.worker_boot)) {
          previous = entry.worker_boot;
        }
      }
      const PlanMutationResult result = governor.register_worker(registration, context);
      response.message = WireMessageId::REGISTER_WORKER_RESPONSE;
      response.payload = encode_payload(result);
      if (result.accepted()) {
        notify_fence(previous);
        remember(registration.worker_boot, session_connection);
      }
      return response;
    }
    case WireMessageId::FENCE_WORKER: {
      WorkerBootId boot;
      if (!decode_payload(request.payload, options.limits, boot)) {
        return malformed("fence worker payload");
      }
      const PlanMutationResult result = governor.fence_worker(boot, context);
      response.message = WireMessageId::FENCE_WORKER_RESPONSE;
      response.payload = encode_payload(result);
      notify_fence(boot);
      return response;
    }
    case WireMessageId::DEFINE_POLICY: {
      ConvergencePolicy policy;
      if (!decode_payload(request.payload, options.limits, policy)) {
        return malformed("policy payload");
      }
      const PlanMutationResult result = governor.define_policy(policy, context);
      response.message = WireMessageId::DEFINE_POLICY_RESPONSE;
      response.payload = encode_payload(result);
      return response;
    }
    case WireMessageId::LIST_POLICIES: {
      PolicyListBody body;
      body.policies = governor.list_policies();
      response.message = WireMessageId::LIST_POLICIES_RESPONSE;
      response.payload = encode_payload(body);
      return response;
    }
    case WireMessageId::CREATE_PLAN: {
      PlanRequest plan_request;
      if (!decode_payload(request.payload, options.limits, plan_request)) {
        return malformed("plan request payload");
      }
      const PlanMutationResult result = governor.create_plan(plan_request, context);
      response.message = WireMessageId::CREATE_PLAN_RESPONSE;
      response.payload = encode_payload(result);
      return response;
    }
    case WireMessageId::QUERY_PLAN: {
      ConvergencePlanId plan;
      PlanQueryBody body;
      if (decode_payload(request.payload, options.limits, plan)) {
        const std::optional<PlanSummary> summary = governor.query_plan(plan);
        body.found = summary.has_value();
        if (summary.has_value()) {
          body.summary = *summary;
        }
      }
      response.message = WireMessageId::QUERY_PLAN_RESPONSE;
      response.payload = encode_payload(body);
      return response;
    }
    case WireMessageId::LIST_PLANS: {
      response.message = WireMessageId::LIST_PLANS_RESPONSE;
      response.payload = encode_payload(governor.list_plans());
      return response;
    }
    case WireMessageId::STEP_READY: {
      StepReadyRequest ready_request;
      if (!decode_payload(request.payload, options.limits, ready_request)) {
        ready_request.max_steps = options.limits.max_parallel_steps;
      }
      // Work is offered only inside a registered authority scope.  An
      // unregistered session is refused rather than answered with an empty list,
      // because an empty answer and a denied answer are different facts.
      const std::optional<PublisherRegistration> registration =
          governor.worker_registration(request.publisher);
      if (!registration.has_value()) {
        return error_response(request, epoch, ConditionCode::PUBLISHER_UNKNOWN,
                              Outcome::UNAUTHORIZED, "ready-step query requires a registration");
      }
      response.message = WireMessageId::STEP_READY_RESPONSE;
      response.payload = encode_payload(
          governor.ready_steps_for(ready_request.max_steps, registration->scope));
      return response;
    }
    case WireMessageId::DISPATCH_STEP: {
      DispatchStepRequest dispatch_request;
      if (!decode_payload(request.payload, options.limits, dispatch_request)) {
        return malformed("dispatch step payload");
      }
      const StepDispatch body =
          governor.dispatch_step(dispatch_request.plan, dispatch_request.step, context);
      response.message = WireMessageId::DISPATCH_STEP_RESPONSE;
      response.payload = encode_payload(body);
      return response;
    }
    case WireMessageId::COMPLETE_STEP: {
      CompletionEvidence evidence;
      if (!decode_payload(request.payload, options.limits, evidence)) {
        return malformed("completion evidence payload");
      }
      const PlanMutationResult result = governor.complete_step(evidence, context);
      response.message = WireMessageId::COMPLETE_STEP_RESPONSE;
      response.payload = encode_payload(result);
      return response;
    }
    case WireMessageId::FAIL_STEP: {
      FailStepRequest fail_request;
      if (!decode_payload(request.payload, options.limits, fail_request)) {
        return malformed("fail step payload");
      }
      const PlanMutationResult result =
          governor.fail_step(fail_request.plan, fail_request.step, fail_request.outcome,
                             fail_request.detail, context);
      response.message = WireMessageId::FAIL_STEP_RESPONSE;
      response.payload = encode_payload(result);
      return response;
    }
    case WireMessageId::RECONCILE_STEP: {
      ReconcileStepRequest reconcile_request;
      if (!decode_payload(request.payload, options.limits, reconcile_request)) {
        return malformed("reconcile payload");
      }
      const PlanMutationResult result = governor.reconcile_step(
          reconcile_request.plan, reconcile_request.step, reconcile_request.applied,
          reconcile_request.detail, context);
      response.message = WireMessageId::RECONCILE_STEP_RESPONSE;
      response.payload = encode_payload(result);
      return response;
    }
    case WireMessageId::REVALIDATE_PLAN:
    case WireMessageId::BEGIN_ROLLBACK:
    case WireMessageId::RETIRE_PLAN:
    case WireMessageId::REVOKE_PLAN: {
      ConvergencePlanId plan;
      if (!decode_payload(request.payload, options.limits, plan)) {
        return malformed("plan identity payload");
      }
      PlanMutationResult result;
      switch (request.message) {
        case WireMessageId::REVALIDATE_PLAN:
          result = governor.revalidate_plan(plan, context);
          response.message = WireMessageId::REVALIDATE_PLAN_RESPONSE;
          break;
        case WireMessageId::BEGIN_ROLLBACK:
          result = governor.begin_rollback(plan, context);
          response.message = WireMessageId::BEGIN_ROLLBACK_RESPONSE;
          break;
        case WireMessageId::RETIRE_PLAN:
          result = governor.retire_plan(plan, context);
          response.message = WireMessageId::RETIRE_PLAN_RESPONSE;
          break;
        default:
          result = governor.revoke_plan(plan, context);
          response.message = WireMessageId::REVOKE_PLAN_RESPONSE;
          break;
      }
      response.payload = encode_payload(result);
      return response;
    }
    case WireMessageId::PAUSE_PLAN: {
      PausePlanRequest pause_request;
      if (!decode_payload(request.payload, options.limits, pause_request)) {
        return malformed("pause payload");
      }
      const PlanMutationResult result =
          governor.pause_plan(pause_request.plan, pause_request.cause, context);
      response.message = WireMessageId::PAUSE_PLAN_RESPONSE;
      response.payload = encode_payload(result);
      return response;
    }
    case WireMessageId::SNAPSHOT_REQUEST: {
      ConvergencePlanId plan;
      SnapshotBody body;
      if (decode_payload(request.payload, options.limits, plan)) {
        const std::optional<ConvergenceSnapshot> snapshot = governor.snapshot(plan);
        body.found = snapshot.has_value();
        if (snapshot.has_value()) {
          body.snapshot = *snapshot;
        }
      }
      response.message = WireMessageId::SNAPSHOT_RESPONSE;
      response.payload = encode_payload(body);
      return response;
    }
    case WireMessageId::DIFF_REQUEST: {
      DiffRequestBody diff_request;
      DiffBody body;
      if (decode_payload(request.payload, options.limits, diff_request)) {
        const std::optional<ConvergenceDiff> diff =
            governor.diff(diff_request.plan, diff_request.from);
        body.found = diff.has_value();
        if (diff.has_value()) {
          body.diff = *diff;
        }
      }
      response.message = WireMessageId::DIFF_RESPONSE;
      response.payload = encode_payload(body);
      return response;
    }
    case WireMessageId::EXPLAIN_REQUEST: {
      ExplainRequest explain_request;
      ExplainResponse body;
      if (decode_payload(request.payload, options.limits, explain_request)) {
        body = governor.explain(explain_request);
      }
      response.message = WireMessageId::EXPLAIN_RESPONSE;
      response.payload = encode_payload(body);
      return response;
    }
    case WireMessageId::ROUTE_CHANGE: {
      RouteChangeNotice notice;
      NoticeResult body;
      if (!decode_payload(request.payload, options.limits, notice)) {
        body.outcome = Outcome::MALFORMED_REQUEST;
        body.conditions.add(
            make_condition(ConditionCode::MALFORMED_PAYLOAD, "route change payload"));
      } else if (options.synthetic_upstream == nullptr) {
        body.outcome = Outcome::UNSUPPORTED;
        body.conditions.add(
            make_condition(ConditionCode::BACKEND_UNSUPPORTED, "no upstream feed attached"));
      } else {
        options.synthetic_upstream->set_route(notice.binding);
        body = governor.note_route_change(notice, context);
      }
      response.message = WireMessageId::ROUTE_CHANGE_RESPONSE;
      response.payload = encode_payload(body);
      return response;
    }
    case WireMessageId::PATH_CHANGE: {
      PathChangeNotice notice;
      NoticeResult body;
      if (!decode_payload(request.payload, options.limits, notice)) {
        body.outcome = Outcome::MALFORMED_REQUEST;
        body.conditions.add(
            make_condition(ConditionCode::MALFORMED_PAYLOAD, "path change payload"));
      } else if (options.synthetic_upstream == nullptr) {
        body.outcome = Outcome::UNSUPPORTED;
        body.conditions.add(
            make_condition(ConditionCode::BACKEND_UNSUPPORTED, "no upstream feed attached"));
      } else {
        options.synthetic_upstream->set_path(notice.legality);
        body = governor.note_path_change(notice, context);
      }
      response.message = WireMessageId::PATH_CHANGE_RESPONSE;
      response.payload = encode_payload(body);
      return response;
    }
    case WireMessageId::EPOCH_CHANGE: {
      EpochChangeNotice notice;
      NoticeResult body;
      if (!decode_payload(request.payload, options.limits, notice)) {
        body.outcome = Outcome::MALFORMED_REQUEST;
        body.conditions.add(
            make_condition(ConditionCode::MALFORMED_PAYLOAD, "epoch change payload"));
      } else if (options.synthetic_upstream == nullptr) {
        body.outcome = Outcome::UNSUPPORTED;
        body.conditions.add(
            make_condition(ConditionCode::BACKEND_UNSUPPORTED, "no upstream feed attached"));
      } else {
        options.synthetic_upstream->set_epoch(notice.current);
        body = governor.note_epoch_change(notice, context);
      }
      response.message = WireMessageId::EPOCH_CHANGE_RESPONSE;
      response.payload = encode_payload(body);
      return response;
    }
    default:
      return error_response(request, epoch, ConditionCode::WIRE_UNKNOWN_MESSAGE,
                            Outcome::WIRE_REJECTED, "unsupported request");
  }
}

void CoordinatorServer::Impl::serve_connection(const std::shared_ptr<TcpConnection>& connection) {
  WorkerBootId session_boot;
  PublisherId session_publisher;
  std::string error;
  for (;;) {
    if (stopping.load()) {
      break;
    }
    if (sessions.load() > options.limits.max_sessions) {
      break;
    }
    std::vector<std::uint8_t> header(kWireHeaderBytes, 0);
    const ReceiveStatus status =
        connection->receive_exactly(header, options.receive_deadline_ms, error);
    if (status != ReceiveStatus::OK) {
      break;
    }
    const std::uint32_t payload_bytes =
        static_cast<std::uint32_t>(header[kWireHeaderBytes - 8]) |
        (static_cast<std::uint32_t>(header[kWireHeaderBytes - 7]) << 8) |
        (static_cast<std::uint32_t>(header[kWireHeaderBytes - 6]) << 16) |
        (static_cast<std::uint32_t>(header[kWireHeaderBytes - 5]) << 24);
    if (payload_bytes > options.limits.max_frame_bytes) {
      Envelope failure;
      failure.message = WireMessageId::ERROR;
      failure.epoch = governor.epoch();
      ErrorBody body;
      body.code = ConditionCode::FRAME_LIMIT;
      body.outcome = Outcome::WIRE_REJECTED;
      body.detail = "declared frame length exceeds the configured limit";
      failure.payload = encode_payload(body);
      (void)write_frame(*connection, failure, options.limits, error);
      break;
    }
    std::vector<std::uint8_t> frame = header;
    frame.resize(kWireHeaderBytes + payload_bytes + kWireTagBytes, 0);
    const ReceiveStatus rest = connection->receive_exactly(
        std::span<std::uint8_t>(frame.data() + kWireHeaderBytes, payload_bytes + kWireTagBytes),
        options.receive_deadline_ms, error);
    if (rest != ReceiveStatus::OK) {
      break;
    }
    Envelope request;
    const WireDefect defect = decode_frame(frame, options.limits, request);
    if (defect != WireDefect::NONE) {
      Envelope failure;
      failure.message = WireMessageId::ERROR;
      failure.epoch = governor.epoch();
      ErrorBody body;
      body.code = condition_for(defect);
      body.outcome = Outcome::WIRE_REJECTED;
      body.detail = std::string(to_string(defect));
      failure.payload = encode_payload(body);
      (void)write_frame(*connection, failure, options.limits, error);
      break;
    }
    if (governor.is_worker_fenced(request.worker_boot)) {
      Envelope notice;
      notice.message = WireMessageId::FENCE_NOTICE;
      notice.epoch = governor.epoch();
      (void)write_frame(*connection, notice, options.limits, error);
      break;
    }

    session_connection = connection;
    const Envelope response = dispatch(request);
    session_connection.reset();
    if (request.message == WireMessageId::REGISTER_WORKER &&
        response.message == WireMessageId::REGISTER_WORKER_RESPONSE) {
      session_boot = request.worker_boot;
      session_publisher = request.publisher;
    }
    // An acknowledgement is sent only after the mutation is durable, so a
    // coordinator that is killed immediately after replying loses nothing that
    // it already told a client it had accepted.
    if (options.autosave && !options.store_path.empty()) {
      const PlanMutationResult saved = governor.save(options.store_path);
      if (!saved.accepted()) {
        Envelope failure;
        failure.message = WireMessageId::ERROR;
        failure.epoch = governor.epoch();
        ErrorBody body;
        body.code = ConditionCode::STORE_IO;
        body.outcome = Outcome::STORE_ERROR;
        body.detail = "durable store could not be written";
        failure.payload = encode_payload(body);
        (void)write_frame(*connection, failure, options.limits, error);
        break;
      }
    }
    if (!write_frame(*connection, response, options.limits, error)) {
      break;
    }
    const std::uint64_t handled_before = handled.fetch_add(1);
    if (options.max_requests != 0 && handled_before + 1 >= options.max_requests) {
      stopping.store(true);
      break;
    }
  }
  forget(session_boot, connection);
  // A session that ends fences the boot it registered: connected is not
  // authorized, and a disconnected worker cannot complete in-flight work.
  if (!session_boot.is_nil()) {
    (void)governor.fence_session_loss(session_publisher, session_boot);
  }
  connection->shutdown();
  connection->close();
  sessions.fetch_sub(1);
}

CoordinatorServer::CoordinatorServer(ConvergenceGovernor& governor,
                                     CoordinatorServerOptions options)
    : impl_(std::make_unique<Impl>(governor, std::move(options))) {}

CoordinatorServer::~CoordinatorServer() {
  stop();
  // The accept loop joins every session it started; a server that was never
  // served has no sessions to join.
}

bool CoordinatorServer::start(std::string& error) {
  std::optional<TcpListener> listener = TcpListener::bind_loopback(impl_->options.port, error);
  if (!listener.has_value()) {
    return false;
  }
  impl_->listener = std::move(*listener);
  return true;
}

std::uint16_t CoordinatorServer::port() const { return impl_->listener.port(); }

void CoordinatorServer::serve() {
  if (!impl_->listener.valid()) {
    return;
  }
  // The listening socket is polled with a bounded wait so that stop() is
  // honoured promptly without ever terminating a socket another thread is using.
  while (!impl_->stopping.load()) {
    std::string error;
    std::optional<TcpConnection> connection = impl_->listener.accept(error, 50);
    if (!connection.has_value()) {
      impl_->reap_finished();
      continue;
    }
    if (impl_->sessions.load() >= impl_->options.limits.max_sessions) {
      connection->shutdown();
      connection->close();
      continue;
    }
    impl_->sessions.fetch_add(1);
    const auto shared = std::make_shared<TcpConnection>(std::move(*connection));
    auto done = std::make_shared<std::atomic<bool>>(false);
    Impl::Session session;
    session.done = done;
    session.thread = std::thread([this, shared, done]() {
      impl_->serve_connection(shared);
      done->store(true);
    });
    {
      const std::lock_guard<std::mutex> lock(impl_->mutex);
      impl_->workers.push_back(std::move(session));
    }
    impl_->reap_finished();
  }
  {
    const std::lock_guard<std::mutex> lock(impl_->mutex);
    for (Impl::Session& session : impl_->workers) {
      if (session.thread.joinable()) {
        session.thread.join();
      }
    }
    impl_->workers.clear();
  }
  impl_->listener.close();
}


void CoordinatorServer::stop() {
  if (impl_ == nullptr) {
    return;
  }
  impl_->stopping.store(true);
  impl_->listener.close();
}

std::uint32_t CoordinatorServer::active_sessions() const { return impl_->sessions.load(); }

std::uint64_t CoordinatorServer::handled_requests() const { return impl_->handled.load(); }

}  // namespace rc
