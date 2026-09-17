#include <algorithm>
#include <set>
#include <string>

#include "governor_state.hpp"
#include "rc/backend.hpp"
#include "rc/bytes.hpp"
#include "rc/graph.hpp"

namespace rc {
namespace {

void apply_epoch_locked(GovernorState& state) {
  const CoordinatorEpoch observed = state.epochs.current_epoch();
  if (observed.value() > state.epoch.value()) {
    apply_epoch(state, observed, ChangeReason::EPOCH_ADVANCE, epoch_provenance(observed));
  }
}

[[nodiscard]] std::string canonical_request_text(const PlanRequest& request) {
  std::string out = request.source.render();
  out += '|';
  out += request.target.render();
  out += '|';
  out += request.policy.render();
  out += "|mode=";
  out += to_string(request.mode);
  out += "|historical=";
  out += request.accept_historical_source ? "1" : "0";
  out += "|steps=";
  out += std::to_string(request.explicit_steps.size());
  for (const StepSpec& step : request.explicit_steps) {
    out += '|';
    out += step.key().render();
    for (const StepKey& dependency : step.depends_on) {
      out += '<';
      out += dependency.render();
    }
  }
  return out;
}

[[nodiscard]] bool step_satisfied(const ConvergencePlan& plan, const StepKey& key) {
  for (const TransitionStep& step : plan.steps) {
    if (step.spec.key() == key) {
      return step.is_satisfied();
    }
  }
  return false;
}

[[nodiscard]] bool plan_has_blocking_step(const ConvergencePlan& plan) {
  for (const TransitionStep& step : plan.steps) {
    switch (step.state) {
      case StepLifecycle::DISPATCHED:
      case StepLifecycle::RECONCILIATION_REQUIRED:
      case StepLifecycle::ROLLBACK_PENDING:
      case StepLifecycle::STALE:
        return true;
      default:
        break;
    }
  }
  return false;
}

[[nodiscard]] bool mandatory_steps_complete(const ConvergencePlan& plan) {
  for (const TransitionStep& step : plan.steps) {
    if (step.spec.mandatory && !step.is_satisfied()) {
      return false;
    }
  }
  return true;
}

// Closes the lineage of a plan that just reached COMPLETED.
void complete_lineage(GovernorState& state, ConvergencePlan& plan) {
  if (plan.is_rollback && !plan.predecessor.is_nil()) {
    const auto entry = state.plans.find(plan.predecessor);
    if (entry != state.plans.end()) {
      ConvergencePlan& forward = entry->second;
      if (forward.lifecycle == PlanLifecycle::ROLLING_BACK) {
        const std::optional<PlanLifecycle> next =
            apply_plan_event(forward.lifecycle, PlanEvent::ROLLBACK_COMPLETED,
                             PlanTransitionInputs{});
        if (next.has_value()) {
          forward.lifecycle = *next;
          forward.supersession_reason = ChangeReason::ROLLBACK_COMPLETED;
          forward.successor = plan.id;
          forward.currentness.add(CurrentnessCause::SUPERSEDED_BY_SUCCESSOR);
          forward.rollback_required = false;
          if (advance_convergence(state)) {
            forward.watermark = state.convergence;
          }
          (void)touch_plan(state, forward, ChangeReason::ROLLBACK_COMPLETED, ConditionCode::NONE,
                           TransitionStepId{});
          reindex_plan(state, forward);
        }
      }
    }
  }
  if (plan.policy.supersede_predecessor_on_success && !plan.predecessor.is_nil()) {
    supersede_entry(state, plan.predecessor, ChangeReason::SUPERSEDE, plan.id);
  }
}

// Performs the completion commit.  The caller holds the exclusive lock, has
// resolved the plan and has authorized the authority claim.
[[nodiscard]] PlanMutationResult apply_completion(GovernorState& state, ConvergencePlan& plan,
                                                  const CompletionEvidence& evidence,
                                                  const AuthorityContext& authority) {
  const std::string payload_text =
      evidence.id.to_text() + ':' + authority.attempt.to_text() + ':' +
      std::string(to_string(evidence.outcome));
  const Digest payload = request_digest("rc.attempt.complete.v1", plan.key, payload_text);
  PlanMutationResult replay;
  switch (check_attempt(state, authority, payload, replay)) {
    case AttemptCheck::REPLAY:
      replay.outcome = Outcome::IDEMPOTENT;
      return replay;
    case AttemptCheck::CONFLICT:
      return rejection(Outcome::ATTEMPT_CONFLICT, ConditionCode::ATTEMPT_CONFLICT,
                       authority.attempt.to_text());
    case AttemptCheck::FRESH:
      break;
  }

  TransitionStep* step = plan.find_step(evidence.step);
  if (step == nullptr) {
    return rejection(Outcome::UNKNOWN_STEP, ConditionCode::STEP_UNKNOWN, evidence.step.to_text());
  }

  if (step->state == StepLifecycle::COMPLETED) {
    if (step->last_evidence == evidence.id) {
      PlanMutationResult result = make_result(state, Outcome::IDEMPOTENT, plan);
      result.step = step->id;
      result.step_generation = step->generation;
      record_attempt(state, authority, payload, result);
      return result;
    }
    ++state.stats.stale_completions_rejected;
    return rejection(Outcome::STALE_STEP, ConditionCode::COMPLETION_STALE, evidence.step.to_text());
  }
  if (step->state != StepLifecycle::DISPATCHED) {
    ++state.stats.stale_completions_rejected;
    return rejection(Outcome::STALE_STEP, ConditionCode::STEP_STALE, step->spec.key().render());
  }
  if (!(evidence.step_generation == step->generation)) {
    ++state.stats.stale_completions_rejected;
    return rejection(Outcome::STALE_STEP, ConditionCode::STEP_GENERATION_MISMATCH,
                     step->spec.key().render(), evidence.step_generation.value(),
                     step->generation.value());
  }
  if (!(evidence.epoch == state.epoch)) {
    ++state.stats.stale_completions_rejected;
    return rejection(Outcome::STALE_EPOCH, ConditionCode::AUTHORITY_EPOCH_STALE, "epoch",
                     evidence.epoch.value(), state.epoch.value());
  }
  if (!(evidence.worker_boot == step->dispatch_boot) ||
      !(evidence.publisher == step->dispatch_publisher)) {
    ++state.stats.stale_completions_rejected;
    return rejection(Outcome::STALE_WORKER, ConditionCode::WORKER_FENCED,
                     evidence.worker_boot.to_text());
  }
  if (!worker_live_locked(state, evidence.publisher, evidence.worker_boot)) {
    ++state.stats.stale_completions_rejected;
    return rejection(Outcome::STALE_WORKER, ConditionCode::WORKER_FENCED,
                     evidence.worker_boot.to_text());
  }
  if (!(evidence.dispatch_watermark == step->dispatch_watermark) ||
      !(step->dispatch_watermark == plan.watermark)) {
    ++state.stats.stale_completions_rejected;
    return rejection(Outcome::STALE_STEP, ConditionCode::WATERMARK_EXCEEDED,
                     step->spec.key().render(), plan.watermark.value(),
                     step->dispatch_watermark.value());
  }
  if (!(evidence.attempt == step->last_attempt)) {
    ++state.stats.stale_completions_rejected;
    return rejection(Outcome::STALE_STEP, ConditionCode::EVIDENCE_GENERATION_MISMATCH,
                     evidence.attempt.to_text());
  }

  ConditionList currentness_conditions(state.options.limits.max_explanation_entries);
  if (!recompute_currentness(state, plan, currentness_conditions)) {
    invalidate_plan(state, plan, CurrentnessCause::REVALIDATION_REQUIRED, ChangeReason::INVALIDATE);
    ++state.stats.stale_completions_rejected;
    PlanMutationResult result = make_result(state, Outcome::REVALIDATION_REQUIRED, plan);
    result.step = step->id;
    for (const Condition& item : currentness_conditions.entries()) {
      result.conditions.add(item);
    }
    return result;
  }

  const RouteGeneration expected = expected_observation(plan);
  const std::optional<RouteBinding> observed = state.routes.observe_route(plan.key.route);
  if (!observed.has_value() || !(observed->generation == expected) || !observed->legal) {
    ++state.stats.stale_completions_rejected;
    invalidate_plan(state, plan, CurrentnessCause::STALE_TARGET_ROUTE, ChangeReason::INVALIDATE);
    return rejection(Outcome::STALE_ROUTE, ConditionCode::TARGET_ROUTE_STALE,
                     plan.key.route.to_text(),
                     observed.has_value() ? observed->generation.value() : 0, expected.value());
  }
  // A step that establishes or verifies the target path must still be executing
  // against a currently authorized path.  A step that removes old state is not
  // gated on the old state's authority: removing a path that has lost its
  // authority is exactly what a convergence plan is for.
  const bool requires_path_authority =
      !step->spec.path.is_nil() &&
      (is_make_step(step->spec.kind) || step->spec.kind == StepKind::VALIDATE_TARGET);
  if (requires_path_authority) {
    const std::optional<PathLegality> legality = state.paths.observe_path(step->spec.path);
    if (!legality.has_value() || !(legality->generation == step->spec.path_authority_generation) ||
        !legality->legal) {
      ++state.stats.stale_completions_rejected;
      invalidate_plan(state, plan, CurrentnessCause::STALE_PATH_AUTHORITY, ChangeReason::INVALIDATE);
      return rejection(Outcome::STALE_PATH_AUTHORITY, ConditionCode::PATH_AUTHORITY_STALE,
                       step->spec.path.to_text(),
                       legality.has_value() ? legality->generation.value() : 0,
                       step->spec.path_authority_generation.value());
    }
  }

  step->last_evidence = evidence.id;
  step->last_change = ChangeReason::COMPLETE_STEP;

  switch (evidence.outcome) {
    case BackendOutcome::APPLIED:
    case BackendOutcome::IDEMPOTENT: {
      const std::optional<StepLifecycle> next = apply_step_event(step->state, StepEvent::COMPLETE);
      if (!next.has_value()) {
        return rejection(Outcome::INTERNAL_ERROR, ConditionCode::LIFECYCLE_DENIED,
                         to_string(step->state));
      }
      step->state = *next;
      step->last_condition = ConditionCode::NONE;
      ++state.stats.steps_completed;
      break;
    }
    case BackendOutcome::AMBIGUOUS: {
      step->state = StepLifecycle::RECONCILIATION_REQUIRED;
      step->last_condition = ConditionCode::AMBIGUOUS_SIDE_EFFECT;
      ++state.stats.ambiguous_steps;
      const std::optional<PlanLifecycle> paused =
          apply_plan_event(plan.lifecycle, PlanEvent::STEP_AMBIGUOUS, PlanTransitionInputs{});
      if (paused.has_value()) {
        plan.lifecycle = *paused;
      }
      plan.currentness.add(CurrentnessCause::REVALIDATION_REQUIRED);
      (void)touch_plan(state, plan, ChangeReason::AMBIGUOUS_STEP,
                       ConditionCode::AMBIGUOUS_SIDE_EFFECT, step->id);
      reindex_plan(state, plan);
      PlanMutationResult result =
          make_result(state, Outcome::AMBIGUOUS_SIDE_EFFECT, plan,
                      ConditionCode::AMBIGUOUS_SIDE_EFFECT, step->spec.key().render());
      result.step = step->id;
      result.step_generation = step->generation;
      record_attempt(state, authority, payload, result);
      return result;
    }
    case BackendOutcome::RETRYABLE_FAILURE:
    case BackendOutcome::PERMANENT_FAILURE:
    case BackendOutcome::UNSUPPORTED:
    case BackendOutcome::STALE: {
      const bool retryable = evidence.outcome == BackendOutcome::RETRYABLE_FAILURE;
      const std::optional<StepLifecycle> next = apply_step_event(
          step->state, retryable ? StepEvent::FAIL_RETRYABLE : StepEvent::FAIL_PERMANENT);
      step->state = next.value_or(StepLifecycle::FAILED);
      step->last_condition = evidence.outcome == BackendOutcome::UNSUPPORTED
                                 ? ConditionCode::BACKEND_UNSUPPORTED
                                 : ConditionCode::NONE;
      ++state.stats.steps_failed;

      // A retryable failure re-arms the step when the operation is declared
      // idempotent and both the bound policy and the configured limit still allow
      // another attempt.  It does not pause the plan: pause means "waiting for a
      // dependency", not "this attempt failed".
      const std::uint32_t retry_bound = std::min(plan.policy.max_retries_per_step,
                                                 state.options.limits.max_retries_per_step);
      bool rearmed = false;
      if (retryable) {
        step->last_condition = ConditionCode::NONE;
        if (step->spec.idempotent && step->attempts <= retry_bound) {
          const std::optional<StepLifecycle> rearm =
              apply_step_event(step->state, StepEvent::MARK_READY);
          if (rearm.has_value()) {
            step->state = *rearm;
            rearmed = true;
          }
        }
      }
      if (!rearmed) {
        PlanTransitionInputs inputs;
        inputs.rollback_required = !retryable;
        const std::optional<PlanLifecycle> transition =
            apply_plan_event(plan.lifecycle, PlanEvent::STEP_FAILED, inputs);
        if (transition.has_value()) {
          plan.lifecycle = *transition;
          if (plan.lifecycle == PlanLifecycle::ROLLBACK_REQUIRED) {
            plan.rollback_required = true;
          }
        }
      }
      (void)touch_plan(state, plan, ChangeReason::FAIL_STEP, step->last_condition, step->id);
      reindex_plan(state, plan);
      PlanMutationResult result = make_result(
          state, retryable ? Outcome::RETRYABLE_FAILURE : Outcome::PERMANENT_FAILURE, plan);
      result.step = step->id;
      result.step_generation = step->generation;
      record_attempt(state, authority, payload, result);
      return result;
    }
  }

  (void)touch_plan(state, plan, ChangeReason::COMPLETE_STEP, ConditionCode::NONE, step->id);

  std::vector<TransitionStepId> pending_before;
  for (const TransitionStep& candidate : plan.steps) {
    if (candidate.state == StepLifecycle::PENDING) {
      pending_before.push_back(candidate.id);
    }
  }
  refresh_ready_steps(state, plan);
  for (const TransitionStepId& id : pending_before) {
    const TransitionStep* candidate = plan.find_step(id);
    if (candidate != nullptr && candidate->state == StepLifecycle::READY) {
      (void)touch_plan(state, plan, ChangeReason::STEP_READY, ConditionCode::NONE, id);
    }
  }
  reindex_plan(state, plan);

  if (plan.lifecycle == PlanLifecycle::EXECUTING && mandatory_steps_complete(plan) &&
      !plan_has_blocking_step(plan)) {
    for (TransitionStep& candidate : plan.steps) {
      if (!candidate.is_satisfied()) {
        const std::optional<StepLifecycle> skipped =
            apply_step_event(candidate.state, StepEvent::SKIP);
        if (skipped.has_value()) {
          candidate.state = *skipped;
          candidate.last_change = ChangeReason::COMPLETE_STEP;
        }
      }
    }
    PlanTransitionInputs inputs;
    inputs.mandatory_steps_terminal = true;
    inputs.target_current = true;
    inputs.dependency_current = true;
    inputs.policy_current = true;
    const std::optional<PlanLifecycle> completed =
        apply_plan_event(plan.lifecycle, PlanEvent::ALL_STEPS_TERMINAL, inputs);
    if (completed.has_value()) {
      plan.lifecycle = *completed;
      ++state.stats.plans_completed;
      complete_lineage(state, plan);
    }
    // Step skips and the terminal lifecycle are semantic content, so the plan
    // digest and generation are recomputed after them.  A completion whose
    // digest did not describe the completed plan could not be recovered from a
    // durable store.
    (void)touch_plan(state, plan, ChangeReason::COMPLETE_STEP, ConditionCode::NONE,
                     TransitionStepId{});
  }

  PlanMutationResult result =
      make_result(state,
                  plan.lifecycle == PlanLifecycle::COMPLETED ? Outcome::PLAN_COMPLETED
                                                             : Outcome::STEP_COMPLETED,
                  plan);
  result.step = step->id;
  result.step_generation = step->generation;
  record_attempt(state, authority, payload, result);
  return result;
}

}  // namespace

// --- convergence policy registry -------------------------------------------

PlanMutationResult ConvergenceGovernor::define_policy(const ConvergencePolicy& policy,
                                                      const AuthorityContext& authority) {
  GovernorState& state = *impl_->state;
  const std::unique_lock<std::shared_mutex> lock(state.mutex);
  apply_epoch_locked(state);

  Condition condition;
  if (!authorize(state, authority, Capability::ADMIN, RouteId{}, ConvergencePlanId{}, condition)) {
    return rejection(Outcome::UNAUTHORIZED, condition.code, condition.subject, condition.observed,
                     condition.expected);
  }
  if (!policy.is_well_formed()) {
    return rejection(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_PAYLOAD, "policy");
  }
  std::string reason;
  if (!policy.is_coherent(reason)) {
    return rejection(Outcome::MALFORMED_REQUEST, ConditionCode::POLICY_INCOHERENT, reason);
  }

  const Digest payload = text_digest("rc.attempt.define_policy.v1", policy.render());
  PlanMutationResult replay;
  if (attempt_gate(state, authority, payload, replay)) {
    return replay;
  }

  const auto existing = state.policies.find(policy.id);
  if (existing == state.policies.end()) {
    state.policies[policy.id] = policy;
    ++state.stats.policies_defined;
    PlanMutationResult result{Outcome::POLICY_DEFINED};
    record_attempt(state, authority, payload, result);
    return result;
  }
  if (existing->second.content_digest() == policy.content_digest()) {
    PlanMutationResult result{Outcome::IDEMPOTENT};
    record_attempt(state, authority, payload, result);
    return result;
  }
  const std::optional<ConvergencePolicyGeneration> next = existing->second.generation.next();
  if (!next.has_value()) {
    return rejection(Outcome::GENERATION_EXHAUSTED, ConditionCode::GENERATION_EXHAUSTED,
                     policy.id.to_text());
  }
  if (!(policy.generation == *next)) {
    return rejection(Outcome::STALE_POLICY, ConditionCode::POLICY_GENERATION_STALE,
                     policy.id.to_text(), policy.generation.value(), next->value());
  }
  state.policies[policy.id] = policy;
  ++state.stats.policies_defined;
  PlanMutationResult result{Outcome::POLICY_DEFINED};
  record_attempt(state, authority, payload, result);
  return result;
}

std::optional<ConvergencePolicy> ConvergenceGovernor::current_policy(
    const ConvergencePolicyId& id) const {
  const GovernorState& state = *impl_->state;
  const std::shared_lock<std::shared_mutex> lock(state.mutex);
  const auto entry = state.policies.find(id);
  if (entry == state.policies.end()) {
    return std::nullopt;
  }
  return entry->second;
}

std::vector<ConvergencePolicy> ConvergenceGovernor::list_policies() const {
  const GovernorState& state = *impl_->state;
  const std::shared_lock<std::shared_mutex> lock(state.mutex);
  std::vector<ConvergencePolicy> out;
  out.reserve(state.policies.size());
  for (const auto& entry : state.policies) {
    out.push_back(entry.second);
  }
  return out;
}

// --- worker registry and fencing -------------------------------------------

PlanMutationResult ConvergenceGovernor::register_worker(const PublisherRegistration& registration,
                                                        const AuthorityContext& authority) {
  GovernorState& state = *impl_->state;
  const std::unique_lock<std::shared_mutex> lock(state.mutex);
  apply_epoch_locked(state);

  if (!state.coherent) {
    return rejection(Outcome::INTERNAL_ERROR, ConditionCode::INTERNAL_INVARIANT,
                     state.incoherence_reason);
  }
  if (!registration.is_well_formed()) {
    return rejection(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_PAYLOAD, "registration");
  }
  if (!(authority.epoch == state.epoch)) {
    return rejection(Outcome::STALE_EPOCH, ConditionCode::AUTHORITY_EPOCH_STALE, "epoch",
                     authority.epoch.value(), state.epoch.value());
  }
  if (!(authority.publisher == registration.publisher) ||
      !(authority.worker_boot == registration.worker_boot)) {
    return rejection(Outcome::UNAUTHORIZED, ConditionCode::MALFORMED_IDENTITY, "registration");
  }
  if (state.fenced_boots.find(registration.worker_boot) != state.fenced_boots.end()) {
    return rejection(Outcome::STALE_WORKER, ConditionCode::WORKER_FENCED,
                     registration.worker_boot.to_text());
  }

  const Digest payload = text_digest("rc.attempt.register_worker.v1",
                                     registration.publisher.to_text() +
                                         registration.worker_boot.to_text() +
                                         std::to_string(registration.capabilities) +
                                         registration.scope.render());
  PlanMutationResult replay;
  if (attempt_gate(state, authority, payload, replay)) {
    return replay;
  }

  const auto existing = state.workers.find(registration.publisher);
  if (existing != state.workers.end()) {
    if (existing->second.registration.worker_boot == registration.worker_boot) {
      if (!(existing->second.registration.scope == registration.scope) ||
          existing->second.registration.capabilities != registration.capabilities) {
        return rejection(Outcome::ATTEMPT_CONFLICT, ConditionCode::ATTEMPT_CONFLICT,
                         registration.publisher.to_text());
      }
      // Re-registration revives a session-loss fence; a permanent fence was
      // already refused above.
      existing->second.live = true;
      return PlanMutationResult{Outcome::IDEMPOTENT};
    }
    fence_boot(state, existing->second.registration.worker_boot, ChangeReason::WORKER_FENCE);
  } else if (state.workers.size() >= state.options.limits.max_workers) {
    return rejection(Outcome::RESOURCE_LIMIT, ConditionCode::WORKER_LIMIT, "workers",
                     static_cast<std::uint64_t>(state.workers.size()),
                     state.options.limits.max_workers);
  }

  WorkerRecord record;
  record.registration = registration;
  record.live = true;
  state.workers[registration.publisher] = std::move(record);
  ++state.stats.workers_registered;
  PlanMutationResult result{Outcome::WORKER_REGISTERED};
  record_attempt(state, authority, payload, result);
  return result;
}

PlanMutationResult ConvergenceGovernor::fence_session_loss(const PublisherId& publisher,
                                                           const WorkerBootId& boot) {
  GovernorState& state = *impl_->state;
  const std::unique_lock<std::shared_mutex> lock(state.mutex);
  if (publisher.is_nil() || boot.is_nil()) {
    return rejection(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_IDENTITY, "session");
  }
  const auto entry = state.workers.find(publisher);
  if (entry == state.workers.end() || !(entry->second.registration.worker_boot == boot)) {
    // A reincarnated or already-fenced boot is nothing to do.
    return PlanMutationResult{Outcome::NO_CHANGE};
  }
  if (state.fenced_boots.find(boot) != state.fenced_boots.end()) {
    return PlanMutationResult{Outcome::IDEMPOTENT};
  }
  if (!entry->second.live) {
    return PlanMutationResult{Outcome::IDEMPOTENT};
  }
  // Session loss is a *soft* fence.  The boot stops being live immediately, so it
  // can neither dispatch nor complete anything, and its in-flight work is
  // invalidated.  Re-registering the same boot from the same publisher revives
  // it, which is what makes a legitimate reconnect different from a reincarnation
  // (that fences the old boot permanently) and from an administrative fence.
  entry->second.live = false;
  ++state.stats.worker_fences;
  stale_in_flight_steps_of_boot(state, boot, ChangeReason::WORKER_FENCE);
  return PlanMutationResult{Outcome::WORKER_FENCED};
}

PlanMutationResult ConvergenceGovernor::fence_worker(const WorkerBootId& boot,
                                                     const AuthorityContext& authority) {
  GovernorState& state = *impl_->state;
  const std::unique_lock<std::shared_mutex> lock(state.mutex);
  apply_epoch_locked(state);

  Condition condition;
  if (!authorize(state, authority, Capability::ADMIN, RouteId{}, ConvergencePlanId{}, condition)) {
    return rejection(Outcome::UNAUTHORIZED, condition.code, condition.subject, condition.observed,
                     condition.expected);
  }
  if (boot.is_nil()) {
    return rejection(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_IDENTITY, "boot");
  }
  const Digest payload = text_digest("rc.attempt.fence_worker.v1", boot.to_text());
  PlanMutationResult replay;
  if (attempt_gate(state, authority, payload, replay)) {
    return replay;
  }
  const bool already = state.fenced_boots.find(boot) != state.fenced_boots.end();
  fence_boot(state, boot, ChangeReason::WORKER_FENCE);
  PlanMutationResult result{already ? Outcome::IDEMPOTENT : Outcome::WORKER_FENCED};
  record_attempt(state, authority, payload, result);
  return result;
}

bool ConvergenceGovernor::is_worker_fenced(const WorkerBootId& boot) const {
  const GovernorState& state = *impl_->state;
  const std::shared_lock<std::shared_mutex> lock(state.mutex);
  return state.fenced_boots.find(boot) != state.fenced_boots.end();
}

bool ConvergenceGovernor::is_worker_live(const PublisherId& publisher,
                                         const WorkerBootId& boot) const {
  const GovernorState& state = *impl_->state;
  const std::shared_lock<std::shared_mutex> lock(state.mutex);
  return worker_live_locked(state, publisher, boot);
}

std::vector<PublisherRegistration> ConvergenceGovernor::list_workers() const {
  const GovernorState& state = *impl_->state;
  const std::shared_lock<std::shared_mutex> lock(state.mutex);
  std::vector<PublisherRegistration> out;
  out.reserve(state.workers.size());
  for (const auto& entry : state.workers) {
    out.push_back(entry.second.registration);
  }
  return out;
}

// --- plan creation ----------------------------------------------------------

PlanMutationResult ConvergenceGovernor::create_plan(const PlanRequest& request,
                                                    const AuthorityContext& authority) {
  GovernorState& state = *impl_->state;
  const std::unique_lock<std::shared_mutex> lock(state.mutex);
  apply_epoch_locked(state);

  Condition condition;
  if (!authorize(state, authority, Capability::CREATE_PLAN, request.target.route,
                 ConvergencePlanId{}, condition)) {
    return rejection(Outcome::UNAUTHORIZED, condition.code, condition.subject, condition.observed,
                     condition.expected);
  }
  if (!request.is_well_formed()) {
    return rejection(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_PAYLOAD, "plan request");
  }

  const std::string request_text = canonical_request_text(request);
  const Digest payload = domain_digest(
      "rc.attempt.create_plan.v1",
      std::vector<std::uint8_t>(request_text.begin(), request_text.end()));
  PlanMutationResult replay;
  switch (check_attempt(state, authority, payload, replay)) {
    case AttemptCheck::REPLAY:
      replay.outcome = Outcome::IDEMPOTENT;
      return replay;
    case AttemptCheck::CONFLICT:
      return rejection(Outcome::ATTEMPT_CONFLICT, ConditionCode::ATTEMPT_CONFLICT,
                       authority.attempt.to_text());
    case AttemptCheck::FRESH:
      break;
  }

  const auto policy_entry = state.policies.find(request.policy.id);
  if (policy_entry == state.policies.end()) {
    return rejection(Outcome::UNKNOWN_POLICY, ConditionCode::POLICY_UNKNOWN,
                     request.policy.id.to_text());
  }
  if (!(policy_entry->second.generation == request.policy.generation) ||
      !(policy_entry->second.content_digest() == request.policy.content_digest())) {
    return rejection(Outcome::STALE_POLICY, ConditionCode::POLICY_GENERATION_STALE,
                     request.policy.id.to_text(), request.policy.generation.value(),
                     policy_entry->second.generation.value());
  }
  std::string incoherent;
  if (!request.policy.is_coherent(incoherent)) {
    return rejection(Outcome::MALFORMED_REQUEST, ConditionCode::POLICY_INCOHERENT, incoherent);
  }

  // Source currentness.  The source is current when Route Fabric still publishes
  // that exact generation, and it is the *immediately preceding* desired
  // generation when Route Fabric has already published the target.  Any other
  // source is an old generation that the caller must declare historical
  // explicitly; ambiguous currentness is never planned from.
  const std::optional<RouteBinding> observed = state.routes.observe_route(request.source.route);
  if (!observed.has_value()) {
    return rejection(Outcome::STALE_ROUTE, ConditionCode::SOURCE_ROUTE_UNKNOWN,
                     request.source.route.to_text());
  }
  const bool source_is_current = observed->generation == request.source.generation;
  const bool source_is_immediate_predecessor =
      observed->generation == request.target.generation &&
      request.source.generation.value() + 1u == request.target.generation.value();
  if (!source_is_current && !source_is_immediate_predecessor &&
      !request.accept_historical_source) {
    return rejection(Outcome::STALE_ROUTE, ConditionCode::SOURCE_ROUTE_STALE,
                     request.source.route.to_text(), observed->generation.value(),
                     request.source.generation.value());
  }
  if (!observed->legal) {
    return rejection(Outcome::STALE_ROUTE, ConditionCode::SOURCE_ROUTE_ILLEGAL,
                     request.source.route.to_text());
  }

  // Target currentness: the exact target generation must still be the
  // authoritative one and it must still be legal.
  if (!(observed->generation == request.target.generation)) {
    return rejection(Outcome::STALE_ROUTE, ConditionCode::TARGET_ROUTE_STALE,
                     request.target.route.to_text(), observed->generation.value(),
                     request.target.generation.value());
  }
  if (!observed->current) {
    return rejection(Outcome::STALE_ROUTE, ConditionCode::TARGET_ROUTE_STALE,
                     request.target.route.to_text(), 0, 1);
  }
  const std::optional<PathLegality> legality = state.paths.observe_path(request.target.path);
  if (!legality.has_value()) {
    return rejection(Outcome::STALE_PATH_AUTHORITY, ConditionCode::PATH_AUTHORITY_UNKNOWN,
                     request.target.path.to_text());
  }
  if (!(legality->generation == request.target.path_authority_generation)) {
    return rejection(Outcome::STALE_PATH_AUTHORITY, ConditionCode::PATH_AUTHORITY_STALE,
                     request.target.path.to_text(), legality->generation.value(),
                     request.target.path_authority_generation.value());
  }
  if (!legality->legal) {
    return rejection(Outcome::STALE_PATH_AUTHORITY, ConditionCode::PATH_AUTHORITY_UNAUTHORIZED,
                     request.target.path.to_text());
  }
  if (!(observed->multipath_generation == request.target.multipath_generation) ||
      !(observed->ecmp_generation == request.target.ecmp_generation) ||
      !(observed->assignment_generation == request.target.assignment_generation) ||
      !(observed->weight_policy_generation == request.target.weight_policy_generation)) {
    return rejection(Outcome::STALE_DEPENDENCY, ConditionCode::ECMP_GENERATION_STALE,
                     request.target.route.to_text());
  }

  if (state.plans.size() >= state.options.limits.max_plans) {
    return rejection(Outcome::RESOURCE_LIMIT, ConditionCode::PLAN_LIMIT, "plans",
                     static_cast<std::uint64_t>(state.plans.size()),
                     state.options.limits.max_plans);
  }

  std::vector<StepSpec> steps;
  if (request.mode == PlanMode::GENERATED) {
    std::string reason;
    const std::optional<std::vector<StepSpec>> generated = generate_steps(
        request.source, request.target, request.policy, state.options.limits, reason);
    if (!generated.has_value()) {
      return rejection(Outcome::GRAPH_INVALID, ConditionCode::DEPENDENCY_MISSING, reason);
    }
    steps = *generated;
  } else {
    steps = request.explicit_steps;
  }
  if (steps.size() > state.options.limits.max_steps_per_plan) {
    return rejection(Outcome::RESOURCE_LIMIT, ConditionCode::STEP_LIMIT, "steps",
                     static_cast<std::uint64_t>(steps.size()),
                     state.options.limits.max_steps_per_plan);
  }

  const GraphValidation conformance =
      validate_policy_conformance(steps, request.policy, state.options.limits);
  if (!conformance.ok) {
    PlanMutationResult result;
    result.outcome = Outcome::GRAPH_INVALID;
    for (const GraphDefect& defect : conformance.defects) {
      result.conditions.add(make_condition(defect.code, defect.subject.render()));
    }
    return result;
  }

  const std::optional<std::vector<std::vector<std::size_t>>> layers = canonical_layers(steps);
  if (!layers.has_value()) {
    return rejection(Outcome::GRAPH_INVALID, ConditionCode::DEPENDENCY_CYCLE, "steps");
  }
  const std::uint32_t parallel_bound =
      std::min(request.policy.max_parallel_steps, state.options.limits.max_parallel_steps);
  for (const std::vector<std::size_t>& layer : *layers) {
    if (layer.size() > parallel_bound) {
      return rejection(Outcome::RESOURCE_LIMIT, ConditionCode::PARALLELISM_LIMIT, "layer",
                       static_cast<std::uint64_t>(layer.size()), parallel_bound);
    }
  }

  PlanKey key;
  key.route = request.target.route;
  key.source_generation = request.source.generation;
  key.target_generation = request.target.generation;
  key.policy_generation = request.policy.generation;
  if (!key.is_well_formed()) {
    return rejection(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_PAYLOAD, "plan key");
  }

  const Digest structure = plan_structure_digest(key, request.source, request.target,
                                                 request.policy, request.mode, steps);
  const ConvergencePlanId plan_id = derive_plan_id(key, structure);

  ConvergencePlanId predecessor;
  const auto existing_by_key = state.by_key.find(key);
  if (existing_by_key != state.by_key.end()) {
    const auto existing_plan = state.plans.find(existing_by_key->second);
    if (existing_plan != state.plans.end()) {
      if (existing_plan->second.id == plan_id) {
        PlanMutationResult result = make_result(state, Outcome::IDEMPOTENT, existing_plan->second);
        record_attempt(state, authority, payload, result);
        return result;
      }
      predecessor = existing_plan->second.id;
      supersede_entry(state, predecessor, ChangeReason::SUPERSEDE, plan_id);
      if (state.plans.find(predecessor) != state.plans.end()) {
        state.plans[predecessor].successor = plan_id;
      }
    }
  } else {
    const auto route_entry = state.by_route.find(key.route);
    if (route_entry != state.by_route.end()) {
      for (auto iterator = route_entry->second.rbegin(); iterator != route_entry->second.rend();
           ++iterator) {
        const auto candidate = state.plans.find(*iterator);
        if (candidate == state.plans.end() || is_absolutely_terminal(candidate->second.lifecycle)) {
          continue;
        }
        predecessor = candidate->second.id;
        break;
      }
    }
  }

  ConvergencePlan plan;
  plan.id = plan_id;
  plan.key = key;
  plan.generation = ConvergencePlanGeneration::from_value(1);
  plan.lifecycle = PlanLifecycle::DECLARED;
  plan.policy = request.policy;
  plan.source = request.source;
  plan.target = request.target;
  plan.mode = request.mode;
  plan.created_epoch = state.epoch;
  plan.bound_epoch = state.epoch;
  plan.provenance = request.provenance;
  plan.owner_publisher = authority.publisher;
  plan.owner_boot = authority.worker_boot;
  plan.authority_generation = state.authority_generation;
  plan.watermark = state.convergence;
  plan.predecessor = predecessor;

  for (const StepSpec& spec : steps) {
    TransitionStep step;
    step.spec = spec;
    step.id = derive_step_id(plan_id, spec.key());
    step.generation = TransitionStepGeneration::from_value(1);
    step.state = StepLifecycle::PENDING;
    step.last_change = ChangeReason::CREATE;
    plan.steps.push_back(std::move(step));
  }
  for (const std::vector<std::size_t>& layer : *layers) {
    std::vector<TransitionStepId> ids;
    ids.reserve(layer.size());
    for (const std::size_t index : layer) {
      ids.push_back(plan.steps[index].id);
    }
    plan.layers.push_back(std::move(ids));
  }

  // DECLARED -> VALIDATING -> READY.  Both transitions are taken through the
  // published table; a plan that cannot traverse them is never created.
  const std::optional<PlanLifecycle> declaring =
      apply_plan_event(plan.lifecycle, PlanEvent::DECLARE, PlanTransitionInputs{});
  if (!declaring.has_value()) {
    return rejection(Outcome::INTERNAL_ERROR, ConditionCode::LIFECYCLE_DENIED, "DECLARED");
  }
  plan.lifecycle = *declaring;
  const std::optional<PlanLifecycle> validating =
      apply_plan_event(plan.lifecycle, PlanEvent::VALIDATE_OK, PlanTransitionInputs{});
  if (!validating.has_value()) {
    return rejection(Outcome::INTERNAL_ERROR, ConditionCode::LIFECYCLE_DENIED, "VALIDATING");
  }
  plan.lifecycle = *validating;
  refresh_ready_steps(state, plan);
  plan.digest = plan_content_digest(plan);

  const auto insert = state.plans.emplace(plan_id, std::move(plan));
  ConvergencePlan& stored = insert.first->second;
  index_plan(state, stored);
  if (!touch_plan(state, stored, ChangeReason::CREATE, ConditionCode::NONE, TransitionStepId{})) {
    return rejection(Outcome::GENERATION_EXHAUSTED, ConditionCode::GENERATION_EXHAUSTED, "plan");
  }
  ++state.stats.plans_created;
  // Lineage is recorded on both sides, so an operator can always walk from a
  // superseded plan to its successor and back.
  if (!stored.predecessor.is_nil()) {
    const auto predecessor_entry = state.plans.find(stored.predecessor);
    if (predecessor_entry != state.plans.end() &&
        predecessor_entry->second.successor.is_nil()) {
      predecessor_entry->second.successor = plan_id;
      (void)touch_plan(state, predecessor_entry->second, ChangeReason::SUPERSEDE,
                       ConditionCode::NONE, TransitionStepId{});
      reindex_plan(state, predecessor_entry->second);
    }
  }

  PlanMutationResult result = make_result(state, Outcome::PLAN_CREATED, stored);
  record_attempt(state, authority, payload, result);
  return result;
}

// --- step execution ---------------------------------------------------------

StepDispatch ConvergenceGovernor::dispatch_step(const ConvergencePlanId& plan_id,
                                                const TransitionStepId& step_id,
                                                const AuthorityContext& authority) {
  StepDispatch dispatch;
  GovernorState& state = *impl_->state;
  const std::unique_lock<std::shared_mutex> lock(state.mutex);
  apply_epoch_locked(state);

  const auto entry = state.plans.find(plan_id);
  if (entry == state.plans.end()) {
    dispatch.outcome = Outcome::UNKNOWN_PLAN;
    dispatch.conditions.add(make_condition(ConditionCode::PLAN_UNKNOWN, plan_id.to_text()));
    return dispatch;
  }
  ConvergencePlan& plan = entry->second;

  Condition condition;
  if (!authorize(state, authority, Capability::DISPATCH_STEP, plan.key.route, plan.id, condition)) {
    dispatch.outcome = Outcome::UNAUTHORIZED;
    dispatch.conditions.add(condition);
    return dispatch;
  }

  const Digest payload = request_digest("rc.attempt.dispatch.v1", plan.key,
                                        step_id.to_text() + ':' + authority.attempt.to_text());
  PlanMutationResult replay;
  switch (check_attempt(state, authority, payload, replay)) {
    case AttemptCheck::REPLAY:
      dispatch.outcome = Outcome::IDEMPOTENT;
      dispatch.plan = plan.id;
      dispatch.step = step_id;
      return dispatch;
    case AttemptCheck::CONFLICT:
      dispatch.outcome = Outcome::ATTEMPT_CONFLICT;
      dispatch.conditions.add(
          make_condition(ConditionCode::ATTEMPT_CONFLICT, authority.attempt.to_text()));
      return dispatch;
    case AttemptCheck::FRESH:
      break;
  }

  TransitionStep* step = plan.find_step(step_id);
  if (step == nullptr) {
    dispatch.outcome = Outcome::UNKNOWN_STEP;
    dispatch.conditions.add(make_condition(ConditionCode::STEP_UNKNOWN, step_id.to_text()));
    return dispatch;
  }
  if (is_terminal_lifecycle(plan.lifecycle)) {
    dispatch.outcome = Outcome::STALE_PLAN;
    dispatch.conditions.add(make_condition(ConditionCode::PLAN_TERMINAL, to_string(plan.lifecycle)));
    return dispatch;
  }

  ConditionList currentness_conditions(state.options.limits.max_explanation_entries);
  if (!recompute_currentness(state, plan, currentness_conditions)) {
    invalidate_plan(state, plan, CurrentnessCause::REVALIDATION_REQUIRED, ChangeReason::INVALIDATE);
    dispatch.outcome = Outcome::REVALIDATION_REQUIRED;
    for (const Condition& item : currentness_conditions.entries()) {
      dispatch.conditions.add(item);
    }
    if (currentness_conditions.empty()) {
      dispatch.conditions.add(make_condition(ConditionCode::REVALIDATION_REQUIRED, "plan"));
    }
    return dispatch;
  }

  if (authority.expected_plan_generation.has_value() &&
      !(authority.expected_plan_generation.value() == plan.generation)) {
    dispatch.outcome = Outcome::STALE_PLAN;
    dispatch.conditions.add(make_condition(ConditionCode::PLAN_GENERATION_MISMATCH, "plan",
                                           plan.generation.value(),
                                           authority.expected_plan_generation->value()));
    return dispatch;
  }

  const auto dispatch_event =
      apply_plan_event(plan.lifecycle, PlanEvent::DISPATCH, PlanTransitionInputs{});
  if (!dispatch_event.has_value()) {
    dispatch.outcome = Outcome::LIFECYCLE_VIOLATION;
    dispatch.conditions.add(
        make_condition(ConditionCode::LIFECYCLE_DENIED, to_string(plan.lifecycle)));
    return dispatch;
  }

  if (step->state != StepLifecycle::READY) {
    dispatch.outcome = Outcome::PREREQUISITE_INCOMPLETE;
    dispatch.conditions.add(
        make_condition(ConditionCode::STEP_NOT_READY, step->spec.key().render()));
    for (const StepKey& dependency : step->spec.depends_on) {
      if (!step_satisfied(plan, dependency)) {
        dispatch.conditions.add(
            make_condition(ConditionCode::PREREQUISITE_INCOMPLETE, dependency.render()));
      }
    }
    return dispatch;
  }
  if (authority.expected_step_generation.has_value() &&
      !(authority.expected_step_generation.value() == step->generation)) {
    dispatch.outcome = Outcome::STALE_STEP;
    dispatch.conditions.add(make_condition(ConditionCode::STEP_GENERATION_MISMATCH,
                                           step->spec.key().render(), step->generation.value(),
                                           authority.expected_step_generation->value()));
    return dispatch;
  }

  const std::optional<TransitionStepGeneration> next_generation = step->generation.next();
  if (!next_generation.has_value()) {
    dispatch.outcome = Outcome::GENERATION_EXHAUSTED;
    dispatch.conditions.add(
        make_condition(ConditionCode::GENERATION_EXHAUSTED, step->spec.key().render()));
    return dispatch;
  }

  step->generation = *next_generation;
  step->state = StepLifecycle::DISPATCHED;
  ++step->attempts;
  step->last_attempt = authority.attempt;
  step->last_change = ChangeReason::DISPATCH_STEP;
  step->last_condition = ConditionCode::NONE;
  step->dispatch_watermark = plan.watermark;
  step->dispatch_epoch = state.epoch;
  step->dispatch_publisher = authority.publisher;
  step->dispatch_boot = authority.worker_boot;

  plan.lifecycle = *dispatch_event;
  plan.owner_publisher = authority.publisher;
  plan.owner_boot = authority.worker_boot;
  if (!advance_authority(state, plan)) {
    dispatch.outcome = Outcome::GENERATION_EXHAUSTED;
    dispatch.conditions.add(make_condition(ConditionCode::GENERATION_EXHAUSTED, "authority"));
    return dispatch;
  }
  (void)touch_plan(state, plan, ChangeReason::DISPATCH_STEP, ConditionCode::NONE, step->id);
  reindex_plan(state, plan);
  ++state.stats.steps_dispatched;

  dispatch.outcome = Outcome::STEP_DISPATCHED;
  dispatch.plan = plan.id;
  dispatch.step = step->id;
  dispatch.step_generation = step->generation;
  dispatch.watermark = step->dispatch_watermark;
  dispatch.epoch = state.epoch;
  dispatch.spec = step->spec;
  record_attempt(state, authority, payload, make_result(state, Outcome::STEP_DISPATCHED, plan));
  return dispatch;
}

PlanMutationResult ConvergenceGovernor::complete_step(const CompletionEvidence& evidence,
                                                      const AuthorityContext& authority) {
  GovernorState& state = *impl_->state;
  const std::unique_lock<std::shared_mutex> lock(state.mutex);
  apply_epoch_locked(state);

  if (!evidence.is_well_formed()) {
    return rejection(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_PAYLOAD, "evidence");
  }
  const auto entry = state.plans.find(evidence.plan);
  if (entry == state.plans.end()) {
    return rejection(Outcome::UNKNOWN_PLAN, ConditionCode::PLAN_UNKNOWN, evidence.plan.to_text());
  }
  Condition condition;
  if (!authorize(state, authority, Capability::COMPLETE_STEP, entry->second.key.route,
                 entry->second.id, condition)) {
    return rejection(Outcome::UNAUTHORIZED, condition.code, condition.subject, condition.observed,
                     condition.expected);
  }
  return apply_completion(state, entry->second, evidence, authority);
}

PlanMutationResult ConvergenceGovernor::fail_step(const ConvergencePlanId& plan_id,
                                                  const TransitionStepId& step_id,
                                                  BackendOutcome outcome, std::string detail,
                                                  const AuthorityContext& authority) {
  GovernorState& state = *impl_->state;
  const std::unique_lock<std::shared_mutex> lock(state.mutex);
  apply_epoch_locked(state);

  const auto entry = state.plans.find(plan_id);
  if (entry == state.plans.end()) {
    return rejection(Outcome::UNKNOWN_PLAN, ConditionCode::PLAN_UNKNOWN, plan_id.to_text());
  }
  ConvergencePlan& plan = entry->second;
  Condition condition;
  if (!authorize(state, authority, Capability::COMPLETE_STEP, plan.key.route, plan.id, condition)) {
    return rejection(Outcome::UNAUTHORIZED, condition.code, condition.subject, condition.observed,
                     condition.expected);
  }
  TransitionStep* step = plan.find_step(step_id);
  if (step == nullptr) {
    return rejection(Outcome::UNKNOWN_STEP, ConditionCode::STEP_UNKNOWN, step_id.to_text());
  }

  CompletionEvidence evidence;
  evidence.plan = plan.id;
  evidence.step = step_id;
  evidence.step_generation = step->generation;
  evidence.epoch = state.epoch;
  evidence.publisher = authority.publisher;
  evidence.worker_boot = authority.worker_boot;
  evidence.outcome = outcome;
  evidence.dispatch_watermark = step->dispatch_watermark;
  // The evidence binds the execution attempt that is being failed, not the
  // mutation attempt identifier of this request.
  evidence.attempt = step->last_attempt;
  evidence.detail = std::move(detail);
  if (evidence.detail.size() > 256) {
    evidence.detail.resize(256);
  }
  evidence.id = derive_evidence_id(evidence);
  return apply_completion(state, plan, evidence, authority);
}

PlanMutationResult ConvergenceGovernor::reconcile_step(const ConvergencePlanId& plan_id,
                                                       const TransitionStepId& step_id,
                                                       bool applied, std::string detail,
                                                       const AuthorityContext& authority) {
  GovernorState& state = *impl_->state;
  const std::unique_lock<std::shared_mutex> lock(state.mutex);
  apply_epoch_locked(state);

  const auto entry = state.plans.find(plan_id);
  if (entry == state.plans.end()) {
    return rejection(Outcome::UNKNOWN_PLAN, ConditionCode::PLAN_UNKNOWN, plan_id.to_text());
  }
  ConvergencePlan& plan = entry->second;
  Condition condition;
  if (!authorize(state, authority, Capability::COMPLETE_STEP, plan.key.route, plan.id, condition)) {
    return rejection(Outcome::UNAUTHORIZED, condition.code, condition.subject, condition.observed,
                     condition.expected);
  }
  TransitionStep* step = plan.find_step(step_id);
  if (step == nullptr) {
    return rejection(Outcome::UNKNOWN_STEP, ConditionCode::STEP_UNKNOWN, step_id.to_text());
  }
  if (step->state != StepLifecycle::RECONCILIATION_REQUIRED) {
    return rejection(Outcome::STALE_STEP, ConditionCode::STEP_STALE, step->spec.key().render());
  }
  if (!worker_live_locked(state, authority.publisher, authority.worker_boot)) {
    return rejection(Outcome::STALE_WORKER, ConditionCode::WORKER_FENCED,
                     authority.worker_boot.to_text());
  }

  const std::optional<StepLifecycle> next = apply_step_event(
      step->state, applied ? StepEvent::RECONCILE_APPLIED : StepEvent::RECONCILE_NOT_APPLIED);
  if (!next.has_value()) {
    return rejection(Outcome::INTERNAL_ERROR, ConditionCode::LIFECYCLE_DENIED,
                     to_string(step->state));
  }
  step->state = *next;
  step->last_change = ChangeReason::RECONCILE_STEP;
  step->last_condition = ConditionCode::NONE;
  ++state.stats.reconciliations;
  if (applied) {
    ++state.stats.steps_completed;
  }
  plan.currentness.remove(CurrentnessCause::REVALIDATION_REQUIRED);
  if (detail.size() > 256) {
    detail.resize(256);
  }
  plan.owner_publisher = authority.publisher;
  plan.owner_boot = authority.worker_boot;
  (void)touch_plan(state, plan, ChangeReason::RECONCILE_STEP, ConditionCode::NONE, step->id);
  refresh_ready_steps(state, plan);
  reindex_plan(state, plan);

  PlanMutationResult result =
      make_result(state, Outcome::STEP_RECONCILED, plan, ConditionCode::NONE, detail);
  result.step = step->id;
  result.step_generation = step->generation;
  return result;
}

}  // namespace rc
