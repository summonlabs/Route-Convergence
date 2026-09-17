#include <algorithm>
#include <set>
#include <string>

#include "governor_state.hpp"
#include "rc/backend.hpp"
#include "rc/graph.hpp"

namespace rc {
namespace {

void apply_epoch_locked(GovernorState& state) {
  const CoordinatorEpoch observed = state.epochs.current_epoch();
  if (observed.value() > state.epoch.value()) {
    apply_epoch(state, observed, ChangeReason::EPOCH_ADVANCE, epoch_provenance(observed));
  }
}

[[nodiscard]] std::set<StepKind> applied_mutations(const ConvergencePlan& plan) {
  std::set<StepKind> kinds;
  for (const TransitionStep& step : plan.steps) {
    if (step.state != StepLifecycle::COMPLETED) {
      continue;
    }
    if (is_observation_step(step.spec.kind) || step.spec.kind == StepKind::FINALIZE) {
      continue;
    }
    kinds.insert(step.spec.kind);
  }
  return kinds;
}

[[nodiscard]] bool keep_rollback_kind(StepKind kind, const std::set<StepKind>& applied,
                                      const std::set<StepKind>& kept) {
  switch (kind) {
    case StepKind::VALIDATE_TARGET:
      return true;
    case StepKind::FINALIZE:
      return true;
    case StepKind::PREPARE_NEW_STATE:
      return applied.count(StepKind::WITHDRAW_OLD_ROUTE) != 0 ||
             applied.count(StepKind::DEACTIVATE_OLD_PATH) != 0;
    case StepKind::INSTALL_NEW_GROUP:
      return applied.count(StepKind::INSTALL_NEW_GROUP) != 0;
    case StepKind::INSTALL_NEW_ROUTE:
      return applied.count(StepKind::WITHDRAW_OLD_ROUTE) != 0;
    case StepKind::ACTIVATE_NEW_PATH:
      return applied.count(StepKind::DEACTIVATE_OLD_PATH) != 0;
    case StepKind::VERIFY_NEW_STATE:
      return kept.count(StepKind::PREPARE_NEW_STATE) != 0 ||
             kept.count(StepKind::INSTALL_NEW_GROUP) != 0 ||
             kept.count(StepKind::INSTALL_NEW_ROUTE) != 0 ||
             kept.count(StepKind::ACTIVATE_NEW_PATH) != 0;
    case StepKind::DEACTIVATE_OLD_PATH:
      return applied.count(StepKind::ACTIVATE_NEW_PATH) != 0;
    case StepKind::WITHDRAW_OLD_ROUTE:
      return applied.count(StepKind::INSTALL_NEW_ROUTE) != 0;
    case StepKind::VERIFY_REMOVAL:
      return kept.count(StepKind::WITHDRAW_OLD_ROUTE) != 0;
  }
  return true;
}

// Drops every rollback step whose effect the forward plan never established and
// contracts the dependency edges through the dropped nodes, so the remaining
// ordering guarantees are preserved exactly.
[[nodiscard]] std::vector<StepSpec> prune_rollback_steps(const std::vector<StepSpec>& steps,
                                                         const std::set<StepKind>& applied) {
  std::set<StepKind> kept;
  bool progressing = true;
  while (progressing) {
    progressing = false;
    for (const StepSpec& step : steps) {
      if (kept.count(step.kind) != 0) {
        continue;
      }
      if (keep_rollback_kind(step.kind, applied, kept)) {
        kept.insert(step.kind);
        progressing = true;
      }
    }
  }

  std::set<StepKey> removed;
  for (const StepSpec& step : steps) {
    if (kept.count(step.kind) == 0) {
      removed.insert(step.key());
    }
  }
  if (removed.empty()) {
    return steps;
  }

  std::map<StepKey, const StepSpec*> by_key;
  for (const StepSpec& step : steps) {
    by_key[step.key()] = &step;
  }
  std::map<StepKey, std::set<StepKey>> ancestors;
  progressing = true;
  while (progressing) {
    progressing = false;
    for (const StepKey& key : removed) {
      const auto entry = by_key.find(key);
      if (entry == by_key.end()) {
        continue;
      }
      std::set<StepKey>& target = ancestors[key];
      const std::size_t before = target.size();
      for (const StepKey& dependency : entry->second->depends_on) {
        if (removed.count(dependency) == 0) {
          target.insert(dependency);
        } else {
          const auto resolved = ancestors.find(dependency);
          if (resolved != ancestors.end()) {
            target.insert(resolved->second.begin(), resolved->second.end());
          }
        }
      }
      if (target.size() != before) {
        progressing = true;
      }
    }
  }

  std::vector<StepSpec> pruned;
  for (const StepSpec& step : steps) {
    if (removed.count(step.key()) != 0) {
      continue;
    }
    StepSpec copy = step;
    std::set<StepKey> dependencies;
    for (const StepKey& dependency : copy.depends_on) {
      if (removed.count(dependency) == 0) {
        dependencies.insert(dependency);
      } else {
        const auto resolved = ancestors.find(dependency);
        if (resolved != ancestors.end()) {
          dependencies.insert(resolved->second.begin(), resolved->second.end());
        }
      }
    }
    dependencies.erase(copy.key());
    copy.depends_on.assign(dependencies.begin(), dependencies.end());
    pruned.push_back(std::move(copy));
  }
  return pruned;
}

}  // namespace

PlanMutationResult ConvergenceGovernor::revalidate_plan(const ConvergencePlanId& plan_id,
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
  if (!authorize(state, authority, Capability::REVALIDATE_PLAN, plan.key.route, plan.id,
                 condition)) {
    return rejection(Outcome::UNAUTHORIZED, condition.code, condition.subject, condition.observed,
                     condition.expected);
  }
  if (is_absolutely_terminal(plan.lifecycle)) {
    return rejection(Outcome::RETIRED, ConditionCode::PLAN_TERMINAL, to_string(plan.lifecycle));
  }
  const Digest payload = text_digest("rc.attempt.revalidate.v1", plan.id.to_text());
  PlanMutationResult replay;
  if (attempt_gate(state, authority, payload, replay)) {
    return replay;
  }

  // Revalidation re-establishes the epoch binding first, then checks everything
  // else.  Otherwise a plan bound to an older epoch could never be revalidated.
  const CoordinatorEpoch previous_bound_epoch = plan.bound_epoch;
  plan.bound_epoch = state.epoch;
  plan.currentness.remove(CurrentnessCause::STALE_EPOCH);

  ConditionList conditions(state.options.limits.max_explanation_entries);
  const bool current = recompute_currentness(state, plan, conditions);
  if (!current) {
    plan.bound_epoch = previous_bound_epoch;
    plan.currentness.add(CurrentnessCause::STALE_EPOCH);
    const std::optional<RouteBinding> observed = state.routes.observe_route(plan.key.route);
    if (observed.has_value() &&
        observed->generation.value() > plan.key.target_generation.value()) {
      supersede_entry(state, plan.id, ChangeReason::SUPERSEDE, ConvergencePlanId{});
      return make_result(state, Outcome::SUPERSEDED, plan);
    }
    const std::optional<PlanLifecycle> failed =
        apply_plan_event(plan.lifecycle, PlanEvent::REVALIDATE_FAIL, PlanTransitionInputs{});
    if (failed.has_value()) {
      plan.lifecycle = *failed;
    }
    if (advance_convergence(state)) {
      plan.watermark = state.convergence;
    }
    (void)touch_plan(state, plan, ChangeReason::REVALIDATE,
                     ConditionCode::REVALIDATION_REQUIRED, TransitionStepId{});
    reindex_plan(state, plan);
    PlanMutationResult result = make_result(state, Outcome::REVALIDATION_REQUIRED, plan);
    for (const Condition& item : conditions.entries()) {
      result.conditions.add(item);
    }
    if (conditions.empty()) {
      result.conditions.add(make_condition(ConditionCode::REVALIDATION_REQUIRED, "plan"));
    }
    return result;
  }

  plan.currentness.remove(CurrentnessCause::REVALIDATION_REQUIRED);
  PlanTransitionInputs inputs;
  inputs.target_current = true;
  inputs.dependency_current = true;
  inputs.policy_current = true;
  const std::optional<PlanLifecycle> ok =
      apply_plan_event(plan.lifecycle, PlanEvent::REVALIDATE_OK, inputs);
  if (!ok.has_value()) {
    return rejection(Outcome::LIFECYCLE_VIOLATION, ConditionCode::LIFECYCLE_DENIED,
                     to_string(plan.lifecycle));
  }
  plan.lifecycle = *ok;
  // Every step that went stale while authority was suspended returns to PENDING
  // and is re-readied below; a step that already completed keeps its completion.
  for (TransitionStep& step : plan.steps) {
    if (step.state != StepLifecycle::STALE) {
      continue;
    }
    const std::optional<StepLifecycle> recovered = apply_step_event(step.state, StepEvent::RECOVER);
    if (recovered.has_value()) {
      step.state = *recovered;
      step.last_change = ChangeReason::REVALIDATE;
      step.last_condition = ConditionCode::NONE;
    }
  }
  plan.owner_publisher = authority.publisher;
  plan.owner_boot = authority.worker_boot;
  if (!advance_authority(state, plan)) {
    return rejection(Outcome::GENERATION_EXHAUSTED, ConditionCode::GENERATION_EXHAUSTED,
                     "authority");
  }
  refresh_ready_steps(state, plan);
  (void)touch_plan(state, plan, ChangeReason::REVALIDATE, ConditionCode::NONE, TransitionStepId{});
  reindex_plan(state, plan);
  PlanMutationResult result = make_result(state, Outcome::PLAN_REVALIDATED, plan);
  record_attempt(state, authority, payload, result);
  return result;
}

PlanMutationResult ConvergenceGovernor::pause_plan(const ConvergencePlanId& plan_id,
                                                   ConditionCode cause,
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
  if (!authorize(state, authority, Capability::REVALIDATE_PLAN, plan.key.route, plan.id,
                 condition)) {
    return rejection(Outcome::UNAUTHORIZED, condition.code, condition.subject, condition.observed,
                     condition.expected);
  }
  const Digest payload = text_digest("rc.attempt.pause.v1",
                                     plan.id.to_text() + std::to_string(static_cast<std::uint32_t>(cause)));
  PlanMutationResult replay;
  if (attempt_gate(state, authority, payload, replay)) {
    return replay;
  }
  const std::optional<PlanLifecycle> next =
      apply_plan_event(plan.lifecycle, PlanEvent::PAUSE, PlanTransitionInputs{});
  if (!next.has_value()) {
    return rejection(Outcome::LIFECYCLE_VIOLATION, ConditionCode::LIFECYCLE_DENIED,
                     to_string(plan.lifecycle));
  }
  plan.lifecycle = *next;
  plan.owner_publisher = authority.publisher;
  plan.owner_boot = authority.worker_boot;
  (void)touch_plan(state, plan, ChangeReason::PAUSE, cause, TransitionStepId{});
  reindex_plan(state, plan);
  PlanMutationResult result = make_result(state, Outcome::PLAN_PAUSED, plan, cause, "pause");
  record_attempt(state, authority, payload, result);
  return result;
}

PlanMutationResult ConvergenceGovernor::revoke_plan(const ConvergencePlanId& plan_id,
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
  if (!authorize(state, authority, Capability::ADMIN, plan.key.route, plan.id, condition)) {
    return rejection(Outcome::UNAUTHORIZED, condition.code, condition.subject, condition.observed,
                     condition.expected);
  }
  const Digest payload = text_digest("rc.attempt.revoke.v1", plan.id.to_text());
  PlanMutationResult replay;
  if (attempt_gate(state, authority, payload, replay)) {
    return replay;
  }
  if (plan.lifecycle == PlanLifecycle::REVOKED) {
    PlanMutationResult result = make_result(state, Outcome::IDEMPOTENT, plan);
    record_attempt(state, authority, payload, result);
    return result;
  }
  const std::optional<PlanLifecycle> next =
      apply_plan_event(plan.lifecycle, PlanEvent::REVOKE, PlanTransitionInputs{});
  if (!next.has_value()) {
    return rejection(Outcome::LIFECYCLE_VIOLATION, ConditionCode::LIFECYCLE_DENIED,
                     to_string(plan.lifecycle));
  }
  plan.lifecycle = *next;
  plan.rollback_required = false;
  if (advance_convergence(state)) {
    plan.watermark = state.convergence;
  }
  stale_in_flight_steps(state, plan);
  plan.owner_publisher = authority.publisher;
  plan.owner_boot = authority.worker_boot;
  ++state.stats.plans_revoked;
  (void)touch_plan(state, plan, ChangeReason::REVOKE, ConditionCode::NONE, TransitionStepId{});
  reindex_plan(state, plan);
  PlanMutationResult result = make_result(state, Outcome::PLAN_REVOKED, plan);
  record_attempt(state, authority, payload, result);
  return result;
}

PlanMutationResult ConvergenceGovernor::retire_plan(const ConvergencePlanId& plan_id,
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
  if (!authorize(state, authority, Capability::ADMIN, plan.key.route, plan.id, condition)) {
    return rejection(Outcome::UNAUTHORIZED, condition.code, condition.subject, condition.observed,
                     condition.expected);
  }
  const Digest payload = text_digest("rc.attempt.retire.v1", plan.id.to_text());
  PlanMutationResult replay;
  if (attempt_gate(state, authority, payload, replay)) {
    return replay;
  }
  if (plan.lifecycle == PlanLifecycle::RETIRED) {
    PlanMutationResult result = make_result(state, Outcome::IDEMPOTENT, plan);
    record_attempt(state, authority, payload, result);
    return result;
  }
  const std::optional<PlanLifecycle> next =
      apply_plan_event(plan.lifecycle, PlanEvent::RETIRE, PlanTransitionInputs{});
  if (!next.has_value()) {
    return rejection(Outcome::LIFECYCLE_VIOLATION, ConditionCode::LIFECYCLE_DENIED,
                     to_string(plan.lifecycle));
  }
  plan.lifecycle = *next;
  plan.rollback_required = false;
  for (TransitionStep& step : plan.steps) {
    if (step.state == StepLifecycle::RETIRED) {
      continue;
    }
    const std::optional<StepLifecycle> retired = apply_step_event(step.state, StepEvent::RETIRE);
    if (retired.has_value()) {
      step.state = *retired;
      step.last_change = ChangeReason::RETIRE;
    }
  }
  if (advance_convergence(state)) {
    plan.watermark = state.convergence;
  }
  plan.owner_publisher = authority.publisher;
  plan.owner_boot = authority.worker_boot;
  ++state.stats.plans_retired;
  (void)touch_plan(state, plan, ChangeReason::RETIRE, ConditionCode::NONE, TransitionStepId{});
  reindex_plan(state, plan);
  PlanMutationResult result = make_result(state, Outcome::PLAN_RETIRED, plan);
  record_attempt(state, authority, payload, result);
  return result;
}

PlanMutationResult ConvergenceGovernor::begin_rollback(const ConvergencePlanId& plan_id,
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
  if (!authorize(state, authority, Capability::ROLLBACK, plan.key.route, plan.id, condition)) {
    return rejection(Outcome::UNAUTHORIZED, condition.code, condition.subject, condition.observed,
                     condition.expected);
  }
  const Digest payload = text_digest("rc.attempt.rollback.v1", plan.id.to_text());
  PlanMutationResult replay;
  if (attempt_gate(state, authority, payload, replay)) {
    return replay;
  }
  if (plan.lifecycle == PlanLifecycle::ROLLING_BACK && !plan.rollback_plan.is_nil()) {
    PlanMutationResult result = make_result(state, Outcome::IDEMPOTENT, plan);
    result.plan = plan.rollback_plan;
    record_attempt(state, authority, payload, result);
    return result;
  }
  if (is_terminal_lifecycle(plan.lifecycle)) {
    return rejection(Outcome::LIFECYCLE_VIOLATION, ConditionCode::PLAN_TERMINAL,
                     to_string(plan.lifecycle));
  }

  const auto unsafe = [&state, &plan](ConditionCode code, std::string subject,
                                     std::uint64_t observed = 0, std::uint64_t expected = 0) {
    plan.rollback_required = true;
    ++state.stats.rollbacks_rejected;
    return rejection(Outcome::UNSAFE_ROLLBACK, code, subject, observed, expected);
  };

  const std::set<StepKind> applied = applied_mutations(plan);
  for (const TransitionStep& step : plan.steps) {
    if (step.state == StepLifecycle::COMPLETED &&
        step.spec.reversibility == Reversibility::IRREVERSIBLE) {
      return unsafe(ConditionCode::ROLLBACK_IRREVERSIBLE, step.spec.key().render());
    }
  }

  const std::optional<RouteBinding> observed = state.routes.observe_route(plan.key.route);
  if (!observed.has_value()) {
    return unsafe(ConditionCode::TARGET_ROUTE_UNKNOWN, plan.key.route.to_text());
  }
  if (observed->generation.value() > plan.key.target_generation.value()) {
    return unsafe(ConditionCode::TARGET_ROUTE_STALE, plan.key.route.to_text(),
                  observed->generation.value(), plan.key.target_generation.value());
  }

  // The plan budget is consulted before anything is mutated, so a rejected
  // rollback leaves the forward plan exactly as it was.
  if (state.plans.size() >= state.options.limits.max_plans) {
    return rejection(Outcome::RESOURCE_LIMIT, ConditionCode::PLAN_LIMIT, "plans",
                     static_cast<std::uint64_t>(state.plans.size()),
                     state.options.limits.max_plans);
  }

  // Revalidate the state we would roll back to before generating anything.
  const std::optional<PathLegality> source_legality = state.paths.observe_path(plan.source.path);
  if (!source_legality.has_value()) {
    return unsafe(ConditionCode::ROLLBACK_TARGET_UNAUTHORIZED, plan.source.path.to_text());
  }
  if (!(source_legality->generation == plan.source.path_authority_generation)) {
    return unsafe(ConditionCode::PATH_AUTHORITY_STALE, plan.source.path.to_text(),
                  source_legality->generation.value(),
                  plan.source.path_authority_generation.value());
  }
  if (!source_legality->legal) {
    return unsafe(ConditionCode::ROLLBACK_TARGET_UNAUTHORIZED, plan.source.path.to_text());
  }
  if (!observed->legal) {
    return unsafe(ConditionCode::ROLLBACK_TARGET_UNAUTHORIZED, plan.key.route.to_text());
  }

  // Move the forward plan into ROLLING_BACK first: this fences every in-flight
  // step of the forward transition before any compensating work is authorized.
  if (plan.lifecycle != PlanLifecycle::ROLLBACK_REQUIRED) {
    const std::optional<PlanLifecycle> required =
        apply_plan_event(plan.lifecycle, PlanEvent::REQUIRE_ROLLBACK, PlanTransitionInputs{});
    if (!required.has_value()) {
      return rejection(Outcome::LIFECYCLE_VIOLATION, ConditionCode::LIFECYCLE_DENIED,
                       to_string(plan.lifecycle));
    }
    plan.lifecycle = *required;
  }
  plan.rollback_required = true;
  if (advance_convergence(state)) {
    plan.watermark = state.convergence;
  }
  stale_in_flight_steps(state, plan);
  const std::optional<PlanLifecycle> rolling =
      apply_plan_event(plan.lifecycle, PlanEvent::BEGIN_ROLLBACK, PlanTransitionInputs{});
  if (!rolling.has_value()) {
    return rejection(Outcome::LIFECYCLE_VIOLATION, ConditionCode::LIFECYCLE_DENIED,
                     to_string(plan.lifecycle));
  }
  plan.lifecycle = *rolling;
  ++state.stats.rollbacks_started;

  // Nothing was applied externally: the rollback is already complete.
  if (observed->generation.value() == plan.key.source_generation.value()) {
    plan.rollback_required = false;
    const std::optional<PlanLifecycle> done = apply_plan_event(
        plan.lifecycle, PlanEvent::ROLLBACK_COMPLETED, PlanTransitionInputs{});
    if (done.has_value()) {
      plan.lifecycle = *done;
      plan.supersession_reason = ChangeReason::ROLLBACK_COMPLETED;
    }
    (void)touch_plan(state, plan, ChangeReason::ROLLBACK_COMPLETED, ConditionCode::NONE,
                     TransitionStepId{});
    reindex_plan(state, plan);
    return make_result(state, Outcome::ROLLBACK_COMPLETED, plan);
  }

  std::string reason;
  const std::optional<std::vector<StepSpec>> generated = generate_steps(
      *observed, plan.source, plan.policy, state.options.limits, reason);
  if (!generated.has_value()) {
    return rejection(Outcome::UNSAFE_ROLLBACK, ConditionCode::GRAPH_INVALID, reason);
  }
  std::vector<StepSpec> steps = prune_rollback_steps(*generated, applied);
  GraphValidation conformance =
      validate_policy_conformance(steps, plan.policy, state.options.limits);
  if (!conformance.ok) {
    steps = *generated;
    conformance = validate_policy_conformance(steps, plan.policy, state.options.limits);
    if (!conformance.ok) {
      return rejection(Outcome::UNSAFE_ROLLBACK, ConditionCode::GRAPH_INVALID,
                       "rollback graph");
    }
  }

  const std::optional<std::vector<std::vector<std::size_t>>> layers = canonical_layers(steps);
  if (!layers.has_value()) {
    return rejection(Outcome::UNSAFE_ROLLBACK, ConditionCode::DEPENDENCY_CYCLE, "rollback graph");
  }

  PlanKey key;
  key.route = plan.key.route;
  key.source_generation = observed->generation;
  key.target_generation = plan.source.generation;
  key.policy_generation = plan.policy.generation;
  if (!key.is_well_formed()) {
    return rejection(Outcome::UNSAFE_ROLLBACK, ConditionCode::MALFORMED_PAYLOAD, "rollback key");
  }
  const Digest structure =
      plan_structure_digest(key, *observed, plan.source, plan.policy, PlanMode::GENERATED, steps);
  const ConvergencePlanId rollback_id = derive_plan_id(key, structure);

  ConvergencePlan rollback;
  rollback.id = rollback_id;
  rollback.key = key;
  rollback.generation = ConvergencePlanGeneration::from_value(1);
  rollback.lifecycle = PlanLifecycle::DECLARED;
  rollback.policy = plan.policy;
  rollback.source = *observed;
  rollback.target = plan.source;
  rollback.mode = PlanMode::GENERATED;
  rollback.created_epoch = state.epoch;
  rollback.bound_epoch = state.epoch;
  rollback.provenance = plan.provenance;
  rollback.owner_publisher = authority.publisher;
  rollback.owner_boot = authority.worker_boot;
  rollback.authority_generation = state.authority_generation;
  rollback.watermark = state.convergence;
  rollback.predecessor = plan.id;
  rollback.is_rollback = true;

  for (const StepSpec& spec : steps) {
    TransitionStep step;
    step.spec = spec;
    step.id = derive_step_id(rollback_id, spec.key());
    step.generation = TransitionStepGeneration::from_value(1);
    step.state = StepLifecycle::PENDING;
    step.last_change = ChangeReason::ROLLBACK_REQUESTED;
    for (const TransitionStep& forward : plan.steps) {
      if (forward.spec.kind == spec.kind &&
          forward.state == StepLifecycle::COMPLETED) {
        step.compensates = forward.id;
        break;
      }
    }
    rollback.steps.push_back(std::move(step));
  }
  for (const std::vector<std::size_t>& layer : *layers) {
    std::vector<TransitionStepId> ids;
    ids.reserve(layer.size());
    for (const std::size_t index : layer) {
      ids.push_back(rollback.steps[index].id);
    }
    rollback.layers.push_back(std::move(ids));
  }

  const std::optional<PlanLifecycle> declaring =
      apply_plan_event(rollback.lifecycle, PlanEvent::DECLARE, PlanTransitionInputs{});
  if (!declaring.has_value()) {
    return rejection(Outcome::INTERNAL_ERROR, ConditionCode::LIFECYCLE_DENIED, "DECLARED");
  }
  rollback.lifecycle = *declaring;
  const std::optional<PlanLifecycle> validating =
      apply_plan_event(rollback.lifecycle, PlanEvent::VALIDATE_OK, PlanTransitionInputs{});
  if (!validating.has_value()) {
    return rejection(Outcome::INTERNAL_ERROR, ConditionCode::LIFECYCLE_DENIED, "VALIDATING");
  }
  rollback.lifecycle = *validating;
  refresh_ready_steps(state, rollback);
  rollback.digest = plan_content_digest(rollback);

  const auto insert = state.plans.emplace(rollback_id, std::move(rollback));
  ConvergencePlan& stored = insert.first->second;
  index_plan(state, stored);
  if (!touch_plan(state, stored, ChangeReason::ROLLBACK_REQUESTED, ConditionCode::NONE,
                  TransitionStepId{})) {
    return rejection(Outcome::GENERATION_EXHAUSTED, ConditionCode::GENERATION_EXHAUSTED, "plan");
  }
  plan.rollback_plan = rollback_id;
  plan.successor = rollback_id;
  (void)touch_plan(state, plan, ChangeReason::ROLLBACK_REQUESTED, ConditionCode::NONE,
                   TransitionStepId{});
  reindex_plan(state, plan);
  ++state.stats.plans_created;

  PlanMutationResult result = make_result(state, Outcome::ROLLBACK_PLAN_CREATED, plan);
  result.plan = rollback_id;
  result.plan_generation = stored.generation;
  result.digest = stored.digest;
  result.conditions.add(
      make_condition(ConditionCode::NONE, "rollback_plan", rollback_id.bytes()[0], 0));
  record_attempt(state, authority, payload, result);
  return result;
}

// --- upstream notices -------------------------------------------------------

NoticeResult ConvergenceGovernor::note_route_change(const RouteChangeNotice& notice,
                                                    const AuthorityContext& authority) {
  NoticeResult result;
  GovernorState& state = *impl_->state;
  const std::unique_lock<std::shared_mutex> lock(state.mutex);
  apply_epoch_locked(state);

  if (!notice.is_well_formed()) {
    result.outcome = Outcome::MALFORMED_REQUEST;
    result.conditions.add(make_condition(ConditionCode::MALFORMED_PAYLOAD, "route notice"));
    return result;
  }
  Condition condition;
  if (!authorize(state, authority, Capability::PUBLISH_UPSTREAM, notice.binding.route,
                 ConvergencePlanId{}, condition)) {
    result.outcome = Outcome::UNAUTHORIZED;
    result.conditions.add(condition);
    return result;
  }

  // A notice is an event, never an observation: the governor re-observes.
  const std::optional<RouteBinding> observed = state.routes.observe_route(notice.binding.route);
  if (!observed.has_value()) {
    result.outcome = Outcome::STALE_ROUTE;
    result.conditions.add(
        make_condition(ConditionCode::TARGET_ROUTE_UNKNOWN, notice.binding.route.to_text()));
    return result;
  }

  const auto route_entry = state.by_route.find(notice.binding.route);
  if (route_entry == state.by_route.end()) {
    result.outcome = Outcome::NO_CHANGE;
    result.epoch = state.epoch;
    result.convergence_generation = state.convergence;
    return result;
  }
  const std::vector<ConvergencePlanId> affected = route_entry->second;
  for (const ConvergencePlanId& id : affected) {
    const auto entry = state.plans.find(id);
    if (entry == state.plans.end()) {
      continue;
    }
    ++result.plans_examined;
    ConvergencePlan& plan = entry->second;
    if (is_terminal_lifecycle(plan.lifecycle)) {
      continue;
    }
    if (observed->generation.value() > plan.key.target_generation.value()) {
      supersede_entry(state, plan.id, ChangeReason::SUPERSEDE, ConvergencePlanId{});
      ++result.plans_superseded;
      continue;
    }
    if (!(observed->generation == plan.key.target_generation)) {
      continue;
    }
    ConditionList conditions(state.options.limits.max_explanation_entries);
    if (!recompute_currentness(state, plan, conditions)) {
      invalidate_plan(state, plan, CurrentnessCause::REVALIDATION_REQUIRED,
                      ChangeReason::INVALIDATE);
      ++result.plans_invalidated;
      for (const Condition& item : conditions.entries()) {
        result.conditions.add(item);
      }
      continue;
    }
    (void)touch_plan(state, plan, ChangeReason::REVALIDATE, ConditionCode::NONE,
                     TransitionStepId{});
    reindex_plan(state, plan);
  }

  result.epoch = state.epoch;
  result.convergence_generation = state.convergence;
  result.outcome = result.plans_superseded > 0
                       ? Outcome::PLAN_SUPERSEDED
                       : (result.plans_invalidated > 0 ? Outcome::PLAN_REVALIDATION_REQUIRED
                                                       : Outcome::NO_CHANGE);
  return result;
}

NoticeResult ConvergenceGovernor::note_path_change(const PathChangeNotice& notice,
                                                   const AuthorityContext& authority) {
  NoticeResult result;
  GovernorState& state = *impl_->state;
  const std::unique_lock<std::shared_mutex> lock(state.mutex);
  apply_epoch_locked(state);

  if (!notice.is_well_formed()) {
    result.outcome = Outcome::MALFORMED_REQUEST;
    result.conditions.add(make_condition(ConditionCode::MALFORMED_PAYLOAD, "path notice"));
    return result;
  }
  Condition condition;
  if (!authorize(state, authority, Capability::PUBLISH_UPSTREAM, RouteId{}, ConvergencePlanId{},
                 condition)) {
    result.outcome = Outcome::UNAUTHORIZED;
    result.conditions.add(condition);
    return result;
  }

  const std::optional<PathLegality> observed = state.paths.observe_path(notice.legality.path);
  if (!observed.has_value()) {
    result.outcome = Outcome::STALE_PATH_AUTHORITY;
    result.conditions.add(
        make_condition(ConditionCode::PATH_AUTHORITY_UNKNOWN, notice.legality.path.to_text()));
    return result;
  }

  const auto path_entry = state.by_path.find(notice.legality.path);
  if (path_entry == state.by_path.end()) {
    result.outcome = Outcome::NO_CHANGE;
    result.epoch = state.epoch;
    result.convergence_generation = state.convergence;
    return result;
  }
  const std::vector<ConvergencePlanId> affected = path_entry->second;
  for (const ConvergencePlanId& id : affected) {
    const auto entry = state.plans.find(id);
    if (entry == state.plans.end()) {
      continue;
    }
    ++result.plans_examined;
    ConvergencePlan& plan = entry->second;
    if (is_terminal_lifecycle(plan.lifecycle)) {
      continue;
    }
    ConditionList conditions(state.options.limits.max_explanation_entries);
    if (!recompute_currentness(state, plan, conditions)) {
      invalidate_plan(state, plan, CurrentnessCause::REVALIDATION_REQUIRED,
                      ChangeReason::INVALIDATE);
      ++result.plans_invalidated;
      for (const Condition& item : conditions.entries()) {
        result.conditions.add(item);
      }
      continue;
    }
    (void)touch_plan(state, plan, ChangeReason::REVALIDATE, ConditionCode::NONE,
                     TransitionStepId{});
    reindex_plan(state, plan);
  }

  result.epoch = state.epoch;
  result.convergence_generation = state.convergence;
  result.outcome = result.plans_invalidated > 0 ? Outcome::PLAN_REVALIDATION_REQUIRED
                                                : Outcome::NO_CHANGE;
  return result;
}

NoticeResult ConvergenceGovernor::note_epoch_change(const EpochChangeNotice& notice,
                                                    const AuthorityContext& authority) {
  NoticeResult result;
  GovernorState& state = *impl_->state;
  const std::unique_lock<std::shared_mutex> lock(state.mutex);

  if (!notice.is_well_formed()) {
    result.outcome = Outcome::MALFORMED_REQUEST;
    result.conditions.add(make_condition(ConditionCode::MALFORMED_PAYLOAD, "epoch notice"));
    return result;
  }
  Condition condition;
  if (!authorize(state, authority, Capability::PUBLISH_UPSTREAM, RouteId{}, ConvergencePlanId{},
                 condition)) {
    result.outcome = Outcome::UNAUTHORIZED;
    result.conditions.add(condition);
    return result;
  }
  if (notice.current.value() <= state.epoch.value()) {
    result.outcome = Outcome::NO_CHANGE;
    result.epoch = state.epoch;
    result.convergence_generation = state.convergence;
    return result;
  }
  apply_epoch(state, notice.current, ChangeReason::EPOCH_ADVANCE, notice.provenance);
  result.outcome = Outcome::EPOCH_ADVANCED;
  result.epoch = state.epoch;
  result.convergence_generation = state.convergence;
  result.conditions.add(make_condition(ConditionCode::NONE, "epoch", state.epoch.value(),
                                       notice.previous.value()));
  return result;
}

NoticeResult ConvergenceGovernor::sync_epoch() {
  NoticeResult result;
  GovernorState& state = *impl_->state;
  const std::unique_lock<std::shared_mutex> lock(state.mutex);
  const CoordinatorEpoch observed = state.epochs.current_epoch();
  if (observed.value() <= state.epoch.value()) {
    result.outcome = Outcome::NO_CHANGE;
    result.epoch = state.epoch;
    result.convergence_generation = state.convergence;
    return result;
  }
  const CoordinatorEpoch previous = state.epoch;
  apply_epoch(state, observed, ChangeReason::EPOCH_ADVANCE, epoch_provenance(observed));
  result.outcome = Outcome::EPOCH_ADVANCED;
  result.epoch = state.epoch;
  result.convergence_generation = state.convergence;
  result.conditions.add(
      make_condition(ConditionCode::NONE, "epoch", state.epoch.value(), previous.value()));
  return result;
}

}  // namespace rc
