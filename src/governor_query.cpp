#include <algorithm>
#include <string>

#include "governor_state.hpp"
#include "rc/graph.hpp"

namespace rc {
namespace {

[[nodiscard]] PlanSummary summarise(const GovernorState& state, const ConvergencePlan& plan) {
  (void)state;
  PlanSummary summary;
  summary.id = plan.id;
  summary.key = plan.key;
  summary.generation = plan.generation;
  summary.lifecycle = plan.lifecycle;
  summary.currentness = plan.currentness;
  summary.digest = plan.digest;
  summary.total_steps = static_cast<std::uint32_t>(plan.steps.size());
  for (const TransitionStep& step : plan.steps) {
    if (step.is_satisfied()) {
      ++summary.completed_steps;
    }
    if (step.state == StepLifecycle::READY) {
      ++summary.ready_steps;
    }
  }
  return summary;
}

[[nodiscard]] bool prerequisites_satisfied(const ConvergencePlan& plan, const TransitionStep& step) {
  for (const StepKey& dependency : step.spec.depends_on) {
    bool found = false;
    for (const TransitionStep& candidate : plan.steps) {
      if (candidate.spec.key() == dependency) {
        found = candidate.is_satisfied();
        break;
      }
    }
    if (!found) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] DiffKind diff_kind_of(const PlanChange& change, bool convergence_completed) {
  switch (change.reason) {
    case ChangeReason::CREATE:
      return DiffKind::PLAN_CREATED;
    case ChangeReason::VALIDATE:
      return DiffKind::LIFECYCLE_CHANGED;
    case ChangeReason::DISPATCH_STEP:
    case ChangeReason::FAIL_STEP:
    case ChangeReason::AMBIGUOUS_STEP:
    case ChangeReason::RECONCILE_STEP:
    case ChangeReason::ROLLBACK_STEP:
      return DiffKind::STEP_STATE_CHANGED;
    case ChangeReason::COMPLETE_STEP:
      return convergence_completed ? DiffKind::CONVERGENCE_COMPLETED
                                   : DiffKind::STEP_STATE_CHANGED;
    case ChangeReason::STEP_READY:
      return DiffKind::PREREQUISITE_SATISFIED;
    case ChangeReason::INVALIDATE:
      switch (change.condition) {
        case ConditionCode::TARGET_ROUTE_STALE:
        case ConditionCode::TARGET_ROUTE_UNKNOWN:
        case ConditionCode::TARGET_ROUTE_ILLEGAL:
        case ConditionCode::SOURCE_ROUTE_STALE:
          return DiffKind::TARGET_SUPERSEDED;
        case ConditionCode::PATH_AUTHORITY_STALE:
        case ConditionCode::PATH_AUTHORITY_UNKNOWN:
        case ConditionCode::PATH_AUTHORITY_UNAUTHORIZED:
        case ConditionCode::MULTIPATH_SET_STALE:
        case ConditionCode::ECMP_GENERATION_STALE:
        case ConditionCode::ASSIGNMENT_GENERATION_STALE:
        case ConditionCode::WEIGHT_POLICY_STALE:
          return DiffKind::PATH_DEPENDENCY_STALE;
        default:
          return DiffKind::CURRENTNESS_CHANGED;
      }
    case ChangeReason::REVALIDATE:
      return DiffKind::CURRENTNESS_CHANGED;
    case ChangeReason::SUPERSEDE:
      return DiffKind::TARGET_SUPERSEDED;
    case ChangeReason::ROLLBACK_REQUESTED:
      return DiffKind::ROLLBACK_ENTERED;
    case ChangeReason::ROLLBACK_COMPLETED:
      return DiffKind::CONVERGENCE_COMPLETED;
    case ChangeReason::REVOKE:
    case ChangeReason::RETIRE:
    case ChangeReason::PAUSE:
    case ChangeReason::RESUME:
      return DiffKind::LIFECYCLE_CHANGED;
    case ChangeReason::EPOCH_ADVANCE:
      return DiffKind::EPOCH_CHANGED;
    case ChangeReason::WORKER_FENCE:
      return DiffKind::AUTHORITY_CHANGED;
    case ChangeReason::RECOVERY:
      return DiffKind::CURRENTNESS_CHANGED;
  }
  return DiffKind::CURRENTNESS_CHANGED;
}

void add_step_conditions(const ConvergencePlan& plan, const TransitionStep& step,
                         Explanation& explanation) {
  explanation.add(make_condition(ConditionCode::NONE, "step_state", 0, 0));
  explanation.add(make_condition(ConditionCode::NONE, to_string(step.state), step.generation.value(),
                                 step.attempts));
  if (step.state == StepLifecycle::DISPATCHED) {
    explanation.add(make_condition(ConditionCode::NONE, "dispatch_watermark",
                                   step.dispatch_watermark.value(), plan.watermark.value()));
    explanation.add(
        make_condition(ConditionCode::NONE, "dispatch_epoch", step.dispatch_epoch.value(), 0));
  }
  for (const StepKey& dependency : step.spec.depends_on) {
    const TransitionStep* prerequisite = nullptr;
    for (const TransitionStep& candidate : plan.steps) {
      if (candidate.spec.key() == dependency) {
        prerequisite = &candidate;
        break;
      }
    }
    if (prerequisite == nullptr) {
      explanation.add(make_condition(ConditionCode::DEPENDENCY_MISSING, dependency.render()));
      continue;
    }
    if (!prerequisite->is_satisfied()) {
      explanation.add(
          make_condition(ConditionCode::PREREQUISITE_INCOMPLETE, dependency.render(),
                         static_cast<std::uint64_t>(prerequisite->state),
                         static_cast<std::uint64_t>(StepLifecycle::COMPLETED)));
    }
  }
}

}  // namespace

std::optional<PlanSummary> ConvergenceGovernor::query_plan(const ConvergencePlanId& plan) const {
  const GovernorState& state = *impl_->state;
  const std::shared_lock<std::shared_mutex> lock(state.mutex);
  const auto entry = state.plans.find(plan);
  if (entry == state.plans.end()) {
    return std::nullopt;
  }
  return summarise(state, entry->second);
}

PlanList ConvergenceGovernor::list_plans() const {
  const GovernorState& state = *impl_->state;
  const std::shared_lock<std::shared_mutex> lock(state.mutex);
  PlanList list;
  const std::size_t bound = state.options.limits.max_batch_size;
  for (const auto& entry : state.plans) {
    if (list.plans.size() >= bound) {
      list.truncated = true;
      break;
    }
    list.plans.push_back(summarise(state, entry.second));
  }
  return list;
}

std::optional<PlanKey> ConvergenceGovernor::plan_key(const ConvergencePlanId& plan) const {
  const GovernorState& state = *impl_->state;
  const std::shared_lock<std::shared_mutex> lock(state.mutex);
  const auto entry = state.plans.find(plan);
  if (entry == state.plans.end()) {
    return std::nullopt;
  }
  return entry->second.key;
}

std::optional<ConvergenceSnapshot> ConvergenceGovernor::snapshot(
    const ConvergencePlanId& plan) const {
  const GovernorState& state = *impl_->state;
  const std::shared_lock<std::shared_mutex> lock(state.mutex);
  const auto entry = state.plans.find(plan);
  if (entry == state.plans.end()) {
    return std::nullopt;
  }
  return build_snapshot(state, entry->second);
}

std::optional<ConvergenceDiff> ConvergenceGovernor::diff(const ConvergencePlanId& plan,
                                                         ConvergencePlanGeneration from) const {
  const GovernorState& state = *impl_->state;
  const std::shared_lock<std::shared_mutex> lock(state.mutex);
  const auto entry = state.plans.find(plan);
  if (entry == state.plans.end()) {
    return std::nullopt;
  }
  const ConvergencePlan& record = entry->second;
  ConvergenceDiff result;
  result.plan = record.id;
  result.from_generation = from;
  result.to_generation = record.generation;
  for (std::size_t index = 0; index < record.history.size(); ++index) {
    const PlanChange& change = record.history[index];
    if (change.plan_generation.value() <= from.value()) {
      continue;
    }
    DiffEntry diff_entry;
    const bool final_entry = index + 1 == record.history.size();
    diff_entry.kind = diff_kind_of(
        change, final_entry && record.lifecycle == PlanLifecycle::COMPLETED);
    diff_entry.plan_generation = change.plan_generation;
    diff_entry.convergence_generation = change.convergence_generation;
    diff_entry.step = change.step;
    diff_entry.subject = change.condition == ConditionCode::NONE
                             ? std::string{}
                             : std::string(to_string(change.condition));
    diff_entry.observed = change.observed;
    diff_entry.expected = change.expected;
    result.entries.push_back(std::move(diff_entry));
  }
  return result;
}

ExplainResponse ConvergenceGovernor::explain(const ExplainRequest& request) const {
  const GovernorState& state = *impl_->state;
  const std::shared_lock<std::shared_mutex> lock(state.mutex);
  ExplainResponse response;
  const auto entry = state.plans.find(request.plan);
  if (entry == state.plans.end()) {
    response.found = false;
    response.explanation.set_subject(request.plan.to_text());
    response.explanation.add(make_condition(ConditionCode::PLAN_UNKNOWN, request.plan.to_text()));
    return response;
  }
  const ConvergencePlan& plan = entry->second;
  response.found = true;
  response.explanation = Explanation(plan.id.to_text(), state.options.limits.max_explanation_entries);

  const TransitionStep* step = nullptr;
  if (!request.step.is_nil()) {
    step = plan.find_step(request.step);
    if (step == nullptr) {
      response.explanation.add(make_condition(ConditionCode::STEP_UNKNOWN, request.step.to_text()));
      return response;
    }
    response.explanation.set_subject(plan.id.to_text() + '/' + step->spec.key().render());
  }

  switch (request.kind) {
    case ExplainKind::PLAN:
      response.explanation.add(
          make_condition(ConditionCode::NONE, to_string(plan.lifecycle), plan.generation.value(),
                         plan.key.policy_generation.value()));
      response.explanation.add(make_condition(ConditionCode::NONE, "source_generation",
                                              plan.key.source_generation.value(),
                                              plan.key.target_generation.value()));
      for (const CurrentnessCause cause : plan.currentness.causes()) {
        response.explanation.add(make_condition(ConditionCode::REVALIDATION_REQUIRED,
                                                std::string(to_string(cause))));
      }
      response.explanation.add(make_condition(ConditionCode::NONE, "stale_steps", 0, 0));
      break;
    case ExplainKind::STEP:
      if (step == nullptr) {
        response.explanation.add(make_condition(ConditionCode::STEP_UNKNOWN, "step"));
        break;
      }
      add_step_conditions(plan, *step, response.explanation);
      break;
    case ExplainKind::READINESS:
      for (const TransitionStep& candidate : plan.steps) {
        if (candidate.state == StepLifecycle::READY) {
          response.explanation.add(make_condition(ConditionCode::NONE,
                                                  candidate.spec.key().render(),
                                                  candidate.generation.value(), 1));
          continue;
        }
        for (const StepKey& dependency : candidate.spec.depends_on) {
          bool satisfied = false;
          for (const TransitionStep& other : plan.steps) {
            if (other.spec.key() == dependency && other.is_satisfied()) {
              satisfied = true;
              break;
            }
          }
          if (!satisfied) {
            response.explanation.add(make_condition(ConditionCode::PREREQUISITE_INCOMPLETE,
                                                    candidate.spec.key().render()));
            break;
          }
        }
      }
      break;
    case ExplainKind::PREREQUISITE:
      if (step == nullptr) {
        response.explanation.add(make_condition(ConditionCode::STEP_UNKNOWN, "step"));
        break;
      }
      add_step_conditions(plan, *step, response.explanation);
      break;
    case ExplainKind::OLD_STATE_RETENTION: {
      const TransitionStep* withdraw = nullptr;
      for (const TransitionStep& candidate : plan.steps) {
        if (candidate.spec.kind == StepKind::WITHDRAW_OLD_ROUTE) {
          withdraw = &candidate;
          break;
        }
      }
      if (withdraw == nullptr) {
        response.explanation.add(make_condition(ConditionCode::ALREADY_SATISFIED, "source_state"));
        break;
      }
      response.explanation.add(make_condition(
          ConditionCode::NONE, withdraw->spec.key().render(), withdraw->generation.value(),
          static_cast<std::uint64_t>(withdraw->state)));
      add_step_conditions(plan, *withdraw, response.explanation);
      break;
    }
    case ExplainKind::TARGET_ACTIVATION: {
      const TransitionStep* activate = nullptr;
      for (const TransitionStep& candidate : plan.steps) {
        if (candidate.spec.kind == StepKind::ACTIVATE_NEW_PATH ||
            candidate.spec.kind == StepKind::INSTALL_NEW_ROUTE) {
          activate = &candidate;
        }
      }
      if (activate == nullptr) {
        response.explanation.add(make_condition(ConditionCode::ALREADY_SATISFIED, "target_state"));
        break;
      }
      response.explanation.add(make_condition(
          ConditionCode::NONE, activate->spec.key().render(), activate->generation.value(),
          static_cast<std::uint64_t>(activate->state)));
      add_step_conditions(plan, *activate, response.explanation);
      break;
    }
    case ExplainKind::ROLLBACK:
      response.explanation.add(make_condition(ConditionCode::NONE, "rollback_required",
                                              plan.rollback_required ? 1 : 0, 0));
      response.explanation.add(make_condition(ConditionCode::NONE, "rollback_plan",
                                              plan.rollback_plan.bytes()[15],
                                              plan.predecessor.bytes()[15]));
      response.explanation.add(
          make_condition(ConditionCode::NONE, to_string(plan.lifecycle), 0, 0));
      break;
    case ExplainKind::STALENESS:
      if (plan.currentness.is_current()) {
        response.explanation.add(make_condition(ConditionCode::NONE, "current"));
        break;
      }
      for (const CurrentnessCause cause : plan.currentness.causes()) {
        response.explanation.add(make_condition(ConditionCode::REVALIDATION_REQUIRED,
                                                std::string(to_string(cause))));
      }
      break;
    case ExplainKind::COMPLETION:
      for (const TransitionStep& candidate : plan.steps) {
        if (candidate.spec.mandatory && !candidate.is_satisfied()) {
          response.explanation.add(make_condition(ConditionCode::PREREQUISITE_INCOMPLETE,
                                                  candidate.spec.key().render(),
                                                  static_cast<std::uint64_t>(candidate.state),
                                                  static_cast<std::uint64_t>(
                                                      StepLifecycle::COMPLETED)));
        }
      }
      if (response.explanation.conditions().empty()) {
        response.explanation.add(make_condition(ConditionCode::ALREADY_SATISFIED, "completion"));
      }
      break;
    case ExplainKind::AUTHORITY:
      response.explanation.add(make_condition(ConditionCode::NONE, "owner_publisher",
                                              plan.owner_publisher.bytes()[15], 0));
      response.explanation.add(make_condition(ConditionCode::NONE, "owner_boot",
                                              plan.owner_boot.bytes()[15], 0));
      response.explanation.add(make_condition(ConditionCode::NONE, "bound_epoch",
                                              plan.bound_epoch.value(), state.epoch.value()));
      response.explanation.add(make_condition(ConditionCode::NONE, "authority_generation",
                                              plan.authority_generation.value(), 0));
      response.explanation.add(
          make_condition(ConditionCode::NONE, "convergence_generation", plan.watermark.value(),
                         state.convergence.value()));
      break;
  }
  return response;
}

std::optional<PublisherRegistration> ConvergenceGovernor::worker_registration(
    const PublisherId& publisher) const {
  const GovernorState& state = *impl_->state;
  const std::shared_lock<std::shared_mutex> lock(state.mutex);
  const auto entry = state.workers.find(publisher);
  if (entry == state.workers.end()) {
    return std::nullopt;
  }
  return entry->second.registration;
}

namespace {

// Shared implementation of both ready-step views.  A null scope is the operator
// view; a non-null scope restricts the answer to the plans that scope covers.
[[nodiscard]] ReadyStepList collect_ready_steps(const GovernorState& state,
                                                std::uint32_t max_steps,
                                                const AuthorityScope* scope) {
  ReadyStepList list;
  const std::uint32_t bound = std::min(
      {max_steps, state.options.limits.max_parallel_steps, state.options.limits.max_batch_size});
  if (bound == 0) {
    return list;
  }
  for (const auto& entry : state.plans) {
    const ConvergencePlan& plan = entry.second;
    if (plan.lifecycle != PlanLifecycle::READY && plan.lifecycle != PlanLifecycle::EXECUTING) {
      continue;
    }
    if (scope != nullptr &&
        !scope->covers_plan(state.options.fabric, state.options.routing_namespace,
                            plan.key.route, plan.id)) {
      continue;
    }
    const std::uint32_t plan_bound =
        std::min(plan.policy.max_parallel_steps, state.options.limits.max_parallel_steps);
    std::uint32_t taken = 0;
    for (const TransitionStep& step : plan.steps) {
      if (step.state != StepLifecycle::READY) {
        continue;
      }
      if (taken >= plan_bound) {
        list.truncated = true;
        break;
      }
      if (list.steps.size() >= bound) {
        list.truncated = true;
        break;
      }
      ReadyStep ready;
      ready.plan = plan.id;
      ready.step = step.id;
      ready.key = step.spec.key();
      ready.generation = step.generation;
      ready.watermark = plan.watermark;
      ready.route = plan.key.route;
      ready.spec = step.spec;
      list.steps.push_back(std::move(ready));
      ++taken;
    }
    if (list.steps.size() >= bound) {
      list.truncated = true;
      break;
    }
  }
  return list;
}

}  // namespace

ReadyStepList ConvergenceGovernor::ready_steps(std::uint32_t max_steps) const {
  const GovernorState& state = *impl_->state;
  const std::shared_lock<std::shared_mutex> lock(state.mutex);
  return collect_ready_steps(state, max_steps, nullptr);
}

ReadyStepList ConvergenceGovernor::ready_steps_for(std::uint32_t max_steps,
                                                   const AuthorityScope& scope) const {
  const GovernorState& state = *impl_->state;
  const std::shared_lock<std::shared_mutex> lock(state.mutex);
  return collect_ready_steps(state, max_steps, &scope);
}

}  // namespace rc
