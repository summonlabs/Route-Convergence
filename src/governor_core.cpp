#include "governor_state.hpp"

#include <algorithm>

#include "rc/bytes.hpp"

namespace rc {
namespace {

// A snapshot identity is the first 128 bits of its own semantic digest: two
// snapshots of the same convergence state therefore carry the same identity.
template <class Id>
[[nodiscard]] Id id_from_digest(const Digest& digest) {
  std::array<std::uint8_t, Id::kByteCount> raw{};
  for (std::size_t index = 0; index < raw.size(); ++index) {
    raw[index] = digest.bytes()[index];
  }
  return Id::from_bytes(raw);
}

}  // namespace

ConvergenceGovernor::ConvergenceGovernor(RouteFabricView& routes, PathAuthorityView& paths,
                                         FabricEpochView& epochs, GovernorOptions options)
    : impl_(std::make_unique<Impl>()) {
  impl_->state = std::make_unique<GovernorState>(routes, paths, epochs, std::move(options));
  std::string reason;
  if (!validate_options(impl_->state->options, reason)) {
    impl_->state->coherent = false;
    impl_->state->incoherence_reason = std::move(reason);
  }
}

ConvergenceGovernor::~ConvergenceGovernor() = default;

bool ConvergenceGovernor::validate_options(const GovernorOptions& options, std::string& reason) {
  if (!options.limits.is_coherent(reason)) {
    return false;
  }
  if (options.initial_epoch.value() == 0) {
    reason = "initial_epoch must be at least 1";
    return false;
  }
  reason.clear();
  return true;
}

bool ConvergenceGovernor::coherent() const {
  const std::shared_lock<std::shared_mutex> lock(impl_->state->mutex);
  return impl_->state->coherent;
}

const ConvergenceLimits& ConvergenceGovernor::limits() const noexcept {
  return impl_->state->options.limits;
}

CoordinatorEpoch ConvergenceGovernor::epoch() const {
  const std::shared_lock<std::shared_mutex> lock(impl_->state->mutex);
  return impl_->state->epoch;
}

ConvergenceGeneration ConvergenceGovernor::convergence_generation() const {
  const std::shared_lock<std::shared_mutex> lock(impl_->state->mutex);
  return impl_->state->convergence;
}

GovernorStats ConvergenceGovernor::stats() const {
  const std::shared_lock<std::shared_mutex> lock(impl_->state->mutex);
  return impl_->state->stats;
}

std::size_t ConvergenceGovernor::plan_count() const {
  const std::shared_lock<std::shared_mutex> lock(impl_->state->mutex);
  return impl_->state->plans.size();
}

std::size_t ConvergenceGovernor::worker_count() const {
  const std::shared_lock<std::shared_mutex> lock(impl_->state->mutex);
  return impl_->state->workers.size();
}

const std::filesystem::path& ConvergenceGovernor::store_path() const {
  return impl_->state->store_path;
}

// --- free helpers -----------------------------------------------------------

bool advance_convergence(GovernorState& state) {
  const std::optional<ConvergenceGeneration> next = state.convergence.next();
  if (!next.has_value()) {
    return false;
  }
  state.convergence = *next;
  return true;
}

bool advance_authority(GovernorState& state, ConvergencePlan& plan) {
  (void)state;
  const std::optional<AuthorityGeneration> next = plan.authority_generation.next();
  if (!next.has_value()) {
    return false;
  }
  plan.authority_generation = *next;
  return true;
}

ProvenanceId epoch_provenance(CoordinatorEpoch epoch) {
  return derive_id<ProvenanceId>("rc.epoch.provenance.v1", epoch.value());
}

Digest request_digest(std::string_view domain, const PlanKey& key, const std::string& extra) {
  Encoder encoder;
  encoder.raw(key.content_digest().bytes());
  encoder.text(extra);
  return domain_digest(domain, encoder.bytes());
}

Digest text_digest(std::string_view domain, std::string_view text) {
  return domain_digest(domain, std::span<const std::uint8_t>(
                                   reinterpret_cast<const std::uint8_t*>(text.data()),
                                   text.size()));
}

bool attempt_gate(GovernorState& state, const AuthorityContext& authority, const Digest& payload,
                  PlanMutationResult& early) {
  switch (check_attempt(state, authority, payload, early)) {
    case AttemptCheck::REPLAY:
      early.outcome = Outcome::IDEMPOTENT;
      return true;
    case AttemptCheck::CONFLICT:
      early = rejection(Outcome::ATTEMPT_CONFLICT, ConditionCode::ATTEMPT_CONFLICT,
                        authority.attempt.to_text());
      return true;
    case AttemptCheck::FRESH:
      return false;
  }
  return false;
}

void record_attempt(GovernorState& state, const AuthorityContext& authority, const Digest& payload,
                    const PlanMutationResult& result) {
  if (authority.attempt.is_nil()) {
    return;
  }
  AttemptRecord record;
  record.payload = payload;
  record.outcome = result.outcome;
  record.plan = result.plan;
  record.step = result.step;
  record.plan_generation = result.plan_generation;
  record.step_generation = result.step_generation;
  record.convergence_generation = result.convergence_generation;
  record.digest = result.digest;
  record.conditions = result.conditions.render();

  if (state.attempts.find(authority.attempt) == state.attempts.end()) {
    state.attempt_order.push_back(authority.attempt);
  }
  state.attempts[authority.attempt] = std::move(record);

  while (state.attempt_order.size() > state.options.limits.max_attempts_remembered) {
    const MutationAttemptId oldest = state.attempt_order.front();
    state.attempt_order.pop_front();
    state.attempts.erase(oldest);
  }
}

AttemptCheck check_attempt(GovernorState& state, const AuthorityContext& authority,
                           const Digest& payload, PlanMutationResult& replay_result) {
  if (authority.attempt.is_nil()) {
    return AttemptCheck::FRESH;
  }
  const auto entry = state.attempts.find(authority.attempt);
  if (entry == state.attempts.end()) {
    return AttemptCheck::FRESH;
  }
  if (!(entry->second.payload == payload)) {
    // A dispatch and the completion of the very step it dispatched are a
    // natural pair that a worker may bind to one execution attempt identifier.
    // Only a genuinely different mutation under the same identifier is a
    // conflict.
    if (entry->second.outcome == Outcome::STEP_DISPATCHED) {
      return AttemptCheck::FRESH;
    }
    ++state.stats.attempt_conflicts;
    return AttemptCheck::CONFLICT;
  }
  ++state.stats.attempt_replays;
  replay_result.outcome = entry->second.outcome;
  replay_result.plan = entry->second.plan;
  replay_result.step = entry->second.step;
  replay_result.plan_generation = entry->second.plan_generation;
  replay_result.step_generation = entry->second.step_generation;
  replay_result.convergence_generation = entry->second.convergence_generation;
  replay_result.digest = entry->second.digest;
  return AttemptCheck::REPLAY;
}

PlanMutationResult rejection(Outcome outcome, ConditionCode code, std::string_view subject,
                             std::uint64_t observed, std::uint64_t expected) {
  PlanMutationResult result;
  result.outcome = outcome;
  result.conditions.add(make_condition(code, subject, observed, expected));
  return result;
}

PlanMutationResult make_result(const GovernorState& state, Outcome outcome,
                               const ConvergencePlan& plan) {
  PlanMutationResult result;
  result.outcome = outcome;
  result.plan = plan.id;
  result.plan_generation = plan.generation;
  result.convergence_generation = state.convergence;
  result.digest = plan.digest;
  return result;
}

PlanMutationResult make_result(const GovernorState& state, Outcome outcome,
                               const ConvergencePlan& plan, ConditionCode code,
                               std::string_view subject, std::uint64_t observed,
                               std::uint64_t expected) {
  PlanMutationResult result = make_result(state, outcome, plan);
  result.conditions.add(make_condition(code, subject, observed, expected));
  return result;
}

bool worker_live_locked(const GovernorState& state, const PublisherId& publisher,
                        const WorkerBootId& boot) {
  if (state.fenced_boots.find(boot) != state.fenced_boots.end()) {
    return false;
  }
  const auto entry = state.workers.find(publisher);
  if (entry == state.workers.end()) {
    return false;
  }
  return entry->second.live && entry->second.registration.worker_boot == boot;
}

void supersede_entry(GovernorState& state, const ConvergencePlanId& id, ChangeReason reason,
                     const ConvergencePlanId& successor) {
  const auto entry = state.plans.find(id);
  if (entry == state.plans.end()) {
    return;
  }
  ConvergencePlan& plan = entry->second;
  const std::optional<PlanLifecycle> next =
      apply_plan_event(plan.lifecycle, PlanEvent::SUPERSEDE, PlanTransitionInputs{});
  if (!next.has_value() || plan.lifecycle == PlanLifecycle::SUPERSEDED) {
    return;
  }
  plan.lifecycle = *next;
  plan.supersession_reason = reason;
  if (!successor.is_nil()) {
    plan.successor = successor;
  }
  plan.currentness.add(CurrentnessCause::SUPERSEDED_BY_SUCCESSOR);
  plan.rollback_required = false;
  if (advance_convergence(state)) {
    plan.watermark = state.convergence;
  }
  stale_in_flight_steps(state, plan);
  ++state.stats.plans_superseded;
  (void)touch_plan(state, plan, reason, ConditionCode::PLAN_SUPERSEDED, TransitionStepId{});
  reindex_plan(state, plan);
}

void index_plan(GovernorState& state, const ConvergencePlan& plan) {
  state.by_key[plan.key] = plan.id;
  const auto add_to = [&plan](auto& container, const auto& key) {
    std::vector<ConvergencePlanId>& list = container[key];
    if (std::find(list.begin(), list.end(), plan.id) == list.end()) {
      list.push_back(plan.id);
      std::sort(list.begin(), list.end());
    }
  };
  add_to(state.by_route, plan.key.route);
  if (!plan.source.path.is_nil()) {
    add_to(state.by_path, plan.source.path);
  }
  if (!plan.target.path.is_nil() && !(plan.target.path == plan.source.path)) {
    add_to(state.by_path, plan.target.path);
  }
  state.by_lifecycle[plan.lifecycle].insert(plan.id);
  for (const TransitionStep& step : plan.steps) {
    if (step.state == StepLifecycle::DISPATCHED && !step.dispatch_boot.is_nil()) {
      state.by_boot[step.dispatch_boot].push_back({plan.id, step.id});
    }
  }
}

void reindex_plan(GovernorState& state, const ConvergencePlan& plan) {
  for (auto& entry : state.by_lifecycle) {
    entry.second.erase(plan.id);
  }
  state.by_lifecycle[plan.lifecycle].insert(plan.id);

  for (auto entry = state.by_boot.begin(); entry != state.by_boot.end();) {
    std::vector<std::pair<ConvergencePlanId, TransitionStepId>>& list = entry->second;
    list.erase(std::remove_if(list.begin(), list.end(),
                              [&plan](const std::pair<ConvergencePlanId, TransitionStepId>& item) {
                                return item.first == plan.id;
                              }),
               list.end());
    if (list.empty()) {
      entry = state.by_boot.erase(entry);
    } else {
      ++entry;
    }
  }
  for (const TransitionStep& step : plan.steps) {
    if (step.state == StepLifecycle::DISPATCHED && !step.dispatch_boot.is_nil()) {
      state.by_boot[step.dispatch_boot].push_back({plan.id, step.id});
    }
  }
}

void deindex_plan(GovernorState& state, const ConvergencePlan& plan) {
  state.by_key.erase(plan.key);
  const auto erase_from = [&plan](auto& container, const auto& key) {
    const auto entry = container.find(key);
    if (entry == container.end()) {
      return;
    }
    std::vector<ConvergencePlanId>& list = entry->second;
    list.erase(std::remove(list.begin(), list.end(), plan.id), list.end());
    if (list.empty()) {
      container.erase(entry);
    }
  };
  erase_from(state.by_route, plan.key.route);
  if (!plan.source.path.is_nil()) {
    erase_from(state.by_path, plan.source.path);
  }
  if (!plan.target.path.is_nil() && !(plan.target.path == plan.source.path)) {
    erase_from(state.by_path, plan.target.path);
  }
  for (auto& entry : state.by_lifecycle) {
    entry.second.erase(plan.id);
  }
  for (auto entry = state.by_boot.begin(); entry != state.by_boot.end();) {
    std::vector<std::pair<ConvergencePlanId, TransitionStepId>>& list = entry->second;
    list.erase(std::remove_if(list.begin(), list.end(),
                              [&plan](const std::pair<ConvergencePlanId, TransitionStepId>& item) {
                                return item.first == plan.id;
                              }),
               list.end());
    if (list.empty()) {
      entry = state.by_boot.erase(entry);
    } else {
      ++entry;
    }
  }
}

bool touch_plan(GovernorState& state, ConvergencePlan& plan, ChangeReason reason,
                ConditionCode condition, const TransitionStepId& step) {
  // The stored digest is always f(current generation, current content), so a
  // change is detected against the digest the plan already has and the digest is
  // recomputed *after* the generation advances.  Storing a digest computed
  // before the advance would make a changed plan unrecoverable, because the
  // persisted record could never reproduce its own digest.
  const Digest content = ConvergenceGovernor::plan_content_digest(plan);
  bool ok = true;
  if (!(content == plan.digest)) {
    const std::optional<ConvergencePlanGeneration> next = plan.next_generation();
    if (!next.has_value()) {
      plan.currentness.add(CurrentnessCause::REVALIDATION_REQUIRED);
      plan.last_condition = ConditionCode::GENERATION_EXHAUSTED;
      return false;
    }
    plan.generation = *next;
    plan.digest = ConvergenceGovernor::plan_content_digest(plan);
  }

  PlanChange change;
  change.reason = reason;
  change.condition = condition;
  change.step = step;
  change.plan_generation = plan.generation;
  change.convergence_generation = state.convergence;
  if (!step.is_nil()) {
    const TransitionStep* record = plan.find_step(step);
    if (record != nullptr) {
      change.step_state = record->state;
    }
  }
  plan.history.push_back(std::move(change));
  while (plan.history.size() > state.options.limits.max_history_per_plan) {
    plan.history.erase(plan.history.begin());
  }
  return ok;
}

void refresh_ready_steps(GovernorState& state, ConvergencePlan& plan) {
  (void)state;
  bool changed = true;
  while (changed) {
    changed = false;
    for (TransitionStep& step : plan.steps) {
      if (step.state != StepLifecycle::PENDING) {
        continue;
      }
      bool satisfied = true;
      for (const StepKey& dependency : step.spec.depends_on) {
        const TransitionStep* prerequisite = nullptr;
        for (const TransitionStep& candidate : plan.steps) {
          if (candidate.spec.key() == dependency) {
            prerequisite = &candidate;
            break;
          }
        }
        if (prerequisite == nullptr || !prerequisite->is_satisfied()) {
          satisfied = false;
          break;
        }
      }
      if (satisfied) {
        step.state = StepLifecycle::READY;
        step.last_change = ChangeReason::STEP_READY;
        changed = true;
      }
    }
  }
}

void stale_in_flight_steps(GovernorState& state, ConvergencePlan& plan) {
  for (TransitionStep& step : plan.steps) {
    if (step.state == StepLifecycle::DISPATCHED) {
      step.state = StepLifecycle::STALE;
      step.last_change = ChangeReason::INVALIDATE;
      step.last_condition = ConditionCode::STEP_STALE;
      ++state.stats.steps_staled;
    }
  }
}

void stale_in_flight_steps_of_boot(GovernorState& state, const WorkerBootId& boot,
                                   ChangeReason reason) {
  const auto dispatch = state.by_boot.find(boot);
  if (dispatch == state.by_boot.end()) {
    return;
  }
  std::vector<ConvergencePlanId> affected;
  for (const auto& item : dispatch->second) {
    if (std::find(affected.begin(), affected.end(), item.first) == affected.end()) {
      affected.push_back(item.first);
    }
  }
  for (const ConvergencePlanId& id : affected) {
    const auto entry = state.plans.find(id);
    if (entry == state.plans.end()) {
      continue;
    }
    ConvergencePlan& plan = entry->second;
    bool staled = false;
    for (TransitionStep& step : plan.steps) {
      if (step.state == StepLifecycle::DISPATCHED && step.dispatch_boot == boot) {
        step.state = StepLifecycle::STALE;
        step.last_change = reason;
        step.last_condition = ConditionCode::WORKER_FENCED;
        ++state.stats.steps_staled;
        staled = true;
      }
    }
    if (!staled || is_terminal_lifecycle(plan.lifecycle)) {
      continue;
    }
    invalidate_plan(state, plan, CurrentnessCause::FENCED_PUBLISHER, reason);
  }
}

void invalidate_plan(GovernorState& state, ConvergencePlan& plan, CurrentnessCause cause,
                     ChangeReason reason) {
  if (is_terminal_lifecycle(plan.lifecycle)) {
    return;
  }
  plan.currentness.add(cause);
  const std::optional<PlanLifecycle> next =
      apply_plan_event(plan.lifecycle, PlanEvent::INVALIDATE, PlanTransitionInputs{});
  if (next.has_value()) {
    plan.lifecycle = *next;
  }
  if (advance_convergence(state)) {
    plan.watermark = state.convergence;
  }
  stale_in_flight_steps(state, plan);
  ++state.stats.plans_invalidated;
  (void)touch_plan(state, plan, reason, ConditionCode::REVALIDATION_REQUIRED, TransitionStepId{});
  reindex_plan(state, plan);
}

bool recompute_currentness(GovernorState& state, ConvergencePlan& plan,
                           ConditionList& conditions) {
  Currentness computed;
  const Currentness previous = plan.currentness;

  if (plan.lifecycle == PlanLifecycle::SUPERSEDED) {
    computed.add(CurrentnessCause::SUPERSEDED_BY_SUCCESSOR);
  }

  const std::optional<RouteBinding> observed = state.routes.observe_route(plan.key.route);
  if (!observed.has_value()) {
    computed.add(CurrentnessCause::STALE_TARGET_ROUTE);
    conditions.add(make_condition(ConditionCode::TARGET_ROUTE_UNKNOWN, plan.key.route.to_text()));
  } else if (plan.is_rollback) {
    // A rollback plan targets an older route generation on purpose, so the
    // forward target-generation rule does not apply.  What must still hold is
    // that the state being compensated has not moved on: if a newer generation
    // appeared, this rollback no longer describes reality and must be replanned.
    if (observed->generation != plan.key.source_generation) {
      computed.add(CurrentnessCause::STALE_TARGET_ROUTE);
      conditions.add(make_condition(ConditionCode::TARGET_ROUTE_STALE, plan.key.route.to_text(),
                                    observed->generation.value(),
                                    plan.key.source_generation.value()));
    }
    if (!observed->legal) {
      computed.add(CurrentnessCause::STALE_TARGET_ROUTE);
      conditions.add(make_condition(ConditionCode::TARGET_ROUTE_ILLEGAL, plan.key.route.to_text()));
    }
  } else {
    if (observed->generation != plan.key.target_generation) {
      computed.add(CurrentnessCause::STALE_TARGET_ROUTE);
      conditions.add(make_condition(ConditionCode::TARGET_ROUTE_STALE, plan.key.route.to_text(),
                                    observed->generation.value(),
                                    plan.key.target_generation.value()));
    } else if (!observed->current) {
      computed.add(CurrentnessCause::STALE_TARGET_ROUTE);
      conditions.add(
          make_condition(ConditionCode::TARGET_ROUTE_STALE, plan.key.route.to_text(), 0, 1));
    }
    if (!observed->legal) {
      computed.add(CurrentnessCause::STALE_TARGET_ROUTE);
      conditions.add(make_condition(ConditionCode::TARGET_ROUTE_ILLEGAL, plan.key.route.to_text()));
    }
    // A source generation that is simply the previous desired generation is
    // normal for a forward plan.  Only a generation that is neither the source
    // nor the target means the plan was built against a state that no longer
    // exists in any form.
    if (observed->generation != plan.key.source_generation &&
        observed->generation != plan.key.target_generation) {
      computed.add(CurrentnessCause::STALE_SOURCE_ROUTE);
      conditions.add(make_condition(ConditionCode::SOURCE_ROUTE_STALE, plan.key.route.to_text(),
                                    observed->generation.value(),
                                    plan.key.source_generation.value()));
    }
    if (!(observed->multipath_set == plan.target.multipath_set) ||
        !(observed->multipath_generation == plan.target.multipath_generation)) {
      computed.add(CurrentnessCause::STALE_MULTIPATH_SET);
      conditions.add(make_condition(ConditionCode::MULTIPATH_SET_STALE,
                                    plan.target.multipath_set.to_text(),
                                    observed->multipath_generation.value(),
                                    plan.target.multipath_generation.value()));
    }
    if (!(observed->ecmp_group == plan.target.ecmp_group) ||
        !(observed->ecmp_generation == plan.target.ecmp_generation)) {
      computed.add(CurrentnessCause::STALE_ECMP_GENERATION);
      conditions.add(make_condition(ConditionCode::ECMP_GENERATION_STALE,
                                    plan.target.ecmp_group.to_text(),
                                    observed->ecmp_generation.value(),
                                    plan.target.ecmp_generation.value()));
    }
    if (!(observed->assignment_generation == plan.target.assignment_generation)) {
      computed.add(CurrentnessCause::STALE_ASSIGNMENT_GENERATION);
      conditions.add(make_condition(ConditionCode::ASSIGNMENT_GENERATION_STALE,
                                    plan.target.ecmp_group.to_text(),
                                    observed->assignment_generation.value(),
                                    plan.target.assignment_generation.value()));
    }
    if (!(observed->weighted_set == plan.target.weighted_set) ||
        !(observed->weight_policy_generation == plan.target.weight_policy_generation)) {
      computed.add(CurrentnessCause::STALE_WEIGHT_POLICY);
      conditions.add(make_condition(ConditionCode::WEIGHT_POLICY_STALE,
                                    plan.target.weighted_set.to_text(),
                                    observed->weight_policy_generation.value(),
                                    plan.target.weight_policy_generation.value()));
    }
  }

  const std::optional<PathLegality> legality = state.paths.observe_path(plan.target.path);
  if (!legality.has_value()) {
    computed.add(CurrentnessCause::STALE_PATH_AUTHORITY);
    conditions.add(
        make_condition(ConditionCode::PATH_AUTHORITY_UNKNOWN, plan.target.path.to_text()));
  } else if (!(legality->generation == plan.target.path_authority_generation)) {
    computed.add(CurrentnessCause::STALE_PATH_AUTHORITY);
    conditions.add(make_condition(ConditionCode::PATH_AUTHORITY_STALE, plan.target.path.to_text(),
                                  legality->generation.value(),
                                  plan.target.path_authority_generation.value()));
  } else if (!legality->legal) {
    computed.add(CurrentnessCause::STALE_PATH_AUTHORITY);
    conditions.add(make_condition(ConditionCode::PATH_AUTHORITY_UNAUTHORIZED,
                                  plan.target.path.to_text()));
  }

  if (!(state.epoch == plan.bound_epoch)) {
    computed.add(CurrentnessCause::STALE_EPOCH);
    conditions.add(make_condition(ConditionCode::AUTHORITY_EPOCH_STALE, "plan", state.epoch.value(),
                                  plan.bound_epoch.value()));
  }

  const auto policy = state.policies.find(plan.policy.id);
  if (policy == state.policies.end() || !(policy->second.generation == plan.key.policy_generation)) {
    computed.add(CurrentnessCause::STALE_POLICY_GENERATION);
    conditions.add(make_condition(
        ConditionCode::POLICY_GENERATION_STALE, plan.policy.id.to_text(),
        policy == state.policies.end() ? 0 : policy->second.generation.value(),
        plan.key.policy_generation.value()));
  }

  // A plan's currentness depends on the state it converges towards, not on which
  // process happened to act on it last.  A fenced worker boot can no longer
  // dispatch or complete anything, and the *steps* it had in flight are marked
  // stale where that happens; the plan itself is not invalidated for having been
  // owned by a process that exited.
  if (previous.has(CurrentnessCause::REVALIDATION_REQUIRED)) {
    computed.add(CurrentnessCause::REVALIDATION_REQUIRED);
  }

  plan.currentness = computed;
  return computed.authority_current();
}

void fence_boot(GovernorState& state, const WorkerBootId& boot, ChangeReason reason) {
  if (boot.is_nil()) {
    return;
  }
  state.fenced_boots.insert(boot);
  for (auto& entry : state.workers) {
    if (entry.second.registration.worker_boot == boot) {
      entry.second.live = false;
    }
  }
  if (const std::optional<AuthorityGeneration> next = state.authority_generation.next();
      next.has_value()) {
    state.authority_generation = *next;
  }
  (void)advance_convergence(state);
  ++state.stats.worker_fences;

  stale_in_flight_steps_of_boot(state, boot, reason);
}

void apply_epoch(GovernorState& state, CoordinatorEpoch next, ChangeReason reason,
                 ProvenanceId provenance) {
  if (next.value() <= state.epoch.value()) {
    return;
  }
  (void)provenance;
  state.epoch = next;
  if (const std::optional<AuthorityGeneration> advanced = state.authority_generation.next();
      advanced.has_value()) {
    state.authority_generation = *advanced;
  }
  if (!advance_convergence(state)) {
    return;
  }
  ++state.stats.epoch_advances;
  for (auto& entry : state.plans) {
    ConvergencePlan& plan = entry.second;
    if (is_terminal_lifecycle(plan.lifecycle)) {
      continue;
    }
    plan.currentness.add(CurrentnessCause::STALE_EPOCH);
    const std::optional<PlanLifecycle> transition =
        apply_plan_event(plan.lifecycle, PlanEvent::INVALIDATE, PlanTransitionInputs{});
    if (transition.has_value()) {
      plan.lifecycle = *transition;
    }
    plan.watermark = state.convergence;
    stale_in_flight_steps(state, plan);
    (void)touch_plan(state, plan, reason, ConditionCode::AUTHORITY_EPOCH_STALE,
                     TransitionStepId{});
    reindex_plan(state, plan);
  }
}

bool authorize(GovernorState& state, const AuthorityContext& authority, Capability capability,
               const RouteId& route, const ConvergencePlanId& plan, Condition& condition) {
  if (!state.coherent) {
    condition = make_condition(ConditionCode::INTERNAL_INVARIANT, state.incoherence_reason);
    return false;
  }
  if (!authority.is_well_formed()) {
    condition = make_condition(ConditionCode::MALFORMED_IDENTITY, "authority");
    return false;
  }
  if (!(authority.epoch == state.epoch)) {
    condition = make_condition(ConditionCode::AUTHORITY_EPOCH_STALE, "epoch",
                               authority.epoch.value(), state.epoch.value());
    return false;
  }
  const auto worker = state.workers.find(authority.publisher);
  if (worker == state.workers.end()) {
    condition = make_condition(ConditionCode::PUBLISHER_UNKNOWN, authority.publisher.to_text());
    return false;
  }
  if (state.fenced_boots.find(authority.worker_boot) != state.fenced_boots.end() ||
      !(worker->second.registration.worker_boot == authority.worker_boot) || !worker->second.live) {
    condition = make_condition(ConditionCode::WORKER_FENCED, authority.worker_boot.to_text());
    return false;
  }
  const std::uint32_t capabilities = worker->second.registration.capabilities;
  if (!has_capability(capabilities, capability) && !has_capability(capabilities, Capability::ADMIN)) {
    condition = make_condition(ConditionCode::CAPABILITY_MISSING, to_string(capability));
    return false;
  }
  const AuthorityScope& scope = worker->second.registration.scope;
  if (!scope.covers_plan(state.options.fabric, state.options.routing_namespace, route, plan)) {
    condition = make_condition(ConditionCode::SCOPE_DENIED, scope.render());
    return false;
  }
  return true;
}

ConvergenceSnapshot build_snapshot(const GovernorState& state, const ConvergencePlan& plan) {
  ConvergenceSnapshot snapshot;
  snapshot.plan = plan.id;
  snapshot.plan_generation = plan.generation;
  snapshot.lifecycle = plan.lifecycle;
  snapshot.currentness = plan.currentness;
  snapshot.policy = plan.policy;
  snapshot.source = plan.source;
  snapshot.target = plan.target;
  snapshot.mode = plan.mode;
  snapshot.epoch = state.epoch;
  snapshot.created_epoch = plan.created_epoch;
  snapshot.owner_publisher = plan.owner_publisher;
  snapshot.owner_boot = plan.owner_boot;
  snapshot.authority_generation = plan.authority_generation;
  snapshot.provenance = plan.provenance;
  snapshot.convergence_generation = state.convergence;
  snapshot.watermark = plan.watermark;
  snapshot.predecessor = plan.predecessor;
  snapshot.successor = plan.successor;
  snapshot.supersession_reason = plan.supersession_reason;
  snapshot.rollback_plan = plan.rollback_plan;
  snapshot.is_rollback = plan.is_rollback;
  snapshot.layers = plan.layers;

  for (const TransitionStep& step : plan.steps) {
    StepSnapshot entry;
    entry.id = step.id;
    entry.key = step.spec.key();
    entry.generation = step.generation;
    entry.state = step.state;
    entry.attempts = step.attempts;
    entry.mandatory = step.spec.mandatory;
    entry.idempotent = step.spec.idempotent;
    entry.verification = step.spec.verification;
    entry.reversibility = step.spec.reversibility;
    entry.conflict_domains = step.spec.conflict_domains;
    entry.last_evidence = step.last_evidence;
    entry.last_attempt = step.last_attempt;
    entry.dispatch_watermark = step.dispatch_watermark;
    entry.dispatch_epoch = step.dispatch_epoch;
    entry.dispatch_publisher = step.dispatch_publisher;
    entry.dispatch_boot = step.dispatch_boot;
    entry.depends_on = step.spec.depends_on;
    entry.prerequisites_satisfied = true;
    for (const StepKey& dependency : step.spec.depends_on) {
      const TransitionStep* prerequisite = nullptr;
      for (const TransitionStep& candidate : plan.steps) {
        if (candidate.spec.key() == dependency) {
          prerequisite = &candidate;
          break;
        }
      }
      if (prerequisite == nullptr || !prerequisite->is_satisfied()) {
        entry.prerequisites_satisfied = false;
        break;
      }
    }
    entry.executable = entry.prerequisites_satisfied && step.state == StepLifecycle::READY;
    snapshot.steps.push_back(std::move(entry));
  }

  snapshot.digest = ConvergenceGovernor::snapshot_digest(snapshot);
  snapshot.id = id_from_digest<SnapshotId>(snapshot.digest);
  return snapshot;
}

PublisherId derive_publisher_id(std::uint64_t seed) {
  return derive_id<PublisherId>("rc.publisher.v1", seed);
}

WorkerBootId derive_worker_boot_id(std::uint64_t seed) {
  return derive_id<WorkerBootId>("rc.worker_boot.v1", seed);
}

ProvenanceId derive_provenance_id(std::uint64_t seed) {
  return derive_id<ProvenanceId>("rc.provenance.v1", seed);
}

}  // namespace rc
