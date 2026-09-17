#include <algorithm>
#include <deque>
#include <string>
#include <vector>

#include "rc/convergence.hpp"

namespace rc {
namespace {

struct Builder {
  // A deque, not a vector: add() hands out references that later add() calls must
  // not invalidate, and a vector reallocation would dangle every key derived from
  // an earlier step.
  std::deque<StepSpec> steps;

  [[nodiscard]] StepSpec* find(StepKind kind) {
    for (StepSpec& step : steps) {
      if (step.kind == kind) {
        return &step;
      }
    }
    return nullptr;
  }

  StepSpec& add(StepKind kind, std::string_view subject, Reversibility reversibility,
                std::uint32_t domains, bool mandatory, bool idempotent, bool verification) {
    StepSpec spec;
    spec.kind = kind;
    const std::optional<SubjectToken> token = SubjectToken::make(subject);
    if (token.has_value()) {
      spec.subject = *token;
    }
    spec.reversibility = reversibility;
    spec.conflict_domains = domains;
    spec.mandatory = mandatory;
    spec.idempotent = idempotent;
    spec.verification = verification;
    steps.push_back(spec);
    return steps.back();
  }

  void require(StepKind kind, const std::vector<StepKey>& keys) {
    StepSpec* step = find(kind);
    if (step == nullptr) {
      return;
    }
    for (const StepKey& key : keys) {
      step->depends_on.push_back(key);
    }
  }

  void require_all(StepKind kind, const std::vector<StepKind>& kinds) {
    StepSpec* step = find(kind);
    if (step == nullptr) {
      return;
    }
    for (const StepKind other : kinds) {
      const StepSpec* dependency = nullptr;
      for (const StepSpec& candidate : steps) {
        if (candidate.kind == other && candidate.kind != kind) {
          dependency = &candidate;
          break;
        }
      }
      if (dependency != nullptr) {
        step->depends_on.push_back(dependency->key());
      }
    }
  }

  void bind_route(RouteBinding binding) {
    for (StepSpec& step : steps) {
      step.route = binding.route;
      step.route_generation = binding.generation;
    }
  }
};

[[nodiscard]] bool same_group_state(const RouteBinding& source, const RouteBinding& target) {
  return source.ecmp_group == target.ecmp_group && source.ecmp_generation == target.ecmp_generation &&
         source.assignment_generation == target.assignment_generation &&
         source.weighted_set == target.weighted_set &&
         source.weight_policy_generation == target.weight_policy_generation &&
         source.multipath_set == target.multipath_set &&
         source.multipath_generation == target.multipath_generation;
}

[[nodiscard]] std::string group_subject(const RouteBinding& binding) {
  if (!binding.ecmp_group.is_nil()) {
    return binding.ecmp_group.to_text();
  }
  if (!binding.weighted_set.is_nil()) {
    return binding.weighted_set.to_text();
  }
  if (!binding.multipath_set.is_nil()) {
    return binding.multipath_set.to_text();
  }
  return {};
}

[[nodiscard]] bool has_group(const RouteBinding& binding) {
  return !binding.ecmp_group.is_nil() || !binding.weighted_set.is_nil() ||
         !binding.multipath_set.is_nil();
}

// Serialises a plan so that no execution layer is wider than the bound.  Adding
// prerequisites can never invalidate make-before-break or break-before-make
// reachability, so the conformance rules still hold afterwards.
void serialise_to_bound(std::vector<StepSpec>& steps, std::uint32_t bound) {
  const std::optional<std::vector<std::vector<std::size_t>>> layers = canonical_layers(steps);
  if (!layers.has_value()) {
    return;
  }
  std::size_t widest = 0;
  for (const std::vector<std::size_t>& layer : *layers) {
    widest = std::max(widest, layer.size());
  }
  if (widest <= bound) {
    return;
  }
  const std::optional<std::vector<std::size_t>> order = canonical_topological_order(steps);
  if (!order.has_value()) {
    return;
  }
  for (std::size_t index = 1; index < order->size(); ++index) {
    const StepKey previous = steps[(*order)[index - 1]].key();
    std::vector<StepKey>& dependencies = steps[(*order)[index]].depends_on;
    if (std::find(dependencies.begin(), dependencies.end(), previous) == dependencies.end()) {
      dependencies.push_back(previous);
    }
  }
}

[[nodiscard]] std::vector<StepSpec> generate_make_before_break(const RouteBinding& source,
                                                              const RouteBinding& target,
                                                              const ConvergencePolicy& policy) {
  Builder builder;
  const bool verify = policy.verification == VerificationMode::REQUIRED;
  const bool paths_differ = !(source.path == target.path);
  const bool group_changes = has_group(target) && !same_group_state(source, target);

  StepSpec& validate = builder.add(StepKind::VALIDATE_TARGET, "target",
                                   Reversibility::OBSERVATION,
                                   static_cast<std::uint32_t>(ConflictDomain::TARGET_STATE), true,
                                   true, false);
  validate.path = target.path;
  validate.path_authority_generation = target.path_authority_generation;

  StepSpec& prepare = builder.add(StepKind::PREPARE_NEW_STATE, target.path.to_text(),
                                  Reversibility::COMPENSATABLE,
                                  static_cast<std::uint32_t>(ConflictDomain::PATH_STATE), true, true,
                                  false);
  prepare.path = target.path;
  prepare.path_authority_generation = target.path_authority_generation;
  builder.require(StepKind::PREPARE_NEW_STATE, {validate.key()});

  if (group_changes) {
    StepSpec& group = builder.add(StepKind::INSTALL_NEW_GROUP, group_subject(target),
                                  Reversibility::COMPENSATABLE,
                                  static_cast<std::uint32_t>(ConflictDomain::GROUP_STATE), true,
                                  true, false);
    group.ecmp_group = target.ecmp_group;
    group.ecmp_generation = target.ecmp_generation;
    group.assignment_generation = target.assignment_generation;
    group.weighted_set = target.weighted_set;
    group.weight_policy_generation = target.weight_policy_generation;
    group.multipath_set = target.multipath_set;
    group.multipath_generation = target.multipath_generation;
    builder.require(StepKind::INSTALL_NEW_GROUP, {validate.key()});
  }

  StepSpec& install = builder.add(StepKind::INSTALL_NEW_ROUTE, target.route.to_text(),
                                  Reversibility::COMPENSATABLE,
                                  static_cast<std::uint32_t>(ConflictDomain::ROUTE_TABLE), true,
                                  true, false);
  builder.require(StepKind::INSTALL_NEW_ROUTE, {prepare.key()});
  if (group_changes) {
    const StepSpec* group = builder.find(StepKind::INSTALL_NEW_GROUP);
    builder.require(StepKind::INSTALL_NEW_ROUTE, {group->key()});
  }

  StepKey anchor = install.key();
  if (paths_differ) {
    StepSpec& activate = builder.add(StepKind::ACTIVATE_NEW_PATH, target.path.to_text(),
                                     Reversibility::COMPENSATABLE,
                                     static_cast<std::uint32_t>(ConflictDomain::PATH_STATE), true,
                                     true, false);
    activate.path = target.path;
    activate.path_authority_generation = target.path_authority_generation;
    builder.require(StepKind::ACTIVATE_NEW_PATH, {install.key()});
    anchor = activate.key();
  }

  if (verify) {
    StepSpec& verify_step =
        builder.add(StepKind::VERIFY_NEW_STATE, target.path.to_text(),
                    Reversibility::OBSERVATION,
                    static_cast<std::uint32_t>(ConflictDomain::TARGET_STATE), true, true, true);
    verify_step.path = target.path;
    verify_step.path_authority_generation = target.path_authority_generation;
    builder.require(StepKind::VERIFY_NEW_STATE, {anchor});
    anchor = verify_step.key();
  }

  if (paths_differ) {
    StepSpec& deactivate =
        builder.add(StepKind::DEACTIVATE_OLD_PATH, source.path.to_text(),
                    Reversibility::COMPENSATABLE,
                    static_cast<std::uint32_t>(ConflictDomain::PATH_STATE), true, true, false);
    deactivate.path = source.path;
    deactivate.path_authority_generation = source.path_authority_generation;
    builder.require(StepKind::DEACTIVATE_OLD_PATH, {anchor});
  }

  StepSpec& withdraw = builder.add(StepKind::WITHDRAW_OLD_ROUTE, source.route.to_text(),
                                   Reversibility::COMPENSATABLE,
                                   static_cast<std::uint32_t>(ConflictDomain::ROUTE_TABLE), true,
                                   true, false);
  if (paths_differ) {
    const StepSpec* deactivate = builder.find(StepKind::DEACTIVATE_OLD_PATH);
    builder.require(StepKind::WITHDRAW_OLD_ROUTE, {deactivate->key()});
  } else {
    builder.require(StepKind::WITHDRAW_OLD_ROUTE, {anchor});
  }
  (void)withdraw;

  if (verify) {
    StepSpec& removal =
        builder.add(StepKind::VERIFY_REMOVAL, source.route.to_text(), Reversibility::OBSERVATION,
                    static_cast<std::uint32_t>(ConflictDomain::TARGET_STATE), true, true, true);
    removal.route = source.route;
    removal.route_generation = source.generation;
    builder.require(StepKind::VERIFY_REMOVAL, {builder.find(StepKind::WITHDRAW_OLD_ROUTE)->key()});
  }

  StepSpec& finalise = builder.add(StepKind::FINALIZE, "plan", Reversibility::OBSERVATION,
                                   static_cast<std::uint32_t>(ConflictDomain::TARGET_STATE), true,
                                   true, false);
  (void)finalise;
  builder.require_all(StepKind::FINALIZE,
                      {StepKind::VALIDATE_TARGET, StepKind::PREPARE_NEW_STATE,
                       StepKind::INSTALL_NEW_GROUP, StepKind::INSTALL_NEW_ROUTE,
                       StepKind::ACTIVATE_NEW_PATH, StepKind::VERIFY_NEW_STATE,
                       StepKind::DEACTIVATE_OLD_PATH, StepKind::WITHDRAW_OLD_ROUTE,
                       StepKind::VERIFY_REMOVAL});

  builder.bind_route(target);
  return std::vector<StepSpec>(builder.steps.begin(), builder.steps.end());
}

[[nodiscard]] std::vector<StepSpec> generate_break_before_make(const RouteBinding& source,
                                                              const RouteBinding& target,
                                                              const ConvergencePolicy& policy) {
  Builder builder;
  const bool verify = policy.verification == VerificationMode::REQUIRED;
  const bool paths_differ = !(source.path == target.path);
  const bool group_changes = has_group(target) && !same_group_state(source, target);

  StepSpec& validate = builder.add(StepKind::VALIDATE_TARGET, "target",
                                   Reversibility::OBSERVATION,
                                   static_cast<std::uint32_t>(ConflictDomain::TARGET_STATE), true,
                                   true, false);
  validate.path = target.path;
  validate.path_authority_generation = target.path_authority_generation;

  if (paths_differ) {
    StepSpec& deactivate =
        builder.add(StepKind::DEACTIVATE_OLD_PATH, source.path.to_text(),
                    Reversibility::COMPENSATABLE,
                    static_cast<std::uint32_t>(ConflictDomain::PATH_STATE), true, true, false);
    deactivate.path = source.path;
    deactivate.path_authority_generation = source.path_authority_generation;
    builder.require(StepKind::DEACTIVATE_OLD_PATH, {validate.key()});
  }

  StepSpec& withdraw = builder.add(StepKind::WITHDRAW_OLD_ROUTE, source.route.to_text(),
                                   Reversibility::COMPENSATABLE,
                                   static_cast<std::uint32_t>(ConflictDomain::ROUTE_TABLE), true,
                                   true, false);
  if (paths_differ) {
    builder.require(StepKind::WITHDRAW_OLD_ROUTE, {builder.find(StepKind::DEACTIVATE_OLD_PATH)->key()});
  } else {
    builder.require(StepKind::WITHDRAW_OLD_ROUTE, {validate.key()});
  }
  (void)withdraw;

  StepKey anchor = builder.find(StepKind::WITHDRAW_OLD_ROUTE)->key();
  if (verify) {
    StepSpec& removal =
        builder.add(StepKind::VERIFY_REMOVAL, source.route.to_text(), Reversibility::OBSERVATION,
                    static_cast<std::uint32_t>(ConflictDomain::TARGET_STATE), true, true, true);
    removal.route = source.route;
    removal.route_generation = source.generation;
    builder.require(StepKind::VERIFY_REMOVAL, {anchor});
    anchor = removal.key();
  }

  StepSpec& prepare = builder.add(StepKind::PREPARE_NEW_STATE, target.path.to_text(),
                                  Reversibility::COMPENSATABLE,
                                  static_cast<std::uint32_t>(ConflictDomain::PATH_STATE), true, true,
                                  false);
  prepare.path = target.path;
  prepare.path_authority_generation = target.path_authority_generation;
  builder.require(StepKind::PREPARE_NEW_STATE, {anchor});

  if (group_changes) {
    StepSpec& group = builder.add(StepKind::INSTALL_NEW_GROUP, group_subject(target),
                                  Reversibility::COMPENSATABLE,
                                  static_cast<std::uint32_t>(ConflictDomain::GROUP_STATE), true,
                                  true, false);
    group.ecmp_group = target.ecmp_group;
    group.ecmp_generation = target.ecmp_generation;
    group.assignment_generation = target.assignment_generation;
    group.weighted_set = target.weighted_set;
    group.weight_policy_generation = target.weight_policy_generation;
    group.multipath_set = target.multipath_set;
    group.multipath_generation = target.multipath_generation;
    builder.require(StepKind::INSTALL_NEW_GROUP, {anchor});
  }

  StepSpec& install = builder.add(StepKind::INSTALL_NEW_ROUTE, target.route.to_text(),
                                  Reversibility::COMPENSATABLE,
                                  static_cast<std::uint32_t>(ConflictDomain::ROUTE_TABLE), true,
                                  true, false);
  builder.require(StepKind::INSTALL_NEW_ROUTE, {prepare.key()});
  if (group_changes) {
    builder.require(StepKind::INSTALL_NEW_ROUTE, {builder.find(StepKind::INSTALL_NEW_GROUP)->key()});
  }

  if (paths_differ) {
    StepSpec& activate = builder.add(StepKind::ACTIVATE_NEW_PATH, target.path.to_text(),
                                     Reversibility::COMPENSATABLE,
                                     static_cast<std::uint32_t>(ConflictDomain::PATH_STATE), true,
                                     true, false);
    activate.path = target.path;
    activate.path_authority_generation = target.path_authority_generation;
    builder.require(StepKind::ACTIVATE_NEW_PATH, {install.key()});
  }

  if (verify) {
    StepSpec& verify_step =
        builder.add(StepKind::VERIFY_NEW_STATE, target.path.to_text(),
                    Reversibility::OBSERVATION,
                    static_cast<std::uint32_t>(ConflictDomain::TARGET_STATE), true, true, true);
    verify_step.path = target.path;
    verify_step.path_authority_generation = target.path_authority_generation;
    const StepSpec* predecessor = builder.find(StepKind::ACTIVATE_NEW_PATH);
    if (predecessor == nullptr) {
      predecessor = builder.find(StepKind::INSTALL_NEW_ROUTE);
    }
    builder.require(StepKind::VERIFY_NEW_STATE, {predecessor->key()});
  }

  StepSpec& finalise = builder.add(StepKind::FINALIZE, "plan", Reversibility::OBSERVATION,
                                   static_cast<std::uint32_t>(ConflictDomain::TARGET_STATE), true,
                                   true, false);
  (void)finalise;
  builder.require_all(StepKind::FINALIZE,
                      {StepKind::VALIDATE_TARGET, StepKind::PREPARE_NEW_STATE,
                       StepKind::INSTALL_NEW_GROUP, StepKind::INSTALL_NEW_ROUTE,
                       StepKind::ACTIVATE_NEW_PATH, StepKind::VERIFY_NEW_STATE,
                       StepKind::DEACTIVATE_OLD_PATH, StepKind::WITHDRAW_OLD_ROUTE,
                       StepKind::VERIFY_REMOVAL});

  builder.bind_route(target);
  return std::vector<StepSpec>(builder.steps.begin(), builder.steps.end());
}

}  // namespace

std::optional<std::vector<StepSpec>> generate_steps(const RouteBinding& source,
                                                    const RouteBinding& target,
                                                    const ConvergencePolicy& policy,
                                                    const ConvergenceLimits& limits,
                                                    std::string& reason) {
  if (!source.is_well_formed() || !target.is_well_formed()) {
    reason = "route binding is malformed";
    return std::nullopt;
  }
  if (!(source.route == target.route)) {
    reason = "source and target bindings describe different routes";
    return std::nullopt;
  }
  if (!policy.is_coherent(reason)) {
    return std::nullopt;
  }
  if (policy.ordering == OrderingMode::BREAK_BEFORE_MAKE && !policy.allow_break_before_make) {
    reason = "break-before-make was requested but the policy does not allow it";
    return std::nullopt;
  }

  std::vector<StepSpec> steps = policy.ordering == OrderingMode::MAKE_BEFORE_BREAK
                                    ? generate_make_before_break(source, target, policy)
                                    : generate_break_before_make(source, target, policy);

  const std::uint32_t bound = std::min(policy.max_parallel_steps, limits.max_parallel_steps);
  if (bound == 0) {
    reason = "no parallel step budget is available";
    return std::nullopt;
  }
  serialise_to_bound(steps, bound);

  // The plan size limit is enforced by the governor, which reports it as a
  // structured STEP_LIMIT rejection rather than as a generic generation failure,
  // so the structural check here deliberately ignores that one bound.
  ConvergenceLimits structural_limits = limits;
  structural_limits.max_steps_per_plan = kAbsoluteMaxStepsPerPlan;
  const GraphValidation graph = validate_dependency_graph(steps, structural_limits);
  if (!graph.ok) {
    reason = "generated dependency graph is invalid";
    return std::nullopt;
  }
  reason.clear();
  return steps;
}

GraphValidation validate_policy_conformance(const std::vector<StepSpec>& steps,
                                            const ConvergencePolicy& policy,
                                            const ConvergenceLimits& limits) {
  GraphValidation result = validate_dependency_graph(steps, limits);
  std::string coherence_reason;
  if (!policy.is_coherent(coherence_reason)) {
    result.defects.push_back(GraphDefect{ConditionCode::POLICY_INCOHERENT, {}, {},
                                         "policy is not internally coherent"});
    result.ok = false;
    return result;
  }

  for (const StepSpec& step : steps) {
    if (step.reversibility == Reversibility::IRREVERSIBLE && policy.require_rollback_capability) {
      result.defects.push_back(GraphDefect{ConditionCode::ROLLBACK_IRREVERSIBLE, step.key(), {},
                                           "policy requires rollback capability"});
    }
  }

  const auto find = [&steps](StepKind kind) -> const StepSpec* {
    for (const StepSpec& step : steps) {
      if (step.kind == kind) {
        return &step;
      }
    }
    return nullptr;
  };

  const StepSpec* validate_target = find(StepKind::VALIDATE_TARGET);
  if (validate_target == nullptr) {
    result.defects.push_back(GraphDefect{ConditionCode::DEPENDENCY_MISSING, {}, {},
                                         "plan has no VALIDATE_TARGET step"});
    result.ok = false;
    return result;
  }
  const StepSpec* finalise = find(StepKind::FINALIZE);
  if (finalise == nullptr) {
    result.defects.push_back(
        GraphDefect{ConditionCode::DEPENDENCY_MISSING, {}, {}, "plan has no FINALIZE step"});
    result.ok = false;
    return result;
  }

  if (policy.ordering == OrderingMode::MAKE_BEFORE_BREAK) {
    const StepSpec* anchor = find(StepKind::VERIFY_NEW_STATE);
    if (anchor == nullptr) {
      anchor = find(StepKind::ACTIVATE_NEW_PATH);
    }
    if (anchor == nullptr) {
      anchor = find(StepKind::INSTALL_NEW_ROUTE);
    }
    for (const StepSpec& step : steps) {
      if (!is_break_step(step.kind)) {
        continue;
      }
      if (anchor == nullptr ||
          !depends_transitively_on(steps, step.key(), anchor->key())) {
        result.defects.push_back(GraphDefect{
            ConditionCode::BREAK_BEFORE_MAKE_NOT_PERMITTED, step.key(),
            anchor != nullptr ? anchor->key() : StepKey{},
            "make-before-break requires the break step to follow target activation"});
      }
    }
  } else {
    const StepSpec* anchor = find(StepKind::VERIFY_REMOVAL);
    if (anchor == nullptr) {
      anchor = find(StepKind::WITHDRAW_OLD_ROUTE);
    }
    if (anchor == nullptr) {
      anchor = find(StepKind::DEACTIVATE_OLD_PATH);
    }
    for (const StepSpec& step : steps) {
      if (!is_make_step(step.kind)) {
        continue;
      }
      if (anchor == nullptr || !depends_transitively_on(steps, step.key(), anchor->key())) {
        result.defects.push_back(GraphDefect{
            ConditionCode::BREAK_BEFORE_MAKE_NOT_PERMITTED, step.key(),
            anchor != nullptr ? anchor->key() : StepKey{},
            "break-before-make requires the make step to follow old-state removal"});
      }
    }
  }

  for (const StepSpec& step : steps) {
    if (step.kind == StepKind::FINALIZE || !step.mandatory) {
      continue;
    }
    if (!depends_transitively_on(steps, finalise->key(), step.key())) {
      result.defects.push_back(GraphDefect{ConditionCode::PREREQUISITE_INCOMPLETE, finalise->key(),
                                           step.key(),
                                           "FINALIZE does not wait for a mandatory step"});
    }
  }

  const std::uint32_t bound = std::min(policy.max_parallel_steps, limits.max_parallel_steps);
  const std::optional<std::vector<std::vector<std::size_t>>> layers = canonical_layers(steps);
  if (layers.has_value()) {
    for (const std::vector<std::size_t>& layer : *layers) {
      if (layer.size() > bound) {
        result.defects.push_back(GraphDefect{
            ConditionCode::PARALLELISM_LIMIT, steps[layer.front()].key(), {},
            "execution layer is wider than the permitted parallel step budget"});
        break;
      }
    }
  }

  result.ok = result.defects.empty();
  return result;
}

}  // namespace rc
