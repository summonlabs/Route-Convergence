#include <algorithm>
#include <set>
#include <string>
#include <vector>

#include "governor_state.hpp"
#include "rc/bytes.hpp"
#include "rc/graph.hpp"

namespace rc {
namespace {

void encode_binding(Encoder& encoder, const RouteBinding& binding) {
  encoder.fixed16(binding.route.bytes());
  encoder.u64(binding.generation.value());
  encoder.fixed16(binding.path.bytes());
  encoder.u64(binding.path_authority_generation.value());
  encoder.fixed16(binding.multipath_set.bytes());
  encoder.u64(binding.multipath_generation.value());
  encoder.fixed16(binding.ecmp_group.bytes());
  encoder.u64(binding.ecmp_generation.value());
  encoder.u64(binding.assignment_generation.value());
  encoder.fixed16(binding.weighted_set.bytes());
  encoder.u64(binding.weight_policy_generation.value());
  encoder.boolean(binding.current);
  encoder.boolean(binding.legal);
}

[[nodiscard]] bool decode_binding(Decoder& decoder, RouteBinding& out) {
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.route = RouteId::from_bytes(raw);
  std::uint64_t value = 0;
  if (!decoder.u64(value)) {
    return false;
  }
  out.generation = RouteGeneration::from_value(value);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.path = PathId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.path_authority_generation = PathAuthorityGeneration::from_value(value);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.multipath_set = MultipathSetId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.multipath_generation = MultipathSetGeneration::from_value(value);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.ecmp_group = ECMPGroupId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.ecmp_generation = ECMPGroupGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return false;
  }
  out.assignment_generation = AssignmentGeneration::from_value(value);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.weighted_set = WeightedPathSetId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.weight_policy_generation = WeightPolicyGeneration::from_value(value);
  return decoder.boolean(out.current) && decoder.boolean(out.legal);
}

void encode_spec(Encoder& encoder, const StepSpec& spec) {
  encoder.u32(static_cast<std::uint32_t>(spec.kind));
  encoder.text(spec.subject.text());
  encoder.u32(static_cast<std::uint32_t>(spec.reversibility));
  encoder.u32(spec.conflict_domains);
  encoder.boolean(spec.mandatory);
  encoder.boolean(spec.idempotent);
  encoder.boolean(spec.verification);
  encoder.fixed16(spec.path.bytes());
  encoder.u64(spec.path_authority_generation.value());
  encoder.fixed16(spec.route.bytes());
  encoder.u64(spec.route_generation.value());
  encoder.fixed16(spec.multipath_set.bytes());
  encoder.u64(spec.multipath_generation.value());
  encoder.fixed16(spec.ecmp_group.bytes());
  encoder.u64(spec.ecmp_generation.value());
  encoder.u64(spec.assignment_generation.value());
  encoder.fixed16(spec.weighted_set.bytes());
  encoder.u64(spec.weight_policy_generation.value());
  encoder.u32(static_cast<std::uint32_t>(spec.depends_on.size()));
  for (const StepKey& dependency : spec.depends_on) {
    encoder.u32(static_cast<std::uint32_t>(dependency.kind));
    encoder.text(dependency.subject.text());
  }
}

[[nodiscard]] bool decode_spec(Decoder& decoder, const ConvergenceLimits& limits, StepSpec& out) {
  std::uint32_t kind = 0;
  std::string subject;
  std::uint32_t reversibility = 0;
  if (!decoder.u32(kind) || kind == 0 || kind > kStepKindCount) {
    return false;
  }
  out.kind = static_cast<StepKind>(kind);
  if (!decoder.text(subject, kAbsoluteMaxSubjectBytes)) {
    return false;
  }
  const std::optional<SubjectToken> token = SubjectToken::make(subject);
  if (!token.has_value()) {
    return false;
  }
  out.subject = *token;
  if (!decoder.u32(reversibility) || reversibility == 0 || reversibility > 3) {
    return false;
  }
  out.reversibility = static_cast<Reversibility>(reversibility);
  if (!decoder.u32(out.conflict_domains) || !decoder.boolean(out.mandatory) ||
      !decoder.boolean(out.idempotent) || !decoder.boolean(out.verification)) {
    return false;
  }
  std::array<std::uint8_t, 16> raw{};
  std::uint64_t value = 0;
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.path = PathId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.path_authority_generation = PathAuthorityGeneration::from_value(value);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.route = RouteId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.route_generation = RouteGeneration::from_value(value);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.multipath_set = MultipathSetId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.multipath_generation = MultipathSetGeneration::from_value(value);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.ecmp_group = ECMPGroupId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.ecmp_generation = ECMPGroupGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return false;
  }
  out.assignment_generation = AssignmentGeneration::from_value(value);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.weighted_set = WeightedPathSetId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.weight_policy_generation = WeightPolicyGeneration::from_value(value);

  std::uint32_t count = 0;
  if (!decoder.u32(count) || count > limits.max_dependencies_per_step ||
      count > kAbsoluteMaxDependenciesPerStep) {
    return false;
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    std::uint32_t dependency_kind = 0;
    std::string dependency_subject;
    if (!decoder.u32(dependency_kind) || dependency_kind == 0 ||
        dependency_kind > kStepKindCount) {
      return false;
    }
    if (!decoder.text(dependency_subject, kAbsoluteMaxSubjectBytes)) {
      return false;
    }
    const std::optional<SubjectToken> dependency_token = SubjectToken::make(dependency_subject);
    if (!dependency_token.has_value()) {
      return false;
    }
    StepKey key;
    key.kind = static_cast<StepKind>(dependency_kind);
    key.subject = *dependency_token;
    out.depends_on.push_back(std::move(key));
  }
  return true;
}

void encode_policy(Encoder& encoder, const ConvergencePolicy& policy) {
  encoder.fixed16(policy.id.bytes());
  encoder.u64(policy.generation.value());
  encoder.u32(static_cast<std::uint32_t>(policy.ordering));
  encoder.u32(static_cast<std::uint32_t>(policy.verification));
  encoder.boolean(policy.allow_overlap);
  encoder.boolean(policy.allow_break_before_make);
  encoder.u32(policy.max_parallel_steps);
  encoder.u32(policy.max_retries_per_step);
  encoder.boolean(policy.require_rollback_capability);
  encoder.boolean(policy.supersede_predecessor_on_success);
}

[[nodiscard]] bool decode_policy(Decoder& decoder, ConvergencePolicy& out) {
  std::array<std::uint8_t, 16> raw{};
  std::uint64_t generation = 0;
  std::uint32_t ordering = 0;
  std::uint32_t verification = 0;
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.id = ConvergencePolicyId::from_bytes(raw);
  if (!decoder.u64(generation) || generation == 0) {
    return false;
  }
  out.generation = ConvergencePolicyGeneration::from_value(generation);
  if (!decoder.u32(ordering) || ordering == 0 || ordering > 2) {
    return false;
  }
  out.ordering = static_cast<OrderingMode>(ordering);
  if (!decoder.u32(verification) || verification == 0 || verification > 2) {
    return false;
  }
  out.verification = static_cast<VerificationMode>(verification);
  if (!decoder.boolean(out.allow_overlap) || !decoder.boolean(out.allow_break_before_make) ||
      !decoder.u32(out.max_parallel_steps) || !decoder.u32(out.max_retries_per_step) ||
      !decoder.boolean(out.require_rollback_capability) ||
      !decoder.boolean(out.supersede_predecessor_on_success)) {
    return false;
  }
  return true;
}

void encode_plan(Encoder& encoder, const ConvergencePlan& plan) {
  encoder.fixed16(plan.id.bytes());
  encoder.fixed16(plan.key.route.bytes());
  encoder.u64(plan.key.source_generation.value());
  encoder.u64(plan.key.target_generation.value());
  encoder.u64(plan.key.policy_generation.value());
  encoder.u64(plan.generation.value());
  encoder.u32(static_cast<std::uint32_t>(plan.lifecycle));
  encoder.u32(plan.currentness.bits());
  encode_policy(encoder, plan.policy);
  encode_binding(encoder, plan.source);
  encode_binding(encoder, plan.target);
  encoder.u32(static_cast<std::uint32_t>(plan.mode));
  encoder.u64(plan.created_epoch.value());
  encoder.u64(plan.bound_epoch.value());
  encoder.fixed16(plan.provenance.bytes());
  encoder.fixed16(plan.owner_publisher.bytes());
  encoder.fixed16(plan.owner_boot.bytes());
  encoder.u64(plan.authority_generation.value());
  encoder.u64(plan.watermark.value());
  encoder.fixed16(plan.predecessor.bytes());
  encoder.fixed16(plan.successor.bytes());
  encoder.u32(static_cast<std::uint32_t>(plan.supersession_reason));
  encoder.fixed16(plan.rollback_plan.bytes());
  encoder.boolean(plan.rollback_required);
  encoder.boolean(plan.is_rollback);
  encoder.raw(plan.digest.bytes());
  encoder.u32(static_cast<std::uint32_t>(plan.steps.size()));
  for (const TransitionStep& step : plan.steps) {
    encoder.fixed16(step.id.bytes());
    encode_spec(encoder, step.spec);
    encoder.u64(step.generation.value());
    encoder.u32(static_cast<std::uint32_t>(step.state));
    encoder.u32(step.attempts);
    encoder.fixed16(step.last_evidence.bytes());
    encoder.fixed16(step.last_attempt.bytes());
    encoder.u64(step.dispatch_watermark.value());
    encoder.u64(step.dispatch_epoch.value());
    encoder.fixed16(step.dispatch_publisher.bytes());
    encoder.fixed16(step.dispatch_boot.bytes());
    encoder.u32(static_cast<std::uint32_t>(step.last_change));
    encoder.u32(static_cast<std::uint32_t>(step.last_condition));
    encoder.fixed16(step.compensates.bytes());
  }
  encoder.u32(static_cast<std::uint32_t>(plan.layers.size()));
  for (const std::vector<TransitionStepId>& layer : plan.layers) {
    encoder.u32(static_cast<std::uint32_t>(layer.size()));
    for (const TransitionStepId& id : layer) {
      encoder.fixed16(id.bytes());
    }
  }
  encoder.u32(static_cast<std::uint32_t>(plan.history.size()));
  for (const PlanChange& change : plan.history) {
    encoder.u32(static_cast<std::uint32_t>(change.reason));
    encoder.u64(change.plan_generation.value());
    encoder.u64(change.convergence_generation.value());
    encoder.u32(static_cast<std::uint32_t>(change.condition));
    encoder.fixed16(change.step.bytes());
    encoder.u32(static_cast<std::uint32_t>(change.step_state));
    encoder.u64(change.observed);
    encoder.u64(change.expected);
  }
}

[[nodiscard]] bool decode_plan(Decoder& decoder, const ConvergenceLimits& limits, bool recovering,
                               ConvergencePlan& plan, std::string& defect) {
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    defect = "plan identity truncated";
    return false;
  }
  plan.id = ConvergencePlanId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    defect = "plan key truncated";
    return false;
  }
  plan.key.route = RouteId::from_bytes(raw);
  std::uint64_t source = 0;
  std::uint64_t target = 0;
  std::uint64_t policy_generation = 0;
  if (!decoder.u64(source) || !decoder.u64(target) || !decoder.u64(policy_generation)) {
    defect = "plan key truncated";
    return false;
  }
  plan.key.source_generation = RouteGeneration::from_value(source);
  plan.key.target_generation = RouteGeneration::from_value(target);
  plan.key.policy_generation = ConvergencePolicyGeneration::from_value(policy_generation);
  std::uint64_t generation = 0;
  std::uint32_t lifecycle = 0;
  if (!decoder.u64(generation) || !decoder.u32(lifecycle)) {
    defect = "plan generation truncated";
    return false;
  }
  plan.generation = ConvergencePlanGeneration::from_value(generation);
  if (lifecycle == 0 || lifecycle > kPlanLifecycleCount) {
    defect = "impossible lifecycle";
    return false;
  }
  plan.lifecycle = static_cast<PlanLifecycle>(lifecycle);
  std::uint32_t currentness = 0;
  if (!decoder.u32(currentness) || currentness > ((1u << kCurrentnessCauseCount) - 1u)) {
    defect = "impossible currentness";
    return false;
  }
  plan.currentness = Currentness::from_bits(currentness);
  if (!decode_policy(decoder, plan.policy)) {
    defect = "malformed policy";
    return false;
  }
  if (!decode_binding(decoder, plan.source) || !decode_binding(decoder, plan.target)) {
    defect = "malformed route binding";
    return false;
  }
  std::uint32_t mode = 0;
  std::uint64_t created_epoch = 0;
  std::uint64_t bound_epoch = 0;
  if (!decoder.u32(mode) || mode == 0 || mode > 2) {
    defect = "impossible plan mode";
    return false;
  }
  plan.mode = static_cast<PlanMode>(mode);
  if (!decoder.u64(created_epoch) || !decoder.u64(bound_epoch)) {
    defect = "plan epoch truncated";
    return false;
  }
  plan.created_epoch = CoordinatorEpoch::from_value(created_epoch);
  plan.bound_epoch = CoordinatorEpoch::from_value(bound_epoch);
  if (!decoder.fixed16(raw)) {
    defect = "provenance truncated";
    return false;
  }
  plan.provenance = ProvenanceId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    defect = "owner publisher truncated";
    return false;
  }
  plan.owner_publisher = PublisherId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    defect = "owner boot truncated";
    return false;
  }
  plan.owner_boot = WorkerBootId::from_bytes(raw);
  std::uint64_t authority = 0;
  std::uint64_t watermark = 0;
  if (!decoder.u64(authority) || !decoder.u64(watermark)) {
    defect = "plan authority truncated";
    return false;
  }
  plan.authority_generation = AuthorityGeneration::from_value(authority);
  plan.watermark = ConvergenceGeneration::from_value(watermark);
  if (!decoder.fixed16(raw)) {
    defect = "predecessor truncated";
    return false;
  }
  plan.predecessor = ConvergencePlanId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    defect = "successor truncated";
    return false;
  }
  plan.successor = ConvergencePlanId::from_bytes(raw);
  std::uint32_t supersession = 0;
  if (!decoder.u32(supersession) || supersession == 0 || supersession > kChangeReasonCount) {
    defect = "impossible supersession reason";
    return false;
  }
  plan.supersession_reason = static_cast<ChangeReason>(supersession);
  if (!decoder.fixed16(raw)) {
    defect = "rollback plan truncated";
    return false;
  }
  plan.rollback_plan = ConvergencePlanId::from_bytes(raw);
  if (!decoder.boolean(plan.rollback_required) || !decoder.boolean(plan.is_rollback)) {
    defect = "rollback flags truncated";
    return false;
  }
  std::array<std::uint8_t, 32> digest_bytes{};
  if (!decoder.raw(digest_bytes)) {
    defect = "plan digest truncated";
    return false;
  }
  plan.digest = Digest::from_bytes(digest_bytes);

  std::uint32_t step_count = 0;
  if (!decoder.u32(step_count) || step_count > limits.max_steps_per_plan ||
      step_count > kAbsoluteMaxStepsPerPlan) {
    defect = "impossible step count";
    return false;
  }
  std::set<TransitionStepId> step_ids;
  std::set<StepKey> step_keys;
  for (std::uint32_t index = 0; index < step_count; ++index) {
    TransitionStep step;
    if (!decoder.fixed16(raw)) {
      defect = "step identity truncated";
      return false;
    }
    step.id = TransitionStepId::from_bytes(raw);
    if (!step_ids.insert(step.id).second) {
      defect = "duplicate step identity";
      return false;
    }
    if (!decode_spec(decoder, limits, step.spec)) {
      defect = "malformed step specification";
      return false;
    }
    if (!step_keys.insert(step.spec.key()).second) {
      defect = "duplicate step key";
      return false;
    }
    std::uint64_t step_generation = 0;
    std::uint32_t state = 0;
    if (!decoder.u64(step_generation) || step_generation == 0 || !decoder.u32(state) || state == 0 ||
        state > kStepLifecycleCount) {
      defect = "impossible step state";
      return false;
    }
    step.generation = TransitionStepGeneration::from_value(step_generation);
    step.state = static_cast<StepLifecycle>(state);
    if (!decoder.u32(step.attempts)) {
      defect = "step attempt count truncated";
      return false;
    }
    std::array<std::uint8_t, 16> evidence{};
    if (!decoder.raw(evidence)) {
      defect = "step evidence truncated";
      return false;
    }
    step.last_evidence = CompletionEvidenceId::from_bytes(evidence);
    if (!decoder.raw(evidence)) {
      defect = "step attempt truncated";
      return false;
    }
    step.last_attempt = MutationAttemptId::from_bytes(evidence);
    std::uint64_t dispatch_watermark = 0;
    std::uint64_t dispatch_epoch = 0;
    if (!decoder.u64(dispatch_watermark) || !decoder.u64(dispatch_epoch)) {
      defect = "step dispatch record truncated";
      return false;
    }
    step.dispatch_watermark = ConvergenceGeneration::from_value(dispatch_watermark);
    step.dispatch_epoch = CoordinatorEpoch::from_value(dispatch_epoch);
    if (!decoder.raw(evidence)) {
      defect = "step publisher truncated";
      return false;
    }
    step.dispatch_publisher = PublisherId::from_bytes(evidence);
    if (!decoder.raw(evidence)) {
      defect = "step boot truncated";
      return false;
    }
    step.dispatch_boot = WorkerBootId::from_bytes(evidence);
    std::uint32_t last_change = 0;
    std::uint32_t last_condition = 0;
    if (!decoder.u32(last_change) || last_change == 0 || last_change > kChangeReasonCount) {
      defect = "impossible change reason";
      return false;
    }
    if (!decoder.u32(last_condition)) {
      defect = "malformed condition code";
      return false;
    }
    step.last_change = static_cast<ChangeReason>(last_change);
    step.last_condition = static_cast<ConditionCode>(last_condition);
    if (!decoder.raw(evidence)) {
      defect = "compensation reference truncated";
      return false;
    }
    step.compensates = TransitionStepId::from_bytes(evidence);
    if (step.state == StepLifecycle::COMPLETED && step.last_evidence.is_nil()) {
      defect = "completed step without completion evidence";
      return false;
    }
    if (step.state == StepLifecycle::DISPATCHED && step.dispatch_boot.is_nil()) {
      defect = "dispatched step without a worker boot";
      return false;
    }
    plan.steps.push_back(std::move(step));
  }

  std::uint32_t layer_count = 0;
  if (!decoder.u32(layer_count) || layer_count > limits.max_steps_per_plan) {
    defect = "impossible layer count";
    return false;
  }
  for (std::uint32_t layer = 0; layer < layer_count; ++layer) {
    std::uint32_t width = 0;
    if (!decoder.u32(width) || width > limits.max_steps_per_plan) {
      defect = "impossible layer width";
      return false;
    }
    std::vector<TransitionStepId> ids;
    for (std::uint32_t index = 0; index < width; ++index) {
      std::array<std::uint8_t, 16> layer_id{};
      if (!decoder.raw(layer_id)) {
        defect = "layer identity truncated";
        return false;
      }
      const TransitionStepId id = TransitionStepId::from_bytes(layer_id);
      if (step_ids.find(id) == step_ids.end()) {
        defect = "layer references an unknown step";
        return false;
      }
      ids.push_back(id);
    }
    plan.layers.push_back(std::move(ids));
  }

  std::uint32_t history_count = 0;
  if (!decoder.u32(history_count) || history_count > limits.max_history_per_plan) {
    defect = "impossible history count";
    return false;
  }
  for (std::uint32_t index = 0; index < history_count; ++index) {
    PlanChange change;
    std::uint32_t reason = 0;
    std::uint64_t change_generation = 0;
    std::uint64_t change_convergence = 0;
    std::uint32_t condition = 0;
    std::array<std::uint8_t, 16> step_id{};
    std::uint32_t step_state = 0;
    if (!decoder.u32(reason) || reason == 0 || reason > kChangeReasonCount) {
      defect = "impossible history reason";
      return false;
    }
    change.reason = static_cast<ChangeReason>(reason);
    if (!decoder.u64(change_generation) || !decoder.u64(change_convergence) ||
        !decoder.u32(condition) || !decoder.raw(step_id) || !decoder.u32(step_state) ||
        step_state == 0 || step_state > kStepLifecycleCount || !decoder.u64(change.observed) ||
        !decoder.u64(change.expected)) {
      defect = "malformed history entry";
      return false;
    }
    change.plan_generation = ConvergencePlanGeneration::from_value(change_generation);
    change.convergence_generation = ConvergenceGeneration::from_value(change_convergence);
    change.condition = static_cast<ConditionCode>(condition);
    change.step = TransitionStepId::from_bytes(step_id);
    change.step_state = static_cast<StepLifecycle>(step_state);
    plan.history.push_back(std::move(change));
  }

  if (!plan.key.is_well_formed() || !plan.is_well_formed()) {
    defect = "plan identity is not well formed";
    return false;
  }
  if (!plan.source.is_well_formed() || !plan.target.is_well_formed()) {
    defect = "plan route binding is not well formed";
    return false;
  }
  if (!plan.policy.is_well_formed()) {
    defect = "plan policy is not well formed";
    return false;
  }
  if (plan.key.policy_generation != plan.policy.generation) {
    defect = "policy generation mismatch";
    return false;
  }

  std::vector<StepSpec> specs;
  specs.reserve(plan.steps.size());
  for (const TransitionStep& step : plan.steps) {
    specs.push_back(step.spec);
  }
  const GraphValidation graph = validate_dependency_graph(specs, limits);
  if (!graph.ok) {
    defect = "plan dependency graph is invalid";
    return false;
  }
  const Digest structure = plan_structure_digest(plan.key, plan.source, plan.target, plan.policy,
                                                 plan.mode, specs);
  if (!(derive_plan_id(plan.key, structure) == plan.id)) {
    defect = "plan identity does not match its content";
    return false;
  }
  if (!(ConvergenceGovernor::plan_content_digest(plan) == plan.digest)) {
    defect = "plan digest does not match its content";
    return false;
  }
  (void)recovering;
  return true;
}

// Encodes the durable state.  The caller must already hold the state lock: no
// public entry point acquires it twice.
[[nodiscard]] std::vector<std::uint8_t> encode_state_locked(const GovernorState& state) {
  Encoder encoder(static_cast<std::size_t>(state.options.limits.max_persistence_record_bytes));
  encoder.u64(state.epoch.value());
  encoder.u64(state.convergence.value());
  encoder.u64(state.authority_generation.value());
  encoder.u32(static_cast<std::uint32_t>(state.policies.size()));
  for (const auto& entry : state.policies) {
    encode_policy(encoder, entry.second);
  }
  encoder.u32(static_cast<std::uint32_t>(state.plans.size()));
  for (const auto& entry : state.plans) {
    encode_plan(encoder, entry.second);
  }
  return encoder.take();
}

}  // namespace

std::vector<std::uint8_t> ConvergenceGovernor::encode_state() const {
  const GovernorState& state = *impl_->state;
  const std::shared_lock<std::shared_mutex> lock(state.mutex);
  return encode_state_locked(state);
}

PlanMutationResult ConvergenceGovernor::decode_state(std::span<const std::uint8_t> payload) {
  GovernorState& state = *impl_->state;
  const std::unique_lock<std::shared_mutex> lock(state.mutex);
  if (!state.plans.empty() || !state.policies.empty()) {
    return rejection(Outcome::STORE_ERROR, ConditionCode::STORE_STRUCTURE,
                     "governor already holds state");
  }
  Decoder decoder(payload, static_cast<std::size_t>(state.options.limits.max_persistence_record_bytes));
  std::uint64_t epoch = 0;
  std::uint64_t convergence = 0;
  std::uint64_t authority = 0;
  if (!decoder.u64(epoch) || !decoder.u64(convergence) || !decoder.u64(authority)) {
    return rejection(Outcome::STORE_ERROR, ConditionCode::STORE_STRUCTURE, "header");
  }

  std::uint32_t policy_count = 0;
  if (!decoder.u32(policy_count) || policy_count > 4096) {
    return rejection(Outcome::STORE_ERROR, ConditionCode::STORE_STRUCTURE, "policy count");
  }
  std::map<ConvergencePolicyId, ConvergencePolicy> policies;
  for (std::uint32_t index = 0; index < policy_count; ++index) {
    ConvergencePolicy policy;
    if (!decode_policy(decoder, policy)) {
      return rejection(Outcome::STORE_ERROR, ConditionCode::STORE_STRUCTURE, "policy record");
    }
    if (policies.find(policy.id) != policies.end()) {
      return rejection(Outcome::STORE_ERROR, ConditionCode::STORE_STRUCTURE, "duplicate policy");
    }
    policies[policy.id] = policy;
  }

  std::uint32_t plan_count = 0;
  if (!decoder.u32(plan_count) || plan_count > state.options.limits.max_plans) {
    return rejection(Outcome::STORE_ERROR, ConditionCode::STORE_RECORD_LIMIT, "plan count");
  }
  std::map<ConvergencePlanId, ConvergencePlan> plans;
  for (std::uint32_t index = 0; index < plan_count; ++index) {
    ConvergencePlan plan;
    std::string defect;
    if (!decode_plan(decoder, state.options.limits, true, plan, defect)) {
      return rejection(Outcome::STORE_ERROR, ConditionCode::STORE_STRUCTURE, defect);
    }
    if (plans.find(plan.id) != plans.end()) {
      return rejection(Outcome::STORE_ERROR, ConditionCode::STORE_STRUCTURE, "duplicate plan");
    }
    plans[plan.id] = std::move(plan);
  }
  if (!decoder.at_end()) {
    return rejection(Outcome::STORE_ERROR, ConditionCode::STORE_TRAILING_BYTES, "trailing bytes");
  }

  // Conservative recovery: durable plans and completed step history survive,
  // live worker authority does not, and in-flight work is never assumed to have
  // completed.
  state.policies = std::move(policies);
  state.plans = std::move(plans);
  state.epoch = CoordinatorEpoch::from_value(epoch);
  state.convergence = ConvergenceGeneration::from_value(convergence);
  state.authority_generation = AuthorityGeneration::from_value(authority == 0 ? 1 : authority);
  state.workers.clear();
  state.fenced_boots.clear();
  state.attempts.clear();
  state.attempt_order.clear();
  state.by_boot.clear();
  state.by_lifecycle.clear();
  state.by_route.clear();
  state.by_path.clear();
  state.by_key.clear();
  ++state.stats.recoveries;

  for (auto& entry : state.plans) {
    ConvergencePlan& plan = entry.second;
    for (TransitionStep& step : plan.steps) {
      const std::optional<StepLifecycle> recovered = apply_step_event(step.state, StepEvent::RECOVER);
      if (recovered.has_value() && *recovered != step.state) {
        step.state = *recovered;
        step.last_change = ChangeReason::RECOVERY;
        step.last_condition = ConditionCode::RECOVERED_CONSERVATIVE;
      }
    }
    const std::optional<PlanLifecycle> recovered =
        apply_plan_event(plan.lifecycle, PlanEvent::RECOVER, PlanTransitionInputs{});
    if (recovered.has_value()) {
      plan.lifecycle = *recovered;
    }
    refresh_ready_steps(state, plan);
    (void)touch_plan(state, plan, ChangeReason::RECOVERY, ConditionCode::RECOVERED_CONSERVATIVE,
                     TransitionStepId{});
  }
  if (advance_convergence(state)) {
    for (auto& entry : state.plans) {
      entry.second.watermark = state.convergence;
    }
  }
  for (const auto& entry : state.plans) {
    index_plan(state, entry.second);
  }

  PlanMutationResult result;
  result.outcome = Outcome::PLAN_UPDATED;
  result.conditions.add(make_condition(ConditionCode::RECOVERED_CONSERVATIVE, "recovery",
                                       state.plans.size(), state.epoch.value()));
  return result;
}

PlanMutationResult ConvergenceGovernor::save(const std::filesystem::path& path) {
  GovernorState& state = *impl_->state;
  std::vector<std::uint8_t> payload;
  std::uint64_t epoch = 0;
  std::uint64_t convergence = 0;
  {
    const std::shared_lock<std::shared_mutex> lock(state.mutex);
    if (!state.coherent) {
      return rejection(Outcome::INTERNAL_ERROR, ConditionCode::INTERNAL_INVARIANT,
                       state.incoherence_reason);
    }
    payload = encode_state_locked(state);
    epoch = state.epoch.value();
    convergence = state.convergence.value();
  }
  if (payload.size() > state.options.limits.max_persistence_record_bytes) {
    return rejection(Outcome::STORE_ERROR, ConditionCode::STORE_RECORD_LIMIT, "payload",
                     payload.size(), state.options.limits.max_persistence_record_bytes);
  }
  const std::vector<std::uint8_t> image = encode_store_file(epoch, convergence, payload);
  std::string error;
  const StoreDefect defect = write_store_file_atomic(path, image, error);
  if (defect != StoreDefect::NONE) {
    return rejection(Outcome::STORE_ERROR, condition_for(defect), error);
  }
  {
    const std::unique_lock<std::shared_mutex> lock(state.mutex);
    state.store_path = path;
  }
  PlanMutationResult result;
  result.outcome = Outcome::PLAN_UPDATED;
  return result;
}

PlanMutationResult ConvergenceGovernor::load(const std::filesystem::path& path) {
  GovernorState& state = *impl_->state;
  std::vector<std::uint8_t> bytes;
  std::string error;
  StoreDefect defect = read_store_file(path, bytes, error);
  if (defect != StoreDefect::NONE) {
    return rejection(Outcome::STORE_ERROR, condition_for(defect), error);
  }
  StoreFileInfo info;
  std::vector<std::uint8_t> payload;
  defect = decode_store_file(bytes, state.options.limits, info, payload);
  if (defect != StoreDefect::NONE) {
    return rejection(Outcome::STORE_ERROR, condition_for(defect), to_string(defect));
  }
  PlanMutationResult result = decode_state(payload);
  if (result.outcome != Outcome::PLAN_UPDATED) {
    return result;
  }
  const std::unique_lock<std::shared_mutex> lock(state.mutex);
  state.store_path = path;
  // The configured epoch may only move forward.  A coordinator that is restarted
  // at a higher epoch consumes it and every plan bound to the old one requires
  // fresh revalidation; a store written at a higher epoch is never regressed.
  if (state.options.initial_epoch.value() > state.epoch.value()) {
    apply_epoch(state, state.options.initial_epoch, ChangeReason::EPOCH_ADVANCE,
                epoch_provenance(state.options.initial_epoch));
  }
  return result;
}

}  // namespace rc
