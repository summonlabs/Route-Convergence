#include "rc/plan.hpp"

#include <algorithm>
#include <map>

#include "rc/bytes.hpp"
#include "rc/convergence.hpp"
#include "rc/graph.hpp"

namespace rc {
namespace {

void encode_step_key(Encoder& encoder, const StepKey& key) {
  encoder.u32(static_cast<std::uint32_t>(key.kind));
  encoder.text(key.subject.text());
}

void encode_step_spec(Encoder& encoder, const StepSpec& spec) {
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
  // Dependencies are hashed in canonical key order so that the declared order of
  // a prerequisite list is not part of the semantic content.
  std::vector<StepKey> dependencies = spec.depends_on;
  std::sort(dependencies.begin(), dependencies.end());
  dependencies.erase(std::unique(dependencies.begin(), dependencies.end()), dependencies.end());
  encoder.u32(static_cast<std::uint32_t>(dependencies.size()));
  for (const StepKey& dependency : dependencies) {
    encode_step_key(encoder, dependency);
  }
}

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

void encode_policy_ref(Encoder& encoder, const ConvergencePolicy& policy) {
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

[[nodiscard]] std::vector<std::size_t> canonical_indices(const std::vector<StepSpec>& steps) {
  const std::optional<std::vector<std::size_t>> order = canonical_topological_order(steps);
  if (order.has_value()) {
    return *order;
  }
  // A malformed graph still has to produce a stable digest, so fall back to the
  // canonical key order rather than to insertion order.
  std::vector<std::size_t> indices(steps.size());
  for (std::size_t index = 0; index < steps.size(); ++index) {
    indices[index] = index;
  }
  std::sort(indices.begin(), indices.end(), [&steps](std::size_t left, std::size_t right) {
    return steps[left].key() < steps[right].key();
  });
  return indices;
}

}  // namespace

bool PlanKey::is_well_formed() const noexcept {
  return !route.is_nil() && source_generation.value() >= 1 && target_generation.value() >= 1 &&
         policy_generation.value() >= 1 && source_generation != target_generation;
}

Digest PlanKey::content_digest() const {
  Encoder encoder;
  encoder.fixed16(route.bytes());
  encoder.u64(source_generation.value());
  encoder.u64(target_generation.value());
  encoder.u64(policy_generation.value());
  return domain_digest("rc.plankey.v1", encoder.bytes());
}

std::string PlanKey::render() const {
  std::string out = "route=";
  out += route.to_text();
  out += " source_generation=" + std::to_string(source_generation.value());
  out += " target_generation=" + std::to_string(target_generation.value());
  out += " policy_generation=" + std::to_string(policy_generation.value());
  return out;
}

std::string_view to_string(PlanMode mode) noexcept {
  switch (mode) {
    case PlanMode::GENERATED: return "GENERATED";
    case PlanMode::EXPLICIT: return "EXPLICIT";
  }
  return "UNKNOWN";
}

std::string_view to_string(DiffKind kind) noexcept {
  switch (kind) {
    case DiffKind::PLAN_CREATED: return "PLAN_CREATED";
    case DiffKind::LIFECYCLE_CHANGED: return "LIFECYCLE_CHANGED";
    case DiffKind::CURRENTNESS_CHANGED: return "CURRENTNESS_CHANGED";
    case DiffKind::STEP_STATE_CHANGED: return "STEP_STATE_CHANGED";
    case DiffKind::PREREQUISITE_SATISFIED: return "PREREQUISITE_SATISFIED";
    case DiffKind::TARGET_SUPERSEDED: return "TARGET_SUPERSEDED";
    case DiffKind::PATH_DEPENDENCY_STALE: return "PATH_DEPENDENCY_STALE";
    case DiffKind::ROLLBACK_ENTERED: return "ROLLBACK_ENTERED";
    case DiffKind::CONVERGENCE_COMPLETED: return "CONVERGENCE_COMPLETED";
    case DiffKind::AUTHORITY_CHANGED: return "AUTHORITY_CHANGED";
    case DiffKind::EPOCH_CHANGED: return "EPOCH_CHANGED";
    case DiffKind::LINEAGE_CHANGED: return "LINEAGE_CHANGED";
  }
  return "UNKNOWN";
}

std::string_view to_string(ExplainKind kind) noexcept {
  switch (kind) {
    case ExplainKind::PLAN: return "PLAN";
    case ExplainKind::STEP: return "STEP";
    case ExplainKind::READINESS: return "READINESS";
    case ExplainKind::PREREQUISITE: return "PREREQUISITE";
    case ExplainKind::OLD_STATE_RETENTION: return "OLD_STATE_RETENTION";
    case ExplainKind::TARGET_ACTIVATION: return "TARGET_ACTIVATION";
    case ExplainKind::ROLLBACK: return "ROLLBACK";
    case ExplainKind::STALENESS: return "STALENESS";
    case ExplainKind::COMPLETION: return "COMPLETION";
    case ExplainKind::AUTHORITY: return "AUTHORITY";
  }
  return "UNKNOWN";
}

bool PlanRequest::is_well_formed() const noexcept {
  if (!source.is_well_formed() || !target.is_well_formed() || !policy.is_well_formed()) {
    return false;
  }
  if (!(source.route == target.route)) {
    return false;
  }
  if (epoch.value() == 0 || provenance.is_nil()) {
    return false;
  }
  if (mode == PlanMode::EXPLICIT && explicit_steps.empty()) {
    return false;
  }
  if (mode == PlanMode::GENERATED && !explicit_steps.empty()) {
    return false;
  }
  return true;
}

bool ConvergencePlan::is_well_formed() const noexcept {
  if (id.is_nil() || !key.is_well_formed() || generation.value() == 0) {
    return false;
  }
  if (!source.is_well_formed() || !target.is_well_formed()) {
    return false;
  }
  if (!(source.route == key.route) || !(target.route == key.route)) {
    return false;
  }
  return true;
}

const TransitionStep* ConvergencePlan::find_step(const TransitionStepId& step) const noexcept {
  for (const TransitionStep& candidate : steps) {
    if (candidate.id == step) {
      return &candidate;
    }
  }
  return nullptr;
}

TransitionStep* ConvergencePlan::find_step(const TransitionStepId& step) noexcept {
  for (TransitionStep& candidate : steps) {
    if (candidate.id == step) {
      return &candidate;
    }
  }
  return nullptr;
}

std::optional<ConvergencePlanGeneration> ConvergencePlan::next_generation() const noexcept {
  return generation.next();
}

Digest plan_structure_digest(const PlanKey& key, const RouteBinding& source,
                             const RouteBinding& target, const ConvergencePolicy& policy,
                             PlanMode mode, const std::vector<StepSpec>& steps) {
  Encoder encoder;
  encoder.fixed16(key.route.bytes());
  encoder.u64(key.source_generation.value());
  encoder.u64(key.target_generation.value());
  encoder.u64(key.policy_generation.value());
  encode_binding(encoder, source);
  encode_binding(encoder, target);
  encode_policy_ref(encoder, policy);
  encoder.u32(static_cast<std::uint32_t>(mode));
  const std::vector<std::size_t> order = canonical_indices(steps);
  encoder.u32(static_cast<std::uint32_t>(order.size()));
  for (const std::size_t index : order) {
    encode_step_spec(encoder, steps[index]);
  }
  return domain_digest("rc.plan.structure.v1", encoder.bytes());
}

ConvergencePlanId derive_plan_id(const PlanKey& key, const Digest& content) {
  Encoder encoder;
  encoder.raw(key.content_digest().bytes());
  encoder.raw(content.bytes());
  const Digest digest = domain_digest("rc.plan.id.v1", encoder.bytes());
  std::array<std::uint8_t, ConvergencePlanId::kByteCount> raw{};
  for (std::size_t index = 0; index < raw.size(); ++index) {
    raw[index] = digest.bytes()[index];
  }
  return ConvergencePlanId::from_bytes(raw);
}

Digest ConvergenceGovernor::plan_content_digest(const ConvergencePlan& plan) {
  Encoder encoder;
  encoder.fixed16(plan.id.bytes());
  encoder.raw(plan_structure_digest(plan.key, plan.source, plan.target, plan.policy, plan.mode,
                                    [&plan]() {
                                      std::vector<StepSpec> specs;
                                      specs.reserve(plan.steps.size());
                                      for (const TransitionStep& step : plan.steps) {
                                        specs.push_back(step.spec);
                                      }
                                      return specs;
                                    }())
                        .bytes());
  encoder.u64(plan.generation.value());
  encoder.u32(static_cast<std::uint32_t>(plan.lifecycle));
  encoder.u32(plan.currentness.bits());
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
  encoder.u32(static_cast<std::uint32_t>(plan.steps.size()));
  for (const TransitionStep& step : plan.steps) {
    encoder.fixed16(step.id.bytes());
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
  return domain_digest("rc.plan.content.v1", encoder.bytes());
}

Digest ConvergenceGovernor::snapshot_digest(const ConvergenceSnapshot& snapshot) {
  Encoder encoder;
  encoder.fixed16(snapshot.plan.bytes());
  encoder.u64(snapshot.plan_generation.value());
  encoder.u32(static_cast<std::uint32_t>(snapshot.lifecycle));
  encoder.u32(snapshot.currentness.bits());
  encode_binding(encoder, snapshot.source);
  encode_binding(encoder, snapshot.target);
  encode_policy_ref(encoder, snapshot.policy);
  encoder.u32(static_cast<std::uint32_t>(snapshot.mode));
  encoder.u64(snapshot.epoch.value());
  encoder.u64(snapshot.created_epoch.value());
  encoder.fixed16(snapshot.owner_publisher.bytes());
  encoder.fixed16(snapshot.owner_boot.bytes());
  encoder.u64(snapshot.authority_generation.value());
  encoder.fixed16(snapshot.provenance.bytes());
  encoder.u64(snapshot.convergence_generation.value());
  encoder.u64(snapshot.watermark.value());
  encoder.fixed16(snapshot.predecessor.bytes());
  encoder.fixed16(snapshot.successor.bytes());
  encoder.u32(static_cast<std::uint32_t>(snapshot.supersession_reason));
  encoder.fixed16(snapshot.rollback_plan.bytes());
  encoder.boolean(snapshot.is_rollback);
  encoder.u32(static_cast<std::uint32_t>(snapshot.layers.size()));
  for (const std::vector<TransitionStepId>& layer : snapshot.layers) {
    encoder.u32(static_cast<std::uint32_t>(layer.size()));
    for (const TransitionStepId& step : layer) {
      encoder.fixed16(step.bytes());
    }
  }
  encoder.u32(static_cast<std::uint32_t>(snapshot.steps.size()));
  for (const StepSnapshot& step : snapshot.steps) {
    encode_step_key(encoder, step.key);
    encoder.fixed16(step.id.bytes());
    encoder.u64(step.generation.value());
    encoder.u32(static_cast<std::uint32_t>(step.state));
    encoder.u32(step.attempts);
    encoder.boolean(step.mandatory);
    encoder.boolean(step.idempotent);
    encoder.boolean(step.verification);
    encoder.u32(static_cast<std::uint32_t>(step.reversibility));
    encoder.u32(step.conflict_domains);
    encoder.fixed16(step.last_evidence.bytes());
    encoder.u32(static_cast<std::uint32_t>(step.last_outcome));
    encoder.fixed16(step.last_attempt.bytes());
    encoder.u64(step.dispatch_watermark.value());
    encoder.u64(step.dispatch_epoch.value());
    encoder.fixed16(step.dispatch_publisher.bytes());
    encoder.fixed16(step.dispatch_boot.bytes());
    std::vector<StepKey> dependencies = step.depends_on;
    std::sort(dependencies.begin(), dependencies.end());
    encoder.u32(static_cast<std::uint32_t>(dependencies.size()));
    for (const StepKey& dependency : dependencies) {
      encode_step_key(encoder, dependency);
    }
    encoder.boolean(step.prerequisites_satisfied);
    encoder.boolean(step.executable);
  }
  return domain_digest("rc.snapshot.v1", encoder.bytes());
}

Digest ConvergenceGovernor::policy_digest(const ConvergencePolicy& policy) {
  return policy.content_digest();
}

std::string PlanMutationResult::render() const {
  std::string out = "outcome=";
  out += to_string(outcome);
  if (!plan.is_nil()) {
    out += " plan=" + plan.to_text();
  }
  if (!step.is_nil()) {
    out += " step=" + step.to_text();
  }
  out += " plan_generation=" + std::to_string(plan_generation.value());
  out += " step_generation=" + std::to_string(step_generation.value());
  out += " convergence_generation=" + std::to_string(convergence_generation.value());
  if (!digest.is_nil()) {
    out += " digest=" + digest.to_text();
  }
  const std::string rendered = conditions.render();
  if (!rendered.empty()) {
    out += '\n';
    out += rendered;
  }
  return out;
}

std::string ReadyStepList::render() const {
  std::string out;
  for (const ReadyStep& step : steps) {
    if (!out.empty()) {
      out += '\n';
    }
    out += "ready plan=";
    out += step.plan.to_text();
    out += " step=";
    out += step.step.to_text();
    out += " key=";
    out += step.key.render();
    out += " generation=" + std::to_string(step.generation.value());
    out += " watermark=" + std::to_string(step.watermark.value());
  }
  if (truncated) {
    if (!out.empty()) {
      out += '\n';
    }
    out += "ready truncated=1";
  }
  return out;
}

std::string DiffEntry::render() const {
  std::string out = "diff kind=";
  out += to_string(kind);
  out += " plan_generation=" + std::to_string(plan_generation.value());
  out += " convergence_generation=" + std::to_string(convergence_generation.value());
  if (!step.is_nil()) {
    out += " step=" + step.to_text();
  }
  if (!subject.empty()) {
    out += " subject=" + subject;
  }
  out += " observed=" + std::to_string(observed);
  out += " expected=" + std::to_string(expected);
  return out;
}

std::string ConvergenceDiff::render() const {
  std::string out = "plan=";
  out += plan.to_text();
  out += " from_generation=" + std::to_string(from_generation.value());
  out += " to_generation=" + std::to_string(to_generation.value());
  for (const DiffEntry& entry : entries) {
    out += '\n';
    out += entry.render();
  }
  return out;
}

}  // namespace rc
