#include "rc/step.hpp"

#include "rc/bytes.hpp"
#include "rc/limits.hpp"

namespace rc {

std::string_view to_string(StepKind kind) noexcept {
  switch (kind) {
    case StepKind::VALIDATE_TARGET: return "VALIDATE_TARGET";
    case StepKind::PREPARE_NEW_STATE: return "PREPARE_NEW_STATE";
    case StepKind::INSTALL_NEW_GROUP: return "INSTALL_NEW_GROUP";
    case StepKind::INSTALL_NEW_ROUTE: return "INSTALL_NEW_ROUTE";
    case StepKind::ACTIVATE_NEW_PATH: return "ACTIVATE_NEW_PATH";
    case StepKind::VERIFY_NEW_STATE: return "VERIFY_NEW_STATE";
    case StepKind::DEACTIVATE_OLD_PATH: return "DEACTIVATE_OLD_PATH";
    case StepKind::WITHDRAW_OLD_ROUTE: return "WITHDRAW_OLD_ROUTE";
    case StepKind::VERIFY_REMOVAL: return "VERIFY_REMOVAL";
    case StepKind::FINALIZE: return "FINALIZE";
  }
  return "UNKNOWN";
}

bool is_observation_step(StepKind kind) noexcept {
  return kind == StepKind::VALIDATE_TARGET || kind == StepKind::VERIFY_NEW_STATE ||
         kind == StepKind::VERIFY_REMOVAL;
}

bool is_verification_step(StepKind kind) noexcept { return is_observation_step(kind); }

bool is_make_step(StepKind kind) noexcept {
  return kind == StepKind::PREPARE_NEW_STATE || kind == StepKind::INSTALL_NEW_GROUP ||
         kind == StepKind::INSTALL_NEW_ROUTE || kind == StepKind::ACTIVATE_NEW_PATH;
}

bool is_break_step(StepKind kind) noexcept {
  return kind == StepKind::DEACTIVATE_OLD_PATH || kind == StepKind::WITHDRAW_OLD_ROUTE;
}

std::string_view to_string(BackendOutcome outcome) noexcept {
  switch (outcome) {
    case BackendOutcome::APPLIED: return "APPLIED";
    case BackendOutcome::IDEMPOTENT: return "IDEMPOTENT";
    case BackendOutcome::RETRYABLE_FAILURE: return "RETRYABLE_FAILURE";
    case BackendOutcome::PERMANENT_FAILURE: return "PERMANENT_FAILURE";
    case BackendOutcome::AMBIGUOUS: return "AMBIGUOUS";
    case BackendOutcome::UNSUPPORTED: return "UNSUPPORTED";
    case BackendOutcome::STALE: return "STALE";
  }
  return "UNKNOWN";
}

bool is_backend_success(BackendOutcome outcome) noexcept {
  return outcome == BackendOutcome::APPLIED || outcome == BackendOutcome::IDEMPOTENT;
}

std::string_view to_string(Reversibility reversibility) noexcept {
  switch (reversibility) {
    case Reversibility::OBSERVATION: return "OBSERVATION";
    case Reversibility::COMPENSATABLE: return "COMPENSATABLE";
    case Reversibility::IRREVERSIBLE: return "IRREVERSIBLE";
  }
  return "UNKNOWN";
}

std::string_view to_string(ConflictDomain domain) noexcept {
  switch (domain) {
    case ConflictDomain::NONE: return "NONE";
    case ConflictDomain::ROUTE_TABLE: return "ROUTE_TABLE";
    case ConflictDomain::PATH_STATE: return "PATH_STATE";
    case ConflictDomain::GROUP_STATE: return "GROUP_STATE";
    case ConflictDomain::TARGET_STATE: return "TARGET_STATE";
  }
  return "UNKNOWN";
}

std::string StepKey::render() const {
  std::string out(to_string(kind));
  out += '/';
  out += subject.text();
  return out;
}

bool CompletionEvidence::is_well_formed() const noexcept {
  if (plan.is_nil() || step.is_nil() || attempt.is_nil() || publisher.is_nil() ||
      worker_boot.is_nil()) {
    return false;
  }
  if (step_generation.value() == 0 || epoch.value() == 0) {
    return false;
  }
  if (detail.size() > 256) {
    return false;
  }
  return true;
}

TransitionStepId derive_step_id(ConvergencePlanId plan, const StepKey& key) {
  Encoder encoder;
  encoder.fixed16(plan.bytes());
  encoder.u32(static_cast<std::uint32_t>(key.kind));
  encoder.text(key.subject.text());
  const Digest digest = domain_digest("rc.step.v1", encoder.bytes());
  std::array<std::uint8_t, TransitionStepId::kByteCount> raw{};
  for (std::size_t index = 0; index < raw.size(); ++index) {
    raw[index] = digest.bytes()[index];
  }
  return TransitionStepId::from_bytes(raw);
}

CompletionEvidenceId derive_evidence_id(const CompletionEvidence& evidence) {
  Encoder encoder;
  encoder.fixed16(evidence.plan.bytes());
  encoder.fixed16(evidence.step.bytes());
  encoder.u64(evidence.step_generation.value());
  encoder.fixed16(evidence.attempt.bytes());
  encoder.u64(evidence.epoch.value());
  encoder.fixed16(evidence.publisher.bytes());
  encoder.fixed16(evidence.worker_boot.bytes());
  encoder.u32(static_cast<std::uint32_t>(evidence.outcome));
  encoder.u64(evidence.applied_route_generation.value());
  encoder.u64(evidence.observed_path_authority_generation.value());
  encoder.u64(evidence.dispatch_watermark.value());
  encoder.text(evidence.detail);
  const Digest digest = domain_digest("rc.evidence.v1", encoder.bytes());
  std::array<std::uint8_t, CompletionEvidenceId::kByteCount> raw{};
  for (std::size_t index = 0; index < raw.size(); ++index) {
    raw[index] = digest.bytes()[index];
  }
  return CompletionEvidenceId::from_bytes(raw);
}

}  // namespace rc
