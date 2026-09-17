#include "rc/protocol.hpp"

#include <algorithm>
#include <array>

namespace rc {
namespace {

constexpr char kFrameMagic[4] = {'R', 'C', 'F', '1'};
constexpr std::size_t kBlobBytes = 1u << 20;

template <class T>
[[nodiscard]] bool decode_value_any(Decoder& decoder, const ConvergenceLimits& limits, T& out) {
  if constexpr (requires { decode_value(decoder, limits, out); }) {
    return decode_value(decoder, limits, out);
  } else {
    (void)limits;
    return decode_value(decoder, out);
  }
}

void encode_conditions(Encoder& encoder, const ConditionList& conditions) {
  encoder.u32(static_cast<std::uint32_t>(conditions.entries().size()));
  for (const Condition& condition : conditions.entries()) {
    encoder.u32(static_cast<std::uint32_t>(condition.code));
    encoder.text(condition.subject);
    encoder.u64(condition.observed);
    encoder.u64(condition.expected);
  }
  encoder.boolean(conditions.truncated());
}

[[nodiscard]] bool decode_conditions(Decoder& decoder, const ConvergenceLimits& limits,
                                     ConditionList& out) {
  std::uint32_t count = 0;
  if (!decoder.u32(count) || count > limits.max_explanation_entries) {
    return false;
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    std::uint32_t code = 0;
    Condition condition;
    if (!decoder.u32(code) || code > 92) {
      return false;
    }
    condition.code = static_cast<ConditionCode>(code);
    if (!decoder.text(condition.subject, 128) || !decoder.u64(condition.observed) ||
        !decoder.u64(condition.expected)) {
      return false;
    }
    out.add(std::move(condition));
  }
  bool truncated = false;
  if (!decoder.boolean(truncated)) {
    return false;
  }
  (void)truncated;
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
  return decoder.boolean(out.allow_overlap) && decoder.boolean(out.allow_break_before_make) &&
         decoder.u32(out.max_parallel_steps) && decoder.u32(out.max_retries_per_step) &&
         decoder.boolean(out.require_rollback_capability) &&
         decoder.boolean(out.supersede_predecessor_on_success);
}

[[nodiscard]] bool decode_summary(Decoder& decoder, PlanSummary& out) {
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.id = ConvergencePlanId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.key.route = RouteId::from_bytes(raw);
  std::uint64_t value = 0;
  if (!decoder.u64(value)) {
    return false;
  }
  out.key.source_generation = RouteGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return false;
  }
  out.key.target_generation = RouteGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return false;
  }
  out.key.policy_generation = ConvergencePolicyGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return false;
  }
  out.generation = ConvergencePlanGeneration::from_value(value);
  std::uint32_t lifecycle = 0;
  std::uint32_t currentness = 0;
  if (!decoder.u32(lifecycle) || lifecycle == 0 || lifecycle > kPlanLifecycleCount) {
    return false;
  }
  out.lifecycle = static_cast<PlanLifecycle>(lifecycle);
  if (!decoder.u32(currentness) || currentness > ((1u << kCurrentnessCauseCount) - 1u)) {
    return false;
  }
  out.currentness = Currentness::from_bits(currentness);
  std::array<std::uint8_t, 32> digest{};
  if (!decoder.u32(out.total_steps) || !decoder.u32(out.completed_steps) ||
      !decoder.u32(out.ready_steps) || !decoder.raw(digest)) {
    return false;
  }
  out.digest = Digest::from_bytes(digest);
  return true;
}

void encode_summary(Encoder& encoder, const PlanSummary& summary) {
  encoder.fixed16(summary.id.bytes());
  encoder.fixed16(summary.key.route.bytes());
  encoder.u64(summary.key.source_generation.value());
  encoder.u64(summary.key.target_generation.value());
  encoder.u64(summary.key.policy_generation.value());
  encoder.u64(summary.generation.value());
  encoder.u32(static_cast<std::uint32_t>(summary.lifecycle));
  encoder.u32(summary.currentness.bits());
  encoder.u32(summary.total_steps);
  encoder.u32(summary.completed_steps);
  encoder.u32(summary.ready_steps);
  encoder.raw(summary.digest.bytes());
}

}  // namespace

std::string_view to_string(WireMessageId id) noexcept {
  switch (id) {
    case WireMessageId::HELLO: return "HELLO";
    case WireMessageId::HELLO_RESPONSE: return "HELLO_RESPONSE";
    case WireMessageId::REGISTER_WORKER: return "REGISTER_WORKER";
    case WireMessageId::REGISTER_WORKER_RESPONSE: return "REGISTER_WORKER_RESPONSE";
    case WireMessageId::CREATE_PLAN: return "CREATE_PLAN";
    case WireMessageId::CREATE_PLAN_RESPONSE: return "CREATE_PLAN_RESPONSE";
    case WireMessageId::QUERY_PLAN: return "QUERY_PLAN";
    case WireMessageId::QUERY_PLAN_RESPONSE: return "QUERY_PLAN_RESPONSE";
    case WireMessageId::LIST_PLANS: return "LIST_PLANS";
    case WireMessageId::LIST_PLANS_RESPONSE: return "LIST_PLANS_RESPONSE";
    case WireMessageId::STEP_READY: return "STEP_READY";
    case WireMessageId::STEP_READY_RESPONSE: return "STEP_READY_RESPONSE";
    case WireMessageId::DISPATCH_STEP: return "DISPATCH_STEP";
    case WireMessageId::DISPATCH_STEP_RESPONSE: return "DISPATCH_STEP_RESPONSE";
    case WireMessageId::COMPLETE_STEP: return "COMPLETE_STEP";
    case WireMessageId::COMPLETE_STEP_RESPONSE: return "COMPLETE_STEP_RESPONSE";
    case WireMessageId::FAIL_STEP: return "FAIL_STEP";
    case WireMessageId::FAIL_STEP_RESPONSE: return "FAIL_STEP_RESPONSE";
    case WireMessageId::RECONCILE_STEP: return "RECONCILE_STEP";
    case WireMessageId::RECONCILE_STEP_RESPONSE: return "RECONCILE_STEP_RESPONSE";
    case WireMessageId::REVALIDATE_PLAN: return "REVALIDATE_PLAN";
    case WireMessageId::REVALIDATE_PLAN_RESPONSE: return "REVALIDATE_PLAN_RESPONSE";
    case WireMessageId::BEGIN_ROLLBACK: return "BEGIN_ROLLBACK";
    case WireMessageId::BEGIN_ROLLBACK_RESPONSE: return "BEGIN_ROLLBACK_RESPONSE";
    case WireMessageId::RETIRE_PLAN: return "RETIRE_PLAN";
    case WireMessageId::RETIRE_PLAN_RESPONSE: return "RETIRE_PLAN_RESPONSE";
    case WireMessageId::REVOKE_PLAN: return "REVOKE_PLAN";
    case WireMessageId::REVOKE_PLAN_RESPONSE: return "REVOKE_PLAN_RESPONSE";
    case WireMessageId::PAUSE_PLAN: return "PAUSE_PLAN";
    case WireMessageId::PAUSE_PLAN_RESPONSE: return "PAUSE_PLAN_RESPONSE";
    case WireMessageId::SNAPSHOT_REQUEST: return "SNAPSHOT_REQUEST";
    case WireMessageId::SNAPSHOT_RESPONSE: return "SNAPSHOT_RESPONSE";
    case WireMessageId::DIFF_REQUEST: return "DIFF_REQUEST";
    case WireMessageId::DIFF_RESPONSE: return "DIFF_RESPONSE";
    case WireMessageId::EXPLAIN_REQUEST: return "EXPLAIN_REQUEST";
    case WireMessageId::EXPLAIN_RESPONSE: return "EXPLAIN_RESPONSE";
    case WireMessageId::DEFINE_POLICY: return "DEFINE_POLICY";
    case WireMessageId::DEFINE_POLICY_RESPONSE: return "DEFINE_POLICY_RESPONSE";
    case WireMessageId::LIST_POLICIES: return "LIST_POLICIES";
    case WireMessageId::LIST_POLICIES_RESPONSE: return "LIST_POLICIES_RESPONSE";
    case WireMessageId::FENCE_WORKER: return "FENCE_WORKER";
    case WireMessageId::FENCE_WORKER_RESPONSE: return "FENCE_WORKER_RESPONSE";
    case WireMessageId::FENCE_NOTICE: return "FENCE_NOTICE";
    case WireMessageId::ROUTE_CHANGE: return "ROUTE_CHANGE";
    case WireMessageId::ROUTE_CHANGE_RESPONSE: return "ROUTE_CHANGE_RESPONSE";
    case WireMessageId::PATH_CHANGE: return "PATH_CHANGE";
    case WireMessageId::PATH_CHANGE_RESPONSE: return "PATH_CHANGE_RESPONSE";
    case WireMessageId::EPOCH_CHANGE: return "EPOCH_CHANGE";
    case WireMessageId::EPOCH_CHANGE_RESPONSE: return "EPOCH_CHANGE_RESPONSE";
    case WireMessageId::RESULT: return "RESULT";
    case WireMessageId::ERROR: return "ERROR";
  }
  return "UNKNOWN";
}

bool is_known_message(std::uint16_t raw) noexcept {
  switch (raw) {
    case 0x0001: case 0x0002:
    case 0x0010: case 0x0011:
    case 0x0020: case 0x0021: case 0x0022: case 0x0023: case 0x0024: case 0x0025:
    case 0x0026: case 0x0027: case 0x0028: case 0x0029: case 0x002A: case 0x002B:
    case 0x002C: case 0x002D: case 0x002E: case 0x002F: case 0x0030: case 0x0031:
    case 0x0032: case 0x0033: case 0x0034: case 0x0035: case 0x0036: case 0x0037:
    case 0x0038: case 0x0039: case 0x003A: case 0x003B: case 0x003C: case 0x003D:
    case 0x003E: case 0x003F: case 0x0040: case 0x0041: case 0x0042: case 0x0043:
    case 0x0044: case 0x0045: case 0x0046:
    case 0x0050: case 0x0051: case 0x0052: case 0x0053: case 0x0054: case 0x0055:
    case 0x0060: case 0x0061:
      return true;
    default:
      return false;
  }
}

bool is_response(WireMessageId id) noexcept {
  switch (id) {
    case WireMessageId::HELLO_RESPONSE:
    case WireMessageId::REGISTER_WORKER_RESPONSE:
    case WireMessageId::CREATE_PLAN_RESPONSE:
    case WireMessageId::QUERY_PLAN_RESPONSE:
    case WireMessageId::LIST_PLANS_RESPONSE:
    case WireMessageId::STEP_READY_RESPONSE:
    case WireMessageId::DISPATCH_STEP_RESPONSE:
    case WireMessageId::COMPLETE_STEP_RESPONSE:
    case WireMessageId::FAIL_STEP_RESPONSE:
    case WireMessageId::RECONCILE_STEP_RESPONSE:
    case WireMessageId::REVALIDATE_PLAN_RESPONSE:
    case WireMessageId::BEGIN_ROLLBACK_RESPONSE:
    case WireMessageId::RETIRE_PLAN_RESPONSE:
    case WireMessageId::REVOKE_PLAN_RESPONSE:
    case WireMessageId::PAUSE_PLAN_RESPONSE:
    case WireMessageId::SNAPSHOT_RESPONSE:
    case WireMessageId::DIFF_RESPONSE:
    case WireMessageId::EXPLAIN_RESPONSE:
    case WireMessageId::DEFINE_POLICY_RESPONSE:
    case WireMessageId::LIST_POLICIES_RESPONSE:
    case WireMessageId::FENCE_WORKER_RESPONSE:
    case WireMessageId::ROUTE_CHANGE_RESPONSE:
    case WireMessageId::PATH_CHANGE_RESPONSE:
    case WireMessageId::EPOCH_CHANGE_RESPONSE:
    case WireMessageId::FENCE_NOTICE:
    case WireMessageId::RESULT:
    case WireMessageId::ERROR:
      return true;
    default:
      return false;
  }
}

std::string_view to_string(WireDefect defect) noexcept {
  switch (defect) {
    case WireDefect::NONE: return "NONE";
    case WireDefect::TRUNCATED: return "TRUNCATED";
    case WireDefect::TRAILING_BYTES: return "TRAILING_BYTES";
    case WireDefect::UNKNOWN_MESSAGE: return "UNKNOWN_MESSAGE";
    case WireDefect::VERSION_MISMATCH: return "VERSION_MISMATCH";
    case WireDefect::INTEGRITY_FAILURE: return "INTEGRITY_FAILURE";
    case WireDefect::FRAME_TOO_LARGE: return "FRAME_TOO_LARGE";
    case WireDefect::MALFORMED_PAYLOAD: return "MALFORMED_PAYLOAD";
    case WireDefect::BAD_MAGIC: return "BAD_MAGIC";
    case WireDefect::RESERVED_NOT_ZERO: return "RESERVED_NOT_ZERO";
    case WireDefect::PEER_TIMEOUT: return "PEER_TIMEOUT";
    case WireDefect::PEER_CLOSED: return "PEER_CLOSED";
  }
  return "TRUNCATED";
}

ConditionCode condition_for(WireDefect defect) noexcept {
  switch (defect) {
    case WireDefect::NONE: return ConditionCode::NONE;
    case WireDefect::TRUNCATED: return ConditionCode::WIRE_TRUNCATED;
    case WireDefect::TRAILING_BYTES: return ConditionCode::WIRE_TRAILING_BYTES;
    case WireDefect::UNKNOWN_MESSAGE: return ConditionCode::WIRE_UNKNOWN_MESSAGE;
    case WireDefect::VERSION_MISMATCH: return ConditionCode::WIRE_VERSION_MISMATCH;
    case WireDefect::INTEGRITY_FAILURE: return ConditionCode::WIRE_INTEGRITY_FAILURE;
    case WireDefect::FRAME_TOO_LARGE: return ConditionCode::FRAME_LIMIT;
    case WireDefect::MALFORMED_PAYLOAD: return ConditionCode::MALFORMED_PAYLOAD;
    case WireDefect::BAD_MAGIC: return ConditionCode::WIRE_INTEGRITY_FAILURE;
    case WireDefect::RESERVED_NOT_ZERO: return ConditionCode::WIRE_INTEGRITY_FAILURE;
    case WireDefect::PEER_TIMEOUT: return ConditionCode::PEER_TIMEOUT;
    case WireDefect::PEER_CLOSED: return ConditionCode::PEER_CLOSED;
  }
  return ConditionCode::WIRE_INTEGRITY_FAILURE;
}

std::vector<std::uint8_t> encode_frame(const Envelope& envelope,
                                       const ConvergenceLimits& limits) {
  if (envelope.payload.size() > limits.max_frame_bytes) {
    return {};
  }
  Encoder encoder;
  encoder.raw(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(kFrameMagic), sizeof(kFrameMagic)));
  encoder.u16(static_cast<std::uint16_t>(kWireVersion));
  encoder.u16(static_cast<std::uint16_t>(envelope.message));
  encoder.u32(0);
  encoder.u64(envelope.sequence);
  encoder.u64(envelope.epoch.value());
  encoder.fixed16(envelope.publisher.bytes());
  encoder.fixed16(envelope.worker_boot.bytes());
  encoder.fixed16(envelope.attempt.bytes());
  encoder.u32(static_cast<std::uint32_t>(envelope.payload.size()));
  encoder.u32(0);
  encoder.raw(envelope.payload);
  const std::vector<std::uint8_t>& body = encoder.bytes();
  const Sha256::Value tag = Sha256::hash(body);
  std::vector<std::uint8_t> frame = body;
  frame.insert(frame.end(), tag.begin(), tag.end());
  return frame;
}

WireDefect decode_frame(std::span<const std::uint8_t> bytes, const ConvergenceLimits& limits,
                        Envelope& out) {
  out = Envelope{};
  if (bytes.size() < kWireOverheadBytes) {
    return WireDefect::TRUNCATED;
  }
  for (std::size_t index = 0; index < sizeof(kFrameMagic); ++index) {
    if (bytes[index] != static_cast<std::uint8_t>(kFrameMagic[index])) {
      return WireDefect::BAD_MAGIC;
    }
  }
  Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));
  if (!decoder.skip(sizeof(kFrameMagic))) {
    return WireDefect::TRUNCATED;
  }
  std::uint16_t version = 0;
  std::uint16_t message = 0;
  std::uint32_t flags = 0;
  std::uint64_t sequence = 0;
  std::uint64_t epoch = 0;
  std::array<std::uint8_t, 16> publisher{};
  std::array<std::uint8_t, 16> boot{};
  std::array<std::uint8_t, 16> attempt{};
  std::uint32_t payload_bytes = 0;
  std::uint32_t reserved = 0;
  if (!decoder.u16(version) || !decoder.u16(message) || !decoder.u32(flags) ||
      !decoder.u64(sequence) || !decoder.u64(epoch) || !decoder.fixed16(publisher) ||
      !decoder.fixed16(boot) || !decoder.fixed16(attempt) || !decoder.u32(payload_bytes) ||
      !decoder.u32(reserved)) {
    return WireDefect::TRUNCATED;
  }
  if (version != kWireVersion) {
    return WireDefect::VERSION_MISMATCH;
  }
  if (!is_known_message(message)) {
    return WireDefect::UNKNOWN_MESSAGE;
  }
  if (flags != 0 || reserved != 0) {
    return WireDefect::RESERVED_NOT_ZERO;
  }
  if (payload_bytes > limits.max_frame_bytes) {
    return WireDefect::FRAME_TOO_LARGE;
  }
  const std::size_t expected = kWireHeaderBytes + payload_bytes + kWireTagBytes;
  if (bytes.size() < expected) {
    return WireDefect::TRUNCATED;
  }
  if (bytes.size() > expected) {
    return WireDefect::TRAILING_BYTES;
  }
  const Sha256::Value tag = Sha256::hash(bytes.subspan(0, kWireHeaderBytes + payload_bytes));
  for (std::size_t index = 0; index < kWireTagBytes; ++index) {
    if (tag[index] != bytes[kWireHeaderBytes + payload_bytes + index]) {
      return WireDefect::INTEGRITY_FAILURE;
    }
  }
  out.message = static_cast<WireMessageId>(message);
  out.sequence = sequence;
  out.epoch = CoordinatorEpoch::from_value(epoch);
  out.publisher = PublisherId::from_bytes(publisher);
  out.worker_boot = WorkerBootId::from_bytes(boot);
  out.attempt = MutationAttemptId::from_bytes(attempt);
  out.payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(kWireHeaderBytes),
                     bytes.begin() + static_cast<std::ptrdiff_t>(kWireHeaderBytes + payload_bytes));
  return WireDefect::NONE;
}

// --- shared value codecs ----------------------------------------------------

void encode_value(Encoder& encoder, const RouteBinding& value) {
  encoder.fixed16(value.route.bytes());
  encoder.u64(value.generation.value());
  encoder.fixed16(value.path.bytes());
  encoder.u64(value.path_authority_generation.value());
  encoder.fixed16(value.multipath_set.bytes());
  encoder.u64(value.multipath_generation.value());
  encoder.fixed16(value.ecmp_group.bytes());
  encoder.u64(value.ecmp_generation.value());
  encoder.u64(value.assignment_generation.value());
  encoder.fixed16(value.weighted_set.bytes());
  encoder.u64(value.weight_policy_generation.value());
  encoder.boolean(value.current);
  encoder.boolean(value.legal);
}

bool decode_value(Decoder& decoder, RouteBinding& out) {
  std::array<std::uint8_t, 16> raw{};
  std::uint64_t value = 0;
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.route = RouteId::from_bytes(raw);
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

void encode_value(Encoder& encoder, const PathLegality& value) {
  encoder.fixed16(value.path.bytes());
  encoder.u64(value.generation.value());
  encoder.boolean(value.legal);
}

bool decode_value(Decoder& decoder, PathLegality& out) {
  std::array<std::uint8_t, 16> raw{};
  std::uint64_t value = 0;
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.path = PathId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.generation = PathAuthorityGeneration::from_value(value);
  return decoder.boolean(out.legal);
}

void encode_value(Encoder& encoder, const StepKey& value) {
  encoder.u32(static_cast<std::uint32_t>(value.kind));
  encoder.text(value.subject.text());
}

bool decode_value(Decoder& decoder, StepKey& out) {
  std::uint32_t kind = 0;
  std::string subject;
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
  return true;
}

void encode_value(Encoder& encoder, const StepSpec& value) {
  encoder.u32(static_cast<std::uint32_t>(value.kind));
  encoder.text(value.subject.text());
  encoder.u32(static_cast<std::uint32_t>(value.reversibility));
  encoder.u32(value.conflict_domains);
  encoder.boolean(value.mandatory);
  encoder.boolean(value.idempotent);
  encoder.boolean(value.verification);
  encoder.fixed16(value.path.bytes());
  encoder.u64(value.path_authority_generation.value());
  encoder.fixed16(value.route.bytes());
  encoder.u64(value.route_generation.value());
  encoder.fixed16(value.multipath_set.bytes());
  encoder.u64(value.multipath_generation.value());
  encoder.fixed16(value.ecmp_group.bytes());
  encoder.u64(value.ecmp_generation.value());
  encoder.u64(value.assignment_generation.value());
  encoder.fixed16(value.weighted_set.bytes());
  encoder.u64(value.weight_policy_generation.value());
  encoder.u32(static_cast<std::uint32_t>(value.depends_on.size()));
  for (const StepKey& dependency : value.depends_on) {
    encode_value(encoder, dependency);
  }
}

bool decode_value(Decoder& decoder, const ConvergenceLimits& limits, StepSpec& out) {
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
    StepKey key;
    if (!decode_value(decoder, key)) {
      return false;
    }
    out.depends_on.push_back(std::move(key));
  }
  return true;
}

void encode_value(Encoder& encoder, const ConvergencePolicy& value) { encode_policy(encoder, value); }
bool decode_value(Decoder& decoder, ConvergencePolicy& out) { return decode_policy(decoder, out); }

void encode_value(Encoder& encoder, const PlanKey& value) {
  encoder.fixed16(value.route.bytes());
  encoder.u64(value.source_generation.value());
  encoder.u64(value.target_generation.value());
  encoder.u64(value.policy_generation.value());
}

bool decode_value(Decoder& decoder, PlanKey& out) {
  std::array<std::uint8_t, 16> raw{};
  std::uint64_t value = 0;
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.route = RouteId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.source_generation = RouteGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return false;
  }
  out.target_generation = RouteGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return false;
  }
  out.policy_generation = ConvergencePolicyGeneration::from_value(value);
  return true;
}

void encode_value(Encoder& encoder, const PlanChange& value) {
  encoder.u32(static_cast<std::uint32_t>(value.reason));
  encoder.u64(value.plan_generation.value());
  encoder.u64(value.convergence_generation.value());
  encoder.u32(static_cast<std::uint32_t>(value.condition));
  encoder.fixed16(value.step.bytes());
  encoder.u32(static_cast<std::uint32_t>(value.step_state));
  encoder.u64(value.observed);
  encoder.u64(value.expected);
}

bool decode_value(Decoder& decoder, PlanChange& out) {
  std::uint32_t reason = 0;
  std::uint64_t generation = 0;
  std::uint64_t convergence = 0;
  std::uint32_t condition = 0;
  std::array<std::uint8_t, 16> step{};
  std::uint32_t step_state = 0;
  if (!decoder.u32(reason) || reason == 0 || reason > kChangeReasonCount) {
    return false;
  }
  out.reason = static_cast<ChangeReason>(reason);
  if (!decoder.u64(generation) || !decoder.u64(convergence) || !decoder.u32(condition) ||
      !decoder.fixed16(step) || !decoder.u32(step_state) || step_state == 0 ||
      step_state > kStepLifecycleCount || !decoder.u64(out.observed) ||
      !decoder.u64(out.expected)) {
    return false;
  }
  out.plan_generation = ConvergencePlanGeneration::from_value(generation);
  out.convergence_generation = ConvergenceGeneration::from_value(convergence);
  out.condition = static_cast<ConditionCode>(condition);
  out.step = TransitionStepId::from_bytes(step);
  out.step_state = static_cast<StepLifecycle>(step_state);
  return true;
}

void encode_value(Encoder& encoder, const Condition& value) {
  encoder.u32(static_cast<std::uint32_t>(value.code));
  encoder.text(value.subject);
  encoder.u64(value.observed);
  encoder.u64(value.expected);
}

bool decode_value(Decoder& decoder, Condition& out) {
  std::uint32_t code = 0;
  if (!decoder.u32(code) || code > 92) {
    return false;
  }
  out.code = static_cast<ConditionCode>(code);
  return decoder.text(out.subject, 128) && decoder.u64(out.observed) && decoder.u64(out.expected);
}

void encode_value(Encoder& encoder, const ConditionList& value) {
  encode_conditions(encoder, value);
}

bool decode_value(Decoder& decoder, const ConvergenceLimits& limits, ConditionList& out) {
  return decode_conditions(decoder, limits, out);
}

void encode_value(Encoder& encoder, const AuthorityScope& value) {
  encoder.u32(static_cast<std::uint32_t>(value.kind));
  encoder.fixed16(value.fabric.bytes());
  encoder.fixed16(value.routing_namespace.bytes());
  encoder.fixed16(value.route.bytes());
  encoder.fixed16(value.plan.bytes());
}

bool decode_value(Decoder& decoder, AuthorityScope& out) {
  std::uint32_t kind = 0;
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.u32(kind) || kind > 4) {
    return false;
  }
  out.kind = static_cast<ScopeKind>(kind);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.fabric = FabricId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.routing_namespace = RoutingNamespaceId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.route = RouteId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.plan = ConvergencePlanId::from_bytes(raw);
  return true;
}

void encode_value(Encoder& encoder, const PublisherRegistration& value) {
  encoder.fixed16(value.publisher.bytes());
  encoder.fixed16(value.worker_boot.bytes());
  encode_value(encoder, value.scope);
  encoder.u32(value.capabilities);
  encoder.fixed16(value.provenance.bytes());
}

bool decode_value(Decoder& decoder, PublisherRegistration& out) {
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.publisher = PublisherId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.worker_boot = WorkerBootId::from_bytes(raw);
  if (!decode_value(decoder, out.scope) || !decoder.u32(out.capabilities) ||
      !decoder.fixed16(raw)) {
    return false;
  }
  out.provenance = ProvenanceId::from_bytes(raw);
  return true;
}

void encode_value(Encoder& encoder, const PlanRequest& value) {
  encoder.u32(static_cast<std::uint32_t>(value.mode));
  encode_value(encoder, value.source);
  encode_value(encoder, value.target);
  encode_value(encoder, value.policy);
  encoder.u64(value.epoch.value());
  encoder.fixed16(value.provenance.bytes());
  encoder.boolean(value.accept_historical_source);
  encoder.u32(static_cast<std::uint32_t>(value.explicit_steps.size()));
  for (const StepSpec& step : value.explicit_steps) {
    encode_value(encoder, step);
  }
}

bool decode_value(Decoder& decoder, const ConvergenceLimits& limits, PlanRequest& out) {
  std::uint32_t mode = 0;
  if (!decoder.u32(mode) || mode == 0 || mode > 2) {
    return false;
  }
  out.mode = static_cast<PlanMode>(mode);
  if (!decode_value(decoder, out.source) || !decode_value(decoder, out.target) ||
      !decode_value(decoder, out.policy)) {
    return false;
  }
  std::uint64_t epoch = 0;
  std::array<std::uint8_t, 16> provenance{};
  if (!decoder.u64(epoch) || !decoder.fixed16(provenance) ||
      !decoder.boolean(out.accept_historical_source)) {
    return false;
  }
  out.epoch = CoordinatorEpoch::from_value(epoch);
  out.provenance = ProvenanceId::from_bytes(provenance);
  std::uint32_t count = 0;
  if (!decoder.u32(count) || count > limits.max_steps_per_plan) {
    return false;
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    StepSpec spec;
    if (!decode_value(decoder, limits, spec)) {
      return false;
    }
    out.explicit_steps.push_back(std::move(spec));
  }
  return true;
}

void encode_value(Encoder& encoder, const PlanMutationResult& value) {
  encoder.u32(static_cast<std::uint32_t>(value.outcome));
  encoder.fixed16(value.plan.bytes());
  encoder.fixed16(value.step.bytes());
  encoder.u64(value.plan_generation.value());
  encoder.u64(value.step_generation.value());
  encoder.u64(value.convergence_generation.value());
  encoder.raw(value.digest.bytes());
  encode_conditions(encoder, value.conditions);
}

bool decode_value(Decoder& decoder, const ConvergenceLimits& limits, PlanMutationResult& out) {
  std::uint32_t outcome = 0;
  std::uint64_t plan_generation = 0;
  std::uint64_t step_generation = 0;
  std::uint64_t convergence = 0;
  std::array<std::uint8_t, 16> plan{};
  std::array<std::uint8_t, 16> step{};
  std::array<std::uint8_t, 32> digest{};
  if (!decoder.u32(outcome) || outcome == 0 || outcome > 64 || !decoder.fixed16(plan) ||
      !decoder.fixed16(step) || !decoder.u64(plan_generation) || !decoder.u64(step_generation) ||
      !decoder.u64(convergence) || !decoder.raw(digest)) {
    return false;
  }
  out.outcome = static_cast<Outcome>(outcome);
  out.plan = ConvergencePlanId::from_bytes(plan);
  out.step = TransitionStepId::from_bytes(step);
  out.plan_generation = ConvergencePlanGeneration::from_value(plan_generation);
  out.step_generation = TransitionStepGeneration::from_value(step_generation);
  out.convergence_generation = ConvergenceGeneration::from_value(convergence);
  out.digest = Digest::from_bytes(digest);
  out.conditions = ConditionList(limits.max_explanation_entries);
  return decode_conditions(decoder, limits, out.conditions);
}

void encode_value(Encoder& encoder, const PlanSummary& value) { encode_summary(encoder, value); }
bool decode_value(Decoder& decoder, PlanSummary& out) { return decode_summary(decoder, out); }

void encode_value(Encoder& encoder, const StepSnapshot& value) {
  encode_value(encoder, value.key);
  encoder.fixed16(value.id.bytes());
  encoder.u64(value.generation.value());
  encoder.u32(static_cast<std::uint32_t>(value.state));
  encoder.u32(value.attempts);
  encoder.boolean(value.mandatory);
  encoder.boolean(value.idempotent);
  encoder.boolean(value.verification);
  encoder.u32(static_cast<std::uint32_t>(value.reversibility));
  encoder.u32(value.conflict_domains);
  encoder.fixed16(value.last_evidence.bytes());
  encoder.u32(static_cast<std::uint32_t>(value.last_outcome));
  encoder.fixed16(value.last_attempt.bytes());
  encoder.u64(value.dispatch_watermark.value());
  encoder.u64(value.dispatch_epoch.value());
  encoder.fixed16(value.dispatch_publisher.bytes());
  encoder.fixed16(value.dispatch_boot.bytes());
  encoder.u32(static_cast<std::uint32_t>(value.depends_on.size()));
  for (const StepKey& dependency : value.depends_on) {
    encode_value(encoder, dependency);
  }
  encoder.boolean(value.prerequisites_satisfied);
  encoder.boolean(value.executable);
}

bool decode_value(Decoder& decoder, const ConvergenceLimits& limits, StepSnapshot& out) {
  if (!decode_value(decoder, out.key)) {
    return false;
  }
  std::array<std::uint8_t, 16> raw{};
  std::uint64_t value = 0;
  std::uint32_t state = 0;
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.id = TransitionStepId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.generation = TransitionStepGeneration::from_value(value);
  if (!decoder.u32(state) || state == 0 || state > kStepLifecycleCount) {
    return false;
  }
  out.state = static_cast<StepLifecycle>(state);
  if (!decoder.u32(out.attempts) || !decoder.boolean(out.mandatory) ||
      !decoder.boolean(out.idempotent) || !decoder.boolean(out.verification)) {
    return false;
  }
  std::uint32_t reversibility = 0;
  if (!decoder.u32(reversibility) || reversibility == 0 || reversibility > 3) {
    return false;
  }
  out.reversibility = static_cast<Reversibility>(reversibility);
  std::uint32_t outcome = 0;
  if (!decoder.u32(out.conflict_domains) || !decoder.fixed16(raw)) {
    return false;
  }
  out.last_evidence = CompletionEvidenceId::from_bytes(raw);
  if (!decoder.u32(outcome) || outcome == 0 || outcome > 7 || !decoder.fixed16(raw)) {
    return false;
  }
  out.last_outcome = static_cast<BackendOutcome>(outcome);
  out.last_attempt = MutationAttemptId::from_bytes(raw);
  std::uint64_t watermark = 0;
  std::uint64_t epoch = 0;
  if (!decoder.u64(watermark) || !decoder.u64(epoch)) {
    return false;
  }
  out.dispatch_watermark = ConvergenceGeneration::from_value(watermark);
  out.dispatch_epoch = CoordinatorEpoch::from_value(epoch);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.dispatch_publisher = PublisherId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.dispatch_boot = WorkerBootId::from_bytes(raw);
  std::uint32_t count = 0;
  if (!decoder.u32(count) || count > limits.max_dependencies_per_step) {
    return false;
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    StepKey key;
    if (!decode_value(decoder, key)) {
      return false;
    }
    out.depends_on.push_back(std::move(key));
  }
  return decoder.boolean(out.prerequisites_satisfied) && decoder.boolean(out.executable);
}

void encode_value(Encoder& encoder, const ConvergenceSnapshot& value) {
  encoder.fixed16(value.id.bytes());
  encoder.fixed16(value.plan.bytes());
  encoder.u64(value.plan_generation.value());
  encoder.u32(static_cast<std::uint32_t>(value.lifecycle));
  encoder.u32(value.currentness.bits());
  encode_policy(encoder, value.policy);
  encode_value(encoder, value.source);
  encode_value(encoder, value.target);
  encoder.u32(static_cast<std::uint32_t>(value.mode));
  encoder.u64(value.epoch.value());
  encoder.u64(value.created_epoch.value());
  encoder.fixed16(value.owner_publisher.bytes());
  encoder.fixed16(value.owner_boot.bytes());
  encoder.u64(value.authority_generation.value());
  encoder.fixed16(value.provenance.bytes());
  encoder.u64(value.convergence_generation.value());
  encoder.u64(value.watermark.value());
  encoder.fixed16(value.predecessor.bytes());
  encoder.fixed16(value.successor.bytes());
  encoder.u32(static_cast<std::uint32_t>(value.supersession_reason));
  encoder.fixed16(value.rollback_plan.bytes());
  encoder.boolean(value.is_rollback);
  encoder.u32(static_cast<std::uint32_t>(value.layers.size()));
  for (const std::vector<TransitionStepId>& layer : value.layers) {
    encoder.u32(static_cast<std::uint32_t>(layer.size()));
    for (const TransitionStepId& id : layer) {
      encoder.fixed16(id.bytes());
    }
  }
  encoder.u32(static_cast<std::uint32_t>(value.steps.size()));
  for (const StepSnapshot& step : value.steps) {
    encode_value(encoder, step);
  }
  encoder.raw(value.digest.bytes());
}

bool decode_value(Decoder& decoder, const ConvergenceLimits& limits, ConvergenceSnapshot& out) {
  std::array<std::uint8_t, 16> raw{};
  std::uint64_t value = 0;
  std::uint32_t lifecycle = 0;
  std::uint32_t currentness = 0;
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.id = SnapshotId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.plan = ConvergencePlanId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.plan_generation = ConvergencePlanGeneration::from_value(value);
  if (!decoder.u32(lifecycle) || lifecycle == 0 || lifecycle > kPlanLifecycleCount) {
    return false;
  }
  out.lifecycle = static_cast<PlanLifecycle>(lifecycle);
  if (!decoder.u32(currentness) || currentness > ((1u << kCurrentnessCauseCount) - 1u)) {
    return false;
  }
  out.currentness = Currentness::from_bits(currentness);
  if (!decode_policy(decoder, out.policy) || !decode_value(decoder, out.source) ||
      !decode_value(decoder, out.target)) {
    return false;
  }
  std::uint32_t mode = 0;
  if (!decoder.u32(mode) || mode == 0 || mode > 2) {
    return false;
  }
  out.mode = static_cast<PlanMode>(mode);
  std::uint64_t epoch = 0;
  std::uint64_t created = 0;
  if (!decoder.u64(epoch) || !decoder.u64(created)) {
    return false;
  }
  out.epoch = CoordinatorEpoch::from_value(epoch);
  out.created_epoch = CoordinatorEpoch::from_value(created);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.owner_publisher = PublisherId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.owner_boot = WorkerBootId::from_bytes(raw);
  std::uint64_t authority = 0;
  if (!decoder.u64(authority) || !decoder.fixed16(raw)) {
    return false;
  }
  out.authority_generation = AuthorityGeneration::from_value(authority);
  out.provenance = ProvenanceId::from_bytes(raw);
  std::uint64_t convergence = 0;
  std::uint64_t watermark = 0;
  if (!decoder.u64(convergence) || !decoder.u64(watermark)) {
    return false;
  }
  out.convergence_generation = ConvergenceGeneration::from_value(convergence);
  out.watermark = ConvergenceGeneration::from_value(watermark);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.predecessor = ConvergencePlanId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.successor = ConvergencePlanId::from_bytes(raw);
  std::uint32_t supersession = 0;
  if (!decoder.u32(supersession) || supersession == 0 || supersession > kChangeReasonCount) {
    return false;
  }
  out.supersession_reason = static_cast<ChangeReason>(supersession);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.rollback_plan = ConvergencePlanId::from_bytes(raw);
  if (!decoder.boolean(out.is_rollback)) {
    return false;
  }
  std::uint32_t layer_count = 0;
  if (!decoder.u32(layer_count) || layer_count > limits.max_steps_per_plan) {
    return false;
  }
  for (std::uint32_t layer = 0; layer < layer_count; ++layer) {
    std::uint32_t width = 0;
    if (!decoder.u32(width) || width > limits.max_steps_per_plan) {
      return false;
    }
    std::vector<TransitionStepId> ids;
    for (std::uint32_t index = 0; index < width; ++index) {
      std::array<std::uint8_t, 16> id{};
      if (!decoder.raw(id)) {
        return false;
      }
      ids.push_back(TransitionStepId::from_bytes(id));
    }
    out.layers.push_back(std::move(ids));
  }
  std::uint32_t step_count = 0;
  if (!decoder.u32(step_count) || step_count > limits.max_steps_per_plan) {
    return false;
  }
  for (std::uint32_t index = 0; index < step_count; ++index) {
    StepSnapshot step;
    if (!decode_value(decoder, limits, step)) {
      return false;
    }
    out.steps.push_back(std::move(step));
  }
  std::array<std::uint8_t, 32> digest{};
  if (!decoder.raw(digest)) {
    return false;
  }
  out.digest = Digest::from_bytes(digest);
  return true;
}

void encode_value(Encoder& encoder, const DiffEntry& value) {
  encoder.u32(static_cast<std::uint32_t>(value.kind));
  encoder.u64(value.plan_generation.value());
  encoder.u64(value.convergence_generation.value());
  encoder.fixed16(value.step.bytes());
  encoder.text(value.subject);
  encoder.u64(value.observed);
  encoder.u64(value.expected);
}

bool decode_value(Decoder& decoder, DiffEntry& out) {
  std::uint32_t kind = 0;
  std::uint64_t plan_generation = 0;
  std::uint64_t convergence = 0;
  std::array<std::uint8_t, 16> step{};
  if (!decoder.u32(kind) || kind == 0 || kind > 12 || !decoder.u64(plan_generation) ||
      !decoder.u64(convergence) || !decoder.fixed16(step) ||
      !decoder.text(out.subject, 128) || !decoder.u64(out.observed) ||
      !decoder.u64(out.expected)) {
    return false;
  }
  out.kind = static_cast<DiffKind>(kind);
  out.plan_generation = ConvergencePlanGeneration::from_value(plan_generation);
  out.convergence_generation = ConvergenceGeneration::from_value(convergence);
  out.step = TransitionStepId::from_bytes(step);
  return true;
}

void encode_value(Encoder& encoder, const ConvergenceDiff& value) {
  encoder.fixed16(value.plan.bytes());
  encoder.u64(value.from_generation.value());
  encoder.u64(value.to_generation.value());
  encoder.u32(static_cast<std::uint32_t>(value.entries.size()));
  for (const DiffEntry& entry : value.entries) {
    encode_value(encoder, entry);
  }
}

bool decode_value(Decoder& decoder, const ConvergenceLimits& limits, ConvergenceDiff& out) {
  std::array<std::uint8_t, 16> plan{};
  std::uint64_t from = 0;
  std::uint64_t to = 0;
  if (!decoder.fixed16(plan) || !decoder.u64(from) || !decoder.u64(to)) {
    return false;
  }
  out.plan = ConvergencePlanId::from_bytes(plan);
  out.from_generation = ConvergencePlanGeneration::from_value(from);
  out.to_generation = ConvergencePlanGeneration::from_value(to);
  std::uint32_t count = 0;
  if (!decoder.u32(count) || count > limits.max_explanation_entries) {
    return false;
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    DiffEntry entry;
    if (!decode_value(decoder, entry)) {
      return false;
    }
    out.entries.push_back(std::move(entry));
  }
  return true;
}

void encode_value(Encoder& encoder, const ExplainRequest& value) {
  encoder.fixed16(value.plan.bytes());
  encoder.fixed16(value.step.bytes());
  encoder.u32(static_cast<std::uint32_t>(value.kind));
}

bool decode_value(Decoder& decoder, ExplainRequest& out) {
  std::array<std::uint8_t, 16> plan{};
  std::array<std::uint8_t, 16> step{};
  std::uint32_t kind = 0;
  if (!decoder.fixed16(plan) || !decoder.fixed16(step) || !decoder.u32(kind) || kind == 0 ||
      kind > 10) {
    return false;
  }
  out.plan = ConvergencePlanId::from_bytes(plan);
  out.step = TransitionStepId::from_bytes(step);
  out.kind = static_cast<ExplainKind>(kind);
  return true;
}

void encode_value(Encoder& encoder, const ExplainResponse& value) {
  encoder.boolean(value.found);
  encoder.text(value.explanation.subject());
  encode_conditions(encoder, value.explanation.conditions());
}

bool decode_value(Decoder& decoder, const ConvergenceLimits& limits, ExplainResponse& out) {
  std::string subject;
  if (!decoder.boolean(out.found) || !decoder.text(subject, 256)) {
    return false;
  }
  out.explanation = Explanation(subject, limits.max_explanation_entries);
  ConditionList conditions(limits.max_explanation_entries);
  if (!decode_conditions(decoder, limits, conditions)) {
    return false;
  }
  for (const Condition& condition : conditions.entries()) {
    out.explanation.add(condition);
  }
  return true;
}

void encode_value(Encoder& encoder, const CompletionEvidence& value) {
  encoder.fixed16(value.id.bytes());
  encoder.fixed16(value.plan.bytes());
  encoder.fixed16(value.step.bytes());
  encoder.u64(value.step_generation.value());
  encoder.fixed16(value.attempt.bytes());
  encoder.u64(value.epoch.value());
  encoder.fixed16(value.publisher.bytes());
  encoder.fixed16(value.worker_boot.bytes());
  encoder.u32(static_cast<std::uint32_t>(value.outcome));
  encoder.u64(value.applied_route_generation.value());
  encoder.u64(value.observed_path_authority_generation.value());
  encoder.u64(value.dispatch_watermark.value());
  encoder.text(value.detail);
}

bool decode_value(Decoder& decoder, const ConvergenceLimits& limits, CompletionEvidence& out) {
  (void)limits;
  std::array<std::uint8_t, 16> raw{};
  std::uint64_t value = 0;
  std::uint32_t outcome = 0;
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.id = CompletionEvidenceId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.plan = ConvergencePlanId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.step = TransitionStepId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.step_generation = TransitionStepGeneration::from_value(value);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.attempt = MutationAttemptId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.epoch = CoordinatorEpoch::from_value(value);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.publisher = PublisherId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.worker_boot = WorkerBootId::from_bytes(raw);
  if (!decoder.u32(outcome) || outcome == 0 || outcome > 7) {
    return false;
  }
  out.outcome = static_cast<BackendOutcome>(outcome);
  if (!decoder.u64(value)) {
    return false;
  }
  out.applied_route_generation = RouteGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return false;
  }
  out.observed_path_authority_generation = PathAuthorityGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return false;
  }
  out.dispatch_watermark = ConvergenceGeneration::from_value(value);
  return decoder.text(out.detail, 256);
}

void encode_value(Encoder& encoder, const StepDispatch& value) {
  encoder.u32(static_cast<std::uint32_t>(value.outcome));
  encoder.fixed16(value.plan.bytes());
  encoder.fixed16(value.step.bytes());
  encoder.u64(value.step_generation.value());
  encoder.u64(value.watermark.value());
  encoder.u64(value.epoch.value());
  // A rejected dispatch carries no executable step, so its presence is explicit.
  const bool has_spec = !value.spec.subject.empty();
  encoder.boolean(has_spec);
  if (has_spec) {
    encode_value(encoder, value.spec);
  }
  encode_conditions(encoder, value.conditions);
}

bool decode_value(Decoder& decoder, const ConvergenceLimits& limits, StepDispatch& out) {
  std::uint32_t outcome = 0;
  std::array<std::uint8_t, 16> plan{};
  std::array<std::uint8_t, 16> step{};
  std::uint64_t generation = 0;
  std::uint64_t watermark = 0;
  std::uint64_t epoch = 0;
  if (!decoder.u32(outcome) || outcome == 0 || outcome > 64 || !decoder.fixed16(plan) ||
      !decoder.fixed16(step) || !decoder.u64(generation) || !decoder.u64(watermark) ||
      !decoder.u64(epoch)) {
    return false;
  }
  out.outcome = static_cast<Outcome>(outcome);
  out.plan = ConvergencePlanId::from_bytes(plan);
  out.step = TransitionStepId::from_bytes(step);
  out.step_generation = TransitionStepGeneration::from_value(generation);
  out.watermark = ConvergenceGeneration::from_value(watermark);
  out.epoch = CoordinatorEpoch::from_value(epoch);
  bool has_spec = false;
  if (!decoder.boolean(has_spec)) {
    return false;
  }
  if (has_spec && !decode_value(decoder, limits, out.spec)) {
    return false;
  }
  out.conditions = ConditionList(limits.max_explanation_entries);
  return decode_conditions(decoder, limits, out.conditions);
}

void encode_value(Encoder& encoder, const ReadyStep& value) {
  encoder.fixed16(value.plan.bytes());
  encoder.fixed16(value.step.bytes());
  encode_value(encoder, value.key);
  encoder.u64(value.generation.value());
  encoder.u64(value.watermark.value());
  encoder.fixed16(value.route.bytes());
  encode_value(encoder, value.spec);
}

bool decode_value(Decoder& decoder, const ConvergenceLimits& limits, ReadyStep& out) {
  std::array<std::uint8_t, 16> raw{};
  std::uint64_t generation = 0;
  std::uint64_t watermark = 0;
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.plan = ConvergencePlanId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.step = TransitionStepId::from_bytes(raw);
  if (!decode_value(decoder, out.key) || !decoder.u64(generation) || !decoder.u64(watermark) ||
      !decoder.fixed16(raw)) {
    return false;
  }
  out.generation = TransitionStepGeneration::from_value(generation);
  out.watermark = ConvergenceGeneration::from_value(watermark);
  out.route = RouteId::from_bytes(raw);
  return decode_value(decoder, limits, out.spec);
}

void encode_value(Encoder& encoder, const ReadyStepList& value) {
  encoder.u32(static_cast<std::uint32_t>(value.steps.size()));
  for (const ReadyStep& step : value.steps) {
    encode_value(encoder, step);
  }
  encoder.boolean(value.truncated);
}

bool decode_value(Decoder& decoder, const ConvergenceLimits& limits, ReadyStepList& out) {
  std::uint32_t count = 0;
  if (!decoder.u32(count) || count > limits.max_parallel_steps * 2) {
    return false;
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    ReadyStep step;
    if (!decode_value(decoder, limits, step)) {
      return false;
    }
    out.steps.push_back(std::move(step));
  }
  return decoder.boolean(out.truncated);
}

void encode_value(Encoder& encoder, const NoticeResult& value) {
  encoder.u32(static_cast<std::uint32_t>(value.outcome));
  encoder.u64(value.epoch.value());
  encoder.u64(value.convergence_generation.value());
  encoder.u32(value.plans_examined);
  encoder.u32(value.plans_invalidated);
  encoder.u32(value.plans_superseded);
  encoder.u32(value.steps_staled);
  encode_conditions(encoder, value.conditions);
}

bool decode_value(Decoder& decoder, const ConvergenceLimits& limits, NoticeResult& out) {
  std::uint32_t outcome = 0;
  std::uint64_t epoch = 0;
  std::uint64_t convergence = 0;
  if (!decoder.u32(outcome) || outcome == 0 || outcome > 64 || !decoder.u64(epoch) ||
      !decoder.u64(convergence) || !decoder.u32(out.plans_examined) ||
      !decoder.u32(out.plans_invalidated) || !decoder.u32(out.plans_superseded) ||
      !decoder.u32(out.steps_staled)) {
    return false;
  }
  out.outcome = static_cast<Outcome>(outcome);
  out.epoch = CoordinatorEpoch::from_value(epoch);
  out.convergence_generation = ConvergenceGeneration::from_value(convergence);
  out.conditions = ConditionList(limits.max_explanation_entries);
  return decode_conditions(decoder, limits, out.conditions);
}

void encode_value(Encoder& encoder, const RouteChangeNotice& value) {
  encode_value(encoder, value.binding);
  encoder.fixed16(value.provenance.bytes());
}

bool decode_value(Decoder& decoder, RouteChangeNotice& out) {
  if (!decode_value(decoder, out.binding)) {
    return false;
  }
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.provenance = ProvenanceId::from_bytes(raw);
  return true;
}

void encode_value(Encoder& encoder, const PathChangeNotice& value) {
  encode_value(encoder, value.legality);
  encoder.fixed16(value.provenance.bytes());
}

bool decode_value(Decoder& decoder, PathChangeNotice& out) {
  if (!decode_value(decoder, out.legality)) {
    return false;
  }
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.provenance = ProvenanceId::from_bytes(raw);
  return true;
}

void encode_value(Encoder& encoder, const EpochChangeNotice& value) {
  encoder.u64(value.previous.value());
  encoder.u64(value.current.value());
  encoder.fixed16(value.provenance.bytes());
}

bool decode_value(Decoder& decoder, EpochChangeNotice& out) {
  std::uint64_t previous = 0;
  std::uint64_t current = 0;
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.u64(previous) || !decoder.u64(current) || !decoder.fixed16(raw)) {
    return false;
  }
  out.previous = CoordinatorEpoch::from_value(previous);
  out.current = CoordinatorEpoch::from_value(current);
  out.provenance = ProvenanceId::from_bytes(raw);
  return true;
}

// --- payload wrappers -------------------------------------------------------

#define RC_DEFINE_PAYLOAD(type)                                                            \
  std::vector<std::uint8_t> encode_payload(const type& value) {                            \
    Encoder encoder(kBlobBytes);                                                           \
    encode_value(encoder, value);                                                          \
    if (!encoder.ok()) {                                                                   \
      return {};                                                                           \
    }                                                                                      \
    return encoder.take();                                                                 \
  }                                                                                        \
  bool decode_payload(std::span<const std::uint8_t> bytes,                                 \
                      const ConvergenceLimits& limits, type& out) {                        \
    Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));              \
    if (!decode_value_any(decoder, limits, out) || decoder.failed()) {                     \
      return false;                                                                        \
    }                                                                                      \
    return decoder.at_end();                                                               \
  }

RC_DEFINE_PAYLOAD(PlanRequest)
RC_DEFINE_PAYLOAD(PlanMutationResult)
RC_DEFINE_PAYLOAD(PublisherRegistration)
RC_DEFINE_PAYLOAD(CompletionEvidence)
RC_DEFINE_PAYLOAD(StepDispatch)
RC_DEFINE_PAYLOAD(ReadyStepList)
RC_DEFINE_PAYLOAD(ExplainRequest)
RC_DEFINE_PAYLOAD(ExplainResponse)
RC_DEFINE_PAYLOAD(ConvergencePolicy)
RC_DEFINE_PAYLOAD(NoticeResult)
RC_DEFINE_PAYLOAD(RouteChangeNotice)
RC_DEFINE_PAYLOAD(PathChangeNotice)
RC_DEFINE_PAYLOAD(EpochChangeNotice)

#undef RC_DEFINE_PAYLOAD

std::vector<std::uint8_t> encode_payload(const HelloResponseBody& value) {
  Encoder encoder(16384);
  encoder.u32(value.wire_version);
  encoder.u64(value.epoch.value());
  encoder.text(value.product);
  encoder.text(value.version);
  encoder.u64(value.convergence_generation.value());
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const ConvergenceLimits& limits,
                    HelloResponseBody& out) {
  Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));
  std::uint64_t epoch = 0;
  std::uint64_t convergence = 0;
  if (!decoder.u32(out.wire_version) || !decoder.u64(epoch) || !decoder.text(out.product, 64) ||
      !decoder.text(out.version, 32) || !decoder.u64(convergence)) {
    return false;
  }
  out.epoch = CoordinatorEpoch::from_value(epoch);
  out.convergence_generation = ConvergenceGeneration::from_value(convergence);
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const PlanList& value) {
  Encoder encoder(1u << 22);
  encoder.u32(static_cast<std::uint32_t>(value.plans.size()));
  for (const PlanSummary& summary : value.plans) {
    encode_summary(encoder, summary);
  }
  encoder.boolean(value.truncated);
  return encoder.ok() ? encoder.take() : std::vector<std::uint8_t>{};
}

bool decode_payload(std::span<const std::uint8_t> bytes, const ConvergenceLimits& limits,
                    PlanList& out) {
  Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));
  std::uint32_t count = 0;
  if (!decoder.u32(count) || count > limits.max_batch_size) {
    return false;
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    PlanSummary summary;
    if (!decode_summary(decoder, summary)) {
      return false;
    }
    out.plans.push_back(std::move(summary));
  }
  return decoder.boolean(out.truncated) && decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const PlanQueryBody& value) {
  Encoder encoder(8192);
  encoder.boolean(value.found);
  encode_summary(encoder, value.summary);
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const ConvergenceLimits& limits,
                    PlanQueryBody& out) {
  Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));
  if (!decoder.boolean(out.found) || !decode_summary(decoder, out.summary)) {
    return false;
  }
  (void)limits;
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const SnapshotBody& value) {
  Encoder encoder(1u << 22);
  encoder.boolean(value.found);
  encode_value(encoder, value.snapshot);
  return encoder.ok() ? encoder.take() : std::vector<std::uint8_t>{};
}

bool decode_payload(std::span<const std::uint8_t> bytes, const ConvergenceLimits& limits,
                    SnapshotBody& out) {
  Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));
  if (!decoder.boolean(out.found) || !decode_value(decoder, limits, out.snapshot)) {
    return false;
  }
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const DiffRequestBody& value) {
  Encoder encoder(256);
  encoder.fixed16(value.plan.bytes());
  encoder.u64(value.from.value());
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const ConvergenceLimits& limits,
                    DiffRequestBody& out) {
  Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));
  std::array<std::uint8_t, 16> plan{};
  std::uint64_t from = 0;
  if (!decoder.fixed16(plan) || !decoder.u64(from)) {
    return false;
  }
  out.plan = ConvergencePlanId::from_bytes(plan);
  out.from = ConvergencePlanGeneration::from_value(from);
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const DiffBody& value) {
  Encoder encoder(1u << 22);
  encoder.boolean(value.found);
  encode_value(encoder, value.diff);
  return encoder.ok() ? encoder.take() : std::vector<std::uint8_t>{};
}

bool decode_payload(std::span<const std::uint8_t> bytes, const ConvergenceLimits& limits,
                    DiffBody& out) {
  Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));
  if (!decoder.boolean(out.found) || !decode_value(decoder, limits, out.diff)) {
    return false;
  }
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const PolicyListBody& value) {
  Encoder encoder(1u << 22);
  encoder.u32(static_cast<std::uint32_t>(value.policies.size()));
  for (const ConvergencePolicy& policy : value.policies) {
    encode_policy(encoder, policy);
  }
  return encoder.ok() ? encoder.take() : std::vector<std::uint8_t>{};
}

bool decode_payload(std::span<const std::uint8_t> bytes, const ConvergenceLimits& limits,
                    PolicyListBody& out) {
  Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));
  std::uint32_t count = 0;
  if (!decoder.u32(count) || count > 4096) {
    return false;
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    ConvergencePolicy policy;
    if (!decode_policy(decoder, policy)) {
      return false;
    }
    out.policies.push_back(std::move(policy));
  }
  (void)limits;
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const FailStepRequest& value) {
  Encoder encoder(1024);
  encoder.fixed16(value.plan.bytes());
  encoder.fixed16(value.step.bytes());
  encoder.u64(value.step_generation.value());
  encoder.u32(static_cast<std::uint32_t>(value.outcome));
  encoder.text(value.detail);
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const ConvergenceLimits& limits,
                    FailStepRequest& out) {
  Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));
  std::array<std::uint8_t, 16> plan{};
  std::array<std::uint8_t, 16> step{};
  std::uint64_t generation = 0;
  std::uint32_t outcome = 0;
  if (!decoder.fixed16(plan) || !decoder.fixed16(step) || !decoder.u64(generation) ||
      !decoder.u32(outcome) || outcome == 0 || outcome > 7 || !decoder.text(out.detail, 256)) {
    return false;
  }
  out.plan = ConvergencePlanId::from_bytes(plan);
  out.step = TransitionStepId::from_bytes(step);
  out.step_generation = TransitionStepGeneration::from_value(generation);
  out.outcome = static_cast<BackendOutcome>(outcome);
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const ReconcileStepRequest& value) {
  Encoder encoder(1024);
  encoder.fixed16(value.plan.bytes());
  encoder.fixed16(value.step.bytes());
  encoder.boolean(value.applied);
  encoder.text(value.detail);
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const ConvergenceLimits& limits,
                    ReconcileStepRequest& out) {
  Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));
  std::array<std::uint8_t, 16> plan{};
  std::array<std::uint8_t, 16> step{};
  if (!decoder.fixed16(plan) || !decoder.fixed16(step) || !decoder.boolean(out.applied) ||
      !decoder.text(out.detail, 256)) {
    return false;
  }
  out.plan = ConvergencePlanId::from_bytes(plan);
  out.step = TransitionStepId::from_bytes(step);
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const PausePlanRequest& value) {
  Encoder encoder(256);
  encoder.fixed16(value.plan.bytes());
  encoder.u32(static_cast<std::uint32_t>(value.cause));
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const ConvergenceLimits& limits,
                    PausePlanRequest& out) {
  Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));
  std::array<std::uint8_t, 16> plan{};
  std::uint32_t cause = 0;
  if (!decoder.fixed16(plan) || !decoder.u32(cause) || cause > 92) {
    return false;
  }
  out.plan = ConvergencePlanId::from_bytes(plan);
  out.cause = static_cast<ConditionCode>(cause);
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const StepReadyRequest& value) {
  Encoder encoder(64);
  encoder.u32(value.max_steps);
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const ConvergenceLimits& limits,
                    StepReadyRequest& out) {
  Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));
  if (!decoder.u32(out.max_steps)) {
    return false;
  }
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const DispatchStepRequest& value) {
  Encoder encoder(128);
  encoder.fixed16(value.plan.bytes());
  encoder.fixed16(value.step.bytes());
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const ConvergenceLimits& limits,
                    DispatchStepRequest& out) {
  Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));
  std::array<std::uint8_t, 16> plan{};
  std::array<std::uint8_t, 16> step{};
  if (!decoder.fixed16(plan) || !decoder.fixed16(step)) {
    return false;
  }
  out.plan = ConvergencePlanId::from_bytes(plan);
  out.step = TransitionStepId::from_bytes(step);
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const ErrorBody& value) {
  Encoder encoder(1024);
  encoder.u32(static_cast<std::uint32_t>(value.code));
  encoder.u32(static_cast<std::uint32_t>(value.outcome));
  encoder.text(value.detail);
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const ConvergenceLimits& limits,
                    ErrorBody& out) {
  Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));
  std::uint32_t code = 0;
  std::uint32_t outcome = 0;
  if (!decoder.u32(code) || code > 92 || !decoder.u32(outcome) || outcome > 64 ||
      !decoder.text(out.detail, 256)) {
    return false;
  }
  out.code = static_cast<ConditionCode>(code);
  out.outcome = static_cast<Outcome>(outcome);
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const ConvergencePlanId& value) {
  Encoder encoder(64);
  encoder.fixed16(value.bytes());
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const ConvergenceLimits& limits,
                    ConvergencePlanId& out) {
  Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out = ConvergencePlanId::from_bytes(raw);
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const ConvergencePolicyId& value) {
  Encoder encoder(64);
  encoder.fixed16(value.bytes());
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const ConvergenceLimits& limits,
                    ConvergencePolicyId& out) {
  Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out = ConvergencePolicyId::from_bytes(raw);
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const WorkerBootId& value) {
  Encoder encoder(64);
  encoder.fixed16(value.bytes());
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const ConvergenceLimits& limits,
                    WorkerBootId& out) {
  Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out = WorkerBootId::from_bytes(raw);
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const TransitionStepId& value) {
  Encoder encoder(64);
  encoder.fixed16(value.bytes());
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const ConvergenceLimits& limits,
                    TransitionStepId& out) {
  Decoder decoder(bytes, static_cast<std::size_t>(limits.max_frame_bytes));
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out = TransitionStepId::from_bytes(raw);
  return decoder.at_end();
}

}  // namespace rc
