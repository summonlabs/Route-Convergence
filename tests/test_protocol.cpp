// Wire-protocol proofs for Route Convergence.
//
// Every frame defect, every payload codec and every rejection path is exercised
// through the public <rc/protocol.hpp> API only.  Real plans, real dispatches
// and real snapshots come from a Fixture governor; nothing here is synthesised
// by re-implementing an encoder.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "fixture.hpp"
#include "test_framework.hpp"

using namespace rc;  // NOLINT(google-build-using-namespace): a test translation unit.

namespace {

using Bytes = std::vector<std::uint8_t>;

constexpr std::size_t kFrameMagicBytes = 4;
constexpr std::size_t kFrameVersionOffset = kFrameMagicBytes;
constexpr std::size_t kFrameMessageOffset = kFrameVersionOffset + 2;
constexpr std::size_t kFrameFlagsOffset = kFrameMessageOffset + 2;
constexpr std::size_t kFrameSequenceOffset = kFrameFlagsOffset + 4;
constexpr std::size_t kFrameEpochOffset = kFrameSequenceOffset + 8;
constexpr std::size_t kFramePublisherOffset = kFrameEpochOffset + 8;
constexpr std::size_t kFrameBootOffset = kFramePublisherOffset + 16;
constexpr std::size_t kFrameAttemptOffset = kFrameBootOffset + 16;
constexpr std::size_t kFramePayloadBytesOffset = kFrameAttemptOffset + 16;
constexpr std::size_t kFrameReservedOffset = kFramePayloadBytesOffset + 4;

void put_u16_le(Bytes& bytes, std::size_t offset, std::uint16_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
  bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
}

void put_u32_le(Bytes& bytes, std::size_t offset, std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    bytes[offset + index] = static_cast<std::uint8_t>((value >> (8u * index)) & 0xFFu);
  }
}

[[nodiscard]] std::uint16_t get_u16_le(const Bytes& bytes, std::size_t offset) {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset]) |
                                    static_cast<std::uint16_t>(
                                        static_cast<std::uint16_t>(bytes[offset + 1]) << 8));
}

[[nodiscard]] std::uint32_t get_u32_le(const Bytes& bytes, std::size_t offset) {
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(bytes[offset + index]) << (8u * index);
  }
  return value;
}

// The defect a single flipped frame bit must produce, derived from the
// documented frame layout and the documented order in which fields are checked.
[[nodiscard]] WireDefect expected_frame_defect_for_flip(const Bytes& frame, std::size_t offset,
                                                        const ConvergenceLimits& limits) {
  if (offset < kFrameVersionOffset) {
    return WireDefect::BAD_MAGIC;
  }
  if (offset < kFrameMessageOffset) {
    return WireDefect::VERSION_MISMATCH;
  }
  if (offset < kFrameFlagsOffset) {
    return is_known_message(get_u16_le(frame, kFrameMessageOffset)) ? WireDefect::INTEGRITY_FAILURE
                                                                   : WireDefect::UNKNOWN_MESSAGE;
  }
  if (offset < kFrameSequenceOffset) {
    return WireDefect::RESERVED_NOT_ZERO;
  }
  if (offset < kFramePayloadBytesOffset) {
    return WireDefect::INTEGRITY_FAILURE;
  }
  if (offset < kFrameReservedOffset) {
    const std::uint32_t declared = get_u32_le(frame, kFramePayloadBytesOffset);
    if (declared > limits.max_frame_bytes) {
      return WireDefect::FRAME_TOO_LARGE;
    }
    const std::size_t expected = kWireHeaderBytes + declared + kWireTagBytes;
    if (frame.size() < expected) {
      return WireDefect::TRUNCATED;
    }
    if (frame.size() > expected) {
      return WireDefect::TRAILING_BYTES;
    }
    return WireDefect::INTEGRITY_FAILURE;
  }
  if (offset < kWireHeaderBytes) {
    return WireDefect::RESERVED_NOT_ZERO;
  }
  return WireDefect::INTEGRITY_FAILURE;
}

// --- payload codecs ---------------------------------------------------------

template <class T>
void check_round_trip(const T& value, const ConvergenceLimits& limits) {
  const Bytes bytes = encode_payload(value);
  RC_REQUIRE(!bytes.empty());
  T decoded{};
  RC_REQUIRE(decode_payload(bytes, limits, decoded));
  RC_CHECK(encode_payload(decoded) == bytes);
}

template <class T>
[[nodiscard]] bool decodes(const T& value, const ConvergenceLimits& limits) {
  const Bytes bytes = encode_payload(value);
  if (bytes.empty()) {
    return false;
  }
  T decoded{};
  return decode_payload(bytes, limits, decoded);
}

// The minimum every codec must reject: nothing at all, an all-zero blob, and a
// valid encoding with one byte appended.
template <class T>
void check_rejects_malformed(const T& value, const ConvergenceLimits& limits) {
  const Bytes bytes = encode_payload(value);
  RC_REQUIRE(!bytes.empty());
  T decoded{};
  const Bytes empty;
  RC_CHECK(!decode_payload(empty, limits, decoded));
  const Bytes zeros(64, 0u);
  RC_CHECK(!decode_payload(zeros, limits, decoded));
  Bytes trailing = bytes;
  trailing.push_back(0x00u);
  RC_CHECK(!decode_payload(trailing, limits, decoded));
}

// A valid encoding with its last byte removed names a field that is no longer
// complete, which every codec must reject.
template <class T>
[[nodiscard]] bool decodes_truncated(const T& value, const ConvergenceLimits& limits) {
  Bytes bytes = encode_payload(value);
  bytes.resize(bytes.size() - 1u);
  T decoded{};
  return decode_payload(bytes, limits, decoded);
}

// One real governor holding one real plan, plus one real dispatch of that plan.
struct PayloadCorpus {
  explicit PayloadCorpus(std::uint64_t seed) : fixture(seed) {
    RC_REQUIRE(fixture.define_policy(kPolicySeed).accepted());
    fixture.publish(target);
    const PlanMutationResult created = fixture.create(source, target, kPolicySeed, kAttempt, true);
    RC_REQUIRE(created.accepted());
    plan = created.plan;
    plan_result = created;

    plan_request.mode = PlanMode::GENERATED;
    plan_request.source = source;
    plan_request.target = target;
    plan_request.policy = policy_value;
    plan_request.epoch = fixture.governor().epoch();
    plan_request.provenance = rc::test::Fixture::provenance_for(kAttempt);
    plan_request.accept_historical_source = true;

    const std::optional<PlanSummary> summary = fixture.governor().query_plan(plan);
    RC_REQUIRE(summary.has_value());
    plan_query.found = true;
    plan_query.summary = *summary;
    plan_list = fixture.governor().list_plans();
    policy_list.policies = fixture.governor().list_policies();

    const std::optional<ConvergenceSnapshot> snapshot = fixture.governor().snapshot(plan);
    RC_REQUIRE(snapshot.has_value());
    snapshot_body.found = true;
    snapshot_body.snapshot = *snapshot;

    diff_request.plan = plan;
    diff_request.from = ConvergencePlanGeneration::from_value(0);
    const std::optional<ConvergenceDiff> diff = fixture.governor().diff(plan, diff_request.from);
    RC_REQUIRE(diff.has_value());
    diff_body.found = true;
    diff_body.diff = *diff;

    explain_request.plan = plan;
    explain_request.kind = ExplainKind::PLAN;
    explain_response = fixture.governor().explain(explain_request);
    notice = fixture.governor().sync_epoch();

    const ReadyStepList ready_steps = fixture.governor().ready_steps(fixture.governor().limits().max_parallel_steps);
    RC_REQUIRE(!ready_steps.steps.empty());
    ready = ready_steps;
    step = ready_steps.steps.front().step;
    plan_for_step = ready_steps.steps.front().plan;
    RC_CHECK(plan_for_step == plan);
    dispatch = fixture.governor().dispatch_step(plan, step, fixture.authority(kDispatchAttempt));
    RC_REQUIRE(dispatch.accepted());

    const std::optional<PublisherRegistration> registration_value = fixture.governor().worker_registration(fixture.publisher());
    RC_REQUIRE(registration_value.has_value());
    registration = *registration_value;

    evidence.plan = plan;
    evidence.step = step;
    evidence.step_generation = dispatch.step_generation;
    evidence.attempt = fixture.authority(kDispatchAttempt).attempt;
    evidence.epoch = dispatch.epoch;
    evidence.publisher = fixture.publisher();
    evidence.worker_boot = fixture.boot();
    evidence.outcome = BackendOutcome::APPLIED;
    evidence.dispatch_watermark = dispatch.watermark;
    evidence.applied_route_generation = dispatch.spec.route_generation;
    evidence.observed_path_authority_generation = dispatch.spec.path_authority_generation;
    evidence.detail = "applied by the protocol fixture";
    evidence.id = derive_evidence_id(evidence);

    fail_request.plan = plan;
    fail_request.step = step;
    fail_request.step_generation = dispatch.step_generation;
    fail_request.outcome = BackendOutcome::PERMANENT_FAILURE;
    fail_request.detail = "backend refused the transition";

    reconcile_request.plan = plan;
    reconcile_request.step = step;
    reconcile_request.applied = true;
    reconcile_request.detail = "observed applied after reconciliation";

    pause_request.plan = plan;
    pause_request.cause = ConditionCode::REVALIDATION_REQUIRED;

    ready_request.max_steps = fixture.governor().limits().max_parallel_steps;

    dispatch_request.plan = plan;
    dispatch_request.step = step;

    error_body.code = ConditionCode::STEP_NOT_READY;
    error_body.outcome = Outcome::PREREQUISITE_INCOMPLETE;
    error_body.detail = "the prerequisite step has not completed";

    route_notice.binding = target;
    route_notice.provenance = rc::test::Fixture::provenance_for(kAttempt + 1u);
    path_notice.legality.path = target.path;
    path_notice.legality.generation = target.path_authority_generation;
    path_notice.legality.legal = true;
    path_notice.provenance = rc::test::Fixture::provenance_for(kAttempt + 2u);
    epoch_notice.previous = fixture.governor().epoch();
    epoch_notice.current = CoordinatorEpoch::from_value(fixture.governor().epoch().value() + 1u);
    epoch_notice.provenance = rc::test::Fixture::provenance_for(kAttempt + 3u);

    hello.wire_version = kWireVersion;
    hello.epoch = fixture.governor().epoch();
    hello.product = std::string(kProductName);
    hello.version = std::string(kVersionString);
    hello.convergence_generation = fixture.governor().convergence_generation();
  }

  static constexpr std::uint64_t kPolicySeed = 7u;
  static constexpr std::uint64_t kAttempt = 23u;
  static constexpr std::uint64_t kDispatchAttempt = 29u;

  rc::test::Fixture fixture;
  RouteBinding source = rc::test::Fixture::binding(61u, 1u, 63u, 1u);
  RouteBinding target = rc::test::Fixture::binding(61u, 2u, 63u, 1u);
  ConvergencePolicy policy_value = rc::test::Fixture::policy(kPolicySeed);
  ConvergencePlanId plan;
  ConvergencePlanId plan_for_step;
  TransitionStepId step;
  ConvergencePolicyId policy_id = rc::test::Fixture::policy_for(kPolicySeed);
  WorkerBootId boot = rc::test::Fixture::boot_for(1u);
  PlanRequest plan_request;
  PlanMutationResult plan_result;
  PublisherRegistration registration;
  CompletionEvidence evidence;
  StepDispatch dispatch;
  ReadyStepList ready;
  PlanList plan_list;
  PlanQueryBody plan_query;
  SnapshotBody snapshot_body;
  DiffRequestBody diff_request;
  DiffBody diff_body;
  ExplainRequest explain_request;
  ExplainResponse explain_response;
  PolicyListBody policy_list;
  FailStepRequest fail_request;
  ReconcileStepRequest reconcile_request;
  PausePlanRequest pause_request;
  StepReadyRequest ready_request;
  DispatchStepRequest dispatch_request;
  ErrorBody error_body;
  NoticeResult notice;
  RouteChangeNotice route_notice;
  PathChangeNotice path_notice;
  EpochChangeNotice epoch_notice;
  HelloResponseBody hello;
};

[[nodiscard]] PayloadCorpus make_corpus() { return PayloadCorpus(31u); }

}  // namespace

// ---------------------------------------------------------------------------
// Every wire message identifier round-trips: header identity and payload are
// returned exactly as they were encoded.
// ---------------------------------------------------------------------------
RC_TEST(protocol_frame_round_trip_covers_every_known_message) {
  const ConvergenceLimits limits;
  rc::test::Fixture fixture(51u);
  const AuthorityContext authority = fixture.authority(7u);
  std::uint32_t known = 0;
  for (std::uint32_t raw = 0; raw <= 0xFFFFu; ++raw) {
    if (!is_known_message(static_cast<std::uint16_t>(raw))) {
      continue;
    }
    ++known;
    const WireMessageId id = static_cast<WireMessageId>(raw);
    RC_CHECK(to_string(id) != std::string_view("UNKNOWN"));
    Envelope envelope;
    envelope.message = id;
    envelope.sequence = 1000u + raw;
    envelope.epoch = authority.epoch;
    envelope.publisher = authority.publisher;
    envelope.worker_boot = authority.worker_boot;
    envelope.attempt = authority.attempt;
    envelope.payload = {static_cast<std::uint8_t>(raw & 0xFFu),
                        static_cast<std::uint8_t>((raw >> 8) & 0xFFu), 0x5Au};
    const Bytes frame = encode_frame(envelope, limits);
    RC_REQUIRE(!frame.empty());
    RC_CHECK_EQ(frame.size(), kWireOverheadBytes + envelope.payload.size());
    Envelope decoded;
    RC_CHECK_EQ(decode_frame(frame, limits, decoded), WireDefect::NONE);
    RC_CHECK_EQ(decoded.message, id);
    RC_CHECK_EQ(decoded.sequence, envelope.sequence);
    RC_CHECK_EQ(decoded.epoch, envelope.epoch);
    RC_CHECK_EQ(decoded.publisher, envelope.publisher);
    RC_CHECK_EQ(decoded.worker_boot, envelope.worker_boot);
    RC_CHECK_EQ(decoded.attempt, envelope.attempt);
    RC_CHECK(decoded.payload == envelope.payload);
  }
  RC_CHECK_EQ(known, 51u);
}

// ---------------------------------------------------------------------------
// Structural frame defects each have exactly one stable code, and an over-long
// payload is refused before a frame is even produced.
// ---------------------------------------------------------------------------
RC_TEST(protocol_frame_rejects_structural_defects) {
  const ConvergenceLimits limits;
  Envelope envelope;
  envelope.message = WireMessageId::SNAPSHOT_REQUEST;
  envelope.sequence = 42u;
  envelope.epoch = CoordinatorEpoch::from_value(9u);
  envelope.publisher = rc::test::Fixture::publisher_for(3u);
  envelope.worker_boot = rc::test::Fixture::boot_for(3u);
  envelope.attempt = rc::test::Fixture::attempt_for(4u);
  envelope.payload = {0x10u, 0x20u, 0x30u, 0x40u};
  const Bytes frame = encode_frame(envelope, limits);
  RC_REQUIRE(!frame.empty());
  Envelope decoded;

  const Bytes short_frame(frame.begin(), frame.end() - 1);
  RC_CHECK_EQ(decode_frame(short_frame, limits, decoded), WireDefect::TRUNCATED);

  Bytes extra = frame;
  extra.push_back(0x00u);
  RC_CHECK_EQ(decode_frame(extra, limits, decoded), WireDefect::TRAILING_BYTES);

  const Bytes tiny(frame.begin(), frame.begin() + 10);
  RC_CHECK_EQ(decode_frame(tiny, limits, decoded), WireDefect::TRUNCATED);

  Bytes bad_magic = frame;
  bad_magic[kFrameMagicBytes - 1] = static_cast<std::uint8_t>(bad_magic[kFrameMagicBytes - 1] ^ 0x01u);
  RC_CHECK_EQ(decode_frame(bad_magic, limits, decoded), WireDefect::BAD_MAGIC);

  Bytes bad_version = frame;
  put_u16_le(bad_version, kFrameVersionOffset, static_cast<std::uint16_t>(kWireVersion + 1u));
  RC_CHECK_EQ(decode_frame(bad_version, limits, decoded), WireDefect::VERSION_MISMATCH);

  Bytes zero_version = frame;
  put_u16_le(zero_version, kFrameVersionOffset, 0u);
  RC_CHECK_EQ(decode_frame(zero_version, limits, decoded), WireDefect::VERSION_MISMATCH);

  Bytes unknown_message = frame;
  put_u16_le(unknown_message, kFrameMessageOffset, 0xFFFFu);
  RC_CHECK_EQ(decode_frame(unknown_message, limits, decoded), WireDefect::UNKNOWN_MESSAGE);

  Bytes bad_flags = frame;
  put_u32_le(bad_flags, kFrameFlagsOffset, 1u);
  RC_CHECK_EQ(decode_frame(bad_flags, limits, decoded), WireDefect::RESERVED_NOT_ZERO);

  Bytes bad_reserved = frame;
  put_u32_le(bad_reserved, kFrameReservedOffset, 0x80000000u);
  RC_CHECK_EQ(decode_frame(bad_reserved, limits, decoded), WireDefect::RESERVED_NOT_ZERO);

  ConvergenceLimits small = limits;
  small.max_frame_bytes = kMinimumFrameBytes;
  Bytes over_declared = frame;
  put_u32_le(over_declared, kFramePayloadBytesOffset, kMinimumFrameBytes + 1u);
  RC_CHECK_EQ(decode_frame(over_declared, small, decoded), WireDefect::FRAME_TOO_LARGE);

  Envelope oversized = envelope;
  oversized.payload.assign(kMinimumFrameBytes + 1u, 0x11u);
  RC_CHECK(encode_frame(oversized, small).empty());
  const Bytes large_frame = encode_frame(oversized, limits);
  RC_REQUIRE(!large_frame.empty());
  RC_CHECK_EQ(decode_frame(large_frame, small, decoded), WireDefect::FRAME_TOO_LARGE);
  RC_CHECK_EQ(decode_frame(large_frame, limits, decoded), WireDefect::NONE);
}

// ---------------------------------------------------------------------------
// The integrity tag covers the whole frame: a flipped bit anywhere in the
// header, the payload or the tag is detected, and every semantic header field
// reports its own exact defect.
// ---------------------------------------------------------------------------
RC_TEST(protocol_frame_integrity_covers_every_byte) {
  const ConvergenceLimits limits;
  Envelope envelope;
  envelope.message = WireMessageId::COMPLETE_STEP;
  envelope.sequence = 7u;
  envelope.epoch = CoordinatorEpoch::from_value(5u);
  envelope.publisher = rc::test::Fixture::publisher_for(5u);
  envelope.worker_boot = rc::test::Fixture::boot_for(5u);
  envelope.attempt = rc::test::Fixture::attempt_for(6u);
  envelope.payload = {0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u};
  const Bytes frame = encode_frame(envelope, limits);
  RC_REQUIRE(!frame.empty());
  Envelope decoded;

  for (const std::size_t offset :
       {kFrameSequenceOffset, kFrameSequenceOffset + 7u, kFrameEpochOffset, kFramePublisherOffset,
        kFrameBootOffset, kFrameAttemptOffset, kWireHeaderBytes, frame.size() - 1u}) {
    Bytes tampered = frame;
    tampered[offset] = static_cast<std::uint8_t>(tampered[offset] ^ 0x01u);
    RC_CHECK_EQ(decode_frame(tampered, limits, decoded), WireDefect::INTEGRITY_FAILURE);
  }

  for (std::size_t offset = 0; offset < frame.size(); ++offset) {
    Bytes tampered = frame;
    tampered[offset] = static_cast<std::uint8_t>(tampered[offset] ^ 0x01u);
    RC_CHECK_EQ(decode_frame(tampered, limits, decoded),
                expected_frame_defect_for_flip(tampered, offset, limits));
  }

  // The message identifier and the declared payload length are the two header
  // fields whose flipped value can still be structurally plausible, so every
  // bit of both is checked against the documented rule order.
  for (std::size_t bit = 0; bit < 16u; ++bit) {
    Bytes tampered = frame;
    put_u16_le(tampered, kFrameMessageOffset,
               static_cast<std::uint16_t>(get_u16_le(frame, kFrameMessageOffset) ^ (1u << bit)));
    RC_CHECK_EQ(decode_frame(tampered, limits, decoded),
                expected_frame_defect_for_flip(tampered, kFrameMessageOffset, limits));
  }
  for (std::size_t bit = 0; bit < 32u; ++bit) {
    Bytes tampered = frame;
    put_u32_le(tampered, kFramePayloadBytesOffset,
               static_cast<std::uint32_t>(get_u32_le(frame, kFramePayloadBytesOffset) ^ (1u << bit)));
    RC_CHECK_EQ(decode_frame(tampered, limits, decoded),
                expected_frame_defect_for_flip(tampered, kFramePayloadBytesOffset, limits));
  }
}

// ---------------------------------------------------------------------------
// Every payload codec round-trips a real value and re-encodes to the same
// bytes.
// ---------------------------------------------------------------------------
RC_TEST(protocol_payload_codecs_round_trip) {
  const ConvergenceLimits limits;
  const PayloadCorpus corpus = make_corpus();

  check_round_trip(corpus.plan_request, limits);
  check_round_trip(corpus.plan_result, limits);
  check_round_trip(corpus.registration, limits);
  check_round_trip(corpus.evidence, limits);
  check_round_trip(corpus.dispatch, limits);
  check_round_trip(corpus.ready, limits);
  check_round_trip(corpus.plan_list, limits);
  check_round_trip(corpus.plan_query, limits);
  check_round_trip(corpus.snapshot_body, limits);
  check_round_trip(corpus.diff_request, limits);
  check_round_trip(corpus.diff_body, limits);
  check_round_trip(corpus.explain_request, limits);
  check_round_trip(corpus.explain_response, limits);
  check_round_trip(corpus.policy_list, limits);
  check_round_trip(corpus.policy_value, limits);
  check_round_trip(corpus.fail_request, limits);
  check_round_trip(corpus.reconcile_request, limits);
  check_round_trip(corpus.pause_request, limits);
  check_round_trip(corpus.ready_request, limits);
  check_round_trip(corpus.dispatch_request, limits);
  check_round_trip(corpus.error_body, limits);
  check_round_trip(corpus.notice, limits);
  check_round_trip(corpus.route_notice, limits);
  check_round_trip(corpus.path_notice, limits);
  check_round_trip(corpus.epoch_notice, limits);
  check_round_trip(corpus.plan, limits);
  check_round_trip(corpus.policy_id, limits);
  check_round_trip(corpus.boot, limits);
  check_round_trip(corpus.step, limits);
  check_round_trip(corpus.hello, limits);

  // The decoded values carry the semantics of the real governor objects.
  PlanRequest request_out;
  RC_REQUIRE(decode_payload(encode_payload(corpus.plan_request), limits, request_out));
  RC_CHECK_EQ(request_out.mode, corpus.plan_request.mode);
  RC_CHECK(request_out.source == corpus.plan_request.source);
  RC_CHECK(request_out.target == corpus.plan_request.target);
  RC_CHECK(request_out.policy == corpus.plan_request.policy);
  RC_CHECK_EQ(request_out.epoch, corpus.plan_request.epoch);
  RC_CHECK_EQ(request_out.provenance, corpus.plan_request.provenance);
  RC_CHECK_EQ(request_out.accept_historical_source, corpus.plan_request.accept_historical_source);

  PlanMutationResult result_out;
  RC_REQUIRE(decode_payload(encode_payload(corpus.plan_result), limits, result_out));
  RC_CHECK_EQ(result_out.outcome, corpus.plan_result.outcome);
  RC_CHECK_EQ(result_out.plan, corpus.plan_result.plan);
  RC_CHECK_EQ(result_out.digest, corpus.plan_result.digest);
  RC_CHECK_EQ(result_out.plan_generation, corpus.plan_result.plan_generation);

  StepDispatch dispatch_out;
  RC_REQUIRE(decode_payload(encode_payload(corpus.dispatch), limits, dispatch_out));
  RC_CHECK_EQ(dispatch_out.outcome, Outcome::STEP_DISPATCHED);
  RC_CHECK_EQ(dispatch_out.plan, corpus.dispatch.plan);
  RC_CHECK_EQ(dispatch_out.step, corpus.dispatch.step);
  RC_CHECK_EQ(dispatch_out.step_generation, corpus.dispatch.step_generation);
  RC_CHECK_EQ(dispatch_out.watermark, corpus.dispatch.watermark);
  RC_CHECK_EQ(dispatch_out.epoch, corpus.dispatch.epoch);
  RC_CHECK(dispatch_out.spec.key() == corpus.dispatch.spec.key());

  SnapshotBody snapshot_out;
  RC_REQUIRE(decode_payload(encode_payload(corpus.snapshot_body), limits, snapshot_out));
  RC_CHECK(snapshot_out.found);
  RC_CHECK_EQ(snapshot_out.snapshot.plan, corpus.plan);
  RC_CHECK_EQ(snapshot_out.snapshot.steps.size(), corpus.snapshot_body.snapshot.steps.size());
  RC_CHECK_EQ(ConvergenceGovernor::snapshot_digest(snapshot_out.snapshot),
              ConvergenceGovernor::snapshot_digest(corpus.snapshot_body.snapshot));

  ConvergencePlanId plan_out;
  RC_REQUIRE(decode_payload(encode_payload(corpus.plan), limits, plan_out));
  RC_CHECK_EQ(plan_out, corpus.plan);
  WorkerBootId boot_out;
  RC_REQUIRE(decode_payload(encode_payload(corpus.boot), limits, boot_out));
  RC_CHECK_EQ(boot_out, corpus.boot);
  ConvergencePolicyId policy_out;
  RC_REQUIRE(decode_payload(encode_payload(corpus.policy_id), limits, policy_out));
  RC_CHECK_EQ(policy_out, corpus.policy_id);
  TransitionStepId step_out;
  RC_REQUIRE(decode_payload(encode_payload(corpus.step), limits, step_out));
  RC_CHECK_EQ(step_out, corpus.step);
}

// ---------------------------------------------------------------------------
// Every codec rejects an empty payload, an all-zero payload, trailing bytes and
// an out-of-range enumeration where it carries one.
// ---------------------------------------------------------------------------
RC_TEST(protocol_payload_decoders_reject_malformed_input) {
  const ConvergenceLimits limits;
  const PayloadCorpus corpus = make_corpus();

  check_rejects_malformed(corpus.plan_request, limits);
  check_rejects_malformed(corpus.plan_result, limits);
  check_rejects_malformed(corpus.registration, limits);
  check_rejects_malformed(corpus.evidence, limits);
  check_rejects_malformed(corpus.dispatch, limits);
  check_rejects_malformed(corpus.ready, limits);
  check_rejects_malformed(corpus.plan_list, limits);
  check_rejects_malformed(corpus.plan_query, limits);
  check_rejects_malformed(corpus.snapshot_body, limits);
  check_rejects_malformed(corpus.diff_request, limits);
  check_rejects_malformed(corpus.diff_body, limits);
  check_rejects_malformed(corpus.explain_request, limits);
  check_rejects_malformed(corpus.explain_response, limits);
  check_rejects_malformed(corpus.policy_list, limits);
  check_rejects_malformed(corpus.policy_value, limits);
  check_rejects_malformed(corpus.fail_request, limits);
  check_rejects_malformed(corpus.reconcile_request, limits);
  check_rejects_malformed(corpus.pause_request, limits);
  check_rejects_malformed(corpus.ready_request, limits);
  check_rejects_malformed(corpus.dispatch_request, limits);
  check_rejects_malformed(corpus.error_body, limits);
  check_rejects_malformed(corpus.notice, limits);
  check_rejects_malformed(corpus.route_notice, limits);
  check_rejects_malformed(corpus.path_notice, limits);
  check_rejects_malformed(corpus.epoch_notice, limits);
  check_rejects_malformed(corpus.plan, limits);
  check_rejects_malformed(corpus.policy_id, limits);
  check_rejects_malformed(corpus.boot, limits);
  check_rejects_malformed(corpus.step, limits);
  check_rejects_malformed(corpus.hello, limits);

  PlanRequest bad_mode = corpus.plan_request;
  bad_mode.mode = static_cast<PlanMode>(0);
  RC_CHECK(!decodes(bad_mode, limits));
  bad_mode.mode = static_cast<PlanMode>(77);
  RC_CHECK(!decodes(bad_mode, limits));

  PlanMutationResult bad_outcome = corpus.plan_result;
  bad_outcome.outcome = static_cast<Outcome>(0);
  RC_CHECK(!decodes(bad_outcome, limits));
  bad_outcome.outcome = static_cast<Outcome>(4096);
  RC_CHECK(!decodes(bad_outcome, limits));

  PublisherRegistration bad_scope = corpus.registration;
  bad_scope.scope.kind = static_cast<ScopeKind>(9);
  RC_CHECK(!decodes(bad_scope, limits));

  CompletionEvidence bad_evidence = corpus.evidence;
  bad_evidence.outcome = static_cast<BackendOutcome>(0);
  RC_CHECK(!decodes(bad_evidence, limits));
  bad_evidence.outcome = static_cast<BackendOutcome>(8);
  RC_CHECK(!decodes(bad_evidence, limits));

  StepDispatch bad_dispatch_outcome = corpus.dispatch;
  bad_dispatch_outcome.outcome = static_cast<Outcome>(0);
  RC_CHECK(!decodes(bad_dispatch_outcome, limits));
  StepDispatch bad_dispatch_spec = corpus.dispatch;
  bad_dispatch_spec.spec.kind = static_cast<StepKind>(0);
  RC_CHECK(!decodes(bad_dispatch_spec, limits));

  ReadyStepList bad_ready = corpus.ready;
  RC_REQUIRE(!bad_ready.steps.empty());
  bad_ready.steps.front().spec.reversibility = static_cast<Reversibility>(4);
  RC_CHECK(!decodes(bad_ready, limits));

  PlanList bad_list = corpus.plan_list;
  RC_REQUIRE(!bad_list.plans.empty());
  bad_list.plans.front().lifecycle = static_cast<PlanLifecycle>(0);
  RC_CHECK(!decodes(bad_list, limits));

  PlanQueryBody bad_query = corpus.plan_query;
  bad_query.summary.lifecycle = static_cast<PlanLifecycle>(kPlanLifecycleCount + 1u);
  RC_CHECK(!decodes(bad_query, limits));

  SnapshotBody bad_snapshot = corpus.snapshot_body;
  bad_snapshot.snapshot.mode = static_cast<PlanMode>(3);
  RC_CHECK(!decodes(bad_snapshot, limits));

  DiffBody bad_diff = corpus.diff_body;
  RC_REQUIRE(!bad_diff.diff.entries.empty());
  bad_diff.diff.entries.front().kind = static_cast<DiffKind>(0);
  RC_CHECK(!decodes(bad_diff, limits));

  ExplainRequest bad_explain = corpus.explain_request;
  bad_explain.kind = static_cast<ExplainKind>(kChangeReasonCount + 1u);
  RC_CHECK(!decodes(bad_explain, limits));

  ExplainResponse bad_explanation = corpus.explain_response;
  bad_explanation.explanation.add(
      make_condition(static_cast<ConditionCode>(4096), "out-of-range condition"));
  RC_CHECK(!decodes(bad_explanation, limits));

  PolicyListBody bad_policies = corpus.policy_list;
  RC_REQUIRE(!bad_policies.policies.empty());
  bad_policies.policies.front().ordering = static_cast<OrderingMode>(3);
  RC_CHECK(!decodes(bad_policies, limits));

  ConvergencePolicy bad_policy = corpus.policy_value;
  bad_policy.generation = ConvergencePolicyGeneration::from_value(0);
  RC_CHECK(!decodes(bad_policy, limits));
  bad_policy = corpus.policy_value;
  bad_policy.verification = static_cast<VerificationMode>(0);
  RC_CHECK(!decodes(bad_policy, limits));

  FailStepRequest bad_fail = corpus.fail_request;
  bad_fail.outcome = static_cast<BackendOutcome>(99);
  RC_CHECK(!decodes(bad_fail, limits));

  PausePlanRequest bad_pause = corpus.pause_request;
  bad_pause.cause = static_cast<ConditionCode>(93);
  RC_CHECK(!decodes(bad_pause, limits));

  ErrorBody bad_error = corpus.error_body;
  bad_error.code = static_cast<ConditionCode>(93);
  RC_CHECK(!decodes(bad_error, limits));
  bad_error = corpus.error_body;
  bad_error.outcome = static_cast<Outcome>(65);
  RC_CHECK(!decodes(bad_error, limits));

  NoticeResult bad_notice = corpus.notice;
  bad_notice.outcome = static_cast<Outcome>(0);
  RC_CHECK(!decodes(bad_notice, limits));

  // The codecs whose payload is a fixed blob or a plain record, and that carry
  // no enumeration, still reject a field that was cut short.
  RC_CHECK(!decodes_truncated(corpus.diff_request, limits));
  RC_CHECK(!decodes_truncated(corpus.reconcile_request, limits));
  RC_CHECK(!decodes_truncated(corpus.dispatch_request, limits));
  RC_CHECK(!decodes_truncated(corpus.route_notice, limits));
  RC_CHECK(!decodes_truncated(corpus.path_notice, limits));
  RC_CHECK(!decodes_truncated(corpus.epoch_notice, limits));
  RC_CHECK(!decodes_truncated(corpus.plan, limits));
  RC_CHECK(!decodes_truncated(corpus.boot, limits));
  RC_CHECK(!decodes_truncated(corpus.step, limits));
  RC_CHECK(!decodes_truncated(corpus.policy_id, limits));
  RC_CHECK(!decodes_truncated(corpus.ready_request, limits));
  RC_CHECK(!decodes_truncated(corpus.plan_request, limits));
}