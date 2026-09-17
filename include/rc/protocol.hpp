#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rc/authority.hpp"
#include "rc/backend.hpp"
#include "rc/bytes.hpp"
#include "rc/convergence.hpp"
#include "rc/limits.hpp"
#include "rc/plan.hpp"
#include "rc/version.hpp"

namespace rc {

// Stable explicit wire message identifiers.  Numeric values are part of the
// protocol contract: they are never renumbered and never derived from a C++
// enum ordinal.
enum class WireMessageId : std::uint16_t {
  HELLO = 0x0001,
  HELLO_RESPONSE = 0x0002,
  REGISTER_WORKER = 0x0010,
  REGISTER_WORKER_RESPONSE = 0x0011,
  CREATE_PLAN = 0x0020,
  CREATE_PLAN_RESPONSE = 0x0021,
  QUERY_PLAN = 0x0022,
  QUERY_PLAN_RESPONSE = 0x0023,
  LIST_PLANS = 0x0024,
  LIST_PLANS_RESPONSE = 0x0025,
  STEP_READY = 0x0026,
  STEP_READY_RESPONSE = 0x0027,
  DISPATCH_STEP = 0x0028,
  DISPATCH_STEP_RESPONSE = 0x0029,
  COMPLETE_STEP = 0x002A,
  COMPLETE_STEP_RESPONSE = 0x002B,
  FAIL_STEP = 0x002C,
  FAIL_STEP_RESPONSE = 0x002D,
  RECONCILE_STEP = 0x002E,
  RECONCILE_STEP_RESPONSE = 0x002F,
  REVALIDATE_PLAN = 0x0030,
  REVALIDATE_PLAN_RESPONSE = 0x0031,
  BEGIN_ROLLBACK = 0x0032,
  BEGIN_ROLLBACK_RESPONSE = 0x0033,
  RETIRE_PLAN = 0x0034,
  RETIRE_PLAN_RESPONSE = 0x0035,
  REVOKE_PLAN = 0x0036,
  REVOKE_PLAN_RESPONSE = 0x0037,
  PAUSE_PLAN = 0x0038,
  PAUSE_PLAN_RESPONSE = 0x0039,
  SNAPSHOT_REQUEST = 0x003A,
  SNAPSHOT_RESPONSE = 0x003B,
  DIFF_REQUEST = 0x003C,
  DIFF_RESPONSE = 0x003D,
  EXPLAIN_REQUEST = 0x003E,
  EXPLAIN_RESPONSE = 0x003F,
  DEFINE_POLICY = 0x0040,
  DEFINE_POLICY_RESPONSE = 0x0041,
  LIST_POLICIES = 0x0042,
  LIST_POLICIES_RESPONSE = 0x0043,
  FENCE_WORKER = 0x0044,
  FENCE_WORKER_RESPONSE = 0x0045,
  FENCE_NOTICE = 0x0046,
  ROUTE_CHANGE = 0x0050,
  ROUTE_CHANGE_RESPONSE = 0x0051,
  PATH_CHANGE = 0x0052,
  PATH_CHANGE_RESPONSE = 0x0053,
  EPOCH_CHANGE = 0x0054,
  EPOCH_CHANGE_RESPONSE = 0x0055,
  RESULT = 0x0060,
  ERROR = 0x0061,
};

[[nodiscard]] std::string_view to_string(WireMessageId id) noexcept;
[[nodiscard]] bool is_known_message(std::uint16_t raw) noexcept;
[[nodiscard]] bool is_response(WireMessageId id) noexcept;

// Complete frame header.  Every field is encoded explicitly, byte by byte; no
// C++ object layout is ever put on the wire.
//
//   magic[4]          'R','C','F','1'
//   wire_version u16
//   message u16
//   flags u32         must be 0
//   sequence u64
//   epoch u64
//   publisher[16]
//   worker_boot[16]
//   attempt[16]
//   payload_bytes u32
//   reserved u32      must be 0
//   payload[payload_bytes]
//   tag[32]           SHA-256 over header || payload
inline constexpr std::size_t kWireHeaderBytes = 84;
inline constexpr std::size_t kWireTagBytes = 32;
inline constexpr std::size_t kWireOverheadBytes = kWireHeaderBytes + kWireTagBytes;

struct Envelope {
  WireMessageId message = WireMessageId::ERROR;
  std::uint64_t sequence = 0;
  CoordinatorEpoch epoch;
  PublisherId publisher;
  WorkerBootId worker_boot;
  MutationAttemptId attempt;
  std::vector<std::uint8_t> payload;
};

enum class WireDefect : std::uint32_t {
  NONE = 0,
  TRUNCATED = 1,
  TRAILING_BYTES = 2,
  UNKNOWN_MESSAGE = 3,
  VERSION_MISMATCH = 4,
  INTEGRITY_FAILURE = 5,
  FRAME_TOO_LARGE = 6,
  MALFORMED_PAYLOAD = 7,
  BAD_MAGIC = 8,
  RESERVED_NOT_ZERO = 9,
  PEER_TIMEOUT = 10,
  PEER_CLOSED = 11,
};

[[nodiscard]] std::string_view to_string(WireDefect defect) noexcept;
[[nodiscard]] ConditionCode condition_for(WireDefect defect) noexcept;

// Complete frame codec.  decode_frame consumes exactly one frame and rejects
// trailing bytes, unknown message ids, a wrong wire version, a non-zero reserved
// field, an over-long payload and any integrity mismatch.
[[nodiscard]] std::vector<std::uint8_t> encode_frame(const Envelope& envelope,
                                                     const ConvergenceLimits& limits);
[[nodiscard]] WireDefect decode_frame(std::span<const std::uint8_t> bytes,
                                      const ConvergenceLimits& limits, Envelope& out);

// --- shared value codecs ----------------------------------------------------
void encode_value(Encoder& encoder, const RouteBinding& value);
[[nodiscard]] bool decode_value(Decoder& decoder, RouteBinding& out);
void encode_value(Encoder& encoder, const PathLegality& value);
[[nodiscard]] bool decode_value(Decoder& decoder, PathLegality& out);
void encode_value(Encoder& encoder, const StepKey& value);
[[nodiscard]] bool decode_value(Decoder& decoder, StepKey& out);
void encode_value(Encoder& encoder, const StepSpec& value);
[[nodiscard]] bool decode_value(Decoder& decoder, const ConvergenceLimits& limits, StepSpec& out);
void encode_value(Encoder& encoder, const ConvergencePolicy& value);
[[nodiscard]] bool decode_value(Decoder& decoder, ConvergencePolicy& out);
void encode_value(Encoder& encoder, const PlanKey& value);
[[nodiscard]] bool decode_value(Decoder& decoder, PlanKey& out);
void encode_value(Encoder& encoder, const PlanChange& value);
[[nodiscard]] bool decode_value(Decoder& decoder, PlanChange& out);
void encode_value(Encoder& encoder, const Condition& value);
[[nodiscard]] bool decode_value(Decoder& decoder, Condition& out);
void encode_value(Encoder& encoder, const ConditionList& value);
[[nodiscard]] bool decode_value(Decoder& decoder, const ConvergenceLimits& limits,
                                ConditionList& out);
void encode_value(Encoder& encoder, const AuthorityScope& value);
[[nodiscard]] bool decode_value(Decoder& decoder, AuthorityScope& out);
void encode_value(Encoder& encoder, const PublisherRegistration& value);
[[nodiscard]] bool decode_value(Decoder& decoder, PublisherRegistration& out);
void encode_value(Encoder& encoder, const PlanRequest& value);
[[nodiscard]] bool decode_value(Decoder& decoder, const ConvergenceLimits& limits, PlanRequest& out);
void encode_value(Encoder& encoder, const PlanMutationResult& value);
[[nodiscard]] bool decode_value(Decoder& decoder, const ConvergenceLimits& limits,
                                PlanMutationResult& out);
void encode_value(Encoder& encoder, const PlanSummary& value);
[[nodiscard]] bool decode_value(Decoder& decoder, PlanSummary& out);
void encode_value(Encoder& encoder, const StepSnapshot& value);
[[nodiscard]] bool decode_value(Decoder& decoder, const ConvergenceLimits& limits,
                                StepSnapshot& out);
void encode_value(Encoder& encoder, const ConvergenceSnapshot& value);
[[nodiscard]] bool decode_value(Decoder& decoder, const ConvergenceLimits& limits,
                                ConvergenceSnapshot& out);
void encode_value(Encoder& encoder, const DiffEntry& value);
[[nodiscard]] bool decode_value(Decoder& decoder, DiffEntry& out);
void encode_value(Encoder& encoder, const ConvergenceDiff& value);
[[nodiscard]] bool decode_value(Decoder& decoder, const ConvergenceLimits& limits,
                                ConvergenceDiff& out);
void encode_value(Encoder& encoder, const ExplainRequest& value);
[[nodiscard]] bool decode_value(Decoder& decoder, ExplainRequest& out);
void encode_value(Encoder& encoder, const ExplainResponse& value);
[[nodiscard]] bool decode_value(Decoder& decoder, const ConvergenceLimits& limits,
                                ExplainResponse& out);
void encode_value(Encoder& encoder, const CompletionEvidence& value);
[[nodiscard]] bool decode_value(Decoder& decoder, const ConvergenceLimits& limits,
                                CompletionEvidence& out);
void encode_value(Encoder& encoder, const StepDispatch& value);
[[nodiscard]] bool decode_value(Decoder& decoder, const ConvergenceLimits& limits, StepDispatch& out);
void encode_value(Encoder& encoder, const ReadyStep& value);
[[nodiscard]] bool decode_value(Decoder& decoder, const ConvergenceLimits& limits, ReadyStep& out);
void encode_value(Encoder& encoder, const ReadyStepList& value);
[[nodiscard]] bool decode_value(Decoder& decoder, const ConvergenceLimits& limits,
                                ReadyStepList& out);
void encode_value(Encoder& encoder, const NoticeResult& value);
[[nodiscard]] bool decode_value(Decoder& decoder, const ConvergenceLimits& limits, NoticeResult& out);
void encode_value(Encoder& encoder, const RouteChangeNotice& value);
[[nodiscard]] bool decode_value(Decoder& decoder, RouteChangeNotice& out);
void encode_value(Encoder& encoder, const PathChangeNotice& value);
[[nodiscard]] bool decode_value(Decoder& decoder, PathChangeNotice& out);
void encode_value(Encoder& encoder, const EpochChangeNotice& value);
[[nodiscard]] bool decode_value(Decoder& decoder, EpochChangeNotice& out);

// --- payload wrappers -------------------------------------------------------
// Each request payload carries only the semantic fields; the authority context
// travels in the envelope.  Every decoder rejects trailing bytes and every
// out-of-range enum value.

struct HelloResponseBody {
  std::uint32_t wire_version = 0;
  CoordinatorEpoch epoch;
  std::string product;
  std::string version;
  ConvergenceGeneration convergence_generation;
};

struct PlanQueryBody {
  bool found = false;
  PlanSummary summary;
};

struct SnapshotBody {
  bool found = false;
  ConvergenceSnapshot snapshot;
};

struct DiffRequestBody {
  ConvergencePlanId plan;
  ConvergencePlanGeneration from;
};

struct DiffBody {
  bool found = false;
  ConvergenceDiff diff;
};

struct PolicyListBody {
  std::vector<ConvergencePolicy> policies;
};

struct FailStepRequest {
  ConvergencePlanId plan;
  TransitionStepId step;
  TransitionStepGeneration step_generation;
  BackendOutcome outcome = BackendOutcome::PERMANENT_FAILURE;
  std::string detail;
};

struct ReconcileStepRequest {
  ConvergencePlanId plan;
  TransitionStepId step;
  bool applied = false;
  std::string detail;
};

struct PausePlanRequest {
  ConvergencePlanId plan;
  ConditionCode cause = ConditionCode::REVALIDATION_REQUIRED;
};

struct StepReadyRequest {
  std::uint32_t max_steps = 16;
};

struct DispatchStepRequest {
  ConvergencePlanId plan;
  TransitionStepId step;
};

struct ErrorBody {
  ConditionCode code = ConditionCode::NONE;
  Outcome outcome = Outcome::INTERNAL_ERROR;
  std::string detail;
};

#define RC_DECLARE_PAYLOAD_CODEC(type)                                              \
  [[nodiscard]] std::vector<std::uint8_t> encode_payload(const type& value);        \
  [[nodiscard]] bool decode_payload(std::span<const std::uint8_t> bytes,            \
                                    const ConvergenceLimits& limits, type& out)

RC_DECLARE_PAYLOAD_CODEC(PlanRequest);
RC_DECLARE_PAYLOAD_CODEC(PlanMutationResult);
RC_DECLARE_PAYLOAD_CODEC(PublisherRegistration);
RC_DECLARE_PAYLOAD_CODEC(CompletionEvidence);
RC_DECLARE_PAYLOAD_CODEC(StepDispatch);
RC_DECLARE_PAYLOAD_CODEC(ReadyStepList);
RC_DECLARE_PAYLOAD_CODEC(HelloResponseBody);
RC_DECLARE_PAYLOAD_CODEC(PlanList);
RC_DECLARE_PAYLOAD_CODEC(PlanQueryBody);
RC_DECLARE_PAYLOAD_CODEC(SnapshotBody);
RC_DECLARE_PAYLOAD_CODEC(DiffRequestBody);
RC_DECLARE_PAYLOAD_CODEC(DiffBody);
RC_DECLARE_PAYLOAD_CODEC(ExplainRequest);
RC_DECLARE_PAYLOAD_CODEC(ExplainResponse);
RC_DECLARE_PAYLOAD_CODEC(PolicyListBody);
RC_DECLARE_PAYLOAD_CODEC(ConvergencePolicy);
RC_DECLARE_PAYLOAD_CODEC(FailStepRequest);
RC_DECLARE_PAYLOAD_CODEC(ReconcileStepRequest);
RC_DECLARE_PAYLOAD_CODEC(PausePlanRequest);
RC_DECLARE_PAYLOAD_CODEC(StepReadyRequest);
RC_DECLARE_PAYLOAD_CODEC(DispatchStepRequest);
RC_DECLARE_PAYLOAD_CODEC(ErrorBody);
RC_DECLARE_PAYLOAD_CODEC(NoticeResult);
RC_DECLARE_PAYLOAD_CODEC(RouteChangeNotice);
RC_DECLARE_PAYLOAD_CODEC(PathChangeNotice);
RC_DECLARE_PAYLOAD_CODEC(EpochChangeNotice);
RC_DECLARE_PAYLOAD_CODEC(ConvergencePlanId);
RC_DECLARE_PAYLOAD_CODEC(ConvergencePolicyId);
RC_DECLARE_PAYLOAD_CODEC(WorkerBootId);
RC_DECLARE_PAYLOAD_CODEC(TransitionStepId);

#undef RC_DECLARE_PAYLOAD_CODEC

}  // namespace rc
