#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace rc {

// Structured mutation outcome.  Numeric values are part of the wire contract and
// are never renumbered: new codes are appended.
enum class Outcome : std::uint32_t {
  PLAN_CREATED = 1,
  PLAN_UPDATED = 2,
  STEP_READY = 3,
  STEP_DISPATCHED = 4,
  STEP_COMPLETED = 5,
  STEP_FAILED = 6,
  STEP_RECONCILED = 7,
  PLAN_PAUSED = 8,
  PLAN_RESUMED = 9,
  PLAN_COMPLETED = 10,
  PLAN_REVALIDATION_REQUIRED = 11,
  PLAN_REVALIDATED = 12,
  ROLLBACK_PLAN_CREATED = 13,
  ROLLBACK_COMPLETED = 14,
  PLAN_SUPERSEDED = 15,
  PLAN_REVOKED = 16,
  PLAN_RETIRED = 17,
  WORKER_REGISTERED = 18,
  WORKER_FENCED = 19,
  POLICY_DEFINED = 20,
  IDEMPOTENT = 21,
  NO_CHANGE = 22,
  EPOCH_ADVANCED = 23,
  STALE_PLAN = 30,
  STALE_STEP = 31,
  STALE_ROUTE = 32,
  STALE_PATH_AUTHORITY = 33,
  STALE_ECMP = 34,
  STALE_WEIGHT_POLICY = 35,
  STALE_EPOCH = 36,
  STALE_WORKER = 37,
  STALE_POLICY = 38,
  STALE_DEPENDENCY = 39,
  PREREQUISITE_INCOMPLETE = 40,
  ROLLBACK_REQUIRED = 41,
  UNSAFE_ROLLBACK = 42,
  AMBIGUOUS_SIDE_EFFECT = 43,
  RETRYABLE_FAILURE = 44,
  PERMANENT_FAILURE = 45,
  SUPERSEDED = 46,
  REVALIDATION_REQUIRED = 47,
  UNAUTHORIZED = 48,
  RESOURCE_LIMIT = 49,
  RETIRED = 50,
  MALFORMED_REQUEST = 51,
  ATTEMPT_CONFLICT = 52,
  LIFECYCLE_VIOLATION = 53,
  DUPLICATE_PLAN = 54,
  UNKNOWN_PLAN = 55,
  UNKNOWN_STEP = 56,
  UNKNOWN_POLICY = 57,
  GRAPH_INVALID = 58,
  GENERATION_EXHAUSTED = 59,
  STORE_ERROR = 60,
  WIRE_REJECTED = 61,
  NO_READY_STEP = 62,
  UNSUPPORTED = 63,
  INTERNAL_ERROR = 64,
};

[[nodiscard]] std::string_view to_string(Outcome outcome) noexcept;

// True for outcomes that report an accepted, applied mutation (including the
// no-op acceptances NO_CHANGE and IDEMPOTENT).
[[nodiscard]] bool is_acceptance(Outcome outcome) noexcept;

// Structured condition code.  Every rejection and every explanation entry is
// expressed with one of these codes; product code never reports a defect as bare
// text.  Numeric values are stable.
enum class ConditionCode : std::uint32_t {
  NONE = 0,
  // authority and scope
  AUTHORITY_EPOCH_STALE = 1,
  WORKER_FENCED = 2,
  PUBLISHER_UNKNOWN = 3,
  SCOPE_DENIED = 4,
  CAPABILITY_MISSING = 5,
  // request identity
  MALFORMED_IDENTITY = 6,
  MALFORMED_PAYLOAD = 7,
  MALFORMED_SUBJECT = 8,
  ATTEMPT_REPLAY = 9,
  ATTEMPT_CONFLICT = 10,
  // plan identity and lifecycle
  PLAN_UNKNOWN = 11,
  PLAN_TERMINAL = 12,
  LIFECYCLE_DENIED = 13,
  PLAN_GENERATION_MISMATCH = 14,
  DUPLICATE_PLAN = 15,
  PLAN_SUPERSEDED = 16,
  PLAN_ALREADY_EXISTS = 17,
  // step identity and lifecycle
  STEP_UNKNOWN = 18,
  STEP_GENERATION_MISMATCH = 19,
  STEP_NOT_READY = 20,
  STEP_STALE = 21,
  STEP_TERMINAL = 22,
  // dependency graph
  DEPENDENCY_MISSING = 23,
  DEPENDENCY_DUPLICATE = 24,
  DEPENDENCY_CYCLE = 25,
  DEPENDENCY_SELF = 26,
  PREREQUISITE_INCOMPLETE = 27,
  CONFLICT_DOMAIN_OVERLAP = 28,
  // upstream currentness
  TARGET_ROUTE_STALE = 29,
  TARGET_ROUTE_UNKNOWN = 30,
  TARGET_ROUTE_ILLEGAL = 31,
  SOURCE_ROUTE_STALE = 32,
  SOURCE_ROUTE_UNKNOWN = 33,
  SOURCE_ROUTE_ILLEGAL = 34,
  PATH_AUTHORITY_STALE = 35,
  PATH_AUTHORITY_UNKNOWN = 36,
  PATH_AUTHORITY_UNAUTHORIZED = 37,
  MULTIPATH_SET_STALE = 38,
  ECMP_GENERATION_STALE = 39,
  ASSIGNMENT_GENERATION_STALE = 40,
  WEIGHT_POLICY_STALE = 41,
  POLICY_UNKNOWN = 42,
  POLICY_GENERATION_STALE = 43,
  POLICY_INCOHERENT = 44,
  BREAK_BEFORE_MAKE_NOT_PERMITTED = 45,
  // evidence and watermarks
  COMPLETION_STALE = 46,
  WATERMARK_EXCEEDED = 47,
  EVIDENCE_MISSING = 48,
  EVIDENCE_GENERATION_MISMATCH = 49,
  AMBIGUOUS_SIDE_EFFECT = 50,
  RECONCILIATION_REQUIRED = 51,
  // rollback
  ROLLBACK_TARGET_UNAUTHORIZED = 52,
  ROLLBACK_NOT_ELIGIBLE = 53,
  ROLLBACK_IRREVERSIBLE = 54,
  UNSAFE_ROLLBACK = 55,
  // resource limits
  PLAN_LIMIT = 56,
  STEP_LIMIT = 57,
  DEPENDENCY_LIMIT = 58,
  TOTAL_DEPENDENCY_LIMIT = 59,
  PARALLELISM_LIMIT = 60,
  HISTORY_LIMIT = 61,
  RETRY_LIMIT = 62,
  FRAME_LIMIT = 63,
  BATCH_LIMIT = 64,
  WORKER_LIMIT = 65,
  SESSION_LIMIT = 66,
  STORE_RECORD_LIMIT = 67,
  EXPLANATION_LIMIT = 68,
  ATTEMPT_MEMORY_LIMIT = 69,
  JOURNAL_LIMIT = 70,
  GENERATION_EXHAUSTED = 71,
  // wire and store
  WIRE_TRUNCATED = 72,
  WIRE_TRAILING_BYTES = 73,
  WIRE_UNKNOWN_MESSAGE = 74,
  WIRE_VERSION_MISMATCH = 75,
  WIRE_INTEGRITY_FAILURE = 76,
  STORE_MAGIC = 77,
  STORE_VERSION = 78,
  STORE_INTEGRITY = 79,
  STORE_STRUCTURE = 80,
  STORE_IO = 81,
  STORE_TRAILING_BYTES = 82,
  // transport
  PEER_TIMEOUT = 83,
  PEER_CLOSED = 84,
  TRANSPORT_FAILURE = 85,
  // recovery and internal
  RECOVERED_CONSERVATIVE = 86,
  INTERNAL_INVARIANT = 87,
  REVALIDATION_REQUIRED = 88,
  BACKEND_UNSUPPORTED = 89,
  NO_READY_STEP = 90,
  ALREADY_SATISFIED = 91,
  DUPLICATE_STEP = 92,
  GRAPH_INVALID = 93,
};

[[nodiscard]] std::string_view to_string(ConditionCode code) noexcept;

// One structured explanatory fact.  `subject` is a short bounded token (an
// identity text, an enum name, or a generation value); it never contains control
// characters, so rendering is stable and script friendly.
struct Condition {
  ConditionCode code = ConditionCode::NONE;
  std::string subject;
  std::uint64_t observed = 0;
  std::uint64_t expected = 0;

  [[nodiscard]] std::string render() const;

  friend bool operator==(const Condition&, const Condition&) = default;
};

[[nodiscard]] Condition make_condition(ConditionCode code, std::string_view subject = {},
                                       std::uint64_t observed = 0, std::uint64_t expected = 0);

// Bounded list of conditions.  Anything beyond the bound is dropped with an
// EXPLANATION_LIMIT marker so that a caller can always tell truncation happened.
class ConditionList {
 public:
  ConditionList() = default;
  explicit ConditionList(std::uint32_t max_entries) : max_entries_(max_entries) {}

  void add(Condition condition);
  [[nodiscard]] const std::vector<Condition>& entries() const noexcept { return entries_; }
  [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }
  [[nodiscard]] bool truncated() const noexcept { return truncated_; }
  [[nodiscard]] std::string render() const;

 private:
  std::vector<Condition> entries_;
  std::uint32_t max_entries_ = 64;
  bool truncated_ = false;
};

// Bounded structured explanation with deterministic rendering.
class Explanation {
 public:
  Explanation() = default;
  explicit Explanation(std::string subject, std::uint32_t max_entries = 64)
      : subject_(std::move(subject)), conditions_(max_entries) {}

  void add(Condition condition);
  void set_subject(std::string subject);
  [[nodiscard]] const std::string& subject() const noexcept { return subject_; }
  [[nodiscard]] const ConditionList& conditions() const noexcept { return conditions_; }
  [[nodiscard]] bool truncated() const noexcept { return conditions_.truncated(); }
  [[nodiscard]] std::string render() const;

 private:
  std::string subject_;
  ConditionList conditions_;
};

}  // namespace rc
