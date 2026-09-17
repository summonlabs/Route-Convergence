#include "rc/outcome.hpp"

#include <algorithm>

namespace rc {
namespace {

[[nodiscard]] std::string sanitize(std::string_view text) {
  std::string out;
  out.reserve(text.size() < 128 ? text.size() : 128);
  for (const char raw : text) {
    if (out.size() == 128) {
      break;
    }
    const unsigned char value = static_cast<unsigned char>(raw);
    if (value >= 0x20u && value <= 0x7Eu) {
      out.push_back(raw);
    } else {
      out.push_back('?');
    }
  }
  return out;
}

}  // namespace

std::string_view to_string(Outcome outcome) noexcept {
  switch (outcome) {
    case Outcome::PLAN_CREATED: return "PLAN_CREATED";
    case Outcome::PLAN_UPDATED: return "PLAN_UPDATED";
    case Outcome::STEP_READY: return "STEP_READY";
    case Outcome::STEP_DISPATCHED: return "STEP_DISPATCHED";
    case Outcome::STEP_COMPLETED: return "STEP_COMPLETED";
    case Outcome::STEP_FAILED: return "STEP_FAILED";
    case Outcome::STEP_RECONCILED: return "STEP_RECONCILED";
    case Outcome::PLAN_PAUSED: return "PLAN_PAUSED";
    case Outcome::PLAN_RESUMED: return "PLAN_RESUMED";
    case Outcome::PLAN_COMPLETED: return "PLAN_COMPLETED";
    case Outcome::PLAN_REVALIDATION_REQUIRED: return "PLAN_REVALIDATION_REQUIRED";
    case Outcome::PLAN_REVALIDATED: return "PLAN_REVALIDATED";
    case Outcome::ROLLBACK_PLAN_CREATED: return "ROLLBACK_PLAN_CREATED";
    case Outcome::ROLLBACK_COMPLETED: return "ROLLBACK_COMPLETED";
    case Outcome::PLAN_SUPERSEDED: return "PLAN_SUPERSEDED";
    case Outcome::PLAN_REVOKED: return "PLAN_REVOKED";
    case Outcome::PLAN_RETIRED: return "PLAN_RETIRED";
    case Outcome::WORKER_REGISTERED: return "WORKER_REGISTERED";
    case Outcome::WORKER_FENCED: return "WORKER_FENCED";
    case Outcome::POLICY_DEFINED: return "POLICY_DEFINED";
    case Outcome::IDEMPOTENT: return "IDEMPOTENT";
    case Outcome::NO_CHANGE: return "NO_CHANGE";
    case Outcome::EPOCH_ADVANCED: return "EPOCH_ADVANCED";
    case Outcome::STALE_PLAN: return "STALE_PLAN";
    case Outcome::STALE_STEP: return "STALE_STEP";
    case Outcome::STALE_ROUTE: return "STALE_ROUTE";
    case Outcome::STALE_PATH_AUTHORITY: return "STALE_PATH_AUTHORITY";
    case Outcome::STALE_ECMP: return "STALE_ECMP";
    case Outcome::STALE_WEIGHT_POLICY: return "STALE_WEIGHT_POLICY";
    case Outcome::STALE_EPOCH: return "STALE_EPOCH";
    case Outcome::STALE_WORKER: return "STALE_WORKER";
    case Outcome::STALE_POLICY: return "STALE_POLICY";
    case Outcome::STALE_DEPENDENCY: return "STALE_DEPENDENCY";
    case Outcome::PREREQUISITE_INCOMPLETE: return "PREREQUISITE_INCOMPLETE";
    case Outcome::ROLLBACK_REQUIRED: return "ROLLBACK_REQUIRED";
    case Outcome::UNSAFE_ROLLBACK: return "UNSAFE_ROLLBACK";
    case Outcome::AMBIGUOUS_SIDE_EFFECT: return "AMBIGUOUS_SIDE_EFFECT";
    case Outcome::RETRYABLE_FAILURE: return "RETRYABLE_FAILURE";
    case Outcome::PERMANENT_FAILURE: return "PERMANENT_FAILURE";
    case Outcome::SUPERSEDED: return "SUPERSEDED";
    case Outcome::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
    case Outcome::UNAUTHORIZED: return "UNAUTHORIZED";
    case Outcome::RESOURCE_LIMIT: return "RESOURCE_LIMIT";
    case Outcome::RETIRED: return "RETIRED";
    case Outcome::MALFORMED_REQUEST: return "MALFORMED_REQUEST";
    case Outcome::ATTEMPT_CONFLICT: return "ATTEMPT_CONFLICT";
    case Outcome::LIFECYCLE_VIOLATION: return "LIFECYCLE_VIOLATION";
    case Outcome::DUPLICATE_PLAN: return "DUPLICATE_PLAN";
    case Outcome::UNKNOWN_PLAN: return "UNKNOWN_PLAN";
    case Outcome::UNKNOWN_STEP: return "UNKNOWN_STEP";
    case Outcome::UNKNOWN_POLICY: return "UNKNOWN_POLICY";
    case Outcome::GRAPH_INVALID: return "GRAPH_INVALID";
    case Outcome::GENERATION_EXHAUSTED: return "GENERATION_EXHAUSTED";
    case Outcome::STORE_ERROR: return "STORE_ERROR";
    case Outcome::WIRE_REJECTED: return "WIRE_REJECTED";
    case Outcome::NO_READY_STEP: return "NO_READY_STEP";
    case Outcome::UNSUPPORTED: return "UNSUPPORTED";
    case Outcome::INTERNAL_ERROR: return "INTERNAL_ERROR";
  }
  return "INTERNAL_ERROR";
}

bool is_acceptance(Outcome outcome) noexcept {
  switch (outcome) {
    case Outcome::PLAN_CREATED:
    case Outcome::PLAN_UPDATED:
    case Outcome::STEP_READY:
    case Outcome::STEP_DISPATCHED:
    case Outcome::STEP_COMPLETED:
    case Outcome::STEP_RECONCILED:
    case Outcome::PLAN_PAUSED:
    case Outcome::PLAN_RESUMED:
    case Outcome::PLAN_COMPLETED:
    case Outcome::PLAN_REVALIDATION_REQUIRED:
    case Outcome::PLAN_REVALIDATED:
    case Outcome::ROLLBACK_PLAN_CREATED:
    case Outcome::ROLLBACK_COMPLETED:
    case Outcome::PLAN_SUPERSEDED:
    case Outcome::PLAN_REVOKED:
    case Outcome::PLAN_RETIRED:
    case Outcome::WORKER_REGISTERED:
    case Outcome::WORKER_FENCED:
    case Outcome::POLICY_DEFINED:
    case Outcome::IDEMPOTENT:
    case Outcome::NO_CHANGE:
    case Outcome::EPOCH_ADVANCED:
      return true;
    default:
      return false;
  }
}

std::string_view to_string(ConditionCode code) noexcept {
  switch (code) {
    case ConditionCode::NONE: return "NONE";
    case ConditionCode::AUTHORITY_EPOCH_STALE: return "AUTHORITY_EPOCH_STALE";
    case ConditionCode::WORKER_FENCED: return "WORKER_FENCED";
    case ConditionCode::PUBLISHER_UNKNOWN: return "PUBLISHER_UNKNOWN";
    case ConditionCode::SCOPE_DENIED: return "SCOPE_DENIED";
    case ConditionCode::CAPABILITY_MISSING: return "CAPABILITY_MISSING";
    case ConditionCode::MALFORMED_IDENTITY: return "MALFORMED_IDENTITY";
    case ConditionCode::MALFORMED_PAYLOAD: return "MALFORMED_PAYLOAD";
    case ConditionCode::MALFORMED_SUBJECT: return "MALFORMED_SUBJECT";
    case ConditionCode::ATTEMPT_REPLAY: return "ATTEMPT_REPLAY";
    case ConditionCode::ATTEMPT_CONFLICT: return "ATTEMPT_CONFLICT";
    case ConditionCode::PLAN_UNKNOWN: return "PLAN_UNKNOWN";
    case ConditionCode::PLAN_TERMINAL: return "PLAN_TERMINAL";
    case ConditionCode::LIFECYCLE_DENIED: return "LIFECYCLE_DENIED";
    case ConditionCode::PLAN_GENERATION_MISMATCH: return "PLAN_GENERATION_MISMATCH";
    case ConditionCode::DUPLICATE_PLAN: return "DUPLICATE_PLAN";
    case ConditionCode::PLAN_SUPERSEDED: return "PLAN_SUPERSEDED";
    case ConditionCode::PLAN_ALREADY_EXISTS: return "PLAN_ALREADY_EXISTS";
    case ConditionCode::STEP_UNKNOWN: return "STEP_UNKNOWN";
    case ConditionCode::STEP_GENERATION_MISMATCH: return "STEP_GENERATION_MISMATCH";
    case ConditionCode::STEP_NOT_READY: return "STEP_NOT_READY";
    case ConditionCode::STEP_STALE: return "STEP_STALE";
    case ConditionCode::STEP_TERMINAL: return "STEP_TERMINAL";
    case ConditionCode::DEPENDENCY_MISSING: return "DEPENDENCY_MISSING";
    case ConditionCode::DEPENDENCY_DUPLICATE: return "DEPENDENCY_DUPLICATE";
    case ConditionCode::DEPENDENCY_CYCLE: return "DEPENDENCY_CYCLE";
    case ConditionCode::DEPENDENCY_SELF: return "DEPENDENCY_SELF";
    case ConditionCode::PREREQUISITE_INCOMPLETE: return "PREREQUISITE_INCOMPLETE";
    case ConditionCode::CONFLICT_DOMAIN_OVERLAP: return "CONFLICT_DOMAIN_OVERLAP";
    case ConditionCode::TARGET_ROUTE_STALE: return "TARGET_ROUTE_STALE";
    case ConditionCode::TARGET_ROUTE_UNKNOWN: return "TARGET_ROUTE_UNKNOWN";
    case ConditionCode::TARGET_ROUTE_ILLEGAL: return "TARGET_ROUTE_ILLEGAL";
    case ConditionCode::SOURCE_ROUTE_STALE: return "SOURCE_ROUTE_STALE";
    case ConditionCode::SOURCE_ROUTE_UNKNOWN: return "SOURCE_ROUTE_UNKNOWN";
    case ConditionCode::SOURCE_ROUTE_ILLEGAL: return "SOURCE_ROUTE_ILLEGAL";
    case ConditionCode::PATH_AUTHORITY_STALE: return "PATH_AUTHORITY_STALE";
    case ConditionCode::PATH_AUTHORITY_UNKNOWN: return "PATH_AUTHORITY_UNKNOWN";
    case ConditionCode::PATH_AUTHORITY_UNAUTHORIZED: return "PATH_AUTHORITY_UNAUTHORIZED";
    case ConditionCode::MULTIPATH_SET_STALE: return "MULTIPATH_SET_STALE";
    case ConditionCode::ECMP_GENERATION_STALE: return "ECMP_GENERATION_STALE";
    case ConditionCode::ASSIGNMENT_GENERATION_STALE: return "ASSIGNMENT_GENERATION_STALE";
    case ConditionCode::WEIGHT_POLICY_STALE: return "WEIGHT_POLICY_STALE";
    case ConditionCode::POLICY_UNKNOWN: return "POLICY_UNKNOWN";
    case ConditionCode::POLICY_GENERATION_STALE: return "POLICY_GENERATION_STALE";
    case ConditionCode::POLICY_INCOHERENT: return "POLICY_INCOHERENT";
    case ConditionCode::BREAK_BEFORE_MAKE_NOT_PERMITTED: return "BREAK_BEFORE_MAKE_NOT_PERMITTED";
    case ConditionCode::COMPLETION_STALE: return "COMPLETION_STALE";
    case ConditionCode::WATERMARK_EXCEEDED: return "WATERMARK_EXCEEDED";
    case ConditionCode::EVIDENCE_MISSING: return "EVIDENCE_MISSING";
    case ConditionCode::EVIDENCE_GENERATION_MISMATCH: return "EVIDENCE_GENERATION_MISMATCH";
    case ConditionCode::AMBIGUOUS_SIDE_EFFECT: return "AMBIGUOUS_SIDE_EFFECT";
    case ConditionCode::RECONCILIATION_REQUIRED: return "RECONCILIATION_REQUIRED";
    case ConditionCode::ROLLBACK_TARGET_UNAUTHORIZED: return "ROLLBACK_TARGET_UNAUTHORIZED";
    case ConditionCode::ROLLBACK_NOT_ELIGIBLE: return "ROLLBACK_NOT_ELIGIBLE";
    case ConditionCode::ROLLBACK_IRREVERSIBLE: return "ROLLBACK_IRREVERSIBLE";
    case ConditionCode::UNSAFE_ROLLBACK: return "UNSAFE_ROLLBACK";
    case ConditionCode::PLAN_LIMIT: return "PLAN_LIMIT";
    case ConditionCode::STEP_LIMIT: return "STEP_LIMIT";
    case ConditionCode::DEPENDENCY_LIMIT: return "DEPENDENCY_LIMIT";
    case ConditionCode::TOTAL_DEPENDENCY_LIMIT: return "TOTAL_DEPENDENCY_LIMIT";
    case ConditionCode::PARALLELISM_LIMIT: return "PARALLELISM_LIMIT";
    case ConditionCode::HISTORY_LIMIT: return "HISTORY_LIMIT";
    case ConditionCode::RETRY_LIMIT: return "RETRY_LIMIT";
    case ConditionCode::FRAME_LIMIT: return "FRAME_LIMIT";
    case ConditionCode::BATCH_LIMIT: return "BATCH_LIMIT";
    case ConditionCode::WORKER_LIMIT: return "WORKER_LIMIT";
    case ConditionCode::SESSION_LIMIT: return "SESSION_LIMIT";
    case ConditionCode::STORE_RECORD_LIMIT: return "STORE_RECORD_LIMIT";
    case ConditionCode::EXPLANATION_LIMIT: return "EXPLANATION_LIMIT";
    case ConditionCode::ATTEMPT_MEMORY_LIMIT: return "ATTEMPT_MEMORY_LIMIT";
    case ConditionCode::JOURNAL_LIMIT: return "JOURNAL_LIMIT";
    case ConditionCode::GENERATION_EXHAUSTED: return "GENERATION_EXHAUSTED";
    case ConditionCode::WIRE_TRUNCATED: return "WIRE_TRUNCATED";
    case ConditionCode::WIRE_TRAILING_BYTES: return "WIRE_TRAILING_BYTES";
    case ConditionCode::WIRE_UNKNOWN_MESSAGE: return "WIRE_UNKNOWN_MESSAGE";
    case ConditionCode::WIRE_VERSION_MISMATCH: return "WIRE_VERSION_MISMATCH";
    case ConditionCode::WIRE_INTEGRITY_FAILURE: return "WIRE_INTEGRITY_FAILURE";
    case ConditionCode::STORE_MAGIC: return "STORE_MAGIC";
    case ConditionCode::STORE_VERSION: return "STORE_VERSION";
    case ConditionCode::STORE_INTEGRITY: return "STORE_INTEGRITY";
    case ConditionCode::STORE_STRUCTURE: return "STORE_STRUCTURE";
    case ConditionCode::STORE_IO: return "STORE_IO";
    case ConditionCode::STORE_TRAILING_BYTES: return "STORE_TRAILING_BYTES";
    case ConditionCode::PEER_TIMEOUT: return "PEER_TIMEOUT";
    case ConditionCode::PEER_CLOSED: return "PEER_CLOSED";
    case ConditionCode::TRANSPORT_FAILURE: return "TRANSPORT_FAILURE";
    case ConditionCode::RECOVERED_CONSERVATIVE: return "RECOVERED_CONSERVATIVE";
    case ConditionCode::INTERNAL_INVARIANT: return "INTERNAL_INVARIANT";
    case ConditionCode::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
    case ConditionCode::BACKEND_UNSUPPORTED: return "BACKEND_UNSUPPORTED";
    case ConditionCode::NO_READY_STEP: return "NO_READY_STEP";
    case ConditionCode::ALREADY_SATISFIED: return "ALREADY_SATISFIED";
    case ConditionCode::DUPLICATE_STEP: return "DUPLICATE_STEP";
    case ConditionCode::GRAPH_INVALID: return "GRAPH_INVALID";
  }
  return "NONE";
}

Condition make_condition(ConditionCode code, std::string_view subject, std::uint64_t observed,
                         std::uint64_t expected) {
  Condition condition;
  condition.code = code;
  condition.subject.assign(subject);
  condition.observed = observed;
  condition.expected = expected;
  return condition;
}

std::string Condition::render() const {
  std::string out = "code=";
  out += to_string(code);
  if (!subject.empty()) {
    out += " subject=";
    out += sanitize(subject);
  }
  if (observed != 0 || expected != 0) {
    out += " observed=";
    out += std::to_string(observed);
    out += " expected=";
    out += std::to_string(expected);
  }
  return out;
}

void ConditionList::add(Condition condition) {
  if (entries_.size() >= max_entries_) {
    truncated_ = true;
    return;
  }
  entries_.push_back(std::move(condition));
}

std::string ConditionList::render() const {
  std::string out;
  for (std::size_t index = 0; index < entries_.size(); ++index) {
    if (index != 0) {
      out += '\n';
    }
    out += entries_[index].render();
  }
  if (truncated_) {
    if (!out.empty()) {
      out += '\n';
    }
    out += "code=EXPLANATION_LIMIT";
  }
  return out;
}

void Explanation::add(Condition condition) { conditions_.add(std::move(condition)); }

void Explanation::set_subject(std::string subject) { subject_ = std::move(subject); }

std::string Explanation::render() const {
  std::string out = "explanation subject=";
  out += sanitize(subject_);
  out += '\n';
  out += conditions_.render();
  return out;
}

}  // namespace rc
