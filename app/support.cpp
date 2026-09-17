#include "support.hpp"

#include <iostream>
#include <map>
#include <sstream>

namespace rc::app {
namespace {

[[nodiscard]] std::string join(const std::vector<std::string>& parts, std::size_t from) {
  std::string out;
  for (std::size_t index = from; index < parts.size(); ++index) {
    if (!out.empty()) {
      out += ' ';
    }
    out += parts[index];
  }
  return out;
}

}  // namespace

CommandLine CommandLine::parse(int argc, char** argv) {
  CommandLine line;
  std::size_t index = 1;
  while (index < static_cast<std::size_t>(argc)) {
    std::string token = argv[index];
    if (token.rfind("--", 0) == 0) {
      const std::size_t equals = token.find('=');
      if (equals != std::string::npos) {
        line.flags_.push_back(token.substr(2, equals - 2));
        line.values_.push_back(token.substr(equals + 1));
        ++index;
        continue;
      }
      const std::string flag = token.substr(2);
      if (index + 1 < static_cast<std::size_t>(argc)) {
        const std::string next = argv[index + 1];
        if (next.rfind("--", 0) != 0) {
          line.flags_.push_back(flag);
          line.values_.push_back(next);
          index += 2;
          continue;
        }
      }
      line.flags_.push_back(flag);
      line.values_.push_back(std::string{});
      ++index;
      continue;
    }
    line.positional_.push_back(std::move(token));
    ++index;
  }
  return line;
}

bool CommandLine::has(std::string_view flag) const {
  for (const std::string& entry : flags_) {
    if (entry == flag) {
      return true;
    }
  }
  return false;
}

std::optional<std::string> CommandLine::value(std::string_view flag) const {
  for (std::size_t index = 0; index < flags_.size(); ++index) {
    if (flags_[index] == flag) {
      return values_[index];
    }
  }
  return std::nullopt;
}

std::string CommandLine::value_or(std::string_view flag, std::string fallback) const {
  const std::optional<std::string> found = value(flag);
  if (!found.has_value() || found->empty()) {
    return fallback;
  }
  return *found;
}

std::uint64_t CommandLine::u64(std::string_view flag, std::uint64_t fallback) const {
  const std::optional<std::string> found = value(flag);
  if (!found.has_value() || found->empty()) {
    return fallback;
  }
  std::uint64_t parsed = fallback;
  if (!parse_u64(*found, parsed)) {
    return fallback;
  }
  return parsed;
}

bool parse_u64(std::string_view text, std::uint64_t& out) {
  if (text.empty()) {
    return false;
  }
  std::uint64_t value = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      return false;
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
    if (value > (0xFFFFFFFFFFFFFFFFull - digit) / 10ull) {
      return false;
    }
    value = (value * 10ull) + digit;
  }
  out = value;
  return true;
}

bool parse_bool(std::string_view text, bool& out) {
  if (text == "1" || text == "true" || text == "yes") {
    out = true;
    return true;
  }
  if (text == "0" || text == "false" || text == "no") {
    out = false;
    return true;
  }
  return false;
}

std::optional<OrderingMode> parse_ordering(std::string_view text) {
  if (text == "mbb" || text == "make-before-break") {
    return OrderingMode::MAKE_BEFORE_BREAK;
  }
  if (text == "bbm" || text == "break-before-make") {
    return OrderingMode::BREAK_BEFORE_MAKE;
  }
  return std::nullopt;
}

std::optional<BackendOutcome> parse_backend_outcome(std::string_view text) {
  if (text == "applied") {
    return BackendOutcome::APPLIED;
  }
  if (text == "idempotent") {
    return BackendOutcome::IDEMPOTENT;
  }
  if (text == "retryable") {
    return BackendOutcome::RETRYABLE_FAILURE;
  }
  if (text == "permanent") {
    return BackendOutcome::PERMANENT_FAILURE;
  }
  if (text == "ambiguous") {
    return BackendOutcome::AMBIGUOUS;
  }
  if (text == "unsupported") {
    return BackendOutcome::UNSUPPORTED;
  }
  if (text == "stale") {
    return BackendOutcome::STALE;
  }
  return std::nullopt;
}

std::optional<ScopeKind> parse_scope(std::string_view text) {
  if (text == "plan") {
    return ScopeKind::PLAN;
  }
  if (text == "route") {
    return ScopeKind::ROUTE;
  }
  if (text == "namespace" || text == "routing-namespace") {
    return ScopeKind::ROUTING_NAMESPACE;
  }
  if (text == "fabric") {
    return ScopeKind::FABRIC;
  }
  if (text == "deny") {
    return ScopeKind::DENY_ALL;
  }
  return std::nullopt;
}

std::optional<ExplainKind> parse_explain_kind(std::string_view text) {
  if (text == "plan") {
    return ExplainKind::PLAN;
  }
  if (text == "step") {
    return ExplainKind::STEP;
  }
  if (text == "readiness") {
    return ExplainKind::READINESS;
  }
  if (text == "prerequisite") {
    return ExplainKind::PREREQUISITE;
  }
  if (text == "old-state" || text == "old_state_retention") {
    return ExplainKind::OLD_STATE_RETENTION;
  }
  if (text == "target" || text == "target_activation") {
    return ExplainKind::TARGET_ACTIVATION;
  }
  if (text == "rollback") {
    return ExplainKind::ROLLBACK;
  }
  if (text == "staleness") {
    return ExplainKind::STALENESS;
  }
  if (text == "completion") {
    return ExplainKind::COMPLETION;
  }
  if (text == "authority") {
    return ExplainKind::AUTHORITY;
  }
  return std::nullopt;
}

std::uint32_t parse_capabilities(const std::vector<std::string>& names) {
  static const std::map<std::string, Capability> kTable = {
      {"create-plan", Capability::CREATE_PLAN},
      {"dispatch", Capability::DISPATCH_STEP},
      {"complete", Capability::COMPLETE_STEP},
      {"revalidate", Capability::REVALIDATE_PLAN},
      {"rollback", Capability::ROLLBACK},
      {"admin", Capability::ADMIN},
      {"publish-upstream", Capability::PUBLISH_UPSTREAM},
  };
  std::uint32_t bits = 0;
  for (const std::string& name : names) {
    const auto entry = kTable.find(name);
    if (entry != kTable.end()) {
      bits |= static_cast<std::uint32_t>(entry->second);
    }
  }
  return bits;
}

void print_line(std::string_view text) {
  std::cout << text << '\n';
  std::cout.flush();
}

void print_result(const PlanMutationResult& result, std::string_view prefix) {
  std::ostringstream stream;
  stream << prefix << " outcome=" << to_string(result.outcome);
  if (!result.plan.is_nil()) {
    stream << " plan=" << result.plan.to_text();
  }
  if (!result.step.is_nil()) {
    stream << " step=" << result.step.to_text();
  }
  stream << " plan_generation=" << result.plan_generation.value();
  stream << " convergence_generation=" << result.convergence_generation.value();
  print_line(stream.str());
  const std::string conditions = result.conditions.render();
  if (!conditions.empty()) {
    std::istringstream lines(conditions);
    std::string line;
    while (std::getline(lines, line)) {
      print_line(std::string(prefix) + " " + line);
    }
  }
}

FabricId fabric_for(std::uint64_t seed) { return derive_id<FabricId>("rc.fixture.fabric", seed); }
RoutingNamespaceId namespace_for(std::uint64_t seed) {
  return derive_id<RoutingNamespaceId>("rc.fixture.namespace", seed);
}
RouteId route_for(std::uint64_t seed) { return derive_id<RouteId>("rc.fixture.route", seed); }
PathId path_for(std::uint64_t seed) { return derive_id<PathId>("rc.fixture.path", seed); }
ConvergencePolicyId policy_for(std::uint64_t seed) {
  return derive_id<ConvergencePolicyId>("rc.fixture.policy", seed);
}
MutationAttemptId attempt_for(std::uint64_t seed) {
  return derive_id<MutationAttemptId>("rc.fixture.attempt", seed);
}

ConvergencePolicy make_policy(const ConvergencePolicyId& id, OrderingMode ordering,
                              bool allow_break_before_make, std::uint32_t parallel,
                              std::uint32_t retries) {
  ConvergencePolicy policy;
  policy.id = id;
  policy.generation = ConvergencePolicyGeneration::from_value(1);
  policy.ordering = ordering;
  policy.allow_break_before_make = allow_break_before_make;
  policy.allow_overlap = ordering == OrderingMode::MAKE_BEFORE_BREAK;
  policy.verification = VerificationMode::REQUIRED;
  policy.max_parallel_steps = parallel;
  policy.max_retries_per_step = retries;
  return policy;
}

}  // namespace rc::app
