#pragma once

// Shared helpers for the Route Convergence applications.  These are command line
// conveniences only: they add no product semantics.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "rc/rc.hpp"

namespace rc::app {

// Minimal deterministic command line parser: --flag value, --flag=value and bare
// positional arguments.  Unknown flags are reported by the caller through
// `value`, so a typo can never be silently ignored.
class CommandLine {
 public:
  [[nodiscard]] static CommandLine parse(int argc, char** argv);

  [[nodiscard]] bool has(std::string_view flag) const;
  [[nodiscard]] std::optional<std::string> value(std::string_view flag) const;
  [[nodiscard]] std::string value_or(std::string_view flag, std::string fallback) const;
  [[nodiscard]] std::uint64_t u64(std::string_view flag, std::uint64_t fallback) const;
  [[nodiscard]] const std::vector<std::string>& positional() const noexcept {
    return positional_;
  }
  [[nodiscard]] const std::vector<std::string>& unknown() const noexcept { return unknown_; }

 private:
  std::vector<std::string> flags_;
  std::vector<std::string> values_;
  std::vector<std::string> positional_;
  std::vector<std::string> unknown_;
};

[[nodiscard]] bool parse_u64(std::string_view text, std::uint64_t& out);
[[nodiscard]] bool parse_bool(std::string_view text, bool& out);

template <class Id>
[[nodiscard]] std::optional<Id> parse_id(std::string_view text) {
  return Id::parse(text);
}

[[nodiscard]] std::optional<OrderingMode> parse_ordering(std::string_view text);
[[nodiscard]] std::optional<BackendOutcome> parse_backend_outcome(std::string_view text);
[[nodiscard]] std::optional<ScopeKind> parse_scope(std::string_view text);
[[nodiscard]] std::optional<ExplainKind> parse_explain_kind(std::string_view text);
[[nodiscard]] std::uint32_t parse_capabilities(const std::vector<std::string>& names);

void print_line(std::string_view text);
void print_result(const PlanMutationResult& result, std::string_view prefix);

// Deterministic fixture identities.
[[nodiscard]] FabricId fabric_for(std::uint64_t seed);
[[nodiscard]] RoutingNamespaceId namespace_for(std::uint64_t seed);
[[nodiscard]] RouteId route_for(std::uint64_t seed);
[[nodiscard]] PathId path_for(std::uint64_t seed);
[[nodiscard]] ConvergencePolicyId policy_for(std::uint64_t seed);
[[nodiscard]] MutationAttemptId attempt_for(std::uint64_t seed);

// A coherent convergence policy with an explicit ordering choice.
[[nodiscard]] ConvergencePolicy make_policy(const ConvergencePolicyId& id, OrderingMode ordering,
                                            bool allow_break_before_make, std::uint32_t parallel,
                                            std::uint32_t retries);

}  // namespace rc::app
