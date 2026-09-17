#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "rc/limits.hpp"
#include "rc/outcome.hpp"
#include "rc/step.hpp"

namespace rc {

// One structural defect found while validating a transition dependency graph.
// Every defect carries a stable condition code and the two step identities it
// relates, so an operator never has to read free text to understand a rejection.
struct GraphDefect {
  ConditionCode code = ConditionCode::NONE;
  StepKey subject;
  StepKey related;
  std::string detail;

  [[nodiscard]] std::string render() const;
};

struct GraphValidation {
  bool ok = false;
  std::vector<GraphDefect> defects;
};

// Validates that the declared steps form a legal DAG:
//   * every step key is unique;
//   * every declared prerequisite exists (after bounded canonicalisation);
//   * no step depends on itself;
//   * no duplicate edges;
//   * no cycles;
//   * dependency count and total dependency count stay inside the limits;
//   * no two steps in the same execution layer share a conflict domain subject.
[[nodiscard]] GraphValidation validate_dependency_graph(const std::vector<StepSpec>& steps,
                                                        const ConvergenceLimits& limits);

// Canonical deterministic topological order, returned as indices into `steps`.
// Ties are broken by StepKey, never by insertion order, so two equivalent graphs
// built in different orders produce the identical order.  Returns std::nullopt
// when the graph contains a cycle.
[[nodiscard]] std::optional<std::vector<std::size_t>> canonical_topological_order(
    const std::vector<StepSpec>& steps);

// Canonical execution layers: layer 0 holds steps with no prerequisites, layer n
// holds steps whose prerequisites are all in earlier layers.  Within a layer the
// order is canonical by StepKey.  Returns std::nullopt when the graph contains a
// cycle.
[[nodiscard]] std::optional<std::vector<std::vector<std::size_t>>> canonical_layers(
    const std::vector<StepSpec>& steps);

// True when `candidate` is a transitive prerequisite of `target`.
[[nodiscard]] bool depends_transitively_on(const std::vector<StepSpec>& steps,
                                           const StepKey& target, const StepKey& candidate);

}  // namespace rc
