#include "rc/graph.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace rc {
namespace {

[[nodiscard]] std::string key_text(const StepKey& key) { return key.render(); }

// Builds a key to index map.  Duplicates are reported through `duplicate`.
[[nodiscard]] std::map<StepKey, std::size_t> index_steps(const std::vector<StepSpec>& steps,
                                                         std::optional<std::size_t>& duplicate) {
  std::map<StepKey, std::size_t> index;
  for (std::size_t position = 0; position < steps.size(); ++position) {
    const auto [iterator, inserted] = index.emplace(steps[position].key(), position);
    if (!inserted && !duplicate.has_value()) {
      duplicate = position;
    }
  }
  return index;
}

}  // namespace

std::string GraphDefect::render() const {
  std::string out = "defect code=";
  out += to_string(code);
  out += " subject=";
  out += key_text(subject);
  if (!related.subject.empty() || related.kind != StepKind::VALIDATE_TARGET) {
    out += " related=";
    out += key_text(related);
  }
  if (!detail.empty()) {
    out += " detail=";
    out += detail;
  }
  return out;
}

GraphValidation validate_dependency_graph(const std::vector<StepSpec>& steps,
                                          const ConvergenceLimits& limits) {
  GraphValidation result;
  if (steps.size() > limits.max_steps_per_plan) {
    result.defects.push_back(GraphDefect{ConditionCode::STEP_LIMIT, {}, {},
                                         "step count exceeds max_steps_per_plan"});
  }
  if (steps.size() > kAbsoluteMaxStepsPerPlan) {
    result.defects.push_back(GraphDefect{ConditionCode::STEP_LIMIT, {}, {},
                                         "step count exceeds the absolute ceiling"});
  }

  std::optional<std::size_t> duplicate;
  const std::map<StepKey, std::size_t> index = index_steps(steps, duplicate);
  if (duplicate.has_value()) {
    result.defects.push_back(GraphDefect{ConditionCode::DUPLICATE_STEP, steps[*duplicate].key(), {},
                                         "two steps share one semantic key"});
  }

  std::uint64_t total_dependencies = 0;
  for (const StepSpec& step : steps) {
    if (step.subject.empty()) {
      result.defects.push_back(
          GraphDefect{ConditionCode::MALFORMED_SUBJECT, step.key(), {}, "empty step subject"});
      continue;
    }
    if (step.depends_on.size() > limits.max_dependencies_per_step ||
        step.depends_on.size() > kAbsoluteMaxDependenciesPerStep) {
      result.defects.push_back(GraphDefect{ConditionCode::DEPENDENCY_LIMIT, step.key(), {},
                                           "dependency count exceeds the configured bound"});
    }
    total_dependencies += step.depends_on.size();
    std::set<StepKey> seen;
    for (const StepKey& dependency : step.depends_on) {
      if (!seen.insert(dependency).second) {
        result.defects.push_back(GraphDefect{ConditionCode::DEPENDENCY_DUPLICATE, step.key(),
                                             dependency, "duplicate dependency edge"});
      }
      if (dependency == step.key()) {
        result.defects.push_back(GraphDefect{ConditionCode::DEPENDENCY_SELF, step.key(),
                                             dependency, "step depends on itself"});
        continue;
      }
      if (index.find(dependency) == index.end()) {
        result.defects.push_back(GraphDefect{ConditionCode::DEPENDENCY_MISSING, step.key(),
                                             dependency, "declared prerequisite does not exist"});
      }
    }
  }
  if (total_dependencies > limits.max_total_dependencies) {
    result.defects.push_back(GraphDefect{ConditionCode::TOTAL_DEPENDENCY_LIMIT, {}, {},
                                         "total dependency count exceeds the configured bound"});
  }

  const std::optional<std::vector<std::vector<std::size_t>>> layers = canonical_layers(steps);
  if (!layers.has_value()) {
    // Report the smallest cycle member in canonical order so the defect is
    // deterministic rather than dependent on traversal start.
    std::vector<StepKey> keys;
    keys.reserve(steps.size());
    for (const StepSpec& step : steps) {
      keys.push_back(step.key());
    }
    std::sort(keys.begin(), keys.end());
    for (const StepKey& key : keys) {
      const auto entry = index.find(key);
      if (entry == index.end()) {
        continue;
      }
      if (depends_transitively_on(steps, key, key)) {
        result.defects.push_back(
            GraphDefect{ConditionCode::DEPENDENCY_CYCLE, key, {}, "dependency cycle"});
        break;
      }
    }
    if (result.defects.empty()) {
      result.defects.push_back(
          GraphDefect{ConditionCode::DEPENDENCY_CYCLE, {}, {}, "dependency cycle"});
    }
  } else {
    for (const std::vector<std::size_t>& layer : *layers) {
      for (std::size_t left = 0; left < layer.size(); ++left) {
        for (std::size_t right = left + 1; right < layer.size(); ++right) {
          const StepSpec& a = steps[layer[left]];
          const StepSpec& b = steps[layer[right]];
          if ((a.conflict_domains & b.conflict_domains) == 0) {
            continue;
          }
          if (a.subject == b.subject) {
            result.defects.push_back(GraphDefect{
                ConditionCode::CONFLICT_DOMAIN_OVERLAP, a.key(), b.key(),
                "parallel steps share a conflict domain on the same subject"});
          }
        }
      }
    }
  }

  result.ok = result.defects.empty();
  return result;
}

std::optional<std::vector<std::size_t>> canonical_topological_order(
    const std::vector<StepSpec>& steps) {
  std::optional<std::size_t> duplicate;
  const std::map<StepKey, std::size_t> index = index_steps(steps, duplicate);
  if (duplicate.has_value()) {
    return std::nullopt;
  }

  std::vector<std::size_t> indegree(steps.size(), 0);
  std::vector<std::vector<std::size_t>> successors(steps.size());
  for (std::size_t position = 0; position < steps.size(); ++position) {
    for (const StepKey& dependency : steps[position].depends_on) {
      const auto entry = index.find(dependency);
      if (entry == index.end()) {
        return std::nullopt;
      }
      if (entry->second == position) {
        return std::nullopt;
      }
      successors[entry->second].push_back(position);
      ++indegree[position];
    }
  }
  for (std::vector<std::size_t>& list : successors) {
    std::sort(list.begin(), list.end());
    list.erase(std::unique(list.begin(), list.end()), list.end());
  }
  // Recompute indegrees over the de-duplicated edge set so a duplicated edge
  // cannot make the order incorrect.
  std::fill(indegree.begin(), indegree.end(), 0);
  for (const std::vector<std::size_t>& list : successors) {
    for (const std::size_t successor : list) {
      ++indegree[successor];
    }
  }

  std::set<std::pair<StepKey, std::size_t>> ready;
  for (std::size_t position = 0; position < steps.size(); ++position) {
    if (indegree[position] == 0) {
      ready.insert({steps[position].key(), position});
    }
  }

  std::vector<std::size_t> order;
  order.reserve(steps.size());
  while (!ready.empty()) {
    const auto iterator = ready.begin();
    const std::size_t position = iterator->second;
    ready.erase(iterator);
    order.push_back(position);
    for (const std::size_t successor : successors[position]) {
      if (indegree[successor] == 0) {
        continue;
      }
      if (--indegree[successor] == 0) {
        ready.insert({steps[successor].key(), successor});
      }
    }
  }
  if (order.size() != steps.size()) {
    return std::nullopt;
  }
  return order;
}

std::optional<std::vector<std::vector<std::size_t>>> canonical_layers(
    const std::vector<StepSpec>& steps) {
  std::optional<std::size_t> duplicate;
  const std::map<StepKey, std::size_t> index = index_steps(steps, duplicate);
  if (duplicate.has_value()) {
    return std::nullopt;
  }

  std::vector<std::size_t> depth(steps.size(), 0);
  const std::optional<std::vector<std::size_t>> order = canonical_topological_order(steps);
  if (!order.has_value()) {
    return std::nullopt;
  }
  for (const std::size_t position : *order) {
    for (const StepKey& dependency : steps[position].depends_on) {
      const auto entry = index.find(dependency);
      if (entry == index.end()) {
        return std::nullopt;
      }
      const std::size_t candidate = depth[entry->second] + 1;
      if (candidate > depth[position]) {
        depth[position] = candidate;
      }
    }
  }

  std::size_t maximum = 0;
  for (const std::size_t value : depth) {
    maximum = std::max(maximum, value);
  }
  std::vector<std::vector<std::size_t>> layers(maximum + 1);
  for (const std::size_t position : *order) {
    layers[depth[position]].push_back(position);
  }
  for (std::vector<std::size_t>& layer : layers) {
    std::sort(layer.begin(), layer.end(), [&steps](std::size_t left, std::size_t right) {
      return steps[left].key() < steps[right].key();
    });
  }
  return layers;
}

bool depends_transitively_on(const std::vector<StepSpec>& steps, const StepKey& target,
                             const StepKey& candidate) {
  std::optional<std::size_t> duplicate;
  const std::map<StepKey, std::size_t> index = index_steps(steps, duplicate);
  const auto start = index.find(target);
  if (start == index.end()) {
    return false;
  }
  std::vector<std::size_t> stack{start->second};
  std::unordered_set<std::size_t> visited;
  while (!stack.empty()) {
    const std::size_t position = stack.back();
    stack.pop_back();
    if (!visited.insert(position).second) {
      continue;
    }
    for (const StepKey& dependency : steps[position].depends_on) {
      if (dependency == candidate) {
        return true;
      }
      const auto entry = index.find(dependency);
      if (entry != index.end()) {
        stack.push_back(entry->second);
      }
    }
  }
  return false;
}

}  // namespace rc
