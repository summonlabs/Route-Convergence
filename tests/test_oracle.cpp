// tests/test_oracle.cpp
//
// Independent small-state DAG oracle for the Route Convergence ordering API.
//
// The oracle in this file is written from scratch: its own adjacency structure,
// its own Kahn cycle detection, its own lexicographic topological order, its own
// longest-path layering and its own reachability closure.  Nothing here calls
// rc::canonical_topological_order, rc::canonical_layers,
// rc::validate_dependency_graph or rc::depends_transitively_on to *derive* an
// expectation: those four functions are the system under test and every
// expectation below is computed independently and then compared against them.
//
// Every failure message carries the seed and the enumerated case identifier.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "fixture.hpp"
#include "rc/rc.hpp"
#include "test_framework.hpp"

namespace {

using rc::ConvergenceLimits;
using rc::StepKey;
using rc::StepKind;
using rc::StepSpec;

// One directed edge: "to" declares "from" as a prerequisite.
struct Edge {
  std::size_t from = 0;
  std::size_t to = 0;
};

// Explicit 64-bit linear congruential generator.  The seed is a parameter of
// every entry point so that a failure names the exact generator state that
// produced the graph.
class Lcg {
 public:
  explicit Lcg(std::uint64_t seed) noexcept
      : state_(seed * 6364136223846793005ull + 1442695040888963407ull) {}

  [[nodiscard]] std::uint64_t next() noexcept {
    state_ = (state_ * 6364136223846793005ull) + 1442695040888963407ull;
    return state_;
  }

  // Uniform-enough bounded draw; the caller guarantees bound != 0.
  [[nodiscard]] std::uint32_t bounded(std::uint32_t bound) noexcept {
    return static_cast<std::uint32_t>((next() >> 33) % bound);
  }

 private:
  std::uint64_t state_ = 0;
};

[[nodiscard]] std::string oracle_context(std::uint64_t seed, std::size_t case_id) {
  return "seed=" + std::to_string(seed) + " case=" + std::to_string(case_id);
}

// Reports a failure with the seed and the case identifier attached.  Only the
// failing branch evaluates the message, so the passing path stays cheap.
#define RC_ORACLE_CHECK(condition, seed, case_id, detail)                                 \
  do {                                                                                    \
    ++::rc::test::g_checks;                                                               \
    if (!(condition)) {                                                                   \
      ::rc::test::report_failure(__FILE__, __LINE__,                                      \
                                 oracle_context((seed), (case_id)) + " " + (detail));     \
    }                                                                                     \
  } while (false)

// --- the independent oracle -------------------------------------------------

class Oracle {
 public:
  // Builds the oracle adjacency from the declared step list.  The map from key
  // to position is the oracle's own; prerequisites are de-duplicated exactly the
  // way a set-valued graph would be.
  [[nodiscard]] static Oracle build(const std::vector<StepSpec>& steps) {
    Oracle oracle;
    std::map<StepKey, std::size_t> index;
    oracle.keys_.reserve(steps.size());
    for (std::size_t position = 0; position < steps.size(); ++position) {
      oracle.keys_.push_back(steps[position].key());
      index.emplace(steps[position].key(), position);
    }
    oracle.prerequisites_.resize(steps.size());
    oracle.successors_.resize(steps.size());
    for (std::size_t position = 0; position < steps.size(); ++position) {
      std::set<std::size_t> unique;
      for (const StepKey& dependency : steps[position].depends_on) {
        const auto entry = index.find(dependency);
        if (entry != index.end()) {
          unique.insert(entry->second);
        }
      }
      oracle.prerequisites_[position].assign(unique.begin(), unique.end());
      for (const std::size_t source : unique) {
        oracle.successors_[source].push_back(position);
      }
    }
    return oracle;
  }

  [[nodiscard]] const std::vector<StepKey>& keys() const noexcept { return keys_; }
  [[nodiscard]] std::size_t size() const noexcept { return keys_.size(); }

  [[nodiscard]] std::optional<std::size_t> position_of(const StepKey& key) const {
    for (std::size_t position = 0; position < keys_.size(); ++position) {
      if (keys_[position] == key) {
        return position;
      }
    }
    return std::nullopt;
  }

  // Kahn's algorithm over the de-duplicated edge set.  A node that never reaches
  // indegree zero proves a cycle, including a self loop.
  [[nodiscard]] bool acyclic() const {
    std::vector<std::size_t> remaining(keys_.size(), 0);
    for (std::size_t position = 0; position < keys_.size(); ++position) {
      remaining[position] = prerequisites_[position].size();
    }
    std::vector<std::size_t> stack;
    for (std::size_t position = 0; position < keys_.size(); ++position) {
      if (remaining[position] == 0) {
        stack.push_back(position);
      }
    }
    std::size_t visited = 0;
    while (!stack.empty()) {
      const std::size_t position = stack.back();
      stack.pop_back();
      ++visited;
      for (const std::size_t successor : successors_[position]) {
        if (remaining[successor] == 0) {
          continue;
        }
        if (--remaining[successor] == 0) {
          stack.push_back(successor);
        }
      }
    }
    return visited == keys_.size();
  }

  // The lexicographically smallest topological order over (StepKind, subject):
  // repeatedly emit the smallest key whose prerequisites have all been emitted.
  [[nodiscard]] std::optional<std::vector<std::size_t>> lexicographic_order() const {
    if (!acyclic()) {
      return std::nullopt;
    }
    std::vector<std::size_t> remaining(keys_.size(), 0);
    for (std::size_t position = 0; position < keys_.size(); ++position) {
      remaining[position] = prerequisites_[position].size();
    }
    std::set<std::pair<StepKey, std::size_t>> ready;
    for (std::size_t position = 0; position < keys_.size(); ++position) {
      if (remaining[position] == 0) {
        ready.insert({keys_[position], position});
      }
    }
    std::vector<std::size_t> order;
    order.reserve(keys_.size());
    while (!ready.empty()) {
      const auto smallest = ready.begin();
      const std::size_t position = smallest->second;
      ready.erase(smallest);
      order.push_back(position);
      for (const std::size_t successor : successors_[position]) {
        if (remaining[successor] == 0) {
          continue;
        }
        if (--remaining[successor] == 0) {
          ready.insert({keys_[successor], successor});
        }
      }
    }
    if (order.size() != keys_.size()) {
      return std::nullopt;
    }
    return order;
  }

  // Longest-path layering: a node sits one layer below its deepest prerequisite.
  // Within a layer the order is canonical by StepKey.
  [[nodiscard]] std::optional<std::vector<std::vector<std::size_t>>> longest_path_layers() const {
    const std::optional<std::vector<std::size_t>> order = lexicographic_order();
    if (!order.has_value()) {
      return std::nullopt;
    }
    std::vector<std::size_t> depth(keys_.size(), 0);
    for (const std::size_t position : *order) {
      for (const std::size_t prerequisite : prerequisites_[position]) {
        depth[position] = std::max(depth[position], depth[prerequisite] + 1);
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
      std::sort(layer.begin(), layer.end(), [this](std::size_t left, std::size_t right) {
        return keys_[left] < keys_[right];
      });
    }
    return layers;
  }

  // True when "candidate" is reachable from "target" by following prerequisites.
  // The walk deliberately never accepts the start node itself: a node is only
  // its own ancestor when a cycle leads back to it, which is exactly the
  // property rc::depends_transitively_on claims.
  [[nodiscard]] bool is_ancestor(std::size_t target, std::size_t candidate) const {
    std::vector<std::size_t> stack{target};
    std::set<std::size_t> visited;
    while (!stack.empty()) {
      const std::size_t position = stack.back();
      stack.pop_back();
      if (!visited.insert(position).second) {
        continue;
      }
      for (const std::size_t prerequisite : prerequisites_[position]) {
        if (prerequisite == candidate) {
          return true;
        }
        stack.push_back(prerequisite);
      }
    }
    return false;
  }

 private:
  std::vector<StepKey> keys_;
  std::vector<std::vector<std::size_t>> prerequisites_;
  std::vector<std::vector<std::size_t>> successors_;
};

// --- graph construction -----------------------------------------------------

// Distinct semantic keys: the kind differs per node, so no two nodes collide.
[[nodiscard]] std::vector<StepKey> node_keys(std::size_t node_count) {
  std::vector<StepKey> keys;
  keys.reserve(node_count);
  for (std::size_t node = 0; node < node_count; ++node) {
    const std::optional<rc::SubjectToken> token =
        rc::SubjectToken::make("node" + std::to_string(node));
    RC_REQUIRE(token.has_value());
    StepKey key;
    key.kind = static_cast<StepKind>(1 + (node % rc::kStepKindCount));
    key.subject = *token;
    keys.push_back(key);
  }
  return keys;
}

// Builds the declared step list in the given declaration order, with each
// prerequisite list shuffled by the caller's generator so that declaration order
// can never be mistaken for semantic order.
[[nodiscard]] std::vector<StepSpec> build_graph(const std::vector<StepKey>& keys,
                                                const std::vector<Edge>& edges,
                                                const std::vector<std::size_t>& declaration_order,
                                                Lcg& shuffle) {
  std::vector<std::vector<std::size_t>> dependencies(keys.size());
  for (const Edge& edge : edges) {
    dependencies[edge.to].push_back(edge.from);
  }
  std::vector<StepSpec> steps;
  steps.reserve(declaration_order.size());
  for (const std::size_t node : declaration_order) {
    StepSpec spec;
    spec.kind = keys[node].kind;
    spec.subject = keys[node].subject;
    spec.conflict_domains = 0;
    std::vector<StepKey> declared;
    declared.reserve(dependencies[node].size());
    for (const std::size_t source : dependencies[node]) {
      declared.push_back(keys[source]);
    }
    for (std::size_t index = declared.size(); index > 1; --index) {
      const std::size_t other = shuffle.bounded(static_cast<std::uint32_t>(index));
      std::swap(declared[index - 1], declared[other]);
    }
    spec.depends_on = declared;
    steps.push_back(std::move(spec));
  }
  return steps;
}

// --- the comparison ---------------------------------------------------------

// Every graph that declares only existing prerequisites and unique keys is
// compared on all four ordering APIs.  A graph that declares a self loop is a
// cycle by construction, which is why the acyclicity comparison is expressed as
// "the DEPENDENCY_CYCLE defect is present".
void compare_graph(const std::vector<StepSpec>& steps, std::uint64_t seed, std::size_t case_id,
                   const ConvergenceLimits& limits) {
  const Oracle oracle = Oracle::build(steps);
  RC_CHECK_EQ(oracle.size(), steps.size());

  const rc::GraphValidation validation = rc::validate_dependency_graph(steps, limits);
  bool cycle_defect = false;
  for (const rc::GraphDefect& defect : validation.defects) {
    if (defect.code == rc::ConditionCode::DEPENDENCY_CYCLE) {
      cycle_defect = true;
    }
  }
  RC_ORACLE_CHECK(!oracle.acyclic() == cycle_defect, seed, case_id,
                  "acyclicity verdict differs from DEPENDENCY_CYCLE presence");

  const std::optional<std::vector<std::size_t>> rc_order = rc::canonical_topological_order(steps);
  const std::optional<std::vector<std::size_t>> oracle_order = oracle.lexicographic_order();
  RC_ORACLE_CHECK(rc_order.has_value() == oracle_order.has_value(), seed, case_id,
                  "topological order availability differs from the oracle");
  if (rc_order.has_value() && oracle_order.has_value()) {
    RC_CHECK_EQ(rc_order->size(), steps.size());
    std::vector<std::size_t> emitted_at(steps.size(), 0);
    for (std::size_t rank = 0; rank < rc_order->size(); ++rank) {
      emitted_at[(*rc_order)[rank]] = rank;
    }
    for (std::size_t position = 0; position < steps.size(); ++position) {
      for (const StepKey& dependency : steps[position].depends_on) {
        const std::optional<std::size_t> dependency_position = oracle.position_of(dependency);
        if (!dependency_position.has_value() || *dependency_position == position) {
          continue;
        }
        RC_ORACLE_CHECK(emitted_at[*dependency_position] < emitted_at[position], seed, case_id,
                        "a dependency does not precede its dependent");
      }
    }
    RC_ORACLE_CHECK(*rc_order == *oracle_order, seed, case_id,
                    "canonical order is not the lexicographically smallest order");
  }

  const std::optional<std::vector<std::vector<std::size_t>>> rc_layers = rc::canonical_layers(steps);
  const std::optional<std::vector<std::vector<std::size_t>>> oracle_layers =
      oracle.longest_path_layers();
  RC_ORACLE_CHECK(rc_layers.has_value() == oracle_layers.has_value(), seed, case_id,
                  "layer availability differs from the oracle");
  if (rc_layers.has_value() && oracle_layers.has_value()) {
    RC_CHECK_EQ(rc_layers->size(), oracle_layers->size());
    for (std::size_t layer = 0; layer < rc_layers->size(); ++layer) {
      RC_ORACLE_CHECK((*rc_layers)[layer] == (*oracle_layers)[layer], seed, case_id,
                      "layer membership differs at layer " + std::to_string(layer));
      const std::vector<std::size_t>& members = (*rc_layers)[layer];
      for (std::size_t index = 1; index < members.size(); ++index) {
        RC_ORACLE_CHECK(oracle.keys()[members[index - 1]] < oracle.keys()[members[index]], seed,
                        case_id, "layer is not sorted by StepKey");
      }
    }
  }

  for (std::size_t target = 0; target < oracle.size(); ++target) {
    for (std::size_t candidate = 0; candidate < oracle.size(); ++candidate) {
      const bool expected = oracle.is_ancestor(target, candidate);
      const bool observed = rc::depends_transitively_on(steps, oracle.keys()[target],
                                                        oracle.keys()[candidate]);
      RC_ORACLE_CHECK(observed == expected, seed, case_id,
                      "reachability differs for target=" + std::to_string(target) +
                          " candidate=" + std::to_string(candidate));
    }
  }
}

// An unknown key must never be reported as a transitive prerequisite.
void compare_unknown_key(const std::vector<StepSpec>& steps, std::uint64_t seed,
                         std::size_t case_id) {
  StepKey unknown;
  unknown.kind = StepKind::FINALIZE;
  const std::optional<rc::SubjectToken> token = rc::SubjectToken::make("absent");
  RC_REQUIRE(token.has_value());
  unknown.subject = *token;
  const Oracle oracle = Oracle::build(steps);
  for (std::size_t target = 0; target < oracle.size(); ++target) {
    RC_ORACLE_CHECK(!rc::depends_transitively_on(steps, oracle.keys()[target], unknown), seed,
                    case_id, "an unknown key was reported as a prerequisite");
    RC_ORACLE_CHECK(!rc::depends_transitively_on(steps, unknown, oracle.keys()[target]), seed,
                    case_id, "an unknown target was reported as having prerequisites");
  }
}

// --- exhaustive and seeded graph populations --------------------------------

void check_all_small_graphs(std::uint64_t seed) {
  const ConvergenceLimits limits;
  Lcg shuffle(seed);
  std::size_t case_id = 0;
  for (std::size_t node_count = 1; node_count <= 3; ++node_count) {
    const std::vector<StepKey> keys = node_keys(node_count);
    const std::size_t pair_count = node_count * node_count;
    const std::uint32_t mask_count = 1u << pair_count;
    for (std::uint32_t mask = 0; mask < mask_count; ++mask) {
      std::vector<Edge> edges;
      for (std::size_t from = 0; from < node_count; ++from) {
        for (std::size_t to = 0; to < node_count; ++to) {
          const std::size_t bit = (from * node_count) + to;
          if ((mask & (1u << bit)) != 0) {
            edges.push_back(Edge{from, to});
          }
        }
      }
      for (int reversed = 0; reversed < 2; ++reversed) {
        std::vector<std::size_t> order;
        order.reserve(node_count);
        for (std::size_t node = 0; node < node_count; ++node) {
          order.push_back(node);
        }
        if (reversed == 1) {
          std::reverse(order.begin(), order.end());
        }
        const std::vector<StepSpec> steps = build_graph(keys, edges, order, shuffle);
        compare_graph(steps, seed, case_id, limits);
        compare_unknown_key(steps, seed, case_id);
        ++case_id;
      }
    }
  }
  RC_CHECK(case_id == 1060);
}

void check_seeded_random_graphs(std::uint64_t seed, std::size_t graph_count) {
  const ConvergenceLimits limits;
  Lcg rng(seed);
  std::size_t case_id = 0;
  std::size_t cyclic = 0;
  for (std::size_t index = 0; index < graph_count; ++index) {
    const std::size_t node_count = 4 + rng.bounded(5);
    const std::vector<StepKey> keys = node_keys(node_count);
    const std::uint32_t density = rng.bounded(100);
    std::vector<Edge> edges;
    for (std::size_t from = 0; from < node_count; ++from) {
      for (std::size_t to = 0; to < node_count; ++to) {
        if (rng.bounded(100) < density) {
          edges.push_back(Edge{from, to});
        }
      }
    }
    std::vector<std::size_t> order;
    order.reserve(node_count);
    for (std::size_t node = 0; node < node_count; ++node) {
      order.push_back(node);
    }
    for (std::size_t size = order.size(); size > 1; --size) {
      const std::size_t other = rng.bounded(static_cast<std::uint32_t>(size));
      std::swap(order[size - 1], order[other]);
    }
    const std::vector<StepSpec> steps = build_graph(keys, edges, order, rng);
    const Oracle oracle = Oracle::build(steps);
    if (!oracle.acyclic()) {
      ++cyclic;
    }
    compare_graph(steps, seed, case_id, limits);
    compare_unknown_key(steps, seed, case_id);
    ++case_id;
  }
  // The population must contain both acyclic and cyclic graphs, otherwise the
  // comparison would be vacuous.
  RC_CHECK(cyclic > 0);
  RC_CHECK(cyclic < graph_count);
}

// --- named shapes -----------------------------------------------------------

void check_named_shapes(std::uint64_t seed) {
  const ConvergenceLimits limits;
  Lcg shuffle(seed);
  const std::vector<StepKey> keys = node_keys(4);
  std::vector<std::size_t> order{0, 1, 2, 3};

  // Diamond: node 1 and node 2 depend on node 0, node 3 depends on both.
  const std::vector<Edge> diamond{Edge{0, 1}, Edge{0, 2}, Edge{1, 3}, Edge{2, 3}};
  const std::vector<StepSpec> acyclic_steps = build_graph(keys, diamond, order, shuffle);
  const Oracle acyclic_oracle = Oracle::build(acyclic_steps);
  RC_ORACLE_CHECK(acyclic_oracle.acyclic(), seed, 0, "diamond must be acyclic");
  const std::optional<std::vector<std::size_t>> acyclic_order = acyclic_oracle.lexicographic_order();
  RC_REQUIRE(acyclic_order.has_value());
  RC_CHECK_EQ(*acyclic_order, (std::vector<std::size_t>{0, 1, 2, 3}));
  RC_CHECK_EQ(rc::canonical_topological_order(acyclic_steps).value_or(std::vector<std::size_t>{}),
              (std::vector<std::size_t>{0, 1, 2, 3}));
  const std::optional<std::vector<std::vector<std::size_t>>> acyclic_layers =
      acyclic_oracle.longest_path_layers();
  RC_REQUIRE(acyclic_layers.has_value());
  RC_CHECK_EQ(acyclic_layers->size(), static_cast<std::size_t>(3));
  RC_CHECK_EQ((*acyclic_layers)[1], (std::vector<std::size_t>{1, 2}));
  RC_ORACLE_CHECK(acyclic_oracle.is_ancestor(3, 0), seed, 0, "node 0 must precede node 3");
  RC_ORACLE_CHECK(!acyclic_oracle.is_ancestor(0, 3), seed, 0, "node 3 must not precede node 0");
  compare_graph(acyclic_steps, seed, 1, limits);

  // The same diamond declared in reverse order keeps the identical canonical
  // order: the answer must not depend on insertion order.
  const std::vector<std::size_t> reversed{3, 2, 1, 0};
  const std::vector<StepSpec> reversed_steps = build_graph(keys, diamond, reversed, shuffle);
  RC_CHECK_EQ(rc::canonical_topological_order(reversed_steps).value_or(std::vector<std::size_t>{}),
              (std::vector<std::size_t>{3, 2, 1, 0}));

  // A self loop is a cycle and must deny both an order and a layering.
  const std::vector<Edge> self_loop{Edge{2, 2}};
  const std::vector<StepSpec> self_loop_steps = build_graph(keys, self_loop, order, shuffle);
  RC_ORACLE_CHECK(!Oracle::build(self_loop_steps).acyclic(), seed, 2, "a self loop is a cycle");
  RC_CHECK(!rc::canonical_topological_order(self_loop_steps).has_value());
  RC_CHECK(!rc::canonical_layers(self_loop_steps).has_value());
  compare_graph(self_loop_steps, seed, 2, limits);

  // A two-node cycle.
  const std::vector<Edge> two_cycle{Edge{1, 2}, Edge{2, 1}};
  const std::vector<StepSpec> two_cycle_steps = build_graph(keys, two_cycle, order, shuffle);
  RC_ORACLE_CHECK(!Oracle::build(two_cycle_steps).acyclic(), seed, 3, "a two node cycle is a cycle");
  RC_CHECK(!rc::canonical_topological_order(two_cycle_steps).has_value());
  compare_graph(two_cycle_steps, seed, 3, limits);
}

// --- generated step graphs --------------------------------------------------

[[nodiscard]] rc::RouteBinding binding_with_group(rc::RouteBinding binding, std::uint64_t group_seed,
                                                  std::uint64_t ecmp_generation,
                                                  std::uint64_t assignment_generation) {
  binding.ecmp_group = rc::test::Fixture::group_for(group_seed);
  binding.ecmp_generation = rc::ECMPGroupGeneration::from_value(ecmp_generation);
  binding.assignment_generation = rc::AssignmentGeneration::from_value(assignment_generation);
  return binding;
}

// Checks the policy-ordering contract with the oracle's own reachability: under
// MAKE_BEFORE_BREAK the make side must strictly precede the break side, and under
// BREAK_BEFORE_MAKE the reverse must hold.
void check_generated_ordering(const rc::RouteBinding& source, const rc::RouteBinding& target,
                              const rc::ConvergencePolicy& policy, std::uint64_t seed,
                              std::size_t case_id) {
  const ConvergenceLimits limits;
  std::string reason;
  const std::optional<std::vector<StepSpec>> generated =
      rc::generate_steps(source, target, policy, limits, reason);
  RC_ORACLE_CHECK(generated.has_value(), seed, case_id, "generate_steps failed: " + reason);
  if (!generated.has_value()) {
    return;
  }
  const std::vector<StepSpec>& steps = *generated;
  const Oracle oracle = Oracle::build(steps);
  RC_ORACLE_CHECK(oracle.acyclic(), seed, case_id, "a generated graph must be acyclic");
  compare_graph(steps, seed, case_id, limits);

  std::optional<std::size_t> install_position;
  std::optional<std::size_t> withdraw_position;
  for (std::size_t position = 0; position < steps.size(); ++position) {
    if (steps[position].kind == StepKind::INSTALL_NEW_ROUTE) {
      install_position = position;
    }
    if (steps[position].kind == StepKind::WITHDRAW_OLD_ROUTE) {
      withdraw_position = position;
    }
  }
  RC_ORACLE_CHECK(install_position.has_value() && withdraw_position.has_value(), seed, case_id,
                  "a generated plan must contain both route-side steps");

  if (policy.ordering == rc::OrderingMode::MAKE_BEFORE_BREAK) {
    RC_ORACLE_CHECK(oracle.is_ancestor(*withdraw_position, *install_position), seed, case_id,
                    "MAKE_BEFORE_BREAK must install the new route before withdrawing the old one");
    RC_ORACLE_CHECK(!oracle.is_ancestor(*install_position, *withdraw_position), seed, case_id,
                    "MAKE_BEFORE_BREAK must not withdraw the old route before installing the new one");
  } else {
    RC_ORACLE_CHECK(oracle.is_ancestor(*install_position, *withdraw_position), seed, case_id,
                    "BREAK_BEFORE_MAKE must withdraw the old route before installing the new one");
    RC_ORACLE_CHECK(!oracle.is_ancestor(*withdraw_position, *install_position), seed, case_id,
                    "BREAK_BEFORE_MAKE must not install the new route before withdrawing the old one");
  }

  const std::optional<std::vector<std::size_t>> order = oracle.lexicographic_order();
  RC_REQUIRE(order.has_value());
  const std::size_t install_rank =
      static_cast<std::size_t>(std::find(order->begin(), order->end(), *install_position) - order->begin());
  const std::size_t withdraw_rank =
      static_cast<std::size_t>(std::find(order->begin(), order->end(), *withdraw_position) - order->begin());
  if (policy.ordering == rc::OrderingMode::MAKE_BEFORE_BREAK) {
    RC_ORACLE_CHECK(install_rank < withdraw_rank, seed, case_id,
                    "canonical order places the break step before the make step");
  } else {
    RC_ORACLE_CHECK(withdraw_rank < install_rank, seed, case_id,
                    "canonical order places the make step before the break step");
  }
}

}  // namespace

RC_TEST(oracle_matches_rc_on_every_small_graph) {
  const std::uint64_t seed = 0x9E3779B97F4A7C15ull;
  check_all_small_graphs(seed);
}

RC_TEST(oracle_matches_rc_on_seeded_random_graphs) {
  const std::uint64_t seed = 0xD1B54A32D192ED03ull;
  check_seeded_random_graphs(seed, 2400);
}

RC_TEST(oracle_matches_rc_on_named_shapes) {
  const std::uint64_t seed = 0x2545F4914F6CDD1Dull;
  check_named_shapes(seed);
}

RC_TEST(generated_make_before_break_keeps_make_side_first) {
  const std::uint64_t seed = 0x8BADF00D5EED1234ull;
  const rc::RouteBinding source = rc::test::Fixture::binding(1, 1, 1, 1);
  const rc::RouteBinding target = rc::test::Fixture::binding(1, 2, 2, 1);
  check_generated_ordering(source, target, rc::test::Fixture::policy(1), seed, 0);
}

RC_TEST(generated_break_before_make_keeps_break_side_first) {
  const std::uint64_t seed = 0x0BADCAFE5EED5678ull;
  const rc::RouteBinding source = rc::test::Fixture::binding(1, 1, 1, 1);
  const rc::RouteBinding target = rc::test::Fixture::binding(1, 2, 2, 1);
  const rc::ConvergencePolicy policy =
      rc::test::Fixture::policy(2, rc::OrderingMode::BREAK_BEFORE_MAKE, true, 4, 2);
  check_generated_ordering(source, target, policy, seed, 0);
}

RC_TEST(generated_ordering_holds_for_shared_path_and_group_change) {
  const std::uint64_t seed = 0x5EEDF00D12345678ull;
  // Shared path: the generator emits no path-side steps, so the ordering
  // guarantee has to come from the verify/finalize chain alone.
  const rc::RouteBinding shared_source = rc::test::Fixture::binding(3, 5, 7, 9);
  const rc::RouteBinding shared_target = rc::test::Fixture::binding(3, 6, 7, 9);
  check_generated_ordering(shared_source, shared_target, rc::test::Fixture::policy(1), seed, 0);
  const rc::ConvergencePolicy break_first =
      rc::test::Fixture::policy(2, rc::OrderingMode::BREAK_BEFORE_MAKE, true, 4, 2);
  check_generated_ordering(shared_source, shared_target, break_first, seed, 1);

  // Group change: an INSTALL_NEW_GROUP step joins the make side.
  const rc::RouteBinding group_source =
      binding_with_group(rc::test::Fixture::binding(5, 11, 13, 17), 21, 1, 1);
  const rc::RouteBinding group_target =
      binding_with_group(rc::test::Fixture::binding(5, 12, 19, 17), 21, 2, 2);
  check_generated_ordering(group_source, group_target, rc::test::Fixture::policy(1), seed, 2);
  check_generated_ordering(group_source, group_target, break_first, seed, 3);
}
