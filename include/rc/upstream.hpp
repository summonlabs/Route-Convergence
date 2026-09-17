#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "rc/identity.hpp"
#include "rc/outcome.hpp"

namespace rc {

// Exact route state as published by Route Fabric.  Route Convergence never
// invents, edits or repairs a route binding: it consumes one, binds it exactly
// and rejects its own work the moment the binding stops being current.
//
// The multipath, ECMP membership, assignment and weighted-policy generations are
// consumed exactly as Route Fabric publishes them.  Route Convergence sequences
// transitions between those exact generations; it never computes bucket
// ownership, never computes a weight and never edits a multipath set.
struct RouteBinding {
  RouteId route;
  RouteGeneration generation;
  PathId path;
  PathAuthorityGeneration path_authority_generation;
  MultipathSetId multipath_set;
  MultipathSetGeneration multipath_generation;
  ECMPGroupId ecmp_group;
  ECMPGroupGeneration ecmp_generation;
  AssignmentGeneration assignment_generation;
  WeightedPathSetId weighted_set;
  WeightPolicyGeneration weight_policy_generation;
  // Route Fabric lifecycle facts.  `current` is "this generation is still the
  // authoritative route generation"; `legal` is "this route is administratively
  // permitted to carry traffic".
  bool current = true;
  bool legal = true;

  [[nodiscard]] bool is_well_formed() const noexcept;
  [[nodiscard]] std::string render() const;

  friend bool operator==(const RouteBinding&, const RouteBinding&) = default;
};

// Exact path legality as published by Path Authority.  A path is usable only for
// the exact generation that Path Authority currently asserts.
struct PathLegality {
  PathId path;
  PathAuthorityGeneration generation;
  bool legal = false;

  [[nodiscard]] bool is_well_formed() const noexcept { return !path.is_nil(); }
  [[nodiscard]] std::string render() const;

  friend bool operator==(const PathLegality&, const PathLegality&) = default;
};

// Upstream observation seams.  Every one of them is read-only: Route Convergence
// never writes route state, path legality, topology or epochs back through them.
class RouteFabricView {
 public:
  RouteFabricView() = default;
  virtual ~RouteFabricView() = default;
  RouteFabricView(const RouteFabricView&) = delete;
  RouteFabricView& operator=(const RouteFabricView&) = delete;

  [[nodiscard]] virtual std::optional<RouteBinding> observe_route(const RouteId& route) const = 0;
};

class PathAuthorityView {
 public:
  PathAuthorityView() = default;
  virtual ~PathAuthorityView() = default;
  PathAuthorityView(const PathAuthorityView&) = delete;
  PathAuthorityView& operator=(const PathAuthorityView&) = delete;

  [[nodiscard]] virtual std::optional<PathLegality> observe_path(const PathId& path) const = 0;
};

class FabricEpochView {
 public:
  FabricEpochView() = default;
  virtual ~FabricEpochView() = default;
  FabricEpochView(const FabricEpochView&) = delete;
  FabricEpochView& operator=(const FabricEpochView&) = delete;

  [[nodiscard]] virtual CoordinatorEpoch current_epoch() const = 0;
};

// Change notices.  A notice is an event, never an observation: the governor
// re-observes through the views above and reacts to the observation, so a forged
// or replayed notice cannot move convergence state on its own.
struct RouteChangeNotice {
  RouteBinding binding;
  ProvenanceId provenance;

  [[nodiscard]] bool is_well_formed() const noexcept {
    return binding.is_well_formed() && !provenance.is_nil();
  }
};

struct PathChangeNotice {
  PathLegality legality;
  ProvenanceId provenance;

  [[nodiscard]] bool is_well_formed() const noexcept {
    return legality.is_well_formed() && !provenance.is_nil();
  }
};

struct EpochChangeNotice {
  CoordinatorEpoch previous;
  CoordinatorEpoch current;
  ProvenanceId provenance;

  [[nodiscard]] bool is_well_formed() const noexcept {
    return !provenance.is_nil() && current.value() > previous.value();
  }
};

}  // namespace rc
