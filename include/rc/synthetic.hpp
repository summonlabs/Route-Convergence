#pragma once

#include <map>
#include <mutex>
#include <optional>
#include <vector>

#include "rc/upstream.hpp"

namespace rc {

// In-memory upstream observation source.
//
// It is named SYNTHETIC on purpose.  When a coordinator is started without a real
// Route Fabric and Path Authority attached, it uses this adapter so that the
// control-plane protocol, the persistence layer and the real-process proofs can
// be exercised end to end.  Nothing observed here is physical convergence: it is
// a control-plane fixture, and the README says so.
class SyntheticUpstream : public RouteFabricView, public PathAuthorityView, public FabricEpochView {
 public:
  explicit SyntheticUpstream(CoordinatorEpoch initial_epoch);

  [[nodiscard]] std::optional<RouteBinding> observe_route(const RouteId& route) const override;
  [[nodiscard]] std::optional<PathLegality> observe_path(const PathId& path) const override;
  [[nodiscard]] CoordinatorEpoch current_epoch() const override;

  // Fixture administration.  Replacing a route binding replaces the whole exact
  // binding: Route Convergence never merges a partial observation into a route.
  void set_route(const RouteBinding& binding);
  bool remove_route(const RouteId& route);
  void set_path(const PathLegality& legality);
  bool remove_path(const PathId& path);
  void set_epoch(CoordinatorEpoch epoch);
  void clear();

  [[nodiscard]] std::vector<RouteBinding> routes() const;
  [[nodiscard]] std::optional<RouteBinding> route(const RouteId& id) const;
  [[nodiscard]] std::optional<PathLegality> path(const PathId& id) const;

 private:
  mutable std::mutex mutex_;
  std::map<RouteId, RouteBinding> routes_;
  std::map<PathId, PathLegality> paths_;
  CoordinatorEpoch epoch_;
};

// Builds a coherent route binding for fixtures.  Every generation is explicit;
// nothing is inferred from anything else.
[[nodiscard]] RouteBinding make_route_binding(const RouteId& route, RouteGeneration route_generation,
                                              const PathId& path,
                                              PathAuthorityGeneration path_generation);

}  // namespace rc
