#include "rc/synthetic.hpp"

namespace rc {

SyntheticUpstream::SyntheticUpstream(CoordinatorEpoch initial_epoch) : epoch_(initial_epoch) {}

std::optional<RouteBinding> SyntheticUpstream::observe_route(const RouteId& route) const {
  const std::lock_guard<std::mutex> lock(mutex_);
  const auto entry = routes_.find(route);
  if (entry == routes_.end()) {
    return std::nullopt;
  }
  return entry->second;
}

std::optional<PathLegality> SyntheticUpstream::observe_path(const PathId& path) const {
  const std::lock_guard<std::mutex> lock(mutex_);
  const auto entry = paths_.find(path);
  if (entry == paths_.end()) {
    return std::nullopt;
  }
  return entry->second;
}

CoordinatorEpoch SyntheticUpstream::current_epoch() const {
  const std::lock_guard<std::mutex> lock(mutex_);
  return epoch_;
}

void SyntheticUpstream::set_route(const RouteBinding& binding) {
  const std::lock_guard<std::mutex> lock(mutex_);
  routes_[binding.route] = binding;
}

bool SyntheticUpstream::remove_route(const RouteId& route) {
  const std::lock_guard<std::mutex> lock(mutex_);
  return routes_.erase(route) != 0;
}

void SyntheticUpstream::set_path(const PathLegality& legality) {
  const std::lock_guard<std::mutex> lock(mutex_);
  paths_[legality.path] = legality;
}

bool SyntheticUpstream::remove_path(const PathId& path) {
  const std::lock_guard<std::mutex> lock(mutex_);
  return paths_.erase(path) != 0;
}

void SyntheticUpstream::set_epoch(CoordinatorEpoch epoch) {
  const std::lock_guard<std::mutex> lock(mutex_);
  epoch_ = epoch;
}

void SyntheticUpstream::clear() {
  const std::lock_guard<std::mutex> lock(mutex_);
  routes_.clear();
  paths_.clear();
}

std::vector<RouteBinding> SyntheticUpstream::routes() const {
  const std::lock_guard<std::mutex> lock(mutex_);
  std::vector<RouteBinding> out;
  out.reserve(routes_.size());
  for (const auto& entry : routes_) {
    out.push_back(entry.second);
  }
  return out;
}

std::optional<RouteBinding> SyntheticUpstream::route(const RouteId& id) const {
  return observe_route(id);
}

std::optional<PathLegality> SyntheticUpstream::path(const PathId& id) const {
  return observe_path(id);
}

RouteBinding make_route_binding(const RouteId& route, RouteGeneration route_generation,
                                const PathId& path, PathAuthorityGeneration path_generation) {
  RouteBinding binding;
  binding.route = route;
  binding.generation = route_generation;
  binding.path = path;
  binding.path_authority_generation = path_generation;
  binding.current = true;
  binding.legal = true;
  return binding;
}

}  // namespace rc
