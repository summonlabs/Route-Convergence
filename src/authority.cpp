#include "rc/authority.hpp"

namespace rc {

std::string_view to_string(ScopeKind kind) noexcept {
  switch (kind) {
    case ScopeKind::DENY_ALL: return "DENY_ALL";
    case ScopeKind::PLAN: return "PLAN";
    case ScopeKind::ROUTE: return "ROUTE";
    case ScopeKind::ROUTING_NAMESPACE: return "ROUTING_NAMESPACE";
    case ScopeKind::FABRIC: return "FABRIC";
  }
  return "UNKNOWN";
}

AuthorityScope AuthorityScope::for_plan(ConvergencePlanId id) noexcept {
  AuthorityScope scope;
  scope.kind = ScopeKind::PLAN;
  scope.plan = id;
  return scope;
}

AuthorityScope AuthorityScope::for_route(RouteId id, RoutingNamespaceId routing_namespace,
                                         FabricId fabric) noexcept {
  AuthorityScope scope;
  scope.kind = ScopeKind::ROUTE;
  scope.route = id;
  scope.routing_namespace = routing_namespace;
  scope.fabric = fabric;
  return scope;
}

AuthorityScope AuthorityScope::for_routing_namespace(RoutingNamespaceId id,
                                                     FabricId fabric) noexcept {
  AuthorityScope scope;
  scope.kind = ScopeKind::ROUTING_NAMESPACE;
  scope.routing_namespace = id;
  scope.fabric = fabric;
  return scope;
}

AuthorityScope AuthorityScope::for_fabric(FabricId id) noexcept {
  AuthorityScope scope;
  scope.kind = ScopeKind::FABRIC;
  scope.fabric = id;
  return scope;
}

bool AuthorityScope::is_well_formed() const noexcept {
  switch (kind) {
    case ScopeKind::DENY_ALL: return true;
    case ScopeKind::PLAN: return !plan.is_nil();
    case ScopeKind::ROUTE: return !route.is_nil();
    case ScopeKind::ROUTING_NAMESPACE: return !routing_namespace.is_nil();
    case ScopeKind::FABRIC: return !fabric.is_nil();
  }
  return false;
}

namespace {

[[nodiscard]] bool identity_matches(const FabricId& scope_fabric, const FabricId& coordinator_fabric,
                                    const RoutingNamespaceId& scope_namespace,
                                    const RoutingNamespaceId& coordinator_namespace) noexcept {
  if (!scope_fabric.is_nil() && !coordinator_fabric.is_nil() && !(scope_fabric == coordinator_fabric)) {
    return false;
  }
  if (!scope_namespace.is_nil() && !coordinator_namespace.is_nil() &&
      !(scope_namespace == coordinator_namespace)) {
    return false;
  }
  return true;
}

}  // namespace

bool AuthorityScope::covers_route(const FabricId& coordinator_fabric,
                                  const RoutingNamespaceId& coordinator_namespace,
                                  const RouteId& route_id) const noexcept {
  if (kind == ScopeKind::DENY_ALL || kind == ScopeKind::PLAN) {
    // A plan scope is not route-level authority.
    return false;
  }
  if (!identity_matches(fabric, coordinator_fabric, routing_namespace, coordinator_namespace)) {
    return false;
  }
  if (kind == ScopeKind::ROUTE) {
    return route == route_id;
  }
  return true;
}

bool AuthorityScope::covers_plan(const FabricId& coordinator_fabric,
                                 const RoutingNamespaceId& coordinator_namespace,
                                 const RouteId& route_id,
                                 const ConvergencePlanId& plan_id) const noexcept {
  if (kind == ScopeKind::DENY_ALL) {
    return false;
  }
  if (!identity_matches(fabric, coordinator_fabric, routing_namespace, coordinator_namespace)) {
    return false;
  }
  if (kind == ScopeKind::PLAN) {
    return plan == plan_id;
  }
  if (kind == ScopeKind::ROUTE) {
    return route == route_id;
  }
  return true;
}

std::string AuthorityScope::render() const {
  std::string out = "scope=";
  out += to_string(kind);
  if (!plan.is_nil()) {
    out += " plan=" + plan.to_text();
  }
  if (!route.is_nil()) {
    out += " route=" + route.to_text();
  }
  if (!routing_namespace.is_nil()) {
    out += " routing_namespace=" + routing_namespace.to_text();
  }
  if (!fabric.is_nil()) {
    out += " fabric=" + fabric.to_text();
  }
  return out;
}

std::string_view to_string(Capability capability) noexcept {
  switch (capability) {
    case Capability::NONE: return "NONE";
    case Capability::CREATE_PLAN: return "CREATE_PLAN";
    case Capability::DISPATCH_STEP: return "DISPATCH_STEP";
    case Capability::COMPLETE_STEP: return "COMPLETE_STEP";
    case Capability::REVALIDATE_PLAN: return "REVALIDATE_PLAN";
    case Capability::ROLLBACK: return "ROLLBACK";
    case Capability::ADMIN: return "ADMIN";
    case Capability::PUBLISH_UPSTREAM: return "PUBLISH_UPSTREAM";
  }
  return "UNKNOWN";
}

bool has_capability(std::uint32_t set, Capability capability) noexcept {
  return (set & static_cast<std::uint32_t>(capability)) != 0;
}

}  // namespace rc
