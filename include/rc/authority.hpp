#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "rc/identity.hpp"

namespace rc {

// Explicit authority scope.  The default value denies everything: a caller that
// presents no scope is never granted wildcard authority.  Connected is not
// authorized, and a persisted plan is not live authority.
//
// Route Convergence does not own route metadata (no fabric membership, no
// namespace membership, no topology).  The precise scopes are therefore PLAN and
// ROUTE.  A ROUTING_NAMESPACE or FABRIC scope is deliberately described for what
// it is: authority over every route the coordinator instance holds, narrowed only
// when the coordinator is configured with a fabric and namespace identity that
// the scope must match.
enum class ScopeKind : std::uint32_t {
  DENY_ALL = 0,
  PLAN = 1,
  ROUTE = 2,
  ROUTING_NAMESPACE = 3,
  FABRIC = 4,
};

[[nodiscard]] std::string_view to_string(ScopeKind kind) noexcept;

struct AuthorityScope {
  ScopeKind kind = ScopeKind::DENY_ALL;
  FabricId fabric;
  RoutingNamespaceId routing_namespace;
  RouteId route;
  ConvergencePlanId plan;

  [[nodiscard]] static AuthorityScope deny_all() noexcept { return AuthorityScope{}; }
  [[nodiscard]] static AuthorityScope for_plan(ConvergencePlanId id) noexcept;
  [[nodiscard]] static AuthorityScope for_route(RouteId id, RoutingNamespaceId routing_namespace,
                                               FabricId fabric) noexcept;
  [[nodiscard]] static AuthorityScope for_routing_namespace(RoutingNamespaceId id,
                                                           FabricId fabric) noexcept;
  [[nodiscard]] static AuthorityScope for_fabric(FabricId id) noexcept;

  // True when this scope is well formed for its kind.
  [[nodiscard]] bool is_well_formed() const noexcept;

  // True when this scope grants authority over `route_id`.  The coordinator
  // identity is compared only for the fields both sides specify; a nil identity
  // field means "not asserted".
  [[nodiscard]] bool covers_route(const FabricId& coordinator_fabric,
                                  const RoutingNamespaceId& coordinator_namespace,
                                  const RouteId& route_id) const noexcept;

  // True when this scope grants authority to mutate the exact plan.
  [[nodiscard]] bool covers_plan(const FabricId& coordinator_fabric,
                                 const RoutingNamespaceId& coordinator_namespace,
                                 const RouteId& route_id,
                                 const ConvergencePlanId& plan_id) const noexcept;

  [[nodiscard]] std::string render() const;

  friend bool operator==(const AuthorityScope&, const AuthorityScope&) = default;
};

enum class Capability : std::uint32_t {
  NONE = 0,
  CREATE_PLAN = 1u << 0,
  DISPATCH_STEP = 1u << 1,
  COMPLETE_STEP = 1u << 2,
  REVALIDATE_PLAN = 1u << 3,
  ROLLBACK = 1u << 4,
  ADMIN = 1u << 5,
  PUBLISH_UPSTREAM = 1u << 6,
};

[[nodiscard]] std::string_view to_string(Capability capability) noexcept;
[[nodiscard]] bool has_capability(std::uint32_t set, Capability capability) noexcept;

struct PublisherRegistration {
  PublisherId publisher;
  WorkerBootId worker_boot;
  AuthorityScope scope;
  std::uint32_t capabilities = 0;
  ProvenanceId provenance;

  [[nodiscard]] bool is_well_formed() const noexcept {
    return !publisher.is_nil() && !worker_boot.is_nil() && scope.is_well_formed();
  }
};

// Everything an authoritative mutation must bind.  A fresh process is a fresh
// WorkerBootId: the old boot is fenced permanently and can never dispatch,
// acknowledge, complete, roll back or finalize anything again.
struct AuthorityContext {
  CoordinatorEpoch epoch;
  PublisherId publisher;
  WorkerBootId worker_boot;
  MutationAttemptId attempt;
  std::optional<ConvergencePlanGeneration> expected_plan_generation;
  std::optional<TransitionStepGeneration> expected_step_generation;

  [[nodiscard]] bool is_well_formed() const noexcept {
    return !publisher.is_nil() && !worker_boot.is_nil() && !attempt.is_nil();
  }
};

}  // namespace rc
