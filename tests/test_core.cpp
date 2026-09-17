// Core determinism tests: identities, encodings, digests, lifecycle tables,
// dependency graphs, policy coherence and authority scopes.
//
// Everything here is REPRODUCIBLE IN-PROCESS state.  Nothing in this file is a
// physical-fabric claim.

#include <algorithm>
#include <array>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "fixture.hpp"
#include "test_framework.hpp"

using namespace rc;
using rc::test::Fixture;
using rc::test::has_condition;

namespace {

[[nodiscard]] StepSpec make_spec(StepKind kind, std::string_view subject,
                                 std::vector<StepKey> dependencies = {},
                                 std::uint32_t domains = 0,
                                 Reversibility reversibility = Reversibility::COMPENSATABLE,
                                 bool mandatory = true) {
  StepSpec spec;
  spec.kind = kind;
  const std::optional<SubjectToken> token = SubjectToken::make(subject);
  RC_REQUIRE(token.has_value());
  spec.subject = *token;
  spec.depends_on = std::move(dependencies);
  spec.conflict_domains = domains;
  spec.reversibility = reversibility;
  spec.mandatory = mandatory;
  spec.idempotent = true;
  return spec;
}

}  // namespace

RC_TEST(identity_round_trip_and_rejection) {
  const ConvergencePlanId id = ConvergencePlanId::from_u64(0x0123456789ABCDEFull, 0x0FEDCBA987654321ull);
  RC_CHECK_EQ(id.to_text().size(), std::size_t{32});
  RC_CHECK(!id.is_nil());
  const std::optional<ConvergencePlanId> parsed = ConvergencePlanId::parse(id.to_text());
  RC_REQUIRE(parsed.has_value());
  RC_CHECK(*parsed == id);
  const std::optional<ConvergencePlanId> upper = ConvergencePlanId::parse("0123456789ABCDEF0FEDCBA987654321");
  RC_REQUIRE(upper.has_value());
  RC_CHECK(*upper == id);
  RC_CHECK(!ConvergencePlanId::parse("").has_value());
  RC_CHECK(!ConvergencePlanId::parse("0123456789abcdef0fedcba98765432").has_value());
  RC_CHECK(!ConvergencePlanId::parse("0123456789abcdef0fedcba987654321g").has_value());
  RC_CHECK(ConvergencePlanId{}.is_nil());
  RC_CHECK(ConvergencePlanId::from_u64(1, 0) < ConvergencePlanId::from_u64(2, 0));
}

RC_TEST(generation_is_checked_and_never_wraps) {
  const ConvergencePlanGeneration maximum =
      ConvergencePlanGeneration::from_value(ConvergencePlanGeneration::kMaximum);
  RC_CHECK(!maximum.next().has_value());
  const ConvergencePlanGeneration one = ConvergencePlanGeneration::from_value(1);
  const std::optional<ConvergencePlanGeneration> two = one.next();
  RC_REQUIRE(two.has_value());
  RC_CHECK_EQ(two->value(), std::uint64_t{2});
  RC_CHECK(ConvergencePlanGeneration{}.is_zero());
  const CoordinatorEpoch epoch = CoordinatorEpoch::from_value(7);
  RC_CHECK_EQ(epoch.value(), std::uint64_t{7});
}

RC_TEST(subject_tokens_reject_malformed_spellings) {
  RC_CHECK(!SubjectToken::make("").has_value());
  RC_CHECK(!SubjectToken::make("with space").has_value());
  RC_CHECK(!SubjectToken::make("line\nbreak").has_value());
  RC_CHECK(!SubjectToken::make(std::string(kAbsoluteMaxSubjectBytes + 1, 'a')).has_value());
  const std::optional<SubjectToken> ok = SubjectToken::make("0123456789abcdef");
  RC_REQUIRE(ok.has_value());
  RC_CHECK_EQ(ok->text(), std::string("0123456789abcdef"));
}

RC_TEST(encoder_decoder_round_trip_and_latching) {
  Encoder encoder(64);
  encoder.u8(0x12);
  encoder.u16(0x1234);
  encoder.u32(0x12345678);
  encoder.u64(0x123456789ABCDEF0ull);
  encoder.boolean(true);
  encoder.text("hello");
  encoder.blob(std::span<const std::uint8_t>());
  const std::vector<std::uint8_t> bytes = encoder.bytes();

  Decoder decoder(bytes, 64);
  std::uint8_t u8 = 0;
  std::uint16_t u16 = 0;
  std::uint32_t u32 = 0;
  std::uint64_t u64 = 0;
  bool flag = false;
  std::string text;
  std::vector<std::uint8_t> blob;
  RC_REQUIRE(decoder.u8(u8));
  RC_REQUIRE(decoder.u16(u16));
  RC_REQUIRE(decoder.u32(u32));
  RC_REQUIRE(decoder.u64(u64));
  RC_REQUIRE(decoder.boolean(flag));
  RC_REQUIRE(decoder.text(text, 64));
  RC_REQUIRE(decoder.blob(blob, 64));
  RC_CHECK_EQ(u8, std::uint8_t{0x12});
  RC_CHECK_EQ(u16, std::uint16_t{0x1234});
  RC_CHECK_EQ(u32, std::uint32_t{0x12345678});
  RC_CHECK_EQ(u64, 0x123456789ABCDEF0ull);
  RC_CHECK(flag);
  RC_CHECK_EQ(text, std::string("hello"));
  RC_CHECK(blob.empty());
  RC_CHECK(decoder.at_end());

  // A failed read latches the decoder: a partially decoded message can never be
  // mistaken for a valid one.
  Decoder latched(bytes, 64);
  std::uint64_t value = 0;
  RC_CHECK(latched.u64(value));
  RC_CHECK(!latched.skip(bytes.size()));  // only 21 bytes remain
  RC_CHECK(latched.failed());
  RC_CHECK(!latched.u8(u8));  // the failure is latched
  RC_CHECK(latched.failed());

  // A boolean that is neither 0 nor 1 is malformed.
  const std::vector<std::uint8_t> malformed{2};
  Decoder boolean_decoder(malformed, 8);
  RC_CHECK(!boolean_decoder.boolean(flag));

  // An over-long blob is refused before anything is allocated.
  Encoder big(4);
  big.blob(std::vector<std::uint8_t>(16, 0));
  RC_CHECK(!big.ok());
}

RC_TEST(sha256_known_vectors_and_domain_separation) {
  const Sha256::Value empty = Sha256::hash(std::span<const std::uint8_t>());
  Digest digest = Digest::from_bytes(empty);
  RC_CHECK_EQ(digest.to_text(),
              std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  Sha256 hasher;
  hasher.update(std::string_view("abc"));
  digest = Digest::from_bytes(hasher.finish());
  RC_CHECK_EQ(digest.to_text(),
              std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  const std::optional<Digest> parsed = Digest::parse(digest.to_text());
  RC_REQUIRE(parsed.has_value());
  RC_CHECK(*parsed == digest);
  RC_CHECK(!Digest::parse("xyz").has_value());

  const std::vector<std::uint8_t> payload{1, 2, 3};
  RC_CHECK(domain_digest("a", payload) != domain_digest("b", payload));
  RC_CHECK(domain_digest("a", payload) == domain_digest("a", payload));
}

RC_TEST(plan_transition_table_is_total_and_consistent) {
  const std::vector<PlanTransitionRule>& table = plan_transition_table();
  RC_CHECK(!table.empty());
  std::map<std::pair<std::uint32_t, std::uint32_t>, std::set<std::uint32_t>> targets;
  for (const PlanTransitionRule& rule : table) {
    targets[{static_cast<std::uint32_t>(rule.from), static_cast<std::uint32_t>(rule.event)}].insert(
        static_cast<std::uint32_t>(rule.to));
  }
  for (const auto& entry : targets) {
    if (entry.first.second == static_cast<std::uint32_t>(PlanEvent::STEP_FAILED)) {
      // STEP_FAILED has two legal targets chosen from the transition inputs.
      RC_CHECK_EQ(entry.second.size(), std::size_t{2});
      continue;
    }
    RC_CHECK_EQ(entry.second.size(), std::size_t{1});
  }
  // Every (state, event) pair is decided: legal or denied, never unspecified.
  for (std::uint32_t state = 1; state <= kPlanLifecycleCount; ++state) {
    for (std::uint32_t event = 1; event <= kPlanEventCount; ++event) {
      const PlanLifecycle lifecycle = static_cast<PlanLifecycle>(state);
      const PlanEvent plan_event = static_cast<PlanEvent>(event);
      const bool allowed = plan_lifecycle_allows(lifecycle, plan_event);
      PlanTransitionInputs inputs;
      inputs.mandatory_steps_terminal = true;
      inputs.target_current = true;
      inputs.dependency_current = true;
      inputs.policy_current = true;
      const std::optional<PlanLifecycle> applied = apply_plan_event(lifecycle, plan_event, inputs);
      RC_CHECK_EQ(allowed, applied.has_value());
      if (applied.has_value()) {
        RC_CHECK_EQ(apply_plan_event(lifecycle, plan_event, inputs).value(), *applied);
      }
    }
  }
  // RETIRED is absolutely terminal.
  for (std::uint32_t event = 1; event <= kPlanEventCount; ++event) {
    RC_CHECK(!plan_lifecycle_allows(PlanLifecycle::RETIRED, static_cast<PlanEvent>(event)));
  }
  RC_CHECK(is_terminal_lifecycle(PlanLifecycle::COMPLETED));
  RC_CHECK(is_terminal_lifecycle(PlanLifecycle::SUPERSEDED));
  RC_CHECK(is_terminal_lifecycle(PlanLifecycle::REVOKED));
  RC_CHECK(is_terminal_lifecycle(PlanLifecycle::RETIRED));
  RC_CHECK(!is_terminal_lifecycle(PlanLifecycle::EXECUTING));
  RC_CHECK(is_absolutely_terminal(PlanLifecycle::RETIRED));
  RC_CHECK(is_retirable(PlanLifecycle::COMPLETED));
  RC_CHECK(!is_retirable(PlanLifecycle::EXECUTING));
}

RC_TEST(step_transition_table_is_total_and_consistent) {
  const std::vector<StepTransitionRule>& table = step_transition_table();
  RC_CHECK(!table.empty());
  std::map<std::pair<std::uint32_t, std::uint32_t>, std::set<std::uint32_t>> targets;
  for (const StepTransitionRule& rule : table) {
    targets[{static_cast<std::uint32_t>(rule.from), static_cast<std::uint32_t>(rule.event)}].insert(
        static_cast<std::uint32_t>(rule.to));
  }
  for (const auto& entry : targets) {
    RC_CHECK_EQ(entry.second.size(), std::size_t{1});
  }
  for (std::uint32_t state = 1; state <= kStepLifecycleCount; ++state) {
    for (std::uint32_t event = 1; event <= kStepEventCount; ++event) {
      const StepLifecycle lifecycle = static_cast<StepLifecycle>(state);
      const StepEvent step_event = static_cast<StepEvent>(event);
      const bool allowed = step_lifecycle_allows(lifecycle, step_event);
      const std::optional<StepLifecycle> applied = apply_step_event(lifecycle, step_event);
      RC_CHECK_EQ(allowed, applied.has_value());
    }
  }
  // Recovery never turns in-flight work into completed work.
  const std::optional<StepLifecycle> recovered =
      apply_step_event(StepLifecycle::DISPATCHED, StepEvent::RECOVER);
  RC_REQUIRE(recovered.has_value());
  RC_CHECK_EQ(*recovered, StepLifecycle::RECONCILIATION_REQUIRED);
  RC_CHECK(!is_step_satisfied(StepLifecycle::DISPATCHED));
  RC_CHECK(is_step_satisfied(StepLifecycle::COMPLETED));
  RC_CHECK(is_step_satisfied(StepLifecycle::SKIPPED));
  RC_CHECK(is_step_terminal(StepLifecycle::STALE));
  RC_CHECK(!is_step_terminal(StepLifecycle::RECONCILIATION_REQUIRED));
}

RC_TEST(currentness_bits_and_authority) {
  Currentness current;
  RC_CHECK(current.is_current());
  RC_CHECK(current.authority_current());
  RC_CHECK_EQ(current.render(), std::string("current"));
  current.add(CurrentnessCause::STALE_SOURCE_ROUTE);
  RC_CHECK(!current.is_current());
  // A stale source route does not end live authority: the plan still moves away
  // from that source.
  RC_CHECK(current.authority_current());
  current.add(CurrentnessCause::STALE_PATH_AUTHORITY);
  RC_CHECK(!current.authority_current());
  current.remove(CurrentnessCause::STALE_PATH_AUTHORITY);
  RC_CHECK(current.authority_current());
  RC_CHECK_EQ(current.causes().size(), std::size_t{1});
  RC_CHECK(current.render().find("STALE_SOURCE_ROUTE") != std::string::npos);
}

RC_TEST(dependency_graph_validation_rejects_structural_defects) {
  ConvergenceLimits limits;
  const StepKey validate =
      make_spec(StepKind::VALIDATE_TARGET, "target", {}, 0, Reversibility::OBSERVATION).key();
  const StepKey install = make_spec(StepKind::INSTALL_NEW_ROUTE, "route", {validate}).key();

  const GraphValidation good =
      validate_dependency_graph({make_spec(StepKind::VALIDATE_TARGET, "target", {}, 0,
                                           Reversibility::OBSERVATION),
                                 make_spec(StepKind::INSTALL_NEW_ROUTE, "route", {validate})},
                                limits);
  RC_CHECK(good.ok);
  (void)install;

  // Duplicate semantic key.
  const GraphValidation duplicate =
      validate_dependency_graph({make_spec(StepKind::VALIDATE_TARGET, "target"),
                                 make_spec(StepKind::VALIDATE_TARGET, "target")},
                                limits);
  RC_CHECK(!duplicate.ok);

  // Missing prerequisite.
  const GraphValidation missing = validate_dependency_graph(
      {make_spec(StepKind::INSTALL_NEW_ROUTE, "route", {make_spec(StepKind::FINALIZE, "plan").key()})},
      limits);
  RC_CHECK(!missing.ok);

  // Self dependency.
  const StepKey self = make_spec(StepKind::FINALIZE, "plan").key();
  const GraphValidation self_dependency =
      validate_dependency_graph({make_spec(StepKind::FINALIZE, "plan", {self})}, limits);
  RC_CHECK(!self_dependency.ok);

  // Duplicate edge.
  const GraphValidation duplicate_edge = validate_dependency_graph(
      {make_spec(StepKind::VALIDATE_TARGET, "target"),
       make_spec(StepKind::FINALIZE, "plan", {make_spec(StepKind::VALIDATE_TARGET, "target").key(),
                                              make_spec(StepKind::VALIDATE_TARGET, "target").key()})},
      limits);
  RC_CHECK(!duplicate_edge.ok);

  // Cycle.
  const GraphValidation cycle = validate_dependency_graph(
      {make_spec(StepKind::PREPARE_NEW_STATE, "a", {make_spec(StepKind::INSTALL_NEW_ROUTE, "b").key()}),
       make_spec(StepKind::INSTALL_NEW_ROUTE, "b", {make_spec(StepKind::PREPARE_NEW_STATE, "a").key()})},
      limits);
  RC_CHECK(!cycle.ok);
  RC_CHECK(!canonical_topological_order(
                {make_spec(StepKind::PREPARE_NEW_STATE, "a",
                           {make_spec(StepKind::INSTALL_NEW_ROUTE, "b").key()}),
                 make_spec(StepKind::INSTALL_NEW_ROUTE, "b",
                           {make_spec(StepKind::PREPARE_NEW_STATE, "a").key()})})
                .has_value());

  // Conflict-domain overlap inside one execution layer.
  const GraphValidation conflict = validate_dependency_graph(
      {make_spec(StepKind::PREPARE_NEW_STATE, "path", {}, 1u << 1),
       make_spec(StepKind::ACTIVATE_NEW_PATH, "path", {}, 1u << 1)},
      limits);
  RC_CHECK(!conflict.ok);
  RC_CHECK(has_condition([] {
              ConditionList list;
              for (const GraphDefect& defect : validate_dependency_graph(
                       {make_spec(StepKind::PREPARE_NEW_STATE, "path", {}, 1u << 1),
                        make_spec(StepKind::ACTIVATE_NEW_PATH, "path", {}, 1u << 1)},
                       ConvergenceLimits{})
                       .defects) {
                list.add(make_condition(defect.code, defect.subject.render()));
              }
              return list;
            }(),
            ConditionCode::CONFLICT_DOMAIN_OVERLAP));

  // Step count limit.
  ConvergenceLimits tiny;
  tiny.max_steps_per_plan = 1;
  std::vector<StepSpec> many;
  for (int index = 0; index < 3; ++index) {
    many.push_back(make_spec(StepKind::VALIDATE_TARGET, "s" + std::to_string(index)));
  }
  RC_CHECK(!validate_dependency_graph(many, tiny).ok);
}

RC_TEST(canonical_order_is_insertion_order_independent) {
  const StepKey a = make_spec(StepKind::VALIDATE_TARGET, "a").key();
  const StepKey b = make_spec(StepKind::PREPARE_NEW_STATE, "b", {a}).key();
  const StepKey c = make_spec(StepKind::INSTALL_NEW_ROUTE, "c", {a}).key();
  const StepKey d = make_spec(StepKind::FINALIZE, "d", {b, c}).key();

  const std::vector<StepSpec> forward{make_spec(StepKind::VALIDATE_TARGET, "a"),
                                      make_spec(StepKind::PREPARE_NEW_STATE, "b", {a}),
                                      make_spec(StepKind::INSTALL_NEW_ROUTE, "c", {a}),
                                      make_spec(StepKind::FINALIZE, "d", {b, c})};
  const std::vector<StepSpec> reversed{make_spec(StepKind::FINALIZE, "d", {b, c}),
                                       make_spec(StepKind::INSTALL_NEW_ROUTE, "c", {a}),
                                       make_spec(StepKind::PREPARE_NEW_STATE, "b", {a}),
                                       make_spec(StepKind::VALIDATE_TARGET, "a")};

  const std::optional<std::vector<std::size_t>> first = canonical_topological_order(forward);
  const std::optional<std::vector<std::size_t>> second = canonical_topological_order(reversed);
  RC_REQUIRE(first.has_value());
  RC_REQUIRE(second.has_value());
  RC_CHECK_EQ(first->size(), std::size_t{4});
  for (std::size_t index = 0; index < first->size(); ++index) {
    RC_CHECK_EQ(forward[(*first)[index]].key(), reversed[(*second)[index]].key());
  }
  // The canonical order is the lexicographically smallest valid one.
  RC_CHECK_EQ(forward[first->front()].key(), a);
  RC_CHECK_EQ(forward[first->back()].key(), d);

  const std::optional<std::vector<std::vector<std::size_t>>> layers = canonical_layers(forward);
  RC_REQUIRE(layers.has_value());
  RC_CHECK_EQ(layers->size(), std::size_t{3});
  RC_CHECK_EQ((*layers)[0].size(), std::size_t{1});
  RC_CHECK_EQ((*layers)[1].size(), std::size_t{2});
  RC_CHECK_EQ((*layers)[2].size(), std::size_t{1});
  const std::optional<std::vector<std::vector<std::size_t>>> layers_reversed =
      canonical_layers(reversed);
  RC_REQUIRE(layers_reversed.has_value());
  RC_CHECK_EQ(layers_reversed->size(), layers->size());

  RC_CHECK(depends_transitively_on(forward, d, a));
  RC_CHECK(!depends_transitively_on(forward, a, d));
}

RC_TEST(plan_structure_digest_is_insertion_order_independent) {
  const PlanKey key = [] {
    PlanKey value;
    value.route = Fixture::route_for(5);
    value.source_generation = RouteGeneration::from_value(1);
    value.target_generation = RouteGeneration::from_value(2);
    value.policy_generation = ConvergencePolicyGeneration::from_value(1);
    return value;
  }();
  const RouteBinding source = Fixture::binding(5, 1, 6, 1);
  const RouteBinding target = Fixture::binding(5, 2, 7, 1);
  const ConvergencePolicy policy = Fixture::policy(1);

  const StepKey a = make_spec(StepKind::VALIDATE_TARGET, "target").key();
  const StepKey b = make_spec(StepKind::PREPARE_NEW_STATE, "b", {a}).key();
  const StepKey c = make_spec(StepKind::FINALIZE, "plan", {b}).key();
  const std::vector<StepSpec> forward{make_spec(StepKind::VALIDATE_TARGET, "target"),
                                      make_spec(StepKind::PREPARE_NEW_STATE, "b", {a}),
                                      make_spec(StepKind::FINALIZE, "plan", {b})};
  const std::vector<StepSpec> shuffled{make_spec(StepKind::FINALIZE, "plan", {b}),
                                       make_spec(StepKind::VALIDATE_TARGET, "target"),
                                       make_spec(StepKind::PREPARE_NEW_STATE, "b", {a})};
  const Digest first =
      plan_structure_digest(key, source, target, policy, PlanMode::EXPLICIT, forward);
  const Digest second =
      plan_structure_digest(key, source, target, policy, PlanMode::EXPLICIT, shuffled);
  RC_CHECK(first == second);
  const ConvergencePlanId id_first = derive_plan_id(key, first);
  const ConvergencePlanId id_second = derive_plan_id(key, second);
  RC_CHECK(id_first == id_second);
  (void)c;

  // A different dependency generation must produce a different structure.
  const RouteBinding other_target = Fixture::binding(5, 2, 7, 2);
  RC_CHECK(!(plan_structure_digest(key, source, other_target, policy, PlanMode::EXPLICIT, forward) ==
             first));
}

RC_TEST(policy_coherence_and_digest) {
  std::string reason;
  ConvergencePolicy policy = Fixture::policy(1);
  RC_CHECK(policy.is_coherent(reason));
  RC_CHECK_EQ(policy.content_digest(), Fixture::policy(1).content_digest());

  ConvergencePolicy incoherent = policy;
  incoherent.allow_overlap = false;
  RC_CHECK(!incoherent.is_coherent(reason));
  RC_CHECK(reason.find("allow_overlap") != std::string::npos);

  ConvergencePolicy break_first = Fixture::policy(2, OrderingMode::BREAK_BEFORE_MAKE, false);
  RC_CHECK(!break_first.is_coherent(reason));
  break_first.allow_break_before_make = true;
  RC_CHECK(break_first.is_coherent(reason));
  break_first.allow_overlap = true;
  RC_CHECK(!break_first.is_coherent(reason));

  ConvergencePolicy bad_parallel = policy;
  bad_parallel.max_parallel_steps = 0;
  RC_CHECK(!bad_parallel.is_coherent(reason));
  ConvergencePolicy bad_retries = policy;
  bad_retries.max_retries_per_step = kAbsoluteMaxRetriesPerStep + 1;
  RC_CHECK(!bad_retries.is_coherent(reason));
  RC_CHECK(policy.content_digest() != break_first.content_digest());
}

RC_TEST(authority_scopes_deny_by_default) {
  const AuthorityScope deny = AuthorityScope::deny_all();
  RC_CHECK(deny.is_well_formed());
  RC_CHECK(!deny.covers_route(FabricId{}, RoutingNamespaceId{}, Fixture::route_for(1)));
  RC_CHECK(!deny.covers_plan(FabricId{}, RoutingNamespaceId{}, Fixture::route_for(1),
                             ConvergencePlanId::from_u64(1, 1)));
  RC_CHECK(has_capability(static_cast<std::uint32_t>(Capability::ADMIN), Capability::ADMIN));
  RC_CHECK(!has_capability(static_cast<std::uint32_t>(Capability::ADMIN),
                           Capability::DISPATCH_STEP));

  const FabricId fabric = Fixture::fabric_for(1);
  const RouteId route = Fixture::route_for(3);
  const AuthorityScope route_scope = AuthorityScope::for_route(route, Fixture::namespace_for(1), fabric);
  RC_CHECK(route_scope.covers_route(fabric, Fixture::namespace_for(1), route));
  RC_CHECK(!route_scope.covers_route(fabric, Fixture::namespace_for(1), Fixture::route_for(4)));
  // A route scope is not plan-scoped authority, but it does cover the exact plan
  // of that route.
  RC_CHECK(route_scope.covers_plan(fabric, Fixture::namespace_for(1), route,
                                   ConvergencePlanId::from_u64(9, 9)));
  const AuthorityScope plan_scope =
      AuthorityScope::for_plan(ConvergencePlanId::from_u64(9, 9));
  RC_CHECK(plan_scope.covers_plan(fabric, Fixture::namespace_for(1), route,
                                  ConvergencePlanId::from_u64(9, 9)));
  RC_CHECK(!plan_scope.covers_plan(fabric, Fixture::namespace_for(1), route,
                                   ConvergencePlanId::from_u64(9, 8)));
  // A scope from another fabric is denied.
  RC_CHECK(!route_scope.covers_route(Fixture::fabric_for(99), Fixture::namespace_for(1), route));
}

RC_TEST(route_binding_well_formedness) {
  RouteBinding binding = Fixture::binding(1, 1, 1, 1);
  RC_CHECK(binding.is_well_formed());
  RouteBinding missing_route = binding;
  missing_route.route = RouteId{};
  RC_CHECK(!missing_route.is_well_formed());
  RouteBinding zero_generation = binding;
  zero_generation.generation = RouteGeneration::from_value(0);
  RC_CHECK(!zero_generation.is_well_formed());
  RouteBinding partial_group = binding;
  partial_group.ecmp_group = Fixture::group_for(1);
  RC_CHECK(!partial_group.is_well_formed());
  partial_group.ecmp_generation = ECMPGroupGeneration::from_value(1);
  partial_group.assignment_generation = AssignmentGeneration::from_value(1);
  RC_CHECK(partial_group.is_well_formed());
  RC_CHECK(!partial_group.render().empty());
}

RC_TEST(generator_orders_make_before_break_and_break_before_make) {
  const RouteBinding source = Fixture::binding(1, 1, 1, 1);
  RouteBinding target = Fixture::binding(1, 2, 2, 1);
  ConvergenceLimits limits;
  std::string reason;

  const ConvergencePolicy mbb = Fixture::policy(1);
  const std::optional<std::vector<StepSpec>> steps =
      generate_steps(source, target, mbb, limits, reason);
  if (!steps.has_value()) {
    ::rc::test::report_failure(__FILE__, __LINE__, "make-before-break generation: " + reason);
  }
  RC_REQUIRE(steps.has_value());
  RC_CHECK(validate_policy_conformance(*steps, mbb, limits).ok);
  const auto find = [&steps](StepKind kind) -> const StepSpec* {
    for (const StepSpec& step : *steps) {
      if (step.kind == kind) {
        return &step;
      }
    }
    return nullptr;
  };
  const StepSpec* verify_new = find(StepKind::VERIFY_NEW_STATE);
  const StepSpec* withdraw = find(StepKind::WITHDRAW_OLD_ROUTE);
  RC_REQUIRE(verify_new != nullptr);
  RC_REQUIRE(withdraw != nullptr);
  RC_CHECK(depends_transitively_on(*steps, withdraw->key(), verify_new->key()));
  RC_CHECK(!depends_transitively_on(*steps, verify_new->key(), withdraw->key()));

  // Break-before-make is never chosen silently.
  ConvergencePolicy silent = Fixture::policy(2, OrderingMode::BREAK_BEFORE_MAKE, false);
  RC_CHECK(!generate_steps(source, target, silent, limits, reason).has_value());
  RC_CHECK(reason.find("BREAK_BEFORE_MAKE") != std::string::npos);

  const ConvergencePolicy bbm = Fixture::policy(3, OrderingMode::BREAK_BEFORE_MAKE, true);
  const std::optional<std::vector<StepSpec>> bbm_steps =
      generate_steps(source, target, bbm, limits, reason);
  if (!bbm_steps.has_value()) {
    ::rc::test::report_failure(__FILE__, __LINE__, "break-before-make generation: " + reason);
  }
  RC_REQUIRE(bbm_steps.has_value());
  RC_CHECK(validate_policy_conformance(*bbm_steps, bbm, limits).ok);
  const auto bbm_find = [&bbm_steps](StepKind kind) -> const StepSpec* {
    for (const StepSpec& step : *bbm_steps) {
      if (step.kind == kind) {
        return &step;
      }
    }
    return nullptr;
  };
  RC_CHECK(depends_transitively_on(*bbm_steps, bbm_find(StepKind::ACTIVATE_NEW_PATH)->key(),
                                   bbm_find(StepKind::WITHDRAW_OLD_ROUTE)->key()));
  RC_CHECK(!depends_transitively_on(*bbm_steps, bbm_find(StepKind::WITHDRAW_OLD_ROUTE)->key(),
                                    bbm_find(StepKind::ACTIVATE_NEW_PATH)->key()));

  // The same request yields the same canonical plan.
  const std::optional<std::vector<StepSpec>> again =
      generate_steps(source, target, mbb, limits, reason);
  RC_REQUIRE(again.has_value());
  RC_CHECK_EQ(steps->size(), again->size());
  for (std::size_t index = 0; index < steps->size(); ++index) {
    RC_CHECK((*steps)[index].key() == (*again)[index].key());
  }

  // A parallel budget of one serialises the plan without changing its semantics.
  const ConvergencePolicy serial = Fixture::policy(1, OrderingMode::MAKE_BEFORE_BREAK, false, 1);
  const std::optional<std::vector<StepSpec>> serial_steps =
      generate_steps(source, target, serial, limits, reason);
  RC_REQUIRE(serial_steps.has_value());
  const std::optional<std::vector<std::vector<std::size_t>>> layers =
      canonical_layers(*serial_steps);
  RC_REQUIRE(layers.has_value());
  for (const std::vector<std::size_t>& layer : *layers) {
    RC_CHECK(layer.size() <= 1);
  }
  const StepSpec* serial_withdraw = nullptr;
  const StepSpec* serial_verify = nullptr;
  for (const StepSpec& step : *serial_steps) {
    if (step.kind == StepKind::WITHDRAW_OLD_ROUTE) {
      serial_withdraw = &step;
    }
    if (step.kind == StepKind::VERIFY_NEW_STATE) {
      serial_verify = &step;
    }
  }
  RC_REQUIRE(serial_withdraw != nullptr);
  RC_REQUIRE(serial_verify != nullptr);
  RC_CHECK(depends_transitively_on(*serial_steps, serial_withdraw->key(), serial_verify->key()));
}

RC_TEST(limits_and_versions_are_coherent) {
  ConvergenceLimits limits;
  std::string reason;
  RC_CHECK(limits.is_coherent(reason));
  ConvergenceLimits bad = limits;
  bad.max_steps_per_plan = 0;
  RC_CHECK(!bad.is_coherent(reason));
  bad = limits;
  bad.max_parallel_steps = 0;
  RC_CHECK(!bad.is_coherent(reason));
  bad = limits;
  bad.max_parallel_steps = kAbsoluteMaxParallelSteps + 1;
  RC_CHECK(!bad.is_coherent(reason));
  bad = limits;
  bad.max_frame_bytes = 4;
  RC_CHECK(!bad.is_coherent(reason));
  bad = limits;
  bad.max_total_dependencies = 1;
  RC_CHECK(!bad.is_coherent(reason));

  RC_CHECK_EQ(std::string(kVersionString), std::string("1.0.0"));
  RC_CHECK(version_line().find("route-convergence") != std::string::npos);
  const std::string report = version_report();
  RC_CHECK(report.find("wire_version: 1") != std::string::npos);
  RC_CHECK(report.find("persistence_format_version: 1") != std::string::npos);
  RC_CHECK(report.find(kLicenseNotice) != std::string::npos);
}

RC_TEST(outcome_and_condition_rendering_is_stable) {
  RC_CHECK_EQ(std::string(to_string(Outcome::PLAN_CREATED)), std::string("PLAN_CREATED"));
  RC_CHECK(is_acceptance(Outcome::IDEMPOTENT));
  RC_CHECK(is_acceptance(Outcome::PLAN_COMPLETED));
  RC_CHECK(!is_acceptance(Outcome::STALE_PLAN));
  RC_CHECK_EQ(std::string(to_string(ConditionCode::WATERMARK_EXCEEDED)),
              std::string("WATERMARK_EXCEEDED"));
  const Condition condition =
      make_condition(ConditionCode::TARGET_ROUTE_STALE, "route", 11, 10);
  RC_CHECK_EQ(condition.render(), std::string("code=TARGET_ROUTE_STALE subject=route observed=11 expected=10"));
  const Condition sanitised = make_condition(ConditionCode::NONE, std::string("bad\nsubject", 11));
  RC_CHECK(sanitised.render().find('\n') == std::string::npos);

  ConditionList list(2);
  list.add(make_condition(ConditionCode::NONE, "a"));
  list.add(make_condition(ConditionCode::NONE, "b"));
  list.add(make_condition(ConditionCode::NONE, "c"));
  RC_CHECK(list.truncated());
  RC_CHECK_EQ(list.entries().size(), std::size_t{2});
  RC_CHECK(list.render().find("EXPLANATION_LIMIT") != std::string::npos);

  Explanation explanation("subject", 1);
  explanation.add(make_condition(ConditionCode::NONE, "only"));
  explanation.add(make_condition(ConditionCode::NONE, "dropped"));
  RC_CHECK(explanation.truncated());
  RC_CHECK(explanation.render().find("explanation subject=subject") == 0);
}
