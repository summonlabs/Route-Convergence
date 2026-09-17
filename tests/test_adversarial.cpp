// Adversarial proofs for Route Convergence.
//
// Every attack enters through the public API only: a real ConvergenceGovernor
// over the SYNTHETIC control-plane fixture, the real wire frame codec, the real
// store codec and a real in-process coordinator server.  Each attack asserts one
// stable structured rejection - an Outcome with the exact ConditionCode, or the
// exact WireDefect / StoreDefect - and, unless the rejection is itself a
// documented state transition, that the governor's semantic state did not
// advance.  Where the governor answers an attack by invalidating a plan, the
// test asserts that exact documented invalidation instead.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <process.h>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "rc/backend.hpp"
#include "rc/client.hpp"
#include "rc/server.hpp"

#include "fixture.hpp"
#include "test_framework.hpp"

using namespace rc;  // NOLINT(google-build-using-namespace): a test translation unit.
using rc::test::Fixture;
using rc::test::has_condition;

namespace {

using Bytes = std::vector<std::uint8_t>;

// Documented frame layout (protocol.hpp) and store layout (persistence.hpp).
constexpr std::size_t kFrameMagicBytes = 4;
constexpr std::size_t kFrameVersionOffset = kFrameMagicBytes;
constexpr std::size_t kFrameMessageOffset = kFrameVersionOffset + 2;
constexpr std::size_t kFrameFlagsOffset = kFrameMessageOffset + 2;
constexpr std::size_t kFrameSequenceOffset = kFrameFlagsOffset + 4;
constexpr std::size_t kFramePayloadBytesOffset = kFrameSequenceOffset + 8 + 8 + 16 + 16 + 16;
constexpr std::size_t kFrameReservedOffset = kFramePayloadBytesOffset + 4;
constexpr std::size_t kStoreVersionOffset = kStoreMagicBytes;
constexpr std::size_t kStoreReservedOffset = kStoreVersionOffset + 4;
constexpr std::size_t kStoreEpochOffset = kStoreReservedOffset + 4;
constexpr std::size_t kStorePayloadBytesOffset = kStoreEpochOffset + 8 + 8;

void put_u16_le(Bytes& bytes, std::size_t offset, std::uint16_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
  bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
}
void put_u32_le(Bytes& bytes, std::size_t offset, std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    bytes[offset + index] = static_cast<std::uint8_t>((value >> (8u * index)) & 0xFFu);
  }
}
[[nodiscard]] std::uint16_t get_u16_le(const Bytes& bytes, std::size_t offset) {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset]) |
                                    static_cast<std::uint16_t>(
                                        static_cast<std::uint16_t>(bytes[offset + 1]) << 8));
}
[[nodiscard]] std::uint32_t get_u32_le(const Bytes& bytes, std::size_t offset) {
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(bytes[offset + index]) << (8u * index);
  }
  return value;
}

// The defect one flipped frame bit must produce, from the documented layout and
// the documented order in which the frame fields are checked.
[[nodiscard]] WireDefect expected_frame_defect_for_flip(const Bytes& frame, std::size_t offset,
                                                        const ConvergenceLimits& limits) {
  if (offset < kFrameVersionOffset) {
    return WireDefect::BAD_MAGIC;
  }
  if (offset < kFrameMessageOffset) {
    return WireDefect::VERSION_MISMATCH;
  }
  if (offset < kFrameFlagsOffset) {
    return is_known_message(get_u16_le(frame, kFrameMessageOffset)) ? WireDefect::INTEGRITY_FAILURE
                                                                   : WireDefect::UNKNOWN_MESSAGE;
  }
  if (offset < kFrameSequenceOffset) {
    return WireDefect::RESERVED_NOT_ZERO;
  }
  if (offset < kFramePayloadBytesOffset) {
    return WireDefect::INTEGRITY_FAILURE;
  }
  if (offset < kFrameReservedOffset) {
    const std::uint32_t declared = get_u32_le(frame, kFramePayloadBytesOffset);
    if (declared > limits.max_frame_bytes) {
      return WireDefect::FRAME_TOO_LARGE;
    }
    const std::size_t expected =
        kWireHeaderBytes + static_cast<std::size_t>(declared) + kWireTagBytes;
    return frame.size() < expected  ? WireDefect::TRUNCATED
           : frame.size() > expected ? WireDefect::TRAILING_BYTES
                                     : WireDefect::INTEGRITY_FAILURE;
  }
  return offset < kWireHeaderBytes ? WireDefect::RESERVED_NOT_ZERO : WireDefect::INTEGRITY_FAILURE;
}

// The same rule for one flipped store byte.
[[nodiscard]] StoreDefect expected_store_defect_for_flip(const Bytes& image, std::size_t offset,
                                                         const ConvergenceLimits& limits) {
  if (offset < kStoreVersionOffset) {
    return StoreDefect::BAD_MAGIC;
  }
  if (offset < kStoreReservedOffset) {
    return StoreDefect::BAD_VERSION;
  }
  if (offset < kStoreEpochOffset) {
    return StoreDefect::RESERVED_NOT_ZERO;
  }
  if (offset < kStorePayloadBytesOffset) {
    return StoreDefect::INTEGRITY_FAILURE;
  }
  if (offset < kStoreHeaderBytes) {
    const std::uint32_t declared = get_u32_le(image, kStorePayloadBytesOffset);
    if (declared > limits.max_persistence_record_bytes) {
      return StoreDefect::PAYLOAD_TOO_LARGE;
    }
    const std::size_t expected =
        kStoreHeaderBytes + static_cast<std::size_t>(declared) + kStoreTagBytes;
    return image.size() < expected  ? StoreDefect::TRUNCATED
           : image.size() > expected ? StoreDefect::TRAILING_BYTES
                                     : StoreDefect::INTEGRITY_FAILURE;
  }
  return StoreDefect::INTEGRITY_FAILURE;
}

// Everything an operator can observe about the governor's semantic state.  Two
// equal views mean no plan, step, digest, generation, currentness, lifecycle,
// worker, epoch or convergence watermark moved.
[[nodiscard]] std::vector<std::string> view(const ConvergenceGovernor& governor) {
  std::vector<std::string> out;
  for (const PlanSummary& summary : governor.list_plans().plans) {
    std::string line = "plan " + summary.id.to_text() + " gen=" +
                       std::to_string(summary.generation.value()) + " lifecycle=" +
                       std::string(to_string(summary.lifecycle)) + " currentness=" +
                       std::to_string(summary.currentness.bits()) + " steps=" +
                       std::to_string(summary.total_steps) + "/" +
                       std::to_string(summary.completed_steps) + "/" +
                       std::to_string(summary.ready_steps) + " digest=" +
                       summary.digest.to_text() + " key=" + summary.key.render();
    out.push_back(std::move(line));
  }
  for (const PublisherRegistration& registration : governor.list_workers()) {
    out.push_back("worker " + registration.publisher.to_text() + " boot=" +
                  registration.worker_boot.to_text() + " scope=" + registration.scope.render() +
                  " capabilities=" + std::to_string(registration.capabilities));
  }
  out.push_back("epoch=" + std::to_string(governor.epoch().value()));
  out.push_back("convergence=" + std::to_string(governor.convergence_generation().value()));
  out.push_back("plans=" + std::to_string(governor.plan_count()));
  out.push_back("workers=" + std::to_string(governor.worker_count()));
  return out;
}

void same(const ConvergenceGovernor& governor, const std::vector<std::string>& before,
          const char* attack) {
  ++::rc::test::g_checks;
  const std::vector<std::string> after = view(governor);
  if (after != before) {
    std::string detail = std::string(attack) + ": the governor advanced";
    for (const std::string& line : after) {
      detail += "\n  after: " + line;
    }
    ::rc::test::report_failure(__FILE__, __LINE__, detail);
  }
}

template <class Result>
void bad(const Result& result, Outcome outcome, ConditionCode code, const char* attack) {
  ++::rc::test::g_checks;
  if (result.outcome != outcome || !has_condition(result.conditions, code)) {
    ::rc::test::report_failure(__FILE__, __LINE__,
                               std::string(attack) + ": expected " +
                                   std::string(to_string(outcome)) + " with " +
                                   std::string(to_string(code)) + " but got " +
                                   std::string(to_string(result.outcome)) + " " +
                                   result.conditions.render());
  }
}

void ok(const PlanMutationResult& result, Outcome outcome, const char* attack) {
  ++::rc::test::g_checks;
  if (result.outcome != outcome) {
    ::rc::test::report_failure(__FILE__, __LINE__, std::string(attack) + ": expected " +
                                                      std::string(to_string(outcome)) +
                                                      " but got " + result.render());
  }
}

// --- corpus builders --------------------------------------------------------
[[nodiscard]] std::uint32_t dom(ConflictDomain value) { return static_cast<std::uint32_t>(value); }

[[nodiscard]] StepSpec step_at(StepKind kind, std::string_view subject, std::uint32_t domains) {
  StepSpec spec;
  spec.kind = kind;
  const std::optional<SubjectToken> token = SubjectToken::make(subject);
  if (token.has_value()) {
    spec.subject = *token;
  }
  spec.conflict_domains = domains;
  spec.idempotent = true;
  return spec;
}

[[nodiscard]] const RouteBinding& src() {
  static const RouteBinding binding = Fixture::binding(1, 1, 1, 1);
  return binding;
}
[[nodiscard]] const RouteBinding& dst() {
  static const RouteBinding binding = Fixture::binding(1, 2, 2, 1);
  return binding;
}

// The smallest policy-conformant explicit plan: it is accepted as it stands, so
// every rejection below is caused by the attack and not by the base shape.
[[nodiscard]] std::vector<StepSpec> legal_plan() {
  std::vector<StepSpec> steps;
  steps.push_back(step_at(StepKind::VALIDATE_TARGET, "target", dom(ConflictDomain::TARGET_STATE)));
  steps.push_back(step_at(StepKind::PREPARE_NEW_STATE, "newpath", dom(ConflictDomain::PATH_STATE)));
  steps.push_back(step_at(StepKind::FINALIZE, "plan", dom(ConflictDomain::TARGET_STATE)));
  steps[1].depends_on.push_back(steps[0].key());
  steps[2].depends_on.push_back(steps[0].key());
  steps[2].depends_on.push_back(steps[1].key());
  return steps;
}

// A binding that carries every optional upstream generation.
[[nodiscard]] RouteBinding grouped(std::uint64_t seed, std::uint64_t route_generation,
                                   std::uint64_t group_generation) {
  RouteBinding binding = Fixture::binding(seed, route_generation, seed, 1);
  binding.multipath_set = Fixture::multipath_for(seed);
  binding.multipath_generation = MultipathSetGeneration::from_value(group_generation);
  binding.ecmp_group = Fixture::group_for(seed);
  binding.ecmp_generation = ECMPGroupGeneration::from_value(group_generation);
  binding.assignment_generation = AssignmentGeneration::from_value(group_generation);
  binding.weighted_set = Fixture::weighted_for(seed);
  binding.weight_policy_generation = WeightPolicyGeneration::from_value(group_generation);
  return binding;
}

// An empty step list asks for PlanMode::GENERATED, a non-empty one for EXPLICIT.
[[nodiscard]] PlanRequest request_at(const std::vector<StepSpec>& steps, const RouteBinding& source,
                                     const RouteBinding& target, CoordinatorEpoch epoch,
                                     std::uint64_t provenance_seed) {
  PlanRequest request;
  request.mode = steps.empty() ? PlanMode::GENERATED : PlanMode::EXPLICIT;
  request.source = source;
  request.target = target;
  request.policy = Fixture::policy(1);
  request.epoch = epoch;
  request.provenance = Fixture::provenance_for(provenance_seed);
  request.explicit_steps = steps;
  return request;
}

[[nodiscard]] TransitionStepId ready_of(const ConvergenceGovernor& governor,
                                        const ConvergencePlanId& plan) {
  for (const ReadyStep& step : governor.ready_steps(64).steps) {
    if (step.plan == plan) {
      return step.step;
    }
  }
  return TransitionStepId{};
}

[[nodiscard]] CompletionEvidence evidence_at(const ConvergencePlanId& plan,
                                             const TransitionStepId& step,
                                             const StepDispatch& dispatch,
                                             const AuthorityContext& dispatch_authority,
                                             const PublisherId& publisher,
                                             const WorkerBootId& boot) {
  CompletionEvidence evidence;
  evidence.plan = plan;
  evidence.step = step;
  evidence.step_generation = dispatch.step_generation;
  evidence.attempt = dispatch_authority.attempt;
  evidence.epoch = dispatch.epoch;
  evidence.publisher = publisher;
  evidence.worker_boot = boot;
  evidence.outcome = BackendOutcome::APPLIED;
  evidence.dispatch_watermark = dispatch.watermark;
  evidence.applied_route_generation = dispatch.spec.route_generation;
  evidence.observed_path_authority_generation = dispatch.spec.path_authority_generation;
  evidence.id = derive_evidence_id(evidence);
  return evidence;
}

// Registers one more publisher/boot pair through the public registry path.
[[nodiscard]] PlanMutationResult add_worker(Fixture& fixture, std::uint64_t publisher_seed,
                                            std::uint64_t boot_seed) {
  PublisherRegistration registration;
  registration.publisher = Fixture::publisher_for(publisher_seed);
  registration.worker_boot = Fixture::boot_for(boot_seed);
  registration.scope = AuthorityScope::for_fabric(Fixture::fabric_for(1));
  registration.capabilities = rc::test::kAllCapabilities;
  registration.provenance = Fixture::provenance_for(boot_seed);
  AuthorityContext context;
  context.epoch = fixture.governor().epoch();
  context.publisher = registration.publisher;
  context.worker_boot = registration.worker_boot;
  context.attempt = Fixture::attempt_for((boot_seed * 7919ull) + 13ull);
  return fixture.governor().register_worker(registration, context);
}

// One governor holding one defined policy, one published observation and one
// created plan with its first ready step: the ordinary state every attack below
// starts from.
struct Corpus {
  explicit Corpus(ConvergenceLimits limits = ConvergenceLimits(), std::uint64_t seed = 1)
      : fixture(seed, CoordinatorEpoch::from_value(1), limits) {
    (void)fixture.define_policy(1);
    fixture.publish(dst());
    const PlanMutationResult created = fixture.create(src(), dst(), 1, 7);
    RC_REQUIRE(created.accepted());
    plan = created.plan;
    step = ready_of(fixture.governor(), plan);
    RC_REQUIRE(!step.is_nil());
  }
  [[nodiscard]] ConvergenceGovernor& governor() { return fixture.governor(); }
  [[nodiscard]] std::vector<std::string> snapshot() { return view(fixture.governor()); }
  rc::test::Fixture fixture;
  ConvergencePlanId plan;
  TransitionStepId step;
};

// One fresh governor with the given limits: its plan request must be refused
// with exactly one structured rejection and must leave the governor untouched.
void create_is_refused(const ConvergenceLimits& limits, const std::vector<StepSpec>& steps,
                       std::uint64_t seed, Outcome outcome, ConditionCode code,
                       const char* attack) {
  Fixture fixture(seed, CoordinatorEpoch::from_value(1), limits);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  fixture.publish(dst());
  const std::vector<std::string> before = view(fixture.governor());
  bad(fixture.governor().create_plan(
          request_at(steps, src(), dst(), fixture.governor().epoch(), seed + 10),
          fixture.authority(seed + 11)),
      outcome, code, attack);
  same(fixture.governor(), before, attack);
}

// A temporary directory derived from this process, never a fixed path.
class Scratch {
 public:
  explicit Scratch(std::string_view name) {
    std::error_code code;
    directory_ = std::filesystem::temp_directory_path(code) /
                 ("rc-adversarial-" + std::to_string(::_getpid()) + "-" + std::string(name));
    std::filesystem::create_directories(directory_, code);
  }
  Scratch(const Scratch&) = delete;
  Scratch& operator=(const Scratch&) = delete;
  ~Scratch() {
    std::error_code code;
    (void)std::filesystem::remove_all(directory_, code);
  }
  [[nodiscard]] std::filesystem::path file(std::string_view name) const {
    return directory_ / std::string(name);
  }

 private:
  std::filesystem::path directory_;
};

// Every identity domain enforces the same text discipline.
template <class Id>
void check_identity_encoding(const char* name) {
  const auto refused = [name](std::string_view text, const char* what) {
    ++::rc::test::g_checks;
    if (Id::parse(text).has_value()) {
      ::rc::test::report_failure(__FILE__, __LINE__, std::string(name) + ": " + what + " parsed");
    }
  };
  const std::string lower = "0123456789abcdef0123456789abcdef";
  const std::optional<Id> nil = Id::parse(std::string(Id::kTextLength, '0'));
  const std::optional<Id> from_lower = Id::parse(lower);
  const std::optional<Id> from_upper = Id::parse("0123456789ABCDEF0123456789ABCDEF");
  ++::rc::test::g_checks;
  if (!nil.has_value() || !nil->is_nil()) {
    ::rc::test::report_failure(__FILE__, __LINE__, std::string(name) + ": all-zero text must be nil");
  }
  ++::rc::test::g_checks;
  if (!from_lower.has_value() || !from_upper.has_value() || !(*from_lower == *from_upper)) {
    ::rc::test::report_failure(__FILE__, __LINE__, std::string(name) + ": case variants must agree");
  }
  ++::rc::test::g_checks;
  if (from_lower.has_value() && from_lower->to_text() != lower) {
    ::rc::test::report_failure(__FILE__, __LINE__, std::string(name) + ": text must be lowercase");
  }
  refused(std::string(), "empty");
  refused(std::string(Id::kTextLength - 1, 'a'), "one byte short");
  refused(std::string(Id::kTextLength + 1, 'a'), "one byte long");
  refused(std::string(64, 'a'), "over-long");
  refused("g123456789abcdef0123456789abcdef", "non-hex");
  refused(std::string(Id::kTextLength, 'z'), "non-hex filler");
}

}  // namespace

// MALFORMED INPUT: identity text and nil identities at every entry point.
RC_TEST(malformed_identity_text_and_nil_identities_are_refused) {
  check_identity_encoding<ConvergencePlanId>("ConvergencePlanId");
  check_identity_encoding<TransitionStepId>("TransitionStepId");
  check_identity_encoding<CompletionEvidenceId>("CompletionEvidenceId");
  check_identity_encoding<RouteId>("RouteId");
  check_identity_encoding<PathId>("PathId");
  check_identity_encoding<PublisherId>("PublisherId");
  check_identity_encoding<WorkerBootId>("WorkerBootId");
  check_identity_encoding<MutationAttemptId>("MutationAttemptId");
  check_identity_encoding<ProvenanceId>("ProvenanceId");
  const std::string lower_digest(64, 'a');
  std::string upper_digest = lower_digest;
  for (char& character : upper_digest) {
    character = static_cast<char>(character - 'a' + 'A');
  }
  const std::optional<Digest> digest_lower = Digest::parse(lower_digest);
  const std::optional<Digest> digest_upper = Digest::parse(upper_digest);
  RC_REQUIRE(digest_lower.has_value() && digest_upper.has_value());
  RC_CHECK(*digest_lower == *digest_upper);
  RC_CHECK_EQ(digest_lower->to_text(), lower_digest);
  RC_CHECK(!Digest::parse(std::string(63, 'a')).has_value());
  RC_CHECK(!Digest::parse(std::string(65, 'a')).has_value());
  RC_CHECK(!Digest::parse(std::string(32, 'a')).has_value());
  RC_CHECK(!Digest::parse(std::string(64, 'g')).has_value());

  Corpus corpus;
  ConvergenceGovernor& governor = corpus.governor();
  Fixture& fixture = corpus.fixture;
  const std::vector<std::string> before = corpus.snapshot();
  const PlanRequest request = request_at({}, src(), dst(), governor.epoch(), 12);
  const auto create = [&](PlanRequest broken, std::uint64_t seed, const char* attack) {
    bad(governor.create_plan(broken, fixture.authority(seed)), Outcome::MALFORMED_REQUEST,
        ConditionCode::MALFORMED_PAYLOAD, attack);
  };
  PlanRequest broken = request;
  broken.provenance = ProvenanceId{};
  create(broken, 21, "nil provenance");
  broken = request;
  broken.target.route = RouteId{};
  create(broken, 22, "nil RouteId");
  broken = request;
  broken.target.path = PathId{};
  create(broken, 23, "nil PathId");
  broken = request;
  broken.target.generation = RouteGeneration::from_value(0);
  create(broken, 24, "zero route generation");
  broken = request;
  broken.policy.id = ConvergencePolicyId{};
  create(broken, 25, "nil policy identity");
  broken = request;
  broken.target.route = Fixture::route_for(9);
  create(broken, 26, "source and target on different routes");
  AuthorityContext context = fixture.authority(27);
  context.publisher = PublisherId{};
  bad(governor.create_plan(request, context), Outcome::UNAUTHORIZED,
      ConditionCode::MALFORMED_IDENTITY, "nil publisher authority");
  context = fixture.authority(28);
  context.worker_boot = WorkerBootId{};
  bad(governor.create_plan(request, context), Outcome::UNAUTHORIZED,
      ConditionCode::MALFORMED_IDENTITY, "nil worker boot authority");
  context = fixture.authority(29);
  context.attempt = MutationAttemptId{};
  bad(governor.create_plan(request, context), Outcome::UNAUTHORIZED,
      ConditionCode::MALFORMED_IDENTITY, "nil attempt authority");
  bad(governor.dispatch_step(ConvergencePlanId{}, corpus.step, fixture.authority(31)),
      Outcome::UNKNOWN_PLAN, ConditionCode::PLAN_UNKNOWN, "nil plan identity");
  bad(governor.dispatch_step(corpus.plan, TransitionStepId{}, fixture.authority(32)),
      Outcome::UNKNOWN_STEP, ConditionCode::STEP_UNKNOWN, "nil step identity");
  bad(governor.fail_step(ConvergencePlanId{}, corpus.step, BackendOutcome::PERMANENT_FAILURE,
                         "detail", fixture.authority(33)),
      Outcome::UNKNOWN_PLAN, ConditionCode::PLAN_UNKNOWN, "nil plan in fail_step");
  bad(governor.begin_rollback(ConvergencePlanId{}, fixture.authority(34)), Outcome::UNKNOWN_PLAN,
      ConditionCode::PLAN_UNKNOWN, "nil plan in begin_rollback");
  bad(governor.register_worker(PublisherRegistration{}, fixture.authority(35)),
      Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_PAYLOAD, "nil registration");
  PublisherRegistration registration;
  registration.publisher = Fixture::publisher_for(2);
  registration.scope = AuthorityScope::for_fabric(Fixture::fabric_for(1));
  registration.capabilities = rc::test::kAllCapabilities;
  registration.provenance = Fixture::provenance_for(2);
  bad(governor.register_worker(registration, fixture.authority(36)), Outcome::MALFORMED_REQUEST,
      ConditionCode::MALFORMED_PAYLOAD, "nil worker boot");
  registration.worker_boot = Fixture::boot_for(2);
  bad(governor.register_worker(registration, fixture.authority(37)), Outcome::UNAUTHORIZED,
      ConditionCode::MALFORMED_IDENTITY, "registration authority mismatch");
  bad(governor.fence_worker(WorkerBootId{}, fixture.authority(38)), Outcome::MALFORMED_REQUEST,
      ConditionCode::MALFORMED_IDENTITY, "nil fenced boot");
  bad(governor.fence_session_loss(PublisherId{}, WorkerBootId{}), Outcome::MALFORMED_REQUEST,
      ConditionCode::MALFORMED_IDENTITY, "nil session identity");
  same(governor, before, "nil identity attacks");
}

// MALFORMED INPUT: subjects, and malformed completion evidence.
RC_TEST(malformed_subjects_and_completion_evidence_are_refused) {
  const std::string over_long(kAbsoluteMaxSubjectBytes + 1, 'a');
  RC_CHECK(!SubjectToken::make("").has_value());
  RC_CHECK(!SubjectToken::make(" ").has_value());
  RC_CHECK(!SubjectToken::make("with space").has_value());
  RC_CHECK(!SubjectToken::make(std::string("tab\there")).has_value());
  RC_CHECK(!SubjectToken::make(std::string("bell\a")).has_value());
  RC_CHECK(!SubjectToken::make(std::string(1, '\x7F')).has_value());
  RC_CHECK(!SubjectToken::make(over_long).has_value());
  RC_REQUIRE(SubjectToken::make(std::string(kAbsoluteMaxSubjectBytes, 'a')).has_value());

  Corpus corpus;
  ConvergenceGovernor& governor = corpus.governor();
  Fixture& fixture = corpus.fixture;
  const ConvergenceLimits limits;
  // A peer cannot even deliver a malformed subject: the decoder applies exactly
  // the constructor rule, so the value never reaches create_plan.
  const std::string subject_text = "advsubject";
  std::vector<StepSpec> steps = legal_plan();
  steps[0].subject = *SubjectToken::make(subject_text);
  const Bytes payload = encode_payload(request_at(steps, src(), dst(), governor.epoch(), 41));
  RC_REQUIRE(!payload.empty());
  const Bytes needle(subject_text.begin(), subject_text.end());
  const auto at = std::search(payload.begin(), payload.end(), needle.begin(), needle.end());
  RC_REQUIRE(at != payload.end());
  const std::size_t subject_offset = static_cast<std::size_t>(at - payload.begin());
  const auto decodes_with_subject = [&](char replacement) {
    Bytes patched = payload;
    for (std::size_t index = 0; index < subject_text.size(); ++index) {
      patched[subject_offset + index] = static_cast<std::uint8_t>(replacement);
    }
    PlanRequest decoded;
    return decode_payload(patched, limits, decoded);
  };
  RC_CHECK(!decodes_with_subject(' '));
  RC_CHECK(!decodes_with_subject('\x01'));
  Encoder encoder;
  encoder.text(over_long);
  Decoder decoder(encoder.bytes());
  std::string text_out;
  RC_CHECK(!decoder.text(text_out, kAbsoluteMaxSubjectBytes));
  // The dispatch below is the one ordinary mutation of this test; every view
  // compared afterwards covers the rejected attacks only.
  const AuthorityContext dispatch_authority = fixture.authority(44);
  const StepDispatch dispatch = governor.dispatch_step(corpus.plan, corpus.step, dispatch_authority);
  RC_REQUIRE(dispatch.accepted());
  const std::vector<std::string> before = corpus.snapshot();
  // The one malformed subject that can be built in process: no subject at all.
  std::vector<StepSpec> empty_subject = legal_plan();
  StepSpec blank;
  blank.kind = StepKind::VALIDATE_TARGET;
  blank.mandatory = false;
  blank.idempotent = true;
  empty_subject.push_back(blank);
  bad(governor.create_plan(request_at(empty_subject, src(), dst(), governor.epoch(), 42),
                           fixture.authority(43)),
      Outcome::GRAPH_INVALID, ConditionCode::MALFORMED_SUBJECT, "empty subject");
  // Malformed completion evidence is refused before anything else is consulted.
  const CompletionEvidence evidence = evidence_at(corpus.plan, corpus.step, dispatch,
                                                  dispatch_authority, fixture.publisher(),
                                                  fixture.boot());
  RC_REQUIRE(evidence.is_well_formed());
  const auto refuse = [&](CompletionEvidence record, std::uint64_t seed, const char* attack) {
    bad(governor.complete_step(record, fixture.authority(seed)), Outcome::MALFORMED_REQUEST,
        ConditionCode::MALFORMED_PAYLOAD, attack);
  };
  CompletionEvidence record = evidence;
  record.plan = ConvergencePlanId{};
  refuse(record, 45, "nil plan");
  record = evidence;
  record.step = TransitionStepId{};
  refuse(record, 46, "nil step");
  record = evidence;
  record.attempt = MutationAttemptId{};
  refuse(record, 47, "nil execution attempt");
  record = evidence;
  record.publisher = PublisherId{};
  refuse(record, 48, "nil publisher");
  record = evidence;
  record.worker_boot = WorkerBootId{};
  refuse(record, 49, "nil worker boot");
  record = evidence;
  record.step_generation = TransitionStepGeneration::from_value(0);
  refuse(record, 51, "zero step generation");
  record = evidence;
  record.epoch = CoordinatorEpoch::from_value(0);
  refuse(record, 52, "zero epoch");
  record = evidence;
  record.detail.assign(257, 'd');
  RC_CHECK(!record.is_well_formed());
  refuse(record, 53, "detail beyond the bound");
  record = evidence;
  record.detail.assign(256, 'd');
  RC_CHECK(record.is_well_formed());
  same(governor, before, "malformed subject and evidence attacks");
}

// GRAPH ATTACKS: duplicate keys, duplicate edges, self dependency, a missing
// prerequisite, cycles of length two and three, and a conflict-domain overlap
// inside one execution layer.
RC_TEST(explicit_graph_defects_are_rejected_with_exact_codes) {
  {
    Corpus control;
    ok(control.governor().create_plan(request_at(legal_plan(), src(), dst(),
                                                 control.governor().epoch(), 11),
                                      control.fixture.authority(12)),
       Outcome::PLAN_CREATED, "control explicit plan");
  }
  Fixture fixture(1);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  fixture.publish(dst());
  const std::vector<std::string> before = view(fixture.governor());
  std::uint64_t seed = 21;
  const auto attack = [&](std::vector<StepSpec> steps, ConditionCode code, const char* what) {
    seed += 2;
    bad(fixture.governor().create_plan(request_at(steps, src(), dst(), fixture.governor().epoch(),
                                                  seed),
                                      fixture.authority(seed)),
        Outcome::GRAPH_INVALID, code, what);
  };
  std::vector<StepSpec> duplicate_key = legal_plan();
  duplicate_key.push_back(duplicate_key[0]);
  attack(duplicate_key, ConditionCode::DUPLICATE_STEP, "duplicate step key");
  std::vector<StepSpec> duplicate_edge = legal_plan();
  duplicate_edge[1].depends_on.push_back(duplicate_edge[0].key());
  attack(duplicate_edge, ConditionCode::DEPENDENCY_DUPLICATE, "duplicate dependency edge");
  std::vector<StepSpec> self_dependency = legal_plan();
  self_dependency[1].depends_on.push_back(self_dependency[1].key());
  attack(self_dependency, ConditionCode::DEPENDENCY_SELF, "self dependency");
  std::vector<StepSpec> missing = legal_plan();
  StepKey ghost;
  ghost.kind = StepKind::INSTALL_NEW_ROUTE;
  ghost.subject = *SubjectToken::make("ghost");
  missing[1].depends_on.push_back(ghost);
  attack(missing, ConditionCode::DEPENDENCY_MISSING, "missing prerequisite");
  std::vector<StepSpec> cycle_two = legal_plan();
  cycle_two[0].depends_on.push_back(cycle_two[1].key());
  attack(cycle_two, ConditionCode::DEPENDENCY_CYCLE, "dependency cycle of length two");
  std::vector<StepSpec> cycle_three;
  cycle_three.push_back(step_at(StepKind::VALIDATE_TARGET, "target", dom(ConflictDomain::TARGET_STATE)));
  cycle_three.push_back(step_at(StepKind::PREPARE_NEW_STATE, "newpath", dom(ConflictDomain::PATH_STATE)));
  cycle_three.push_back(step_at(StepKind::FINALIZE, "plan", dom(ConflictDomain::TARGET_STATE)));
  cycle_three[0].depends_on.push_back(cycle_three[2].key());
  cycle_three[1].depends_on.push_back(cycle_three[0].key());
  cycle_three[2].depends_on.push_back(cycle_three[1].key());
  attack(cycle_three, ConditionCode::DEPENDENCY_CYCLE, "dependency cycle of length three");
  std::vector<StepSpec> overlap;
  overlap.push_back(step_at(StepKind::VALIDATE_TARGET, "target", dom(ConflictDomain::TARGET_STATE)));
  overlap.push_back(step_at(StepKind::VERIFY_NEW_STATE, "target", dom(ConflictDomain::TARGET_STATE)));
  overlap.push_back(step_at(StepKind::FINALIZE, "plan", dom(ConflictDomain::TARGET_STATE)));
  overlap[2].depends_on.push_back(overlap[0].key());
  overlap[2].depends_on.push_back(overlap[1].key());
  attack(overlap, ConditionCode::CONFLICT_DOMAIN_OVERLAP, "conflict-domain overlap in one layer");
  same(fixture.governor(), before, "graph attacks");
  RC_CHECK_EQ(fixture.governor().plan_count(), std::size_t{0});
}

// GENERATION ATTACKS: stale source/target route generations, a stale path
// authority generation, every stale optional upstream generation and a stale
// authority epoch.
RC_TEST(stale_upstream_generations_are_refused_with_exact_codes) {
  {
    Fixture fixture(1);
    RC_REQUIRE(fixture.define_policy(1).accepted());
    const RouteBinding observed = Fixture::binding(1, 3, 1, 1);
    fixture.publish(observed);
    const std::vector<std::string> before = view(fixture.governor());
    bad(fixture.create(src(), observed, 1, 31), Outcome::STALE_ROUTE,
        ConditionCode::SOURCE_ROUTE_STALE, "stale source route generation");
    same(fixture.governor(), before, "stale source generation");
  }
  {
    Fixture fixture(1);
    RC_REQUIRE(fixture.define_policy(1).accepted());
    const RouteBinding observed = Fixture::binding(1, 2, 1, 1);
    fixture.publish(observed);
    const std::vector<std::string> before = view(fixture.governor());
    bad(fixture.create(observed, Fixture::binding(1, 5, 1, 1), 1, 32), Outcome::STALE_ROUTE,
        ConditionCode::TARGET_ROUTE_STALE, "stale target route generation");
    same(fixture.governor(), before, "stale target generation");
  }
  {
    Fixture fixture(1);
    RC_REQUIRE(fixture.define_policy(1).accepted());
    const RouteBinding observed = Fixture::binding(1, 2, 2, 1);
    fixture.publish(observed);
    PathLegality advanced;
    advanced.path = observed.path;
    advanced.generation = PathAuthorityGeneration::from_value(2);
    advanced.legal = true;
    fixture.upstream().set_path(advanced);
    const std::vector<std::string> before = view(fixture.governor());
    bad(fixture.create(src(), observed, 1, 33), Outcome::STALE_PATH_AUTHORITY,
        ConditionCode::PATH_AUTHORITY_STALE, "stale PathAuthorityGeneration");
    same(fixture.governor(), before, "stale path authority generation");
  }
  {
    Fixture fixture(1);
    RC_REQUIRE(fixture.define_policy(1).accepted());
    const RouteBinding target = grouped(1, 2, 1);
    fixture.publish_pair(src(), target);
    RouteBinding moved = target;
    moved.assignment_generation = AssignmentGeneration::from_value(9);
    const std::vector<std::string> before = view(fixture.governor());
    bad(fixture.create(src(), moved, 1, 34), Outcome::STALE_DEPENDENCY,
        ConditionCode::ECMP_GENERATION_STALE, "stale group generations");
    same(fixture.governor(), before, "stale group generations");
  }
  // Each optional upstream generation is independently load-bearing: the
  // documented reaction is invalidation naming the exact stale cause.
  for (std::uint32_t field = 0; field < 4u; ++field) {
    Fixture fixture(1);
    RC_REQUIRE(fixture.define_policy(1).accepted());
    const RouteBinding target = grouped(1, 2, 1);
    fixture.publish_pair(src(), target);
    const PlanMutationResult created = fixture.create(src(), target, 1, 35);
    RC_REQUIRE(created.accepted());
    const TransitionStepId step = ready_of(fixture.governor(), created.plan);
    RC_REQUIRE(!step.is_nil());
    RouteBinding moved = target;
    ConditionCode expected = ConditionCode::NONE;
    CurrentnessCause cause = CurrentnessCause::STALE_MULTIPATH_SET;
    if (field == 0u) {
      moved.multipath_generation = MultipathSetGeneration::from_value(2);
      expected = ConditionCode::MULTIPATH_SET_STALE;
    } else if (field == 1u) {
      moved.ecmp_generation = ECMPGroupGeneration::from_value(2);
      expected = ConditionCode::ECMP_GENERATION_STALE;
      cause = CurrentnessCause::STALE_ECMP_GENERATION;
    } else if (field == 2u) {
      moved.assignment_generation = AssignmentGeneration::from_value(2);
      expected = ConditionCode::ASSIGNMENT_GENERATION_STALE;
      cause = CurrentnessCause::STALE_ASSIGNMENT_GENERATION;
    } else {
      moved.weight_policy_generation = WeightPolicyGeneration::from_value(2);
      expected = ConditionCode::WEIGHT_POLICY_STALE;
      cause = CurrentnessCause::STALE_WEIGHT_POLICY;
    }
    fixture.upstream().set_route(moved);
    bad(fixture.governor().dispatch_step(created.plan, step, fixture.authority(36)),
        Outcome::REVALIDATION_REQUIRED, expected, "stale optional upstream generation");
    const std::optional<PlanSummary> summary = fixture.governor().query_plan(created.plan);
    RC_REQUIRE(summary.has_value());
    RC_CHECK_EQ(summary->lifecycle, PlanLifecycle::REVALIDATION_REQUIRED);
    RC_CHECK(summary->currentness.has(cause));
  }
  {
    Corpus corpus;
    const std::vector<std::string> before = corpus.snapshot();
    AuthorityContext stale_epoch = corpus.fixture.authority(38);
    stale_epoch.epoch = CoordinatorEpoch::from_value(corpus.governor().epoch().value() + 3u);
    bad(corpus.governor().dispatch_step(corpus.plan, corpus.step, stale_epoch),
        Outcome::UNAUTHORIZED, ConditionCode::AUTHORITY_EPOCH_STALE, "stale epoch");
    same(corpus.governor(), before, "stale epoch");
  }
}

// GENERATION ATTACKS: a fenced worker boot, a stale policy generation, a policy
// ahead of the registry, and expected plan/step generation mismatches.
RC_TEST(stale_worker_policy_and_expected_generations_are_refused) {
  {
    Corpus corpus;
    const WorkerBootId original_boot = corpus.fixture.boot();
    // A reincarnated worker for the same publisher fences the previous boot.
    ok(corpus.fixture.register_worker(1, 99, rc::test::kAllCapabilities),
       Outcome::WORKER_REGISTERED, "reincarnated worker");
    RC_CHECK(corpus.governor().is_worker_fenced(original_boot));
    const std::vector<std::string> after_fence = corpus.snapshot();
    AuthorityContext old_boot = corpus.fixture.authority(39);
    old_boot.worker_boot = original_boot;
    bad(corpus.governor().dispatch_step(corpus.plan, corpus.step, old_boot), Outcome::UNAUTHORIZED,
        ConditionCode::WORKER_FENCED, "fenced worker boot");
    same(corpus.governor(), after_fence, "fenced worker boot attack");
  }
  {
    Fixture fixture(1);
    RC_REQUIRE(fixture.define_policy(1).accepted());
    fixture.publish(dst());
    const std::vector<std::string> before = view(fixture.governor());
    PlanRequest stale = request_at({}, src(), dst(), fixture.governor().epoch(), 43);
    stale.policy.generation = ConvergencePolicyGeneration::from_value(2);
    bad(fixture.governor().create_plan(stale, fixture.authority(44)), Outcome::STALE_POLICY,
        ConditionCode::POLICY_GENERATION_STALE, "stale policy generation");
    ConvergencePolicy ahead = Fixture::policy(1);
    ahead.generation = ConvergencePolicyGeneration::from_value(5);
    ahead.verification = VerificationMode::NONE;
    bad(fixture.governor().define_policy(ahead, fixture.authority(45)), Outcome::STALE_POLICY,
        ConditionCode::POLICY_GENERATION_STALE, "policy generation ahead of the registry");
    same(fixture.governor(), before, "policy generation attacks");
  }
  {
    Corpus corpus;
    ConvergencePolicy next = Fixture::policy(1);
    next.generation = ConvergencePolicyGeneration::from_value(2);
    next.verification = VerificationMode::NONE;
    ok(corpus.governor().define_policy(next, corpus.fixture.authority(46)), Outcome::POLICY_DEFINED,
       "policy generation two");
    bad(corpus.governor().dispatch_step(corpus.plan, corpus.step, corpus.fixture.authority(47)),
        Outcome::REVALIDATION_REQUIRED, ConditionCode::POLICY_GENERATION_STALE,
        "plan bound to a stale policy");
    const std::optional<PlanSummary> summary = corpus.governor().query_plan(corpus.plan);
    RC_REQUIRE(summary.has_value());
    RC_CHECK_EQ(summary->lifecycle, PlanLifecycle::REVALIDATION_REQUIRED);
  }
  {
    Corpus corpus;
    const std::vector<std::string> before = corpus.snapshot();
    AuthorityContext wrong_plan = corpus.fixture.authority(48);
    wrong_plan.expected_plan_generation = ConvergencePlanGeneration::from_value(99);
    bad(corpus.governor().dispatch_step(corpus.plan, corpus.step, wrong_plan), Outcome::STALE_PLAN,
        ConditionCode::PLAN_GENERATION_MISMATCH, "expected plan generation mismatch");
    AuthorityContext wrong_step = corpus.fixture.authority(49);
    wrong_step.expected_step_generation = TransitionStepGeneration::from_value(99);
    bad(corpus.governor().dispatch_step(corpus.plan, corpus.step, wrong_step), Outcome::STALE_STEP,
        ConditionCode::STEP_GENERATION_MISMATCH, "expected step generation mismatch");
    same(corpus.governor(), before, "expected generation attacks");
  }
}

// GENERATION ATTACKS: a rollback whose target state is no longer authorized.
RC_TEST(unsafe_rollback_is_rejected_without_a_rollback_plan) {
  Fixture fixture(1);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  fixture.publish_pair(src(), dst());
  const PlanMutationResult created = fixture.create(src(), dst(), 1, 61);
  RC_REQUIRE(created.accepted());
  RC_REQUIRE(fixture.drain(created.plan, 2).accepted());
  PathLegality withdrawn;
  withdrawn.path = src().path;
  withdrawn.generation = src().path_authority_generation;
  withdrawn.legal = false;
  fixture.upstream().set_path(withdrawn);
  const std::vector<std::string> before = view(fixture.governor());
  bad(fixture.governor().begin_rollback(created.plan, fixture.authority(63)),
      Outcome::UNSAFE_ROLLBACK, ConditionCode::ROLLBACK_TARGET_UNAUTHORIZED,
      "rollback target unauthorized");
  RC_CHECK(fixture.governor().stats().rollbacks_rejected > 0);
  same(fixture.governor(), before, "unsafe rollback");
  const std::optional<PlanSummary> summary = fixture.governor().query_plan(created.plan);
  RC_REQUIRE(summary.has_value());
  RC_CHECK(summary->lifecycle != PlanLifecycle::ROLLING_BACK);
}

// IDENTITY AND REPLAY ATTACKS: an attempt conflict, an exact replay, the
// documented STEP_DISPATCHED exception, another worker's boot, another plan's
// step and a forged dispatch watermark.
RC_TEST(attempt_conflicts_replays_and_forgeries_are_exact) {
  const RouteBinding other_source = Fixture::binding(2, 1, 3, 1);
  const RouteBinding other_target = Fixture::binding(2, 2, 4, 1);
  Fixture fixture(1);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  fixture.publish(dst());
  const PlanMutationResult first = fixture.create(src(), dst(), 1, 11);
  RC_REQUIRE(first.accepted());
  const TransitionStepId first_step = ready_of(fixture.governor(), first.plan);
  RC_REQUIRE(!first_step.is_nil());
  fixture.publish(other_target);
  const PlanMutationResult second = fixture.create(other_source, other_target, 1, 12);
  RC_REQUIRE(second.accepted());
  const TransitionStepId second_step = ready_of(fixture.governor(), second.plan);
  RC_REQUIRE(!second_step.is_nil());
  const std::vector<std::string> before = view(fixture.governor());
  // One mutation attempt identifier per request: two different mutations under
  // one identifier is a conflict, and an exact replay is idempotent.
  bad(fixture.governor().create_plan(
          request_at({}, other_source, other_target, fixture.governor().epoch(), 13),
          fixture.authority(11)),
      Outcome::ATTEMPT_CONFLICT, ConditionCode::ATTEMPT_CONFLICT, "attempt conflict");
  ok(fixture.create(src(), dst(), 1, 11), Outcome::IDEMPOTENT, "attempt replay");
  same(fixture.governor(), before, "attempt conflict and replay");
  // A stored STEP_DISPATCHED record is fresh for a later, different payload.
  const StepDispatch dispatched =
      fixture.governor().dispatch_step(second.plan, second_step, fixture.authority(14));
  RC_REQUIRE(dispatched.accepted());
  RC_CHECK_EQ(fixture.governor().dispatch_step(first.plan, first_step, fixture.authority(14)).outcome,
              Outcome::STEP_DISPATCHED);
  ok(add_worker(fixture, 2, 2), Outcome::WORKER_REGISTERED, "second worker");
  CompletionEvidence foreign = evidence_at(second.plan, second_step, dispatched,
                                           fixture.authority(14), fixture.publisher(),
                                           fixture.boot());
  foreign.publisher = Fixture::publisher_for(2);
  foreign.worker_boot = Fixture::boot_for(2);
  foreign.id = derive_evidence_id(foreign);
  bad(fixture.governor().complete_step(foreign, fixture.authority(16)), Outcome::STALE_WORKER,
      ConditionCode::WORKER_FENCED, "foreign worker boot");
  CompletionEvidence foreign_step = evidence_at(second.plan, second_step, dispatched,
                                                fixture.authority(14), fixture.publisher(),
                                                fixture.boot());
  foreign_step.step = first_step;
  foreign_step.id = derive_evidence_id(foreign_step);
  bad(fixture.governor().complete_step(foreign_step, fixture.authority(17)), Outcome::UNKNOWN_STEP,
      ConditionCode::STEP_UNKNOWN, "another plan's step");
  CompletionEvidence forged = evidence_at(second.plan, second_step, dispatched,
                                          fixture.authority(14), fixture.publisher(),
                                          fixture.boot());
  forged.dispatch_watermark = ConvergenceGeneration::from_value(4242);
  forged.id = derive_evidence_id(forged);
  bad(fixture.governor().complete_step(forged, fixture.authority(18)), Outcome::STALE_STEP,
      ConditionCode::WATERMARK_EXCEEDED, "forged dispatch watermark");
  // Every attack above left the step exactly where it was, so the genuine
  // completion still commits.
  ok(fixture.governor().complete_step(
         evidence_at(second.plan, second_step, dispatched, fixture.authority(14),
                     fixture.publisher(), fixture.boot()),
         fixture.authority(19)),
     Outcome::STEP_COMPLETED, "genuine completion after attacks");
}

// RESOURCE EXHAUSTION: the plan budget, the worker budget and the bounded
// attempt memory.
RC_TEST(plan_worker_and_attempt_bounds_are_exact) {
  const RouteBinding other_source = Fixture::binding(2, 1, 3, 1);
  const RouteBinding other_target = Fixture::binding(2, 2, 4, 1);
  const RouteBinding third_source = Fixture::binding(3, 1, 5, 1);
  const RouteBinding third_target = Fixture::binding(3, 2, 6, 1);
  {  // max_plans
    ConvergenceLimits limits;
    limits.max_plans = 1;
    Corpus corpus(limits);
    corpus.fixture.publish(other_target);
    const std::vector<std::string> before = corpus.snapshot();
    bad(corpus.fixture.create(other_source, other_target, 1, 12), Outcome::RESOURCE_LIMIT,
        ConditionCode::PLAN_LIMIT, "plan budget");
    same(corpus.governor(), before, "plan budget");
  }
  {  // max_workers
    ConvergenceLimits limits;
    limits.max_workers = 1;
    Fixture fixture(1, CoordinatorEpoch::from_value(1), limits);
    const std::vector<std::string> before = view(fixture.governor());
    bad(add_worker(fixture, 2, 2), Outcome::RESOURCE_LIMIT, ConditionCode::WORKER_LIMIT,
        "worker budget");
    same(fixture.governor(), before, "worker budget");
  }
  {  // max_attempts_remembered
    ConvergenceLimits limits;
    limits.max_attempts_remembered = 1;
    Fixture fixture(1, CoordinatorEpoch::from_value(1), limits);
    RC_REQUIRE(fixture.define_policy(1).accepted());
    fixture.publish(dst());
    RC_REQUIRE(fixture.create(src(), dst(), 1, 11).accepted());
    fixture.publish(other_target);
    // Inside the bound the record is remembered, so a different payload under
    // the same attempt identifier is a conflict.
    bad(fixture.create(other_source, other_target, 1, 11), Outcome::ATTEMPT_CONFLICT,
        ConditionCode::ATTEMPT_CONFLICT, "remembered attempt conflict");
    RC_CHECK_EQ(fixture.governor().stats().attempt_conflicts, std::uint64_t{1});
    // One more recorded mutation evicts the oldest record of a memory that is
    // bounded by max_attempts_remembered.
    RC_REQUIRE(fixture.create(other_source, other_target, 1, 13).accepted());
    fixture.publish(third_target);
    ok(fixture.create(third_source, third_target, 1, 11), Outcome::PLAN_CREATED,
       "attempt forgotten at the bound");
  }
  {  // Control: with the default bound the same sequence is still a conflict.
    Fixture control(1);
    RC_REQUIRE(control.define_policy(1).accepted());
    control.publish(dst());
    RC_REQUIRE(control.create(src(), dst(), 1, 11).accepted());
    control.publish(other_target);
    RC_REQUIRE(control.create(other_source, other_target, 1, 13).accepted());
    control.publish(third_target);
    bad(control.create(third_source, third_target, 1, 11), Outcome::ATTEMPT_CONFLICT,
        ConditionCode::ATTEMPT_CONFLICT, "default attempt memory");
  }
}

// RESOURCE EXHAUSTION: the explanation list and the per-plan history are bounded
// and the truncation is reported.
RC_TEST(explanation_and_history_bounds_are_reported) {
  {  // max_explanation_entries
    ConvergenceLimits limits;
    limits.max_explanation_entries = 2;
    Corpus corpus(limits);
    ConvergenceGovernor& governor = corpus.governor();
    // Several independent currentness causes are made true at once.
    PathLegality moved_path;
    moved_path.path = dst().path;
    moved_path.generation = PathAuthorityGeneration::from_value(7);
    moved_path.legal = true;
    corpus.fixture.upstream().set_path(moved_path);
    corpus.fixture.upstream().set_route(Fixture::binding(1, 9, 2, 1));
    corpus.fixture.upstream().set_epoch(CoordinatorEpoch::from_value(4));
    RC_CHECK_EQ(governor.sync_epoch().epoch.value(), std::uint64_t{4});
    ConvergencePolicy next = Fixture::policy(1);
    next.generation = ConvergencePolicyGeneration::from_value(2);
    next.verification = VerificationMode::NONE;
    ok(governor.define_policy(next, corpus.fixture.authority(72)), Outcome::POLICY_DEFINED,
       "policy generation two");
    const StepDispatch dispatch =
        governor.dispatch_step(corpus.plan, corpus.step, corpus.fixture.authority(73));
    RC_CHECK_EQ(dispatch.outcome, Outcome::REVALIDATION_REQUIRED);
    RC_CHECK(dispatch.conditions.entries().size() <= limits.max_explanation_entries);
    RC_CHECK(!dispatch.conditions.entries().empty());
    ExplainRequest request;
    request.plan = corpus.plan;
    request.kind = ExplainKind::STALENESS;
    const ExplainResponse response = governor.explain(request);
    RC_CHECK(response.found);
    RC_CHECK(response.explanation.truncated());
    RC_CHECK(response.explanation.conditions().entries().size() <= limits.max_explanation_entries);
    RC_CHECK(response.render().find("EXPLANATION_LIMIT") != std::string::npos);
  }
  {  // max_history_per_plan: two completed steps produce more than two entries,
     // so an exact count of two proves the bound was the binding constraint.
    ConvergenceLimits limits;
    limits.max_history_per_plan = 2;
    Corpus corpus(limits);
    RC_REQUIRE(corpus.fixture.drain(corpus.plan, 2).accepted());
    const std::optional<ConvergenceDiff> diff =
        corpus.governor().diff(corpus.plan, ConvergencePlanGeneration::from_value(0));
    RC_REQUIRE(diff.has_value());
    RC_CHECK_EQ(diff->entries.size(), std::size_t{2});
    RC_CHECK(diff->entries.size() <= limits.max_history_per_plan);
  }
}

// RESOURCE EXHAUSTION: every remaining ConvergenceLimits bound bites exactly.
RC_TEST(every_remaining_limit_bound_bites_with_a_stable_result) {
  {  // max_steps_per_plan
    ConvergenceLimits limits;
    limits.max_steps_per_plan = 4;
    limits.max_parallel_steps = 1;
    create_is_refused(limits, {}, 81, Outcome::RESOURCE_LIMIT, ConditionCode::STEP_LIMIT,
                      "step count budget");
  }
  {  // max_dependencies_per_step: only the per-step bound is exceeded.
    ConvergenceLimits limits;
    limits.max_dependencies_per_step = 2;
    limits.max_total_dependencies = 8;
    limits.max_parallel_steps = 4;
    limits.max_steps_per_plan = 8;
    std::vector<StepSpec> steps;
    steps.push_back(step_at(StepKind::VALIDATE_TARGET, "target", dom(ConflictDomain::TARGET_STATE)));
    steps.push_back(step_at(StepKind::INSTALL_NEW_ROUTE, "route", dom(ConflictDomain::ROUTE_TABLE)));
    steps.push_back(step_at(StepKind::PREPARE_NEW_STATE, "newpath", dom(ConflictDomain::PATH_STATE)));
    steps[2].depends_on.push_back(steps[0].key());
    steps.push_back(step_at(StepKind::FINALIZE, "plan", dom(ConflictDomain::TARGET_STATE)));
    steps[3].depends_on.push_back(steps[0].key());
    steps[3].depends_on.push_back(steps[1].key());
    steps[3].depends_on.push_back(steps[2].key());
    create_is_refused(limits, steps, 83, Outcome::GRAPH_INVALID, ConditionCode::DEPENDENCY_LIMIT,
                      "per-step dependency budget");
    Fixture fixture(83, CoordinatorEpoch::from_value(1), limits);
    RC_REQUIRE(fixture.define_policy(1).accepted());
    fixture.publish(dst());
    const PlanMutationResult result =
        fixture.governor().create_plan(request_at(steps, src(), dst(), fixture.governor().epoch(), 93),
                                       fixture.authority(94));
    RC_CHECK(!has_condition(result.conditions, ConditionCode::TOTAL_DEPENDENCY_LIMIT));
  }
  {  // max_total_dependencies: every step stays inside the per-step bound.
    ConvergenceLimits limits;
    limits.max_dependencies_per_step = 2;
    limits.max_total_dependencies = 2;
    limits.max_parallel_steps = 4;
    limits.max_steps_per_plan = 8;
    std::vector<StepSpec> steps;
    steps.push_back(step_at(StepKind::VALIDATE_TARGET, "target", dom(ConflictDomain::TARGET_STATE)));
    steps.push_back(step_at(StepKind::PREPARE_NEW_STATE, "newpath", dom(ConflictDomain::PATH_STATE)));
    steps[1].depends_on.push_back(steps[0].key());
    steps.push_back(step_at(StepKind::INSTALL_NEW_ROUTE, "route", dom(ConflictDomain::ROUTE_TABLE)));
    steps[2].depends_on.push_back(steps[1].key());
    steps.push_back(step_at(StepKind::FINALIZE, "plan", dom(ConflictDomain::TARGET_STATE)));
    steps[3].depends_on.push_back(steps[1].key());
    steps[3].depends_on.push_back(steps[2].key());
    create_is_refused(limits, steps, 85, Outcome::GRAPH_INVALID,
                      ConditionCode::TOTAL_DEPENDENCY_LIMIT, "total dependency budget");
    Fixture fixture(85, CoordinatorEpoch::from_value(1), limits);
    RC_REQUIRE(fixture.define_policy(1).accepted());
    fixture.publish(dst());
    const PlanMutationResult result =
        fixture.governor().create_plan(request_at(steps, src(), dst(), fixture.governor().epoch(), 95),
                                       fixture.authority(96));
    RC_CHECK(!has_condition(result.conditions, ConditionCode::DEPENDENCY_LIMIT));
  }
  {  // max_parallel_steps
    ConvergenceLimits limits;
    limits.max_parallel_steps = 1;
    limits.max_steps_per_plan = 8;
    std::vector<StepSpec> steps;
    steps.push_back(step_at(StepKind::VALIDATE_TARGET, "target", dom(ConflictDomain::TARGET_STATE)));
    steps.push_back(step_at(StepKind::INSTALL_NEW_ROUTE, "route", dom(ConflictDomain::ROUTE_TABLE)));
    steps.push_back(step_at(StepKind::FINALIZE, "plan", dom(ConflictDomain::TARGET_STATE)));
    steps[2].depends_on.push_back(steps[0].key());
    steps[2].depends_on.push_back(steps[1].key());
    create_is_refused(limits, steps, 87, Outcome::GRAPH_INVALID, ConditionCode::PARALLELISM_LIMIT,
                      "parallel step budget");
  }
  {  // max_retries_per_step: a retryable failure re-arms the step only while the
     // bound allows another attempt.
    ConvergenceLimits limits;
    limits.max_retries_per_step = 0;
    Corpus corpus(limits);
    RC_REQUIRE(corpus.governor()
                   .dispatch_step(corpus.plan, corpus.step, corpus.fixture.authority(88))
                   .accepted());
    ok(corpus.governor().fail_step(corpus.plan, corpus.step, BackendOutcome::RETRYABLE_FAILURE,
                                   "transient", corpus.fixture.authority(89)),
       Outcome::RETRYABLE_FAILURE, "retry budget");
    const std::optional<ConvergenceSnapshot> snapshot = corpus.governor().snapshot(corpus.plan);
    RC_REQUIRE(snapshot.has_value());
    bool observed_failed = false;
    for (const StepSnapshot& candidate : snapshot->steps) {
      if (candidate.id == corpus.step) {
        observed_failed = candidate.state == StepLifecycle::FAILED;
      }
    }
    RC_CHECK(observed_failed);
    const std::optional<PlanSummary> summary = corpus.governor().query_plan(corpus.plan);
    RC_REQUIRE(summary.has_value());
    RC_CHECK_EQ(summary->lifecycle, PlanLifecycle::PAUSED);
  }
  {  // max_frame_bytes
    ConvergenceLimits limits;
    limits.max_frame_bytes = kMinimumFrameBytes;
    Envelope envelope;
    envelope.message = WireMessageId::HELLO;
    envelope.epoch = CoordinatorEpoch::from_value(1);
    envelope.publisher = Fixture::publisher_for(1);
    envelope.worker_boot = Fixture::boot_for(1);
    envelope.attempt = Fixture::attempt_for(1);
    envelope.payload.assign(kMinimumFrameBytes + 1u, 0x5Au);
    RC_CHECK(encode_frame(envelope, limits).empty());
    const Bytes oversized = encode_frame(envelope, ConvergenceLimits{});
    RC_REQUIRE(!oversized.empty());
    Envelope decoded;
    RC_CHECK_EQ(decode_frame(oversized, limits, decoded), WireDefect::FRAME_TOO_LARGE);
    RC_CHECK_EQ(condition_for(WireDefect::FRAME_TOO_LARGE), ConditionCode::FRAME_LIMIT);
  }
  {  // max_batch_size
    ConvergenceLimits limits;
    limits.max_batch_size = 1;
    Fixture fixture(1, CoordinatorEpoch::from_value(1), limits);
    RC_REQUIRE(fixture.define_policy(1).accepted());
    fixture.publish(dst());
    const PlanMutationResult created = fixture.create(src(), dst(), 1, 91);
    RC_REQUIRE(created.accepted());
    const RouteBinding other_source = Fixture::binding(2, 1, 3, 1);
    const RouteBinding other_target = Fixture::binding(2, 2, 4, 1);
    fixture.publish(other_target);
    RC_REQUIRE(fixture.create(other_source, other_target, 1, 92).accepted());
    const PlanList plans = fixture.governor().list_plans();
    RC_CHECK_EQ(plans.plans.size(), std::size_t{1});
    RC_CHECK(plans.truncated);
    const ReadyStepList ready = fixture.governor().ready_steps(64);
    RC_CHECK(ready.steps.size() <= std::size_t{1});
    RC_CHECK(ready.truncated);
    const std::optional<PlanSummary> first = fixture.governor().query_plan(created.plan);
    RC_REQUIRE(first.has_value());
    PlanList two;
    two.plans.push_back(*first);
    two.plans.push_back(*first);
    const Bytes encoded = encode_payload(two);
    RC_REQUIRE(!encoded.empty());
    PlanList decoded;
    RC_CHECK(!decode_payload(encoded, limits, decoded));
    RC_CHECK(decode_payload(encoded, ConvergenceLimits{}, decoded));
  }
  {  // max_journal_entries: the journal seam is bounded by its capacity and
     // reports exhaustion as a structured backend outcome.
    ConvergenceLimits limits;
    limits.max_journal_entries = 1;
    std::string reason;
    RC_CHECK(limits.is_coherent(reason));
    JournalBackend journal(1);
    StepExecutionRequest first;
    first.plan = derive_id<ConvergencePlanId>("rc.adversarial.plan", 1);
    first.step = derive_id<TransitionStepId>("rc.adversarial.step", 1);
    StepExecutionRequest second = first;
    second.step = derive_id<TransitionStepId>("rc.adversarial.step", 2);
    std::string detail;
    RC_CHECK_EQ(journal.apply(first, detail), BackendOutcome::APPLIED);
    RC_CHECK_EQ(journal.apply(second, detail), BackendOutcome::PERMANENT_FAILURE);
    RC_CHECK_EQ(journal.applied_count(), std::size_t{1});
    RC_CHECK_EQ(journal.apply(first, detail), BackendOutcome::IDEMPOTENT);
    RC_CHECK_EQ(journal.applied_count(), std::size_t{1});
  }
}

// WIRE ATTACKS: for every known message identifier, a frame that is one byte
// short, one byte long, header-flipped, tag-flipped, unknown, version-flipped,
// flagged, reserved, over-long and empty; every byte of a reference frame; and
// the exact ConditionCode of every WireDefect.
RC_TEST(wire_frames_and_wire_defect_codes_are_exact) {
  const ConvergenceLimits limits;
  Envelope envelope;
  envelope.message = WireMessageId::HELLO;
  envelope.sequence = 77;
  envelope.epoch = CoordinatorEpoch::from_value(3);
  envelope.publisher = Fixture::publisher_for(3);
  envelope.worker_boot = Fixture::boot_for(3);
  envelope.attempt = Fixture::attempt_for(4);
  envelope.payload = {0x01u, 0x02u, 0x03u, 0x04u, 0x05u};
  std::vector<WireMessageId> known;
  for (std::uint32_t raw = 0; raw <= 0xFFFFu; ++raw) {
    if (is_known_message(static_cast<std::uint16_t>(raw))) {
      known.push_back(static_cast<WireMessageId>(raw));
    }
  }
  RC_CHECK_EQ(known.size(), std::size_t{51});
  Envelope decoded;
  for (const WireMessageId id : known) {
    envelope.message = id;
    const Bytes frame = encode_frame(envelope, limits);
    RC_REQUIRE(!frame.empty());
    RC_CHECK_EQ(frame.size(), kWireOverheadBytes + envelope.payload.size());
    RC_CHECK_EQ(decode_frame(frame, limits, decoded), WireDefect::NONE);
    RC_CHECK_EQ(decoded.message, id);
    const Bytes short_frame(frame.begin(), frame.end() - 1);
    RC_CHECK_EQ(decode_frame(short_frame, limits, decoded), WireDefect::TRUNCATED);
    Bytes long_frame = frame;
    long_frame.push_back(0x00u);
    RC_CHECK_EQ(decode_frame(long_frame, limits, decoded), WireDefect::TRAILING_BYTES);
    Bytes header_flip = frame;
    header_flip[kFrameSequenceOffset + 3] =
        static_cast<std::uint8_t>(header_flip[kFrameSequenceOffset + 3] ^ 0x01u);
    RC_CHECK_EQ(decode_frame(header_flip, limits, decoded), WireDefect::INTEGRITY_FAILURE);
    Bytes tag_flip = frame;
    tag_flip[frame.size() - 1] = static_cast<std::uint8_t>(tag_flip[frame.size() - 1] ^ 0x01u);
    RC_CHECK_EQ(decode_frame(tag_flip, limits, decoded), WireDefect::INTEGRITY_FAILURE);
    Bytes unknown = frame;
    put_u16_le(unknown, kFrameMessageOffset, 0xFFFFu);
    RC_CHECK_EQ(decode_frame(unknown, limits, decoded), WireDefect::UNKNOWN_MESSAGE);
    Bytes version = frame;
    put_u16_le(version, kFrameVersionOffset, static_cast<std::uint16_t>(kWireVersion + 1u));
    RC_CHECK_EQ(decode_frame(version, limits, decoded), WireDefect::VERSION_MISMATCH);
    Bytes flags = frame;
    put_u32_le(flags, kFrameFlagsOffset, 1u);
    RC_CHECK_EQ(decode_frame(flags, limits, decoded), WireDefect::RESERVED_NOT_ZERO);
    Bytes reserved = frame;
    put_u32_le(reserved, kFrameReservedOffset, 0x80000000u);
    RC_CHECK_EQ(decode_frame(reserved, limits, decoded), WireDefect::RESERVED_NOT_ZERO);
    Bytes over_long = frame;
    put_u32_le(over_long, kFramePayloadBytesOffset, limits.max_frame_bytes + 1u);
    RC_CHECK_EQ(decode_frame(over_long, limits, decoded), WireDefect::FRAME_TOO_LARGE);
    RC_CHECK_EQ(decode_frame(Bytes{}, limits, decoded), WireDefect::TRUNCATED);
    const Bytes ten_bytes(frame.begin(), frame.begin() + 10);
    RC_CHECK_EQ(decode_frame(ten_bytes, limits, decoded), WireDefect::TRUNCATED);
  }
  const Bytes reference = encode_frame(envelope, limits);
  RC_REQUIRE(!reference.empty());
  for (std::size_t offset = 0; offset < reference.size(); ++offset) {
    Bytes tampered = reference;
    tampered[offset] = static_cast<std::uint8_t>(tampered[offset] ^ 0x01u);
    RC_CHECK_EQ(decode_frame(tampered, limits, decoded),
                expected_frame_defect_for_flip(tampered, offset, limits));
  }
  const std::pair<WireDefect, ConditionCode> wire_codes[] = {
      {WireDefect::NONE, ConditionCode::NONE},
      {WireDefect::TRUNCATED, ConditionCode::WIRE_TRUNCATED},
      {WireDefect::TRAILING_BYTES, ConditionCode::WIRE_TRAILING_BYTES},
      {WireDefect::UNKNOWN_MESSAGE, ConditionCode::WIRE_UNKNOWN_MESSAGE},
      {WireDefect::VERSION_MISMATCH, ConditionCode::WIRE_VERSION_MISMATCH},
      {WireDefect::INTEGRITY_FAILURE, ConditionCode::WIRE_INTEGRITY_FAILURE},
      {WireDefect::FRAME_TOO_LARGE, ConditionCode::FRAME_LIMIT},
      {WireDefect::MALFORMED_PAYLOAD, ConditionCode::MALFORMED_PAYLOAD},
      {WireDefect::BAD_MAGIC, ConditionCode::WIRE_INTEGRITY_FAILURE},
      {WireDefect::RESERVED_NOT_ZERO, ConditionCode::WIRE_INTEGRITY_FAILURE},
      {WireDefect::PEER_TIMEOUT, ConditionCode::PEER_TIMEOUT},
      {WireDefect::PEER_CLOSED, ConditionCode::PEER_CLOSED},
  };
  for (const std::pair<WireDefect, ConditionCode>& entry : wire_codes) {
    RC_CHECK_EQ(condition_for(entry.first), entry.second);
  }
}

// STORE ATTACKS: empty, bad magic, unsupported version, every truncation length,
// corruption at every offset, an over-long declared payload, trailing bytes, the
// exact ConditionCode of every StoreDefect, and a real governor load.
RC_TEST(store_images_and_store_defect_codes_are_exact) {
  const ConvergenceLimits limits;
  Bytes payload;
  for (std::uint32_t index = 0; index < 24u; ++index) {
    payload.push_back(static_cast<std::uint8_t>(((index * 7u) + 3u) & 0xFFu));
  }
  const Bytes image = encode_store_file(3u, 9u, payload);
  RC_CHECK_EQ(image.size(), kStoreHeaderBytes + payload.size() + kStoreTagBytes);
  StoreFileInfo info;
  Bytes decoded;
  RC_CHECK_EQ(decode_store_file(image, limits, info, decoded), StoreDefect::NONE);
  RC_CHECK_EQ(info.format_version, kPersistenceFormatVersion);
  RC_CHECK_EQ(info.coordinator_epoch, std::uint64_t{3});
  RC_CHECK_EQ(info.convergence_generation, std::uint64_t{9});
  RC_CHECK_EQ(info.payload_bytes, 24u);
  RC_CHECK(decoded == payload);
  RC_CHECK_EQ(decode_store_file(Bytes{}, limits, info, decoded), StoreDefect::EMPTY);
  for (std::size_t index = 0; index < kStoreMagicBytes; ++index) {
    Bytes bad_magic = image;
    bad_magic[index] = static_cast<std::uint8_t>(bad_magic[index] ^ 0x20u);
    RC_CHECK_EQ(decode_store_file(bad_magic, limits, info, decoded), StoreDefect::BAD_MAGIC);
  }
  Bytes unsupported = image;
  put_u32_le(unsupported, kStoreVersionOffset, kPersistenceFormatVersion + 1u);
  RC_CHECK_EQ(decode_store_file(unsupported, limits, info, decoded), StoreDefect::BAD_VERSION);
  Bytes zero_version = image;
  put_u32_le(zero_version, kStoreVersionOffset, 0u);
  RC_CHECK_EQ(decode_store_file(zero_version, limits, info, decoded), StoreDefect::BAD_VERSION);
  Bytes reserved = image;
  put_u32_le(reserved, kStoreReservedOffset, 1u);
  RC_CHECK_EQ(decode_store_file(reserved, limits, info, decoded), StoreDefect::RESERVED_NOT_ZERO);
  for (std::size_t length = 0; length < image.size(); ++length) {
    const Bytes truncated(image.begin(), image.begin() + static_cast<std::ptrdiff_t>(length));
    RC_CHECK_EQ(decode_store_file(truncated, limits, info, decoded),
                length == 0 ? StoreDefect::EMPTY : StoreDefect::TRUNCATED);
  }
  Bytes trailing = image;
  trailing.push_back(0x00u);
  RC_CHECK_EQ(decode_store_file(trailing, limits, info, decoded), StoreDefect::TRAILING_BYTES);
  Bytes over_long = image;
  put_u32_le(over_long, kStorePayloadBytesOffset, limits.max_persistence_record_bytes + 1u);
  RC_CHECK_EQ(decode_store_file(over_long, limits, info, decoded), StoreDefect::PAYLOAD_TOO_LARGE);
  for (std::size_t offset = 0; offset < image.size(); ++offset) {
    Bytes corrupted = image;
    corrupted[offset] = static_cast<std::uint8_t>(corrupted[offset] ^ 0x01u);
    RC_CHECK_EQ(decode_store_file(corrupted, limits, info, decoded),
                expected_store_defect_for_flip(corrupted, offset, limits));
  }
  const std::pair<StoreDefect, ConditionCode> store_codes[] = {
      {StoreDefect::NONE, ConditionCode::NONE},
      {StoreDefect::IO_ERROR, ConditionCode::STORE_IO},
      {StoreDefect::EMPTY, ConditionCode::STORE_STRUCTURE},
      {StoreDefect::BAD_MAGIC, ConditionCode::STORE_MAGIC},
      {StoreDefect::BAD_VERSION, ConditionCode::STORE_VERSION},
      {StoreDefect::RESERVED_NOT_ZERO, ConditionCode::STORE_STRUCTURE},
      {StoreDefect::TRUNCATED, ConditionCode::STORE_STRUCTURE},
      {StoreDefect::TRAILING_BYTES, ConditionCode::STORE_TRAILING_BYTES},
      {StoreDefect::INTEGRITY_FAILURE, ConditionCode::STORE_INTEGRITY},
      {StoreDefect::PAYLOAD_TOO_LARGE, ConditionCode::STORE_RECORD_LIMIT},
      {StoreDefect::STRUCTURE, ConditionCode::STORE_STRUCTURE},
  };
  for (const std::pair<StoreDefect, ConditionCode>& entry : store_codes) {
    RC_CHECK_EQ(condition_for(entry.first), entry.second);
  }
  // A real governor refuses a defective file and keeps its state, and the
  // record budget is consulted by save() before anything is written.
  Scratch directory("store");
  Corpus corpus;
  const std::vector<std::string> before = corpus.snapshot();
  const std::filesystem::path path = directory.file("attacked.store");
  std::string error;
  RC_CHECK_EQ(write_store_file_atomic(path, Bytes{}, error), StoreDefect::NONE);
  bad(corpus.governor().load(path), Outcome::STORE_ERROR, ConditionCode::STORE_STRUCTURE,
      "empty store file");
  same(corpus.governor(), before, "empty store file");
  Bytes corrupted = image;
  corrupted[image.size() - 1] = static_cast<std::uint8_t>(corrupted[image.size() - 1] ^ 0x01u);
  RC_CHECK_EQ(write_store_file_atomic(path, corrupted, error), StoreDefect::NONE);
  bad(corpus.governor().load(path), Outcome::STORE_ERROR, ConditionCode::STORE_INTEGRITY,
      "corrupted store tag");
  same(corpus.governor(), before, "corrupted store tag");
  ConvergenceLimits tiny;
  tiny.max_persistence_record_bytes = 1;
  Corpus bounded(tiny);
  bad(bounded.governor().save(directory.file("never.store")), Outcome::STORE_ERROR,
      ConditionCode::STORE_RECORD_LIMIT, "store record budget");
  RC_CHECK(!std::filesystem::exists(directory.file("never.store")));
}

// RESOURCE EXHAUSTION: the session budget is consulted by the real coordinator
// server, which refuses a connection beyond the bound without making it a
// session.
RC_TEST(session_limit_refuses_a_session_beyond_the_bound) {
  ConvergenceLimits limits;
  limits.max_sessions = 1;
  Fixture fixture(1);
  RC_REQUIRE(fixture.define_policy(1).accepted());
  CoordinatorServerOptions options;
  options.port = 0;
  options.limits = limits;
  options.synthetic_upstream = &fixture.upstream();
  CoordinatorServer server(fixture.governor(), options);
  std::string error;
  RC_REQUIRE(server.start(error));
  RC_REQUIRE(server.port() != 0);
  std::thread serving([&server]() { server.serve(); });
  std::optional<RcClient> first = RcClient::connect("127.0.0.1", server.port(), 5000, error);
  RC_REQUIRE(first.has_value());
  HelloResponseBody hello;
  RC_REQUIRE(first->hello(hello, error));
  RC_CHECK_EQ(server.active_sessions(), 1u);
  std::optional<TcpConnection> second = connect_loopback(server.port(), error);
  RC_REQUIRE(second.has_value());
  Bytes buffer(1, 0);
  RC_CHECK_EQ(second->receive_exactly(buffer, 5000, error), ReceiveStatus::CLOSED);
  RC_CHECK(server.active_sessions() <= 1u);
  second->close();
  first->close();
  server.stop();
  serving.join();
  RC_CHECK(server.active_sessions() <= 1u);
}
