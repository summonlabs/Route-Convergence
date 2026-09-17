# Route Convergence

**Route Convergence 1.0.0** is the deterministic route-transition ordering,
dependency-safe state change and convergence-governance runtime of the
Distributed Fabric Infrastructure / Fabric OS stack, published by Summon
Software Labs.

It answers exactly one question:

> Given an authoritative current route state, an authoritative desired route
> state, exact path and dependency generations and an explicit convergence
> policy, which ordered transition steps are legally required to move the fabric
> from the old state to the new state, which steps may execute now, what evidence
> proves each step completed, and when must the transition pause, roll back,
> revalidate, supersede or reject stale work?

Route Convergence governs the **transition**, not the route. It plans and
sequences control-plane route-state transitions. It does not compute paths, does
not decide legality, does not own route records, does not program hardware and
does not move packets.

## Boundary

Route Convergence owns:

- convergence-plan identity, plan generations and plan lifecycle;
- transition-step identity, step generations and step lifecycle;
- the explicit transition dependency DAG, its validation and its canonical
  topological execution order;
- make-before-break and break-before-make sequencing, and explicit overlap
  semantics;
- prerequisite enforcement and dispatch authority;
- structured completion evidence and stale-completion fencing;
- invalidation watermarks, plan currentness and plan revalidation;
- transition supersession and lineage;
- explicit rollback planning, rollback eligibility and unsafe-rollback refusal;
- ambiguous side effects and reconciliation;
- deterministic snapshots, diffs, explanations and semantic digests;
- versioned integrity-checked persistence and conservative recovery;
- distributed execution authority, real worker-death proof and real
  coordinator-restart proof.

Route Convergence does **not** own, and never reimplements:

| Domain | Owner | What Route Convergence does instead |
| --- | --- | --- |
| canonical entity identity | Fabric Registry | consumes RouteId, PathId, FabricId, RoutingNamespaceId, PublisherId, WorkerBootId |
| topology | Fabric Topology | never walks the graph |
| live link health | Link State Fabric | never reads link state |
| port configuration | Port Fabric | never touches a port |
| capability truth | Fabric Capability Registry | never infers capability |
| failure-domain truth | Failure Domain Registry | never derives failure domains |
| epoch issuance | Fabric Epoch | consumes the current CoordinatorEpoch and refuses work bound to an old one |
| path computation | Path Planner | never searches, ranks or synthesises a path |
| path legality | Path Authority | binds the exact PathAuthorityGeneration; a newer generation makes the plan stale |
| route lifecycle and route state | Route Fabric | consumes the exact source and target RouteBinding observations; never edits a route record |
| simultaneous multipath membership | Multipath Fabric | binds the exact MultipathSetId and MultipathSetGeneration |
| equal-cost assignment | ECMP Governor | binds the exact ECMPGroupId, membership generation and AssignmentGeneration; never assigns a bucket |
| unequal path weighting | Weighted Path Fabric | binds the exact WeightedPathSetId and WeightPolicyGeneration; never computes a weight |
| adaptation policy | Adaptive Routing Fabric | never decides that routing preference should change |
| global optimisation | Traffic Engineering | consumes a target state; never solves one |

**A desired route is not convergence, and an acknowledged update is not a
transition.** The whole point of this runtime is that the following are
different facts, and it keeps them different:

    DESIRED ROUTE STATE EXISTS
    CONVERGENCE PLAN EXISTS
    TRANSITION STEP IS AUTHORIZED
    TRANSITION STEP IS DISPATCHED
    TRANSITION STEP COMPLETED
    DEPENDENCIES ARE SATISFIED
    NEW STATE IS SAFE TO ACTIVATE
    OLD STATE IS SAFE TO REMOVE
    CONVERGENCE IS COMPLETE

## Transition is a first-class object

A convergence plan is not an implicit side effect of a route update. It is a
governed object with:

- a stable `ConvergencePlanId`, derived from its semantic content;
- an exact source `RouteGeneration` and an exact target `RouteGeneration`;
- an exact bound `ConvergencePolicyGeneration`;
- a `ConvergencePlanGeneration` that advances only when semantic content
  changes;
- an explicit lifecycle;
- an ordered, dependency-constrained step DAG;
- an explicit authority generation, owner publisher and owner worker boot;
- an invalidation watermark;
- lineage: predecessor, successor and supersession reason;
- a semantic digest.

### Plan identity and plan key

The **plan key** is the semantic uniqueness of a plan:

    (RouteId, source RouteGeneration, target RouteGeneration, ConvergencePolicyGeneration)

Two requests with the same key are the same *semantic* plan. Exact replay of the
same semantic plan is **idempotent** and advances nothing. If the content of the
same key changes — a different path authority generation, a different generated
DAG — the plan identity changes, and the earlier plan is superseded with the
lineage recorded.

The **plan identity** is content-addressed:
`ConvergencePlanId = H(plan key || plan structure digest)`, where the structure
digest covers the exact bindings, the policy generation and the canonical step
DAG. Identity therefore depends on nothing but semantics: not on arrival order,
not on insertion order, not on memory address, not on a process-local counter.

### Step identity

A step is identified by `TransitionStepId = H(ConvergencePlanId || step kind ||
step subject)`. Its **generation** starts at one and advances on every dispatch,
so a completion from an earlier dispatch can never be mistaken for a completion
of the current one. Step state is never reduced to a boolean.

### Step vocabulary

Route Convergence 1.0.0 supports exactly ten control-plane step classes:

| Step kind | Role | Reversibility |
| --- | --- | --- |
| `VALIDATE_TARGET` | confirm the target binding is current and legal | observation |
| `PREPARE_NEW_STATE` | idempotent preparation of the new path state | compensatable (implicit release) |
| `INSTALL_NEW_GROUP` | install the target multipath/ECMP/weighted generation | compensatable |
| `INSTALL_NEW_ROUTE` | install the target route record | compensatable |
| `ACTIVATE_NEW_PATH` | make the target path carrying | compensatable |
| `VERIFY_NEW_STATE` | verify the target state is applied | observation |
| `DEACTIVATE_OLD_PATH` | stop the source path carrying | compensatable |
| `WITHDRAW_OLD_ROUTE` | remove the source route record | compensatable |
| `VERIFY_REMOVAL` | verify the old state is gone | observation |
| `FINALIZE` | barrier and commit of convergence | observation |

No hardware-specific command exists in this vocabulary. Route Convergence 1.0.0
never programmes a switch.

### Dependency graph and canonical order

Steps form an explicit DAG. The governor validates, on every plan:

- every step key is unique;
- every declared prerequisite exists;
- no step depends on itself;
- no duplicate edges;
- no cycles (of any length);
- per-step and total dependency counts stay inside the configured limits;
- no two steps in the same execution layer share a conflict domain on the same
  subject.

Canonical topological order is deterministic and tie-broken by `StepKey`
(kind, then subject), never by insertion order. Two equivalent graphs built in
different orders produce the identical order, the identical layer decomposition
and the identical plan digest; this is asserted by an independent small-state
oracle that does not share a line of code with the production implementation.

### Make-before-break, break-before-make and overlap

Make-before-break is the default: the target is validated, prepared, installed,
activated and verified before the source is deactivated or withdrawn. The
generated MBB plan is

    VALIDATE_TARGET -> PREPARE_NEW_STATE -> [INSTALL_NEW_GROUP] -> INSTALL_NEW_ROUTE
      -> ACTIVATE_NEW_PATH -> VERIFY_NEW_STATE -> DEACTIVATE_OLD_PATH
      -> WITHDRAW_OLD_ROUTE -> VERIFY_REMOVAL -> FINALIZE

and a policy-conformance check refuses any plan (generated or explicitly
supplied) in which a break-side step is not a transitive successor of the
required make-side and verification steps.

Break-before-make is supported only when the bound policy says so explicitly
(`allow_break_before_make` **and** `ordering == BREAK_BEFORE_MAKE`). It is
never chosen silently, and it is never a fallback. Under it old state is removed
first and every make-side step must be a transitive successor of the removal and
its verification. Its constraint is stated plainly: between removal and
activation the route has no carrying path, so a break-before-make transition has
a real outage window that make-before-break does not.

Overlap is explicit, not implied. `MAKE_BEFORE_BREAK` requires
`allow_overlap = true`; `BREAK_BEFORE_MAKE` requires `allow_overlap = false`.
A policy that says otherwise is incoherent and is refused. Overlap is a
bounded, planned phase of a transition and never the steady state.

### Scope of the safety claim

Route Convergence proves that a **local control-plane transition order** is
dependency-safe: prerequisites are satisfied, generations are current, evidence
is structured and stale work is rejected. It does **not** prove network-wide
loop freedom, and no packet-level convergence claim is made. Those are outside
this runtime's boundary, and the SYNTHETIC/UNSUPPORTED section below says so
again in the terms the validation uses.

## Dispatch, completion evidence and stale-work defence

### Dispatch authority

A step may be dispatched only when the plan is current, the step is `READY`,
every prerequisite is satisfied, the step generation matches, the presented
epoch is current, the publisher and worker boot are registered, live and not
fenced, the authority scope covers the exact route and plan, the capability is
present and the resource limits allow it. Connected is not authorized.

### Completion evidence

A completion is never a naked boolean. `CompletionEvidence` binds the plan, the
step, the exact **step generation**, the **execution attempt** (the dispatch's
attempt identifier), the epoch, the publisher, the worker boot, a structured
`BackendOutcome`, the state generation the backend observed, the **dispatch
watermark**, and a bounded detail. The evidence identity is derived from that
content, so an exact replay of the same completion is recognised as
`IDEMPOTENT` and an exact replay of the same `create_plan` request advances
nothing.

External operation results are structured:
`APPLIED`, `IDEMPOTENT`, `RETRYABLE_FAILURE`, `PERMANENT_FAILURE`,
`AMBIGUOUS`, `UNSUPPORTED`, `STALE`.

### Invalidation watermarks

Every event that invalidates a plan's in-flight work — a dependency
invalidation, a rollback request, a supersession, a revocation, an epoch
advance, a session loss, a worker fence — advances the governor-wide
convergence generation and records it on the plan. A completion dispatched under
an older watermark is refused with `WATERMARK_EXCEEDED` even if every
generation it names still happens to match. This is what makes the mandatory
race safe:

    step dispatched at watermark W
      -> target state invalidated            (plan watermark advances)
      -> old completion arrives
      -> completion rejected, convergence state unchanged

The race is proven directly in-process for target supersession, path-authority
invalidation, epoch advance and worker fencing, and again over real processes.

### Attempt identity

Every authoritative mutation — plan creation, dispatch, completion, failure,
reconciliation, policy definition, worker registration and fencing, plan pause,
revoke, retirement, revalidation and rollback — binds a `MutationAttemptId` and is
remembered under it. An exact replay of the same attempt with the same payload is
`IDEMPOTENT` and advances nothing; the same identifier with a different payload
is an `ATTEMPT_CONFLICT` rejection. One attempt identifier per request is
therefore the ownership contract: a dispatch and its completion are different
requests and carry different identifiers, while the completion's *evidence*
still names the execution attempt the dispatch issued. A stored dispatch is
deliberately treated as fresh for a later different payload, because a dispatch
and its own completion are a natural pair rather than a conflicting replay.

### Retry semantics

Retry is bounded and explicit. A `RETRYABLE_FAILURE` re-arms the step only when
the backend declares the operation idempotent and both the bound policy's
`max_retries_per_step` and the configured
`ConvergenceLimits::max_retries_per_step` still allow another attempt; the plan
is not paused by a transient failure. When retries are exhausted, or the failure
is permanent, unsupported or stale, the plan pauses or requires rollback
according to policy. `AMBIGUOUS` is never retried at all.

### Ambiguous side effects and reconciliation

When an external action may have completed but its acknowledgement was lost, the
honest answer is `AMBIGUOUS`. Route Convergence moves the step to
`RECONCILIATION_REQUIRED` and the plan to `PAUSED`; nothing is re-applied.
An operator or a backend observation then reconciles explicitly: applied work is
recorded as `COMPLETED`, unapplied work returns to `READY`. Reconciliation is
the only path out, and it always produces structured evidence.

## Supersession, rollback and retirement

**Supersession.** When Route Fabric publishes a newer desired route generation,
every non-terminal plan whose target generation is older becomes `SUPERSEDED`
with the reason recorded, in-flight steps become `STALE`, and late completions
are refused. Lineage is preserved on both sides: the superseded plan names its
successor and the successor names its predecessor. A successor plan moves from
the previous desired generation to the new one; that source is accepted because
it is the immediately preceding desired generation, and any older source must be
declared historical explicitly.

**Rollback is a governed transition, not a reversed vector.** `begin_rollback`
revalidates the state it would restore — the old path must still be legal at the
exact bound `PathAuthorityGeneration` and the route must still be one it may
return to — then generates an **explicit compensating plan** from the observed
current state and prunes it to exactly the steps whose effect the forward plan
actually established, contracting the dependency edges so the ordering
guarantees survive the pruning. The forward plan moves through
`ROLLBACK_REQUIRED` and `ROLLING_BACK`; its in-flight steps are fenced before
any compensating work is authorized. When the compensating plan completes, the
forward plan becomes `SUPERSEDED` with reason `ROLLBACK_COMPLETED` and the
lineage records both directions.

**Unsafe rollback is refused.** If the old route or its exact path authority
generation is no longer legal, `begin_rollback` returns `UNSAFE_ROLLBACK` with
`ROLLBACK_TARGET_UNAUTHORIZED` (or the precise stale-dependency code) and
creates nothing. If the observed state moved past the forward plan's target, the
rollback is refused as stale: forward replanning is required instead. A completed
`IRREVERSIBLE` step makes a rollback plan impossible, and that is reported
rather than papered over. Route Convergence 1.0.0 declares every step in its own
vocabulary compensatable or observational, so no irreversible step is generated
by the library itself; the classification exists so a caller-supplied explicit
plan cannot smuggle one past the policy.

**Retirement.** `REVOKED` and `RETIRED` are terminal; retirement is the only
move out of a terminal state, it retires the remaining steps explicitly, and a
retired plan never becomes active again. Revoking a plan fences its in-flight
work immediately.

## Persistence and conservative recovery

The store file is versioned and integrity-checked:

    magic[8] "RCONVGOV"
    format_version u32
    reserved u32 (must be zero)
    coordinator_epoch u64
    convergence_generation u64
    payload_bytes u32
    payload[payload_bytes]
    tag[32]  SHA-256 over everything preceding

Files are replaced atomically through a temporary file and a rename, so a crash
leaves either the old complete file or the new complete file and never a mixture.

The payload carries plans, generations, the canonical step DAG, durable
completed step state, lineage, rollback state, invalidation watermarks, the
convergence policy registry, bounded history and every digest. It never carries a
live socket, a session, a worker registration or an attempt memory as current
authority.

Loading is conservative:

- durable plans and their completed step history are recovered;
- **live worker authority is not restored** and the previous publisher/boot is
  unknown after a restart;
- a step persisted as `DISPATCHED` is **never** turned into `COMPLETED`; it
  becomes `RECONCILIATION_REQUIRED` and its plan requires fresh revalidation;
- plans that were executing require revalidation;
- a governed rollback resumes as a rollback, because its compensating plan is
  durable and is revalidated before any of its steps run;
- the configured epoch may only move forward; a store written at a higher epoch
  is never regressed, and every plan bound to an older epoch requires
  revalidation.

Decoding rejects an empty file, a bad magic, an unsupported format version, every
truncation length, a corrupted tag, an over-long declared payload, trailing
bytes, a duplicate plan, a duplicate step, a missing prerequisite, a cyclic DAG,
an impossible generation, an impossible lifecycle, an impossible currentness
mask, an invalid route or path binding, a completed step without completion
evidence and a plan whose identity or digest does not match its own content.

## Distributed execution

The coordinator, the worker and the CLI are real OS processes. The wire protocol
is explicitly framed:

    magic[4] 'R','C','F','1'
    wire_version u16
    message u16            (stable numeric ids, never an enum ordinal)
    flags u32              (must be zero)
    sequence u64
    epoch u64
    publisher[16]
    worker_boot[16]
    attempt[16]
    payload_bytes u32
    reserved u32           (must be zero)
    payload[payload_bytes]
    tag[32]                SHA-256 over header || payload

Every decoder rejects trailing bytes, an unknown message identifier, a wrong wire
version, a non-zero reserved field, an over-long payload and any integrity
mismatch. No C++ object layout is ever put on the wire.

**A partial frame cannot pin a session.** A peer that stops mid-frame is
disconnected with an explicit `PEER_TIMEOUT` failure once the configured read
budget is exhausted; the declared payload length is validated before anything is
allocated.

**Session loss fences the boot.** When a session that registered a worker ends,
the coordinator fences that boot. A disconnected worker cannot complete work it
already had in flight. Fencing is permanent, and a fresh process is a fresh
`WorkerBootId`: the previous boot of the same publisher is fenced the moment the
new boot registers.

**Acknowledgement follows durability.** When a store is configured, the
coordinator makes every mutation durable *before* it replies, so a coordinator
killed immediately after answering loses nothing it told a client it had
accepted.

Single authoritative coordinator, stated plainly: Route Convergence 1.0.0 is
**not a consensus system**. Exactly one coordinator owns the durable store at a
time, stale epochs are fenced by epoch comparison rather than by distributed
agreement, and no split-brain prevention across independent coordinators is
claimed. There is no leader election and no quorum.

There is also **no cryptographic authentication**. The digest detects corruption
and accidental divergence; it is not a MAC. A peer is identified by the
publisher and boot it presents, and the coordinator enforces epoch, scope,
capability and fence rules on that claim. Running the transport on an untrusted
network is outside what this release validates.

## Deterministic snapshots, diffs, explanations and digests

**Snapshots** are immutable values carrying the plan identity, generations,
lifecycle, currentness, bindings, policy, epoch, owner authority, provenance,
lineage, the canonical step DAG with per-step state and prerequisites, and a
digest. Two snapshots of the same convergence state carry the same digest and the
same snapshot identity.

**Diffs** are deterministic and stably ordered, derived from a bounded plan
history: plan created, lifecycle changed, currentness changed, step state
changed, prerequisite satisfied, target superseded, path dependency stale,
rollback entered, convergence completed, authority changed, epoch changed,
lineage changed.

**Explanations** answer the operator questions directly and render
deterministically: why a plan is ready or paused, why a step cannot execute,
which prerequisite is incomplete, why old state was retained, why target state
was not activated, why rollback was requested or rejected, which generation made
the plan stale, which completion was rejected, what remains before convergence is
complete, and which publisher and epoch own the transition.

**The semantic digest** covers identity, generations, the canonical step DAG and
step states, the bound dependency generations, lifecycle and currentness, and the
policy generation. It excludes timestamps, thread identifiers, sockets, memory
addresses, arrival order and process-local counters. Equivalent DAG construction
orders produce the same digest, which is asserted for shuffled insertion orders
and against the independent oracle.

## Resource limits

Every field of `ConvergenceLimits` is consulted on the path it bounds, and a
zero value disables the capability it bounds rather than meaning "unlimited":
`max_plans`, `max_steps_per_plan`, `max_dependencies_per_step`,
`max_total_dependencies`, `max_parallel_steps`, `max_history_per_plan`,
`max_retries_per_step`, `max_frame_bytes`, `max_batch_size`, `max_workers`,
`max_sessions`, `max_persistence_record_bytes`, `max_explanation_entries`,
`max_attempts_remembered` and `max_journal_entries`. An incoherent limit set is
refused before the governor is used, and a governor that was nevertheless built
from one rejects every mutation with `INTERNAL_INVARIANT` rather than silently
ignoring a bound.

## Concurrency model

Every public method is thread safe. Queries take a shared lock and mutations an
exclusive lock. The upstream observation views are read while a lock is held, so
an implementation must be a pure in-memory observation and must never call back
into the governor; the shipped `SyntheticUpstream` satisfies that. **No
external I/O ever happens under the lock**: a worker performs the external
operation in its own process, and persistence encodes under the lock while the
file write happens outside it. Independent plans, independent completions,
invalidations, snapshots and distributed sessions proceed concurrently; the test
suite drives four independent plans to completion from four threads and asserts
all four converge.

## Validation: REAL, SYNTHETIC and UNSUPPORTED

This release labels every proof. The labels are part of the deliverable, not
decoration.

**REAL** (proven by the test suite in this repository):

- real coordinator and worker OS processes with real process termination for the
  worker-death and coordinator-restart proofs;
- real loopback TCP transport with framing, integrity and partial-frame defence;
- real on-disk persistence with atomic replacement, integrity tags and the full
  corruption matrix;
- real commit, supersession, rollback, unsafe-rollback, epoch-advance,
  path-authority and worker-fence races;
- real CMake package installation and an independent `find_package` consumer.

**SYNTHETIC** (control-plane fixtures, not physical fabrics):

- the `SyntheticUpstream` observation source that stands in for Route Fabric and
  Path Authority when no real one is attached;
- the transition backend: `JournalBackend`, a deterministic idempotent
  control-plane journal applier. Route Convergence 1.0.0 ships exactly one
  backend and it is not a switch;
- multi-step transition graphs, shared-path populations, mass supersession and
  mass epoch recovery at 1k/10k/100k-plan scale;
- every simulated backend acknowledgement, including scripted retryable,
  permanent and ambiguous outcomes.

**UNSUPPORTED** (not implemented and not claimed):

- physical switch or line-card programming of any kind;
- packet-level loop-freedom or traffic-continuity proof;
- real multi-rack, multi-device or production-fabric convergence;
- vendor SDK operations;
- cryptographic peer authentication;
- consensus, leader election or split-brain prevention across independent
  coordinators;
- any non-Windows build. The control-plane library is portable C++20 with no OS
  headers in its core, but the loopback transport, the coordinator service, the
  worker client and the real-process proofs are implemented against
  Win32/Winsock, and 1.0.0 does not claim a validated non-Windows build.

A simulated backend acknowledgement is not physical convergence, and nothing in
this repository turns simulated state into physical proof.

## Public library API

Everything the runtime does is reachable from `#include <rc/rc.hpp>`; the
networked runtime adds `<rc/net.hpp>`, `<rc/server.hpp>`, `<rc/client.hpp>` and
`<rc/process.hpp>`.

- identity and generations: `rc/identity.hpp`
- deterministic encoding and decoding: `rc/bytes.hpp`
- SHA-256 and domain-separated digests: `rc/digest.hpp`
- structured outcomes, conditions and explanations: `rc/outcome.hpp`
- plan and step lifecycles and the transition tables: `rc/lifecycle.hpp`
- convergence policy: `rc/policy.hpp`
- route bindings, path legality and the observation seams: `rc/upstream.hpp`
- step vocabulary, specifications and completion evidence: `rc/step.hpp`
- dependency graph validation and canonical order: `rc/graph.hpp`
- plan identity, lifecycle, snapshots, diffs, explanations: `rc/plan.hpp`
- authority scopes, capabilities and mutation authority: `rc/authority.hpp`
- the governor itself: `rc/convergence.hpp`
- versioned persistence: `rc/persistence.hpp`
- the external operation seam and the journal backend: `rc/backend.hpp`
- the synthetic upstream fixture: `rc/synthetic.hpp`
- the wire protocol: `rc/protocol.hpp`

### Ownership, lifetime and thread safety

Value types are copyable and own their storage. `ConvergenceGovernor` holds
non-owning references to a `RouteFabricView`, a `PathAuthorityView` and a
`FabricEpochView`, all of which must outlive it; it is neither copyable nor
movable. `CoordinatorServer`, `RcClient`, `TcpConnection`, `TcpListener`,
`LocalProcess` and `JournalBackend` are movable and not copyable. Every public
governor method is thread safe; a view implementation must be callable from any
thread and must not call back into the governor.

### Authority and currentness

A plan binds `created_epoch`, `bound_epoch`, an `AuthorityGeneration`, an owner
publisher and an owner worker boot. A mutation presents a `CoordinatorEpoch`, a
`PublisherId`, a `WorkerBootId`, a `MutationAttemptId` and, where relevant,
expected plan and step generations. Authorization is checked before any
generation check, in a fixed order, and multi-defect inputs always report the
first applicable rejection.

### Stale-completion semantics

A completion is accepted only if it names the current step generation, the
dispatch's execution attempt, the dispatch watermark, a live and unfenced boot,
the current epoch, a plan that is still current, and an observation of the exact
route generation and (for make-side steps) the exact path authority generation
the step was planned against. Anything else is refused without mutating
convergence state, and the refusal carries a stable condition code.

### Rollback semantics

Rollback is a new governed plan plus a lifecycle transition on the forward plan.
It never reverses the forward step list, never assumes reversibility, and never
restores state whose authority has moved.

### Unsupported physical claims

Nothing in this API programmes hardware, moves a packet or proves network-wide
convergence.

## CLI

`rc_cli` is deterministic and script friendly: every command emits `key=value`
lines and every rejection is `RC_CLI_ERROR code=<CONDITION_CODE>`.

    rc_cli version
    rc_cli plan create --port P --policy HEX --ordering mbb [--allow-bbm]
                       --source-route HEX --source-path HEX --source-generation N
                       --target-route HEX --target-path HEX --target-generation N
    rc_cli plan show --port P --plan HEX
    rc_cli plan list --port P
    rc_cli step ready --port P --publisher HEX [--max N]
    rc_cli step run --port P --publisher HEX --plan HEX --step HEX [--outcome applied]
    rc_cli step dispatch --port P --publisher HEX --plan HEX --step HEX
    rc_cli step complete --port P --publisher HEX --plan HEX --step HEX [--outcome applied]
    rc_cli step fail --port P --publisher HEX --plan HEX --step HEX [--outcome permanent]
    rc_cli step reconcile --port P --plan HEX --step HEX --applied 1
    rc_cli revalidate | rollback | retire | revoke | pause --port P --plan HEX
    rc_cli policy define --port P --policy HEX [--ordering mbb] [--verify 1]
    rc_cli policy list --port P
    rc_cli explain --port P --plan HEX [--step HEX] [--kind plan|step|readiness|...]
    rc_cli snapshot --port P --plan HEX
    rc_cli diff --port P --plan HEX --from N
    rc_cli notice route|path|epoch --port P ...
    rc_cli worker register|fence --port P ...
    rc_cli store inspect --store PATH

A dispatch and its completion cannot be split across two CLI invocations: the
completion must come from the boot that dispatched the step, and the CLI is a
fresh process each time. `step run` therefore dispatches, performs the external
control-plane operation through the local journal backend and commits the
structured completion in one process; `step dispatch` and `step complete` exist
for a driver that keeps one session alive. A mutation requires `--publisher`;
`--boot` is optional and pins an identity instead of registering a fresh one, and
a fresh process is a fresh worker boot.

`rc_coordinator` serves one authoritative governor over loopback and prints
`RC_COORDINATOR_READY port=<n> epoch=<n> recovered=<0|1> synthetic=<0|1>`.
`rc_worker` registers, pumps the steps it is authorized to execute, performs the
external operation through its backend and commits structured completion
evidence, printing one deterministic line per event.

## Build

Requirements: Windows x64, MSVC with the C++20 toolset, CMake 3.25 or newer, and
Ninja (or any generator CMake supports).

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build

Options: `RC_BUILD_TESTS`, `RC_BUILD_EXAMPLES`, `RC_BUILD_BENCHMARKS`,
`RC_BUILD_APPS`, `RC_ENABLE_ASAN`, `RC_ENABLE_ANALYZE`,
`RC_WARNINGS_AS_ERRORS`. First-party code is compiled with `/W4 /permissive-
/Zc:__cplusplus /utf-8 /EHsc` and `/WX` by default.

## Test

    ctest --test-dir build --output-on-failure

There are **no timeouts and no retries anywhere in the suite**. A hanging test is
a defect, not something to hide behind a watchdog, and a flaky assertion is a
defect, not something to re-run until it passes. Ports are always ephemeral and
temporary paths are always derived per process, so the suite is safe to run
concurrently. Suites: core, governance, persistence, protocol, oracle, property,
adversarial, scale and distributed; the distributed suite starts real processes.

    scripts\validate-release.cmd <source-dir> <work-dir>

runs the complete Release and Debug configure/build/test cycles, the install and
independent-consumer validation and the benchmark.

## Install and find_package

    cmake --install build --prefix <prefix>

    find_package(RouteConvergence CONFIG REQUIRED)
    target_link_libraries(app PRIVATE SummonSoftwareLabs::RouteConvergence)

The exported target carries its own include directories and its platform link
dependencies. `tests/consumer` is an independent CMake project that sees only
the installed package; it creates an old and a target route generation, creates a
make-before-break plan, inspects the canonical steps, completes the prerequisites
in order, verifies that the old route is retained until target activation and
verification, finishes convergence and exits successfully.

## Examples

    build\examples\rc_examples.exe
    build\examples\rc_examples_distributed.exe

`rc_examples` runs the in-process scenarios: basic make-before-break, target
invalidation, supersession, rollback, unsafe rollback rejection and a stale
completion. `rc_examples_distributed` starts real coordinator and worker
processes and demonstrates worker death and coordinator restart. Both use only
the public API.

## Benchmarks

    build\bench\rc_benchmark.exe

The benchmark measures completed operations only — plan creation, DAG
validation, canonical topological ordering, ready-step query, completion commit,
targeted path invalidation with many plans sharing one path, snapshot, digest,
persistence save and load, and a synthetic 100k-plan population — and reports
machine-specific observations, not promises.

## Genuine limitations

- **Platform.** 1.0.0 is validated on Windows x64 only.
- **Single authoritative coordinator.** Not a consensus system; no split-brain
  prevention across independent coordinators is claimed.
- **No cryptographic authentication.** The integrity digest detects corruption,
  not forgery.
- **No physical convergence proof.** The transition order is provably
  dependency-safe; packet-level loop freedom and traffic continuity are not
  proven and are not claimed.
- **One external backend.** `JournalBackend` is a control-plane journal applier.
  A production deployment supplies its own `TransitionBackend`; the library
  guarantees the governance around it, not the behaviour of the device behind it.
- **Attempt memory is not durable.** Attempt replay detection is process-local
  and bounded. After a restart, a replay is re-evaluated against durable state
  and refused by the current-state rules rather than by the replay memory; a
  completion that exactly matches the durable completion evidence is still
  `IDEMPOTENT`, because that check reads the durable step record.
- **Limits are enforced, not tuned.** The default limits are chosen so that the
  documented guarantees hold, not to maximise throughput.
- **Representation versions are independent of the product version.** Wire
  version, persistence format version, digest encoding version, plan encoding
  version and step semantics version do not change merely because the product
  version changes.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
