# R5 execution contract: an actual MCP stdio integration

**Artifact type:** a preimplementation contract and frozen-oracle candidate, not
an execution report. No R5 scenario, SDK integration, Windows run or hosted CI
result is asserted by this document. The accompanying `r5_scenarios.json`
contains **8 scenarios, 20 normal variants and 2 targeted integration mutants**.
One complete normal run means those 20 variants, not 20 distinct security
properties. Mutants are counted separately.

The preparing director approves this initial contract for implementation in
`review/PREPARATION_REVIEW.md`; this is not approval of an unexecuted result.
Codex records the hashes of both contract files before implementation. If
implementation exposes a contradiction or an unavailable SDK capability,
preserve the original contract, report the specific obstruction and obtain an
explicitly reviewed, versioned contract amendment. Use the director channel
when permitted or the documented, honestly labeled local-review fallback when
it is unavailable. Do not quietly change an expected refusal or weaken an
oracle to get a green run. Do not invent a subsequent director approval.

## 1. Objective and preserved baseline

Build one reproducible local demonstration in which actual MCP clients discover
an actual MCP provider, exchange the five proposed control methods and invoke
protected tools over stdio between distinct operating-system processes. The
provider must persist the harmless business effect, consume the reservation and
persist its receipt in **one SQLite transaction**. This closes a concrete gap
between the R4 local authority fixture and its documentary wire examples.

Preserve the published baseline commit
`fc350b219f4f8ed452a6e59784ea69ea68fbaf07` and the historical `reference/` corpus.
The two historical source files remain byte-identical:

| File | SHA-256 |
| --- | --- |
| `reference/authority.py` | `0489bf76fc482558051e65ac3517aab9189109bc3d1647724e54211b623aa11f` |
| `reference/run_r4.py` | `56e382fa65a079ee8b24b03aa5a9d0874a09938400442a9c707cd54fa0394741` |

Put the successor implementation, integration harness and independent reader in
a new, clearly named directory, `integration/stdio_r5/`. Reuse or adapt
small helpers only with a visible source comparison. Do not wrap the old
`Authority.commit()` return dictionary and describe it as a durable receipt:
the historical code does not persist the complete wire receipt or a root state
revision. Its local registration, retry and cancellation interfaces also need
an explicit successor mapping.

This contract does not establish remote effect atomicity, a production identity
system, a general intent classifier, two-vendor interoperability, full MCP
conformance, standards adoption or a production-ready security product.

## 2. Compatibility gate, before implementing the effect path

The candidate is the official Python package **`mcp==2.3.0`**, release commit
`2118f14f8a19bc158d8a1cf90af58d85d187f849`, with Python 3.12. These version facts
were checked during preparation; compatibility with this integration still has
to be demonstrated. Pin the actual resolved dependency set and record its
versions and provenance. Do not invent dependency hashes or assume a successful
package installation demonstrates protocol support.

The implementation must use the SDK's public extension surface for the private
methods and its normal tool surface for `tools/call`. Public `Extension` and
`MethodBinding` support is the candidate route. A tool interceptor can locate
the final tool boundary, but raw-request middleware is not itself the
transactional effect guard. Confirm the exact public APIs against the pinned
version before coding. Do not modify SDK internals, manufacture MCP transcripts
or substitute an in-memory `Client(server_object)` for the subprocess transport.

Use `Client(StdioServerParameters(...))` or its documented public equivalent.
Observe an actual `server/discover` request and response. `mode="auto"` plus a
strict assertion on the observed result is acceptable. Explicit public discovery
is also acceptable. Merely setting `mode="2026-07-28"` is not discovery: that
mode can assume a version without sending a probe. A legacy `initialize`
fallback does not satisfy this contract.

Require the observed protocol version `2026-07-28` and the exact lab extension
advertisement before an ordinary protected operation:

```json
{
  "revision": "0.1",
  "profile": "zti-mcp/0.1",
  "mode": "current-online",
  "effect_coupling": "required"
}
```

The lab identifier is `org.example/zti-mcp`. This is reserved documentation
space, not a claimed production namespace. This demonstration uses the same
experimental profile `zti-mcp/0.1`; it introduces no new protocol name.

Primary references to consult at execution time:

- [Pinned Python SDK release](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.3.0)
- [Protocol versions and discovery](https://py.sdk.modelcontextprotocol.io/protocol-versions/)
- [Client transports](https://py.sdk.modelcontextprotocol.io/client/transports/)
- [SDK extensions](https://py.sdk.modelcontextprotocol.io/advanced/extensions/)
- [SDK middleware](https://py.sdk.modelcontextprotocol.io/advanced/middleware/)
- The baseline draft Sections 4, 5 and 8 and `schema/zti-control-0.1.schema.json`.

If the pinned SDK cannot deliver the required extension methods, metadata or
result shape through a documented public API, report `BLOCKED_COMPATIBILITY`
with the observed evidence. Do not silently switch protocol versions, advertise
unsupported coupling, replace a missing method by an ordinary tool, or claim
that a handwritten JSON-RPC imitation tested the SDK.

## 3. One logical provider, several local stdio endpoints

All endpoints represent the same configured provider, executor and resource.
Each SDK stdio endpoint runs in its own process and uses a separate SQLite
connection to the **same provider-owned database**. The harness may own several
SDK clients in one process. The admin channel, agent A channel and agent B
channel have distinct configured roles/principals. The unauthorized-principal
variant uses an additional channel. Each client/provider PID and endpoint
instance identifier is recorded; SDK `clientInfo` and `serverInfo` are not
authentication evidence.

The trusted launcher fixes the principal for each channel before any application
request. An endpoint must not select its principal from `clientInfo`, `_meta`,
arguments, a client-supplied `actor` field or the token's `sub`. The ICT `sub`
must match the independently configured channel principal and leaf delegatee.
The admin has explicit fixture permissions to register and revoke this tenant's
mandates. Agent roles cannot acquire those permissions by knowing a mandate ID
or possessing its publicly readable JWS. This is a **trusted local process
identity fixture**, not an implementation of OAuth, remote peer authentication
or protection against a hostile host administrator.

Multiple processes sharing one local SQLite database are not a distributed
consensus system or independent implementations. The accepted effect boundary
is `resource-mutation`: insertion of the actual harmless business row in that
database. The demonstration has no separately irreversible HTTP, email, payment
or physical effect. A proxy that commits its own ledger and then calls an
uncontrolled downstream effect would fail this contract.

Use real stdio byte streams. A transparent local recording relay is permissible
if needed to capture SDK traffic, provided it only forwards bytes and does not
make policy decisions or fabricate replies. Record the actual provider PID, not
just a relay PID. Keep protocol stdout free of diagnostics. Capture wire frames
at the pipe boundary, per-connection sequence numbers, method/JSON-RPC ID,
direction and endpoint instance. Trace files contain only explicit public lab
fixtures. Test hooks, barriers and fault controls travel through a separate
trusted harness channel or startup configuration; they are not exposed as
unprotected MCP methods or selected by application arguments.

## 4. Wire binding and successor behavior

The five methods are exactly:

```text
org.example/zti-mcp.register
org.example/zti-mcp.reserve
org.example/zti-mcp.lookup
org.example/zti-mcp.cancel
org.example/zti-mcp.revoke
```

They use the corresponding method-specific definitions in the frozen control
schema, with actual compact ES256 signed mandates for `.register`. They are
private extension methods, not MCP core methods. The schema's top-level `anyOf`
is not a substitute for dispatch to the correct method definition. Control
requests carry protocol and client extension metadata but do not require an
execution ICT. No public `.commit` method is introduced.

Protected `tools/call` requests carry the normal tool name/arguments, the pinned
MCP metadata and `params._meta["org.example/zti-mcp"]` containing exactly
`revision`, `operation_id` and `ict`. S02's incompatible-request variant changes
only this action metadata revision to `0.2`, retaining the SDK client's
configured capability at `0.1`; the captured frame must establish both values.
It does not claim two independent capability-validation tests. Protected tool results use standard
`resultType: "complete"` and the stored receipt in
`result._meta["org.example/zti-mcp"]`. Control results use the draft's distinct
result schemas and carry a `receipt` member only for consumed outcomes.

The successor must implement these currently absent or different R4 behaviors:

| Boundary | R5 behavior |
| --- | --- |
| Signed mandate import | Verify the received JWS segments and configured issuer/key/type, then register the immutable root or attenuated child after channel authorization. An identical authorized registration is idempotent; changed content under the same identity is refused. |
| Returned ICT | Return it only for currently usable `RESERVED` authority. An identical reserve retry with an expired or stale-epoch token returns recorded `RESERVED` without an ICT; it does not refresh or resurrect that authority. |
| Consumed retry | An identical authorized retry returns the stored outcome/receipt and causes no second effect or charge. A changed Action Binding under the same operation is `OPERATION_CONFLICT`. |
| Lookup | Read the recorded state and, when consumed, the stored receipt. It does not rerun the action or require a still-usable execution token. History access remains authorized by recorded invoker/admin rights. |
| Cancellation | Before consumption, atomically invalidate the reservation and release its held cost/facts. After consumption, this demonstration returns unchanged `COMMITTED` and its receipt, with no refund. |
| Receipt | Persist the exact full receipt with consumption and effect; return that same object on lookup/retry. An offline projection is insufficient. |

Use ES256 with P-256/SHA-256 and 64-byte `R || S` JWS signatures. Verify the
received signing segments rather than canonicalizing and reserializing claims
before signature verification. Public lab signing material must be plainly
identified as such. No claim of secret key custody is made. The accepted JSON
domain remains the explicitly rejected-outside subset: ASCII object keys,
valid Unicode string values, booleans/null, arrays/objects, safe JSON integers
and canonical uint64 strings for quantities/epochs/revisions. Do not label the
old serializer as a complete RFC 8785 implementation. Reject duplicate keys in
the JWS protected header and payload parsed by the profile. Do not claim that
an extension hook detects duplicate MCP wire keys already normalized by the SDK.
The action binding and execution use the same final decoded object; a new raw
transport prevalidator is outside this demonstrated contract.

### Exact final action

Construct the Action Binding after SDK decoding/validation and after every
transformation that could change the arguments actually used by the effect:

```text
profile, tenant_id, root_mandate_id, mandate_id, operation_id,
executor_id, resource_id, method, tool_name, tool_revision, arguments
```

The issuer, logical executor/resource, tool revision and catalog come from
trusted configuration. The provider cross-checks all bound identities against
the token and reservation; it does not trust an unverified token to configure
them. Compute the digest of the final value and pass that same immutable value
to the business-row insertion. A pre-SDK hash or a check on one object followed
by execution from a mutable second object is insufficient. S03's post-parse
test transformation changes `payload` from `alpha` to `bravo`, keeping the
footprint constant, so a cost check alone cannot satisfy its oracle.

### Operation identity and errors

`Operation_Key = (tenant_id, root_mandate_id, operation_id)` and
`Reservation_Key = (tenant_id, root_mandate_id, reservation_id)` are durable
identities within the configured authority. JSON-RPC request IDs identify
transport exchanges; they never mint a new operation or reservation. The
positive scenario repeats a call in the same session with a different observed
SDK request ID. After a restart, a numeric JSON-RPC ID may legitimately recur;
identify attempts by `(endpoint_instance_id, request_id)` plus a harness attempt
ID. Do not alter private SDK counters to manufacture an observation.

ZTI refusals use `-31001`, `data.profile`, the frozen `reason` and status
`REFUSED`; unavailable necessary authority uses `SUSPENDED`. Native protocol
errors retain their native meaning. R5 fixes these mappings for its tested
inputs: missing/bad ICT → `INVALID_TOKEN`; incompatible profile →
`PROFILE_UNSUPPORTED`; final action mismatch → `BINDING_MISMATCH`; channel
principal mismatch → `NOT_AUTHORIZED`; cumulative gate failure →
`CUMULATIVE_VIOLATION`; time expiry → `EXPIRED`; root/ancestor revocation or a
stale authority epoch → `REVOKED`. Exercising a cancelled internal reservation
also returns `REVOKED`, while lookup still records `CANCELLED` and the root
itself remains active. Error responses must not contain a success receipt.
Missing state, crashes, SQLite lock errors and timeouts are never counted as
successful policy refusals.

## 5. Authoritative transaction, counters and durable receipt

Use exact nonnegative arithmetic over the fixed quantity dimensions `ops`
(`operation`) and `bytes` (`byte`). Cost comes from the provider catalog:
`ops = int(arguments.units)` and `bytes = len(payload.encode("utf-8"))`.
The three tools are `lab.compute`, `lab.read_sensitive` and
`lab.export_external`; their monotone fact sets are respectively `[]`,
`["read_sensitive"]` and `["export_external"]`. These names denote symbolic
fixture actions whose only business effect is a SQLite row. They perform no
sensitive read or external export.

Keep root budgets and forbidden sets immutable and common to every descendant.
All ancestors remain checked; child constraints can only attenuate authority,
and child action caps do not create independent cumulative budgets.

Let `D` be costs of `COMMITTED`, `COMPLETED` and `UNKNOWN` rows; let `R` be costs
of `RESERVED` rows. Admission requires `D + R + candidate_cost <= B` in every
dimension. The fact union includes charged **and outstanding reserved** rows.
Consumption checks its existing reservation once, then transfers cost from `R`
to `D`; it does not add the cost again. A cancelled reservation is unexercisable
before its held cost/facts are released. No time-based cleanup or expiry refund
runs implicitly in these variants.

Inside the provider's write transaction, reload current time, root/ancestor
state, epoch, exact reservation, footprint and cumulative state. Check the
current final binding, then atomically insert the business effect, transition
`RESERVED` to `COMMITTED`, increment the root state revision, persist the
complete receipt and persist the transition record. `BEGIN IMMEDIATE` with
separate connections is an acceptable local serialization mechanism. Complete
the transaction before writing a success response to stdio. A uniqueness
constraint on the durable operation identity must prevent a second business
effect and a second receipt. No request may obtain a transferable `ALLOW`
decision for later unguarded execution.

The immutable receipt fields are exactly:

```text
profile, tenant_id, root_mandate_id, mandate_id, operation_id,
reservation_id, action_hash, effect_boundary, status, state_revision
```

R5 receipts use `effect_boundary: "resource-mutation"` and `status:
"COMMITTED"`. The selected variants need no later `COMPLETED` or `UNKNOWN`
transition. Losing a reply creates an unresolved **client observation**, not
proof that the authoritative operation state became `UNKNOWN`. Lookup resolves
it from the preserved database. This bounded choice does not remove the
profile's rule that a genuine `UNKNOWN` consumed outcome remains charged.

R5 fixes an implementation choice that the draft leaves less specific:

- `state_revision` is a canonical uint64 root-scoped monotone counter. A new
  root registration starts it at `1`. Each persisted new child, new reservation,
  consumption, effective cancellation or new revocation advances it once.
  Lookups, identical retries and refused requests do not advance it.
- A receipt stores the revision of its consumption transaction and is immutable.
  The outer control result reports the current root revision at its read; it may
  be greater than the receipt revision after other operations or revocation.
- `authority_epoch` starts at `0` and changes only for an authority revocation
  or explicitly defined authority decision, never ordinary reserve, consume,
  cancel or lookup. S04 revokes an otherwise unused sibling to distinguish a
  stale epoch from an actually revoked execution lineage. No ICT refresh is
  added in R5.
- Neither counter wraps. Overflow cannot permit a business effect. The fixtures
  do not approach overflow; no new exhaustive counter claim is made.

### Stable independent-readback surface

Document the new database schema before the first run. The reader accesses
SQLite base tables directly, not provider getters or a provider-produced
summary. At minimum those tables expose these logical records and fields:

| Record | Fields required by the reader |
| --- | --- |
| Root | tenant/root identity, exact root policy, active/revoked state, `authority_epoch`, `state_revision` |
| Mandate | immutable body/hash, parent identity/hash, configured delegatee, current revocation state |
| Reservation | operation/reservation identities, subject, full action and digest, exact cost/facts, state, stored ICT claims/JWS |
| Actual business effect | unique operation/reservation identities, exact executed arguments/full action, action digest, cost/facts, provider PID |
| Durable receipt | unique operation identity, exact receipt JSON, consumption revision |
| Transition | tenant/root, revision, event, operation/reservation when applicable, provider PID |

The schema-to-record mapping is recorded before execution, with column names and
plain SQL used by the independent reader. It may adapt names to the new
implementation; it may not reinterpret a missing effect or receipt as a pass.
Readback is performed with no writers active, in read-only mode. Recompute
counts, integer sums, unions and linkage from actual rows. The reader may use
the standard library and an independently written canonical-subset/digest
routine. It must not import the provider/controller, call its gate, use its
aggregate helper, or take its `PASS` labels as evidence. Frozen expected values
come from `r5_scenarios.json`; test-only expected values never reach the
controller as claims or inputs.

## 6. Scheduling, crash points and fixture boundaries

Use a fresh database and fresh run directory for every normal variant and every
mutant. Restart variants preserve their own original database and logical root.
Bootstrap root and required children through actual signed `.register`
requests. Do not preload the mandate tables to bypass wire import. Keep
application fixtures, expected oracles and test control channels separate.

For S05 and S06, send the two `.reserve` requests on different SDK stdio
endpoints. Each provider announces that it received the request and reached a
barrier **before** opening its write transaction. Release both only after both
arrivals. Two distinct provider PIDs and this handshake establish overlapping
pending requests. The transactions themselves serialize; no claim of physically
simultaneous commits or every possible interleaving is made. Record admission
results as a multiset and then invoke every admitted operation exactly once.
If both were admitted under sufficient budget, both actual effects must occur.

For revoke-before-effect, suspend the tool call before the authoritative write
transaction, complete `.revoke` over the admin SDK channel, then release the
call. Do not hold the SQLite write lock while waiting for a revocation that
needs the same lock. For commit-before-revoke, complete the call first, then
revoke. S08 likewise imposes the two cancel/commit orders; it is not a claim of
measured cancellation contention.

Use a harness-owned clock source read inside the transaction. The expiry
variant advances it to the issued ICT's exact `exp` after admission. Record that
value and its scope. These are injected-time tests, not real-time latency or
clock-synchronization measurements. Root and child validity extend beyond the
ICT expiry used in this variant.

S07 uses two explicit provider fault points:

1. After SQLite commit returns but before a successful response is written:
   terminate that endpoint. After restart, the effect, charge and receipt must
   survive and an identical retry must not repeat them.
2. After the business insert/consumption/receipt have been staged inside the
   transaction but before commit: terminate that endpoint without a graceful
   commit. After restart the whole transaction must have rolled back. The old
   reservation remains held and usable under the unchanged fixture clock; one
   later authorized call can create exactly one effect.

These are process-crash tests on a local SQLite setup, not power-loss,
filesystem-corruption or distributed failure proofs. Record SQLite version,
journal/synchronous configuration and actual fault/event ordering. A lost reply
must be recorded as transport uncertainty; it must not be relabeled `REFUSED`.

## 7. Eight scenarios and two deliberately broken integrations

The JSON file specifies the exact variants, checkpoints and expected outcomes.
The main comparisons are:

| Scenario | Normal variants | Main independent observation |
| --- | ---: | --- |
| S01 Discovery, signed import and complete positive path | 1 | One business effect, one consumption, one durable receipt despite an identical second call |
| S02 Mandatory negotiated profile and ICT | 3 | Client stops when support is absent; provider blocks malformed protected requests when directly sent |
| S03 Final action, signature and trusted principal | 3 | No effect/consumption after a final-argument change, invalid signature or channel-principal mismatch |
| S04 Current authority/time at the effect | 4 | Revoke/expiry/stale epoch before effect block it; revocation after commit preserves its charge and receipt |
| S05 Shared cumulative budget with actual pending requests | 2 | Budget 3 admits one cost-2 operation; budget 4 admits and executes both |
| S06 Shared forbidden fact pair | 3 | Outstanding sibling facts prevent the pair; each action alone still executes |
| S07 Lost response, transaction rollback and restart | 2 | Durable receipt recovery, exactly one effect, stable operation identity and preserved reservation after rollback |
| S08 Ordered cancellation and consumption | 2 | Cancel first releases only unused authority; commit first cannot be refunded by cancellation |

Run two integration mutants in separate fresh databases, with a visible patch
or narrowly scoped test implementation that cannot be enabled by a normal MCP
caller:

- **M01 Missing-ICT permissive fallback.** In S02/missing_ict, replace the
  missing-token refusal by retrieval of the stored ICT for the caller's named
  operation, then continue through the ordinary transactional effect path. All
  other checks stay enabled. The normal independent oracle must reject the
  actual effect/consumption produced by this prohibited automatic completion of
  missing request authority. This checks the required wire binding, not a
  probability of compromise or a new production mode.
- **M02 Revalidate, then execute later.** In S04/revoke_before_effect, perform
  current validation in an earlier transaction, end that transaction, pause,
  let revocation commit, then write consumption/effect/receipt from the cached
  decision without revalidation. The normal oracle must detect a real effect
  ordered after acknowledged revocation. This is the precise integration gap
  being tested, not evidence that a correctly placed gateway is insufficient.

For a mutant to be counted as detected, its specified broken path must actually
run and the ordinary frozen oracle must fail for the expected semantic reason.
A syntax error, failed launch, timeout, SQLite lock failure or deliberately
returned `FAIL` is not mutation detection. Preserve the complete observed
database and wire evidence, including any unexpected outcome.

## 8. Evidence, Windows/CI and exit conditions

Each run records source commit/diff, dependency versions, baseline source hash
checks, contract/oracle hashes, actual discovery transcript, endpoint identities
and PIDs, actual MCP frames, barrier/fault event order, read-only database
observations and separate expected/observed comparisons. Wire tests must use
the same provider entry point that is shipped as the demonstration. Do not test
a second, simplified copy of the gate or invoke internal handlers from the
integration client. The historical 40 R4 cases and 3 R4 mutants remain their
own regression evidence; they are not relabeled as R5 wire tests.

The technical GO requires all of the following, not merely a green process exit:

1. Exact SDK candidate and observed protocol discovery work over real stdio;
   all five control methods and `tools/call` have captured successful or
   relevant refusal exchanges through the actual SDK dispatch path.
2. All 20 normal variants match their frozen oracles, including positive effects,
   actual durable receipts, intermediate held state and independent readback.
3. Both targeted mutants are detected by those ordinary oracles with the
   intended actual counterexample, without infrastructure errors as substitutes.
4. The preserved historical source hashes and regression contract remain intact.
   Any successor differences are disclosed; no historic evidence is overwritten.
5. Three separate proofs execute the actual commands at final merge_head M:
   native Windows on Codex's local Windows host, hosted CI Windows, and hosted
   CI Ubuntu. Each uses fresh output directories and records the SHA actually
   checked out. A candidate H run, a synthetic PR merge or a hosted Windows
   runner cannot replace these three proofs. Record run IDs, exact
   workflow/job/step identities and non-skipped successful steps. WSL output,
   workflow source, a pending job or a local Linux run does not prove Windows
   or hosted CI success. Use the director's publication runbook for release
   identity and required job names.
6. A reviewer reads the effect transaction and independent reader, checks the
   source/trace/SQL linkage, and reports any remaining limitation. An AI review
   is identified as such; it is not described as an independent human audit.

Do not advance past a failed gate or unresolved discrepancy. Diagnose, repair
and recheck the affected work under the authorized execution loop; report exact
evidence through the permitted director channel when an arbitration is needed.
If an external capability truly remains unavailable, complete the independent
work and report that concrete incomplete gate. A partial SDK demo may still be
useful evidence, but it is not the completed R5 milestone. Publication and
external messages are governed by the mission's authorization and runbook, not
by this technical contract alone.

The allowed conclusion after success is bounded: the selected Python SDK,
protocol version and trusted local stdio topology carried these messages and
preserved the stated local SQLite invariants in the specified schedules and
crash points. It does not establish remote atomicity, hidden-intent detection,
truth of arbitrary fact labels, protection of unmediated tools, global attack
prevention or deployment security.
