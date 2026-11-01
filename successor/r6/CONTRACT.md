# R6 preexecution contract

Original technical execution specification, Apache-2.0. This successor is a
bounded local research implementation of the experimental `zti-mcp/0.1`
profile, not an official MCP extension. R4 and R5 remain historical snapshots.

## Claim and trusted boundary

A separately built and installed consumer adds `demo.add_record` through the
public `ToolSpec` API without modifying the authority package. Official Python
and TypeScript clients use actual MCP stdio, revision `2026-07-28`, explicit
active discovery and modern extension capabilities. Independent canonical
binding and an audit reader compare authority, commitments and the consumer's
own durable business rows. The provider owns a single SQLite transaction for
current authorization, exact final arguments, charge, business INSERT, receipt
and revision. Concurrent requests are distinct from serialized SQLite commits.

The consumer callback, launch configuration, local clock and host administrator
are trusted. A bounded writer reduces accidental transaction misuse; it is not
a sandbox for hostile Python. No remote service effect, distributed authority,
general JCS conformance, exhaustive schedule exploration, production readiness,
official adoption or independent human certification is claimed.

This is FREEZE-002. ERRATUM_S1.json identifies the preserved FREEZE-001 and the
director's prequalification corrections. S0_COVERAGE.json maps every obligation
to concrete cases. No completed provider qualification observation selected
these corrected expectations. An author-distinct delta review precedes use.

## Canonical action and demonstration tool

An action has exactly `profile`, `tenant_id`, `root_mandate_id`, `mandate_id`,
`operation_id`, `executor_id`, `resource_id`, `method`, `tool_name`,
`tool_revision`, `arguments`. All identifiers are nonempty strings, method is
`tools/call`, tool is `demo.add_record`, revision is `1`. The canonical form is
UTF-8 JSON with ASCII object keys in lexical order, no insignificant whitespace,
valid Unicode, arrays in input order, safe JSON integers only, no floats or
nonfinite numbers. Quantities are canonical decimal strings `0|[1-9][0-9]*`
within `0..18446744073709551615`. The binding is lowercase hex SHA-256 of that
representation. Tests distinguish raw byte rejection from decoded-object
binding; lexical distinctions erased by the SDK cannot be recovered later.

Arguments are exactly `{quantity,label,tags}`. Label is valid Unicode of at most
256 UTF-8 bytes. Tags are a unique list of at most eight values drawn from
`red`, `blue`, `neutral`. The footprint is:

```json
{"ops":{"unit":"operation","amount":"<quantity>"},"bytes":{"unit":"byte","amount":"<UTF-8 label byte count>"}}
```

`ops` measures the requested quantity, not a fixed callback count. Facts are
sorted tags. The root composition policy forbids the joint set `red,blue`.
The consumer's `demo_records` table has a generated row identifier and permits
multiple rows with the same operation identifier: a duplicate callback must
remain observable. The audit log alone is not the business-effect oracle.

## Authority and signing roles

The separate local issuer owns ephemeral KI.private. The provider receives
KI.public and KP.private only; it neither imports the issuer nor receives its
private-key path. Clients and audit readers receive authorized public keys.
The same OS administrator can still access both roles. Header `alg=ES256`,
role-specific `typ`, `kid`, issuer, audience and subject all matter, as does the
signature. The provider rejects identical signing public keys for the two
roles. Private key material remains outside the repository and release evidence.
Authorized public keys and their role contexts are included in audit evidence.

I05's negative mandate is signed by KP and announces KP's kid; I06's negative
ICT is signed by KI and announces KI's kid. The independent reader establishes
mathematical validity under the announced key separately from the role refusal.
I05 also isolates correctly KI-signed wrong typ, unknown kid, wrong iss, wrong
aud, and a signature bit alteration that preserves width/encoding. The valid
leafC remains importable. A raw duplicated-iss signed payload and no-duplicate
control separately test strict raw JWS parsing, without an SDK scenario count.

Mandate bodies, typed cost vectors, lineage and receipt fields preserve the
profile's R5 wire shapes. Each is closed and validated before membership,
hashing or SQL. Body and JWS dates are integers, never Python Booleans, with
`0 <= valid_from < valid_until <= 9007199254740991`; mandate nbf/exp match those
dates. JWS dates satisfy `0 <= iat <= nbf < exp <= 9007199254740991`.
Default mandate iat equals body valid_from; diagnostic JWT dates are specified
separately to isolate deliberately invalid body dates. Child constraints, caps
and validity only attenuate their parent. An ICT
lasts at most 60 seconds and never exceeds its lineage. The trusted fixture
clock starts at `2000000000`.

## State and transactions

For each root and cost dimension, consumed plus active reserved never exceeds
the root budget. Reserved facts participate in composition checks. The current
lineage and root epoch are reread in the effect transaction. A committed local
revocation blocks unused permits; a later revocation preserves historical
effects and receipts. Identical committed retry returns the same receipt with
no callback, charge or revision. Same operation with a different action is an
operation conflict. A timeout or lost response does not refund a charge.
Cancellation releases an unused reservation safely, including an expired held
reservation; it does not erase a committed effect or refund it retrospectively.

Transactions use provider-owned `BEGIN IMMEDIATE`. Callback failure after
INSERT must roll back consumer rows, charge, receipt and revision together.
The callback result is validated and serialized before commit. A precommit
crash leaves no durable effect; a postcommit crash before reply retains one
effect and permits historical lookup/retry. Barrier events record actual
arrival, release and commit order rather than inferring causality from sleeps.

C01-C04 and I12 dispatch two actual admission RPCs to distinct provider
processes. Both request-correlated reserve:before_transaction arrivals precede
the first release. The prescribed winner then commits and returns RESERVED
before the loser is released and refused. This selected overlapping schedule
is distinct from merely sending the second request after the first response.
I04 presents A's original ICT to configured executor B with a misleading A
identity hint, then uses the valid A control. I15 repeats the original tools/call
after revoke and requires the same historical receipt without a new callback.

The normal revision sequence begins with ROOT_REGISTERED at 1, then increments
once for each CHILD_REGISTERED, RESERVED, COMMITTED, CANCELLED or REVOKED event.
No-op retry and lookup do not increment it. Revocation increments authority
epoch once. Decimal revisions are exact uint64 strings. Roots, mandates,
reservations, business_effects, receipts, transitions and demo_records are read
at checkpoints, including before recovery and admission-only violations.

## Error classification

Profile/domain refusals are JSON-RPC `-31001`, message `ZTI-MCP authorization
refused`, data `{profile,reason,status}` with status REFUSED or SUSPENDED.
The vocabulary is INVALID_TOKEN, PROFILE_UNSUPPORTED, BINDING_MISMATCH,
CONSTRAINT_VIOLATION, CUMULATIVE_VIOLATION, OPERATION_CONFLICT, NOT_AUTHORIZED,
NOT_FOUND, REVOKED, EXPIRED, AUTHORITY_UNAVAILABLE, MANDATE_CONFLICT and
EXECUTION_FAILED. Reusing a mandate identifier with a different signed body is
MANDATE_CONFLICT.
Malformed bound identifiers such as list/dict tool names are BINDING_MISMATCH,
not an internal exception. A callback exception is EXECUTION_FAILED after
rollback. SDK outer-model `-32602` is separately counted as parameter rejection.
Unexpected timeouts, imports, process exits and parser failures are infrastructure
errors, not successful semantic refusals or mutant detections. Expected crash
exit 86 requires both the causal hook and the appropriate durable checkpoint.

## Frozen corpus and interpretation

Machine-readable fixtures define all concrete inputs and admissible projections
before qualification. Twenty integration stories run once with each primary
client (40 executions). Twelve causal plans run with PP/PT/TP/TT (48 replays),
two orders or fault points for each of budget, composition, same operation,
revocation, cancellation and crash/recovery. These reuse the integration threats;
they are not 88 independent attacks. Twenty-four core binding vectors and four
auxiliary binding diagnostics run through each independent binder. Eight date
diagnostics run through each client. Three synthetic discovery copies and three
other synthetic evidence alterations are reported separately. A raw duplicated
iss JWS and positive control are a direct reader diagnostic, not SDK executions.
Additional typing regressions also have their own category. No combined
security score is formed.

The six startup-only defects have specific witnesses: M01 Number precision
loss in a uint64 vector; M02 mutation after validation reaching I01's callback;
M03 a durable orphan consumer INSERT before charge/receipt; M04 a second
consumer row on consumed retry; M05 completed authority precheck, then pause,
committed revoke, then effect; M06 omitted reserved facts visible at admission.
The ordinary independent checks must reject the broken state. A flag, an
exception, a timeout or an unreachable mutation is not sufficient detection.

The oracle imports no provider canonicalizer, verifier, ToolSpec, decision
helper, harness fixture module or R5 reader. It independently verifies captured
ES256 and context, modern discovery fields, request/final-action/reservation/
business-row/receipt binding, conservation, revisions and selected causal order.
Deliberately invalid tokens are valid negative inputs if the provider refuses
them; they must not make every negative trace fail audit automatically.

## Review and publication gates

R1 technical cross-review receives the frozen contract, complete first campaign,
source diff, wire, SQL checkpoints, state model, mutants and retained failures.
Findings state exact property, bytes/source, reproducer, minimal correction and
closure evidence. R2 is an author-distinct strategic review from fresh installed
distributions. Functional R2 corrections repeat affected R1 checks and receive
R2 closure. These are same-team AI-assisted reviews.

DISTRIBUTION.md fixes the native TypeScript application procedure: build the
tgz, extract outside checkout and node_modules, copy the frozen runtime lock
byte-for-byte, npm ci, run the extracted source with Node24.22.2 and record
actual loaded paths/hashes. Native stripping is not static type checking.
Python wheels are also installed outside the checkout without editable mode.

The exact candidate H needs native Windows and hosted Windows/Ubuntu campaigns,
closed R1/R2 and a completed matching director GO before an expected-H merge.
Actual merged M and its parents/tree are identified separately. M is built once;
the same distribution bytes are qualified on hosted Windows/Ubuntu and native
Windows, then published to v0.3.0-research as a prerelease in the personal repo.
Anonymous asset downloads must match size/hash, pass data-only audit and install
smoke. No npm/PyPI publication, new email or outside adoption is a closure gate.
The final matching director verdict must be READY_TO_CLOSE.
