# ZTI-MCP R5: local stdio integration

This is a bounded demonstration using the official Python MCP SDK **2.3.0**,
MCP **2026-07-28**, real stdio subprocesses, and one provider-owned local SQLite
database. It implements the individual experimental `zti-mcp/0.1` profile. The
documentation namespace `org.example/zti-mcp` is not a production registration.
Using the SDK does not make this an official SDK extension or adopted standard.

The three tools only insert harmless fictional records in SQLite. The named
`read_sensitive` and `export_external` facts do not read private data or export
anything. No model API, public server or paid service is needed.

## Install and reproduce

Use Python 3.12 and a fresh clone. From the repository root:

```text
python -m venv .venv
```

Activate that environment (`.venv\Scripts\Activate.ps1` on Windows,
`source .venv/bin/activate` on POSIX), then run:

```text
python -m pip install -r integration/stdio_r5/requirements.txt
python -I scripts/verify_handoff.py
python -I integration/stdio_r5/verify_package.py
python -I integration/stdio_r5/harness.py --output-dir work/r5-first
python -I integration/stdio_r5/diagnostics.py --output-dir work/r5-date-diagnostics-first
python -I integration/stdio_r5/reader_regressions.py --source-variant work/r5-first/S01_nominal --output-dir work/r5-reader-regressions-first
python -I integration/stdio_r5/verify_package.py --summary work/r5-first/SUMMARY.json
```

Every campaign needs a **new** output directory. The harness preserves failed
results and never overwrites a nonempty run. The ordinary campaign runs eight
scenarios, twenty normal variants, and two deliberately defective integration
mutants in separate fresh databases. Frozen expected refusals and actual positive
effects both matter; this is not a universal security score.

The separate date diagnostics have two integer-date positive controls and six
Boolean-date rejection cases through actual SDK registration requests. They
check both root and child signed mandate bodies and independently read back
the resulting registry. These were added after review reproduced Python's
`True == 1` type confusion in the initial R5 candidate. The provider now requires
actual safe-range integers for both validity dates at import and lineage use.
These diagnostics do not change or enlarge the twenty frozen normal variants
or the two integration mutants. Their output directories must also be fresh.

The reader regressions keep the original positive evidence unchanged and mutate
two disposable copies consistently: one announces incompatible modern
`supportedVersions` alongside a compatible legacy field, and another omits the
required modern field. Both must fail the modern discovery check. These are
explicitly synthetic tests of the evidence reader, not real malformed SDK
responses, new MCP scenarios or integration mutants.

Historical regression remains separate:

```text
python -I reference/run_r4.py --output-dir work/r4-regression-first
python -I reference/verify_examples.py --output work/r4-examples-first.json
python -I scripts/verify_handoff.py --summary work/r4-regression-first/SUMMARY.json
```

The R5 dependency file pins the complete resolved runtime set. Its Windows-only
`pywin32` dependency has a platform marker. There is no SDK patch or private API
override. Environment installation uses the package index; experiments themselves
make no remote model or business-service calls.

## Implementation and wire mapping

`endpoint.py` constructs the official SDK `MCPServer`, an `Extension` with five
`MethodBinding` methods, and ordinary SDK tools. `harness.py` uses the public
SDK `Client`/`StdioServerParameters` and public session methods. `relay.py`
forwards each stdio line unchanged and records its original Base64 bytes,
direction, sequence and parsed frame. It makes no authorization decisions.

Actual discovery is `server/discover`. The SDK response identifies the supported
version in `supportedVersions`; the harness requires exactly `2026-07-28`, the
adopted client version and exact capability settings. `session.send_discover`
explicitly sends the probe; the cached `discover()` accessor alone is not counted
as a new exchange. A request action revision of `0.2` is rejected while the
client's stamped capability remains `0.1`, and both are checked on the raw frame.

Requests use the method-specific models in `models.py` with explicit snake_case
aliases. Standard MCP metadata remains open. The independent reader checks
method-specific wire shapes, result fields and semantic predicates; it is not
a general MCP/JSON Schema conformance engine. The base R4 verification
limitations remain historical.

The extension's guarded `tools/call` handler binds and executes the same decoded
arguments. It short-circuits the stub tool function, so no later function-argument
coercion changes the protected action. The supported canonical subset is ASCII
object keys, valid Unicode values, safe integer JSON numbers and canonical
uint64 strings. Unsupported values are rejected. This is not full RFC 8785 JCS;
duplicate JWS keys are rejected, but no universal raw MCP duplicate-key rejection
is claimed after SDK parsing.

## Authority and effect boundary

The trusted launcher fixes each endpoint's lab principal and role, database,
clock and test-control directory. MCP `clientInfo`, request metadata, token `sub`
and business arguments cannot choose the channel principal. The scalar-1 P-256
key is intentionally **public laboratory test material**, never a deployment key.

All roots and signed descendants are registered through actual MCP methods.
Descendants share root budgets, policy and outstanding reservations. The normal
provider transaction reloads current authority/time, checks the exact final
action, consumes once, inserts the business row, advances state revision, and
persists the immutable receipt and transition before committing. See
[DATABASE_SCHEMA.md](DATABASE_SCHEMA.md). Lookup/retry returns the recorded
receipt without a second effect. A later cancellation does not refund a commit.

An identical registration retry reports stored record/root status: `ACTIVE`
means the record itself is unrevoked and its root remains active. It does not
attest that every intermediate ancestor is active. New reservations and execution
revalidate the complete lineage. A retry never clears revocation, refreshes an
ICT, changes counters or produces an effect. This explicit R5 status mapping
must not be interpreted as a current authorization decision.

The registry, effect and receipt inhabit one SQLite transaction. This establishes
no atomicity for a later HTTP, payment, physical or other remote provider effect.
Launch identity, fixture clock, catalog and local host administration are trusted;
no OAuth service, hostile-host isolation or distributed consensus is implemented.

## Evidence and limits

The harness stores raw frames, actual provider/relay/launcher identities, trusted
hook events, process exits, checkpoint databases, independent readback and
expected/observed differences under ignored `work/`. On Windows, the interpreter
PID is observed from its trusted startup event because a venv executable may be
a separate redirector. Two provider arrivals before barrier release demonstrate
overlapping pending requests; SQLite write transactions then serialize.

`readback.py` opens base tables read-only after writers stop, recomputes costs,
facts, revisions and linkage without importing the provider, and compares with
the frozen [scenarios.json](scenarios.json). Precommit and postcommit process
crashes demonstrate rollback and durable recovery in the selected schedules.
They do not establish power-loss, filesystem-corruption or every-interleaving
guarantees. Mutants M01/M02 are startup-only test fixtures, not production modes.

Results on a candidate, a PR synthetic merge and the final merged revision are
attributed separately. The final release must have native local Windows plus
hosted Windows and Ubuntu runs on its exact final commit. The same twenty
variants repeated across platforms are not additional independent attacks.

The original R4 core, oracles, fixtures, results and specification snapshots
remain preserved. The baseline manifest is retained under
`docs/evidence/baseline-v0.1.0-research/`. Its historical references to preparation
files do not imply those private mission files are part of this repository.

Research, implementation, tests and reviews used AI assistance. These are
same-team experiments and AI reviews, not an independent human certification or
two-implementation interoperability result. Original code, schemas and fixtures
follow Apache-2.0; original explanatory prose follows CC-BY-4.0, under the scoped
licensing and third-party notices at repository root.
