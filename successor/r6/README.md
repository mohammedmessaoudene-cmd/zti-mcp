# R6: installed local tools and two real MCP SDK clients

R6 adds an installable provider and a separately packaged application tool to
the preserved R4/R5 research corpus. The provider imports `ToolSpec` factories
from its trusted startup configuration. The application supplies validation,
an exact cost/fact footprint, a declared table and an INSERT callback. The
provider owns the SQLite transaction, authorization, accounting and receipt.

The external example is [zti_r6_demo.tools](consumer/src/zti_r6_demo/tools.py).
It imports the installed public API and writes fictional `demo_records` rows.
Its operation identifier deliberately has no UNIQUE constraint: a duplicate
callback must remain observable. The provider requires no application-specific
core patch. [API.md](API.md) defines the interface and wire contract.

This is one local provider and SQLite effect boundary. Startup configuration,
Python plugins and the OS administrator are trusted. The Writer interface is
bounded, but Python plugins are not sandboxed. No network/physical effect,
production authentication, exhaustive scheduling, standard adoption or outside
human reproduction is established. Reviews and implementation are AI-assisted.

## Reproduce from a verified checkout

Prerequisites: Git, Python 3.12, **Node 24.22.2** with npm, network access to the
locked package registries, and disk space for retained evidence. Run from the
repository root. Choose a fresh output directory for each invocation.

Windows PowerShell:

```powershell
py -3.12 -I scripts/reproduce_r6.py --mode live --output-dir work/r6-new
```

Ubuntu:

```sh
python3.12 -I scripts/reproduce_r6.py --mode live --output-dir work/r6-new
```

If Node/npm are outside PATH, supply `--node` and `--npm` with their executable
paths. The command verifies the public manifest, the 14 frozen inputs and 101
preserved historical files, requires a clean exact Git revision, builds two
own wheels plus a native TypeScript application archive, and installs them in
a fresh retained directory **outside the checkout**. It uses hash-locked
Python dependencies and a frozen npm lock, with no editable installation or
global upgrade. The actual loaded module identities and wheel installation
hashes are checked. Private key material and settings stay outside public data.

`AUDIT.json` is the independent reader's verdict. `BOOTSTRAP.json` also requires
unchanged source at the end. A collector's completion message alone is not a
PASS. Failures remain available at their original paths.

## Build once, qualify the same bytes

```sh
python3.12 -I scripts/reproduce_r6.py --mode build --output-dir work/r6-build
python3.12 -I scripts/reproduce_r6.py --mode live --distributions work/r6-build/distributions --output-dir work/r6-same-bytes
```

The second command checks BUILD.json's exact commit, tree and all distribution
hashes before installation. A build from a PR head cannot be attributed to its
later merge commit, even when their trees are equal. The hosted workflow builds
one distribution set and gives the same bytes to Windows and Ubuntu. Release
qualification also installs those bytes on native Windows. Actual run IDs,
commits and results belong in the release evidence, not in a workflow claim.

## Audit portable data without executing a captured application

Export a completed private run using the allowlist:

```sh
python3.12 -I successor/r6/package_evidence.py --run-dir work/r6-new --output-dir work/r6-export
python3.12 -I scripts/reproduce_r6.py --mode audit --evidence work/r6-export/R6_PUBLIC_EVIDENCE.zip --output-dir work/r6-audit
```

Use the trusted checkout corresponding to the evidence's exact source revision.
The audit command reads data only from the archive; it never runs its code.
It checks raw protocol frames, mathematical signatures, current-state and
historical SQL relations, actual consumer rows, receipts, and selected causal
orders. Real SQLite checkpoints are authoritative; JSON table exports are
compared auxiliary views. Selected metadata path projections record original
and exported hashes. Wire, provider event and SQLite bytes are preserved.
Hashes prove consistency, not authenticity or independent execution.

## What the frozen campaign contains

| Category | Separate obligation |
| --- | --- |
| Base histories | 20 stories through each SDK: 40 executions |
| Causal schedules | 12 plans through PP/PT/TP/TT: 48 replays |
| Canonical binding | 24 core vectors and 4 auxiliary vectors through each binder |
| Date diagnostics | 8 through each SDK: 16 executions |
| Malformed tool identifiers | 2 through each SDK: 4 executions |
| Isolated fact controls | Red and blue alone through each SDK: 4 executions |
| Deliberate defects | 6, requiring actual activation and semantic detection |
| Altered evidence | 3 discovery and 3 other synthetic data copies; no new SDK execution |
| Raw duplicated JSON key | 1 signed negative input and 1 signed positive control; no SDK execution |

These counts are not summed into a security score. Concurrent admission plans
observe two actual pending requests before release; selected winner/loser
orders use request, process, commit and checkpoint links, not wall-clock sorting.
Rollback or a precommit crash may cause a callback attempt to be retried. The
durable requirement is one committed business effect per operation. Consumed
retries return the immutable historical receipt and do not replay the callback.

The ordinary reader is separate from provider code. A fault flag, import error,
timeout or crash alone never counts as detecting an injected defect. Full
source attribution, distribution installation and case-set gates are required
before the aggregate reader reports PASS.

## Integrate another local tool

Start from the separate consumer package, build it as its own wheel and install
it beside `zti-mcp-r6`. Define `TableSpec`, `validate`, `footprint` and `apply`,
then return a `ToolSpec` from an installed `module:factory`. Name that factory
in trusted launch JSON `tools`; launch `python -I -m zti_mcp_r6 --config ...`.
The provider receives only the configured mandate public key and permit private
key; mandate issuance is a separate component. Principals come from trusted
launch settings, not client-supplied names or metadata.

The footprint and final immutable arguments must describe the same business
effect. Each additional tool needs its own client binding, semantic checks and
independent effect oracle. The demo's tag/cost policy is not a universal policy
language. [DISTRIBUTION.md](DISTRIBUTION.md) explains the archive adaptation:
Node executes erasable TypeScript directly, without static type checking.

Own code and original technical materials use Apache-2.0 under
[LICENSE_SCOPE.md](../../LICENSE_SCOPE.md); the historical specification license
and third-party notices retain their existing scope. The SDKs are external
dependencies, not independent implementation attestations. No npm/PyPI
publication is implied by the research release's downloadable distributions.

[Implementation notes](IMPLEMENTATION_NOTES.md) record the prequalification
corrections and their validation limits. The independent reader has its own
content seal in addition to the 14 frozen scientific/package inputs. Selected
upstream SDK entry identities are derived from the pinned official archives.
