# ZTI-MCP: constraint-preserving delegation and cumulative effect authorization

ZTI-MCP is an **individual experimental specification candidate and a local reference corpus** for delegated agents. It explores a precise authorization contract: descendants share root-level budgets and cumulative policy, children can only narrow authority, and current authorization is checked together with the protected effect.

The repository includes an English draft, a French engineering note, schemas, real signed laboratory examples and a Python/SQLite implementation. **It is not a complete MCP server, an adopted standard, a production security product or a detector of mental intent.** The draft identifier is proposed; publication of this repository does not establish submission to or acceptance by the IETF.

The design, code, documentation and internal reviews were prepared with AI assistance under the author's direction. No independent human or institutional review is claimed.

## Start here

| Material | Purpose |
| --- | --- |
| [English specification PDF](docs/specification/ZTI_MCP_SPECIFICATION_00_EN.pdf) | Read the full candidate specification. |
| [Internet-Draft text](docs/specification/draft-messaoudene-zti-mcp-00.txt) and [RFCXML source](docs/specification/draft-messaoudene-zti-mcp-00.xml) | Review requirements and the proposed binding. |
| [French engineering note](docs/fr/NOTE_IMPLEMENTATION_ET_STRATEGIE_FR.txt) | Understand the design choices, results and positioning. |
| [Requirement coverage](docs/evidence/COVERAGE_R4.txt) | See which parts of R01–R28 were exercised and which were not. |
| [Public package scope](docs/PUBLIC_PACKAGE_SCOPE.md) | Understand provenance, omissions and packaging adaptations. |
| [Windows reproduction](docs/REPRODUCE_WINDOWS.md) | Run the corpus non-interactively from PowerShell. |

The French note preserves its historical “private working document” label and the specification preserves its original review status. These are snapshots now included on the owner's publication instruction, not private correspondence. Status must be updated from actual publication/submission receipts when those events occur; no such receipt is inferred from this checkout.

## What the reference code does

The local authority creates immutable signed root and child mandates. All children share one root budget vector and root policy. Child constraints contain allowed executors, resources, methods and tools, plus per-action caps and a validity interval; delegation cannot widen these constraints.

Admission creates a revocable reservation. A trusted fixture catalog derives exact nonnegative costs and possible fact labels from the final command. Admission checks both consumed and reserved state. In the example policy, `read_sensitive` and `export_external` can each be allowed alone while their combination is forbidden in the same root.

At consumption, the authority checks the signed permit, current ancestry, identity, time, epoch and exact action. One SQLite transaction consumes the reservation and inserts the harmless local effect row. This closes the authorization/effect gap **for that SQLite mutation**. It does not close a later network or physical side-effect boundary.

`UNKNOWN` follows a protected commit and retains charge and facts. A lost client acknowledgement is resolved through the existing operation, without creating another effect. Cancellation releases only a reservation atomically made unusable before commit.

The word *Intent* names declared context. Facts and costs here come from a deterministic trusted catalog, not an LLM classifier, vector embedding or assertion that an agent's purpose is harmless.

## Reproduce the local evidence

The preserved reference uses Python **3.12** and the direct dependency in [requirements.txt](requirements.txt), `cryptography==50.0.2`. SQLite and multiprocessing come from Python's standard library. Dependency installation needs access to the configured package index; the experiment itself uses no network or model API.

On Linux or macOS, from the repository root:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check --no-input -r requirements.txt
.venv/bin/python -I scripts/verify_handoff.py
.venv/bin/python -I reference/run_r4.py --output-dir work/first-run
.venv/bin/python -I reference/verify_examples.py --output work/example-verification.json
.venv/bin/python -I scripts/verify_handoff.py --summary work/first-run/SUMMARY.json
```

Use a **new output directory** for every run. The runner refuses to overwrite a nonempty directory. It checks the four frozen inputs before executing the forty scenarios and three selected mutants. Each run creates its own local SQLite ledgers and traces beneath `work/`, which is excluded from version control.

Random IDs, signatures, PIDs and legitimate concurrency winners can differ. Compare expected effects, accounting and verdicts rather than requiring byte-identical traces. Unexpected process failures, SQLite errors and timeouts are errors; they do not count as policy refusals.

The package verifier uses only Python's standard library. It verifies presence, hashes, preserved source/input identity and release-asset equality. It starts no shell or subprocess, uses no network, and publishes nothing. Its manifest detects changes; it is not an authenticated signature or a conformance certificate.

The workflow [reproduce.yml](.github/workflows/reproduce.yml) runs the same corpus and signed-example verification on GitHub Actions with read-only repository permission. It has no release, repository-creation, email or draft-submission step. Its hosted run status must be obtained from the actual CI run; a workflow file alone is not evidence that CI has passed.

## Recorded results

The initial R4 run and the coordinator's separate reproduction each recorded the following, with the same core source and frozen inputs:

| Observation | Recorded value per run |
| --- | ---: |
| Frozen scenarios | 40 |
| Scenarios matching their expected observations | 40 |
| Selected mutant witnesses | 3 |
| Mutants that diverged from the original oracle | 3 |
| Child processes | 13 |
| Operational errors | 0 |

These are **finite corpus results**, not a 100% security score. The repeated run is a reproduction of the same forty scenarios, not forty additional independent attacks. Aggregates are retained in [results/](results/); full historical ledgers, raw traces and toolchain caches are outside this public subset. A separate AI reviewer used an independently written readback script on the original SQLite state. Seven diagnostics arising from actual review findings are recorded separately in [review_probes.json](results/review_probes.json), not added to the frozen scenario count.

### What changed when controls were removed

| Mutant | Observed consequence |
| --- | --- |
| Omit ancestor attenuation | A widened child creates an effect that the parent's tool restriction should prevent. |
| Ignore other outstanding reservation facts | Two incompatible reservations are admitted; one effect commits, the second commit is refused, and one incompatible reservation remains held. This demonstrates a possible-fact admission violation, not two completed incompatible effects. |
| Release `UNKNOWN` charge | Two effects consume cost 4 under a root budget of 3. |

Positive controls matter: two concurrent cost-2 proposals under budget 4 both reserve and commit. The controller is not judged successful merely for refusing all actions.

The concurrent admission cases use distinct spawned processes and a barrier. The cancellation/commit cases impose two explicit orders between processes; they do not measure lock contention or establish every possible interleaving. Individual worker timestamps were not recorded. See the preserved [observation erratum](docs/evidence/OBSERVATION_ERRATA.txt).

## Signed examples and schemas

[examples/](examples/) contains actual ES256 root/child/ICT JWS values, decoded claims, the action, a public JWK and an offline receipt projection from a successful run. The laboratory private key is deliberately public test material: **P-256 scalar 1**. It is not a deployment credential. All identities are fictional and the example dates belong to the deterministic fixture clock.

`reference/verify_examples.py` verifies three 64-byte JOSE ES256 signatures using the exported public key and checks action, scope, policy and mandate bindings. The optional `--output` argument is a packaging adaptation that avoids rewriting tracked example reports. The authority and scenario runner are unchanged.

The receipt is a documentary view of the persisted local effect/audit entry, not a receipt captured from an MCP server. [examples/wire/](examples/wire/) contains explicitly illustrative protocol messages; no MCP peers or SDK exchanged them.

[schema/](schema/) contains five structural base schemas and the documentary control schema. Schema parsing, local references and selected boundary checks are described in the evidence. A full standards-complete JSON Schema validation engine was not used for the base example checks.

The executable canonicalizer supports a documented JCS-compatible subset: ASCII object keys, safe integer JSON numbers and valid Unicode strings. It is **not** a complete RFC 8785 implementation. Signature verification uses the received JWS segments; canonical body hashes serve a different purpose.

## Scope and remaining work

The current executable catalog has two fixed dimensions. Identity authentication, root issuance, the clock and catalog truth are trusted fixture inputs. The implementation has no deployed OAuth service, real MCP negotiation, external provider, distributed consensus, complete parser/resource-limit audit or production key custody.

The local Python API is simpler than the proposed wire API. It does not implement the whole signed-mandate registration interface, every cleanup state transition, authenticated receipt transport or all document-level conformance requirements. Exact gaps are mapped in [COVERAGE_R4.txt](docs/evidence/COVERAGE_R4.txt).

A production integration must establish the provider's actual effect boundary, common authority ordering, trustworthy footprint, authentication and complete mediation. Separate roots, direct bypass paths and malicious registry administrators are not made safe merely by attaching a token.

## Provenance and maintenance

The preserved core hashes are:

```text
reference/authority.py
0489bf76fc482558051e65ac3517aab9189109bc3d1647724e54211b623aa11f

reference/run_r4.py
56e382fa65a079ee8b24b03aa5a9d0874a09938400442a9c707cd54fa0394741
```

[SOURCE_PROVENANCE.json](results/SOURCE_PROVENANCE.json) distinguishes exact copies from packaging adaptations. [PUBLIC_MANIFEST.json](PUBLIC_MANIFEST.json) covers the public tree. Maintain the preexecution oracles and historical evidence when changing behavior; do not rewrite an expected outcome to conceal a regression. `--write-manifest` is only for an intentional reviewed packaging update and is never used by CI to excuse a mismatch.

The three files under [release_assets/](release_assets/) are byte-identical copies of the English PDF, text and RFCXML under `docs/specification/`. No downloaded upstream Relax NG/bibxml files, dependency installation logs or provenance database bundle is included. Regenerating the draft may require separate formatting tooling and bibliographic access; the reproduction workflow verifies the existing artifacts and does not rebuild the publication format.

See [LICENSE_SCOPE.md](LICENSE_SCOPE.md), [LICENSE](LICENSE), [NOTICE](NOTICE) and [LICENSES/CC-BY-4.0.txt](LICENSES/CC-BY-4.0.txt) for the actual licensing boundaries. The draft's IETF notices and third-party components retain their applicable terms.
