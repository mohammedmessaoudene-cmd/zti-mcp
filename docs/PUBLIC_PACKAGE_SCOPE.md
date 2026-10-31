# Public package scope and provenance

This tree is a publication-oriented subset of the validated R4 dossier, prepared separately on 31 October 2026. Preparing the tree did not change R4 or publish anything.

## Later integration

This dated note describes the initial R4 subset. R5 adds a separately named
`integration/stdio_r5/` successor with real stdio clients/endpoints, frozen tests,
a direct SQL reader and a separate integration manifest/workflow. Its commands
and limits are documented in that directory. R4 historical statements remain
attributed to their original scope. New execution evidence is attributed to its
actual source revision, never inferred from this note.

## Included

- The two original executable core files, all forty scenario definitions, three mutant definitions and four frozen preexecution inputs.
- Real signed laboratory examples, structural schemas and separately identified illustrative wire messages.
- English RFCXML/text/PDF snapshots, the French engineering note and selected review/coverage documents.
- Aggregate results of the initial run and the coordinator's reproduction, plus the seven targeted review diagnostics.
- A read-only-by-default package verifier, a noninteractive PowerShell reproduction script and a reproduction-only CI workflow.

The handoff's frozen source hashes are checked explicitly, in addition to the public manifest. `results/SOURCE_PROVENANCE.json` records original relative paths and source hashes without private machine paths.

## Packaging adaptations

The authority and scenario runner are exact copies. The example verification helper adds an optional `--output` path so a run can write a fresh report under ignored `work/` instead of changing tracked fixtures. No signature, binding or scenario decision logic is changed by that option.

One private absolute path in the historical format-review note is replaced by the corresponding repository-relative specification path. An adaptation entry records that change. New README, workflow, PowerShell and manifest-verification files belong to this packaging layer.

Historical text files retain references to the original R4 archive layout. For example, `experiment/runs/initial`, `../review/probes/` and preserved toolchain logs describe the original dossier. This repository instead includes the portable runner under `reference/`, public aggregate results under `results/`, and selected review text under `docs/evidence/`. An absent archival path is not an implied downloadable dataset or a claimed new execution.

The French note's historical private-working label is preserved as part of the dated snapshot. The owner has instructed preparation for public release. No private correspondence, inbox extract, account credential or unrelated project material is included.

## Excluded

- Raw historical SQLite ledgers, WAL/SHM files and large per-case trace bundles. New reproduction runs create their own local evidence under ignored `work/`.
- Installation logs, downloaded formatting grammars/bibliography files, vendored dependencies, virtual environments and toolchain caches.
- Private workspaces and absolute machine-specific paths.
- Any assertion that illustrative wire messages were captured from real peers.

The original RFCXML retains external bibliography references. This repository does not vendor the third-party bibliography/grammar files. The publication documents and their notices are preserved; their detailed licensing boundaries are described separately in `LICENSE_SCOPE.md`.

## Validation boundary

The preserved R4 evidence comprises the original run and a coordinator reproduction. Packaging does not count as another successful forty-scenario run. The core runner was not modified, so no optional third campaign was added merely to inflate the count.

The package verifier checks file hashes, required files, frozen inputs and asset equality. Example verification checks real signatures and the selected bindings. Neither operation executes an MCP server, a remote model or a publication action. The first GitHub-hosted CI run and the PowerShell procedure must be observed on their actual target environments; prepared files are not proof that those hosted/platform runs have succeeded.

The current package uses GitHub Actions checkout and Python setup pinned to specific commits. Official source references for those selections are the [checkout repository](https://github.com/actions/checkout) and the [setup-python v5.6.0 release](https://github.com/actions/setup-python/releases/tag/v5.6.0). These are fixed selections for the workflow, not a statement that they are the latest available releases.
