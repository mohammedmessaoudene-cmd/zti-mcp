# Packaging review

The public package was prepared separately from R4. The original authority, scenario runner, frozen inputs and specification snapshots retain their recorded bytes. The displayed helper diff records the added fresh-report output option; it does not change signature checks or scenario decisions.

## Checks performed during packaging

- Python source syntax was parsed without launching the forty-scenario corpus again.
- The workflow YAML was parsed and its intended read-only repository permission, fixed action commits, fresh run directory and example-verification step were checked.
- The adapted example helper ran against the public copies: three ES256 signatures and the selected bindings passed, with a fresh report outside tracked fixtures.
- File-copy hashes and release-asset equality are covered by the package verifier.

The helper's unchanged cryptographic checks are inherited from R4. This packaging step is not another independent JCS implementation or an additional successful forty-scenario campaign.

## Material issue found and corrected

A separate AI agent's static review found that the first package-verifier implementation accepted an arbitrary `--report` path and wrote it after verification. An accidental target such as a source file or the public manifest could therefore overwrite a file that had just passed verification.

The corrected verifier checks the report destination before its other work. Reports must be fresh files under `work/`; the directory itself, paths through symbolic links and existing targets are refused. Final creation uses exclusive mode. The new explicit `--output` option of the example helper has the same restriction.

Three targeted guard probes rejected a protected source target, the public-manifest target and an existing report. A fresh `work/` destination was accepted. The source hashes remained unchanged. The reviewing agent read the fix and these observations; it did not independently execute the probes. No additional defect was retained in the requested review scope.

These checks prevent the demonstrated ordinary CLI misuse. They do not establish resistance to adversarial concurrent filesystem modification by another privileged process.

## Results still to obtain in their actual environment

No GitHub-hosted CI job or Windows PowerShell execution occurred while packaging this Linux workspace. The workflow and Windows procedure are prepared for those runs; their success must be recorded from actual executions. No repository, release, message or Internet-Draft submission was published by the packaging scripts.
