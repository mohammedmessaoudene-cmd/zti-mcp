# R7: local effect-complete messaging and durable recovery

R7 compares an attributed R6 authorization core with an independently implemented durable classical ACL. Both execute the same small messaging engine in local SQLite, with the same structured permissions, observations and recovery opportunities. The question is whether their effects and completion claims remain correct after a refusal, a changed state or a lost response. Equality is an acceptable result.

This directory contains a separate research successor. Historical R6 source and evidence retain their original identity. R7 extends the trusted application writer with bounded reads from the effect transaction; this is new R7 behavior, not a result attributed to unchanged R6.

The fixed comparative corpus is **12 authored task templates × 2 variants = 24 pairs, or 48 controller executions per complete campaign**. Variants reuse templates and are not independent population samples. Development probes, six separate instrument-control categories, positive witnesses, smoke uses and data-only audits are reported separately. The source and any `PASS` label alone do not establish that a campaign ran: inspect its exact source/build identity, SQL backups, delivered observations, claims and audit receipts.

The pilot is deterministic and adaptive. It receives public obligations and proposals, reacts to actual responses, and can use an explicit permitted continuation. It receives no expected verdict, case identity or injection schedule. A restarted process uses the same service principal and durable operation journal. Before dispatch it persists the exact obligation, operation and action binding, along with cumulative counters: at most **16 provider calls, including 4 lookups**, across restarts.

## Local model and its limits

One authority and one tenant manage synthetic messages, a bounded directory, alias/group expansion, outbox occurrences, recipient deliveries and read-state events. A single trusted `message.mutate` tool owns the business tables. `reply`, `reply_all` and `mark_read` use the closed semantics in [CONTRACT.md](CONTRACT.md); this is not an implementation of all email RFCs.

The effect transaction rereads the relevant state, recomputes the complete recipient/mutation plan, checks the bound versions and plan, applies each arm's independently written authorization, and couples business events with consumption and receipt. A writer reads only its declared table, returns immutable copies in row order, and refuses more than 1,024 rows instead of silently truncating.

A successful same-operation retry returns the historical receipt and produces no additional callback or charge. `lookup` supplies status and receipt, **not the full business result**. The pilot can justify a historical completion by linking a delivered receipt to its exact journaled action and obligation. That receipt does not grant fresh authority after revocation. Missing observations remain uncertainty until resolved within the fixed budget.

There is **no semantic deduplication guarantee across new operation identifiers** and no business uniqueness constraint on obligation identity. Repeating one obligation under two operations must remain detectable. Two different obligations with identical message content may legitimately produce two occurrences.

This lot does not execute an LLM, an HTTP/OAuth flow, a new MCP SDK or wire qualification, real email, a remote atomic effect, multi-tenant authorization or cross-principal delegation. Trusted launch configuration, application code, clock and host administration remain inside the laboratory boundary. Same-team AI reviews are not independent human validation, production certification or standards adoption.

## Build and run

Use Python **3.12** and the exact dependencies in [REQUIREMENTS.txt](REQUIREMENTS.txt). Build once, install the resulting wheel without editable mode in a fresh environment, and run from a directory outside the checkout. Preserve every earlier output; commands require fresh output directories/archive names. The commands below are procedures, not claims of executed qualification. Qualification requires the recorded S1 clearance and a matching frozen input manifest.

POSIX, from the verified checkout root:

```sh
r7_root="$(mktemp -d)"
python3.12 -m venv "$r7_root/runtime"
r7_py="$r7_root/runtime/bin/python"
"$r7_py" -m pip install -r successor/r7/REQUIREMENTS.txt
cp -R successor/r7 "$r7_root/build-source"
"$r7_py" -m pip wheel --no-deps --no-build-isolation --wheel-dir "$r7_root/dist" "$r7_root/build-source"
"$r7_py" -m pip install --no-deps "$r7_root"/dist/zti_r7_research-0.4.0-*.whl
cd "$r7_root"
"$r7_py" -I -m zti_r7 qualify --output qualification
"$r7_py" -I -m zti_r7 instrument --output controls
"$r7_py" -I -m zti_r7 export --run qualification --archive R7_PUBLIC_EVIDENCE.zip
"$r7_py" -I -m zti_r7 audit --archive R7_PUBLIC_EVIDENCE.zip --output data-audit
"$r7_py" -I -m zti_r7 smoke --output installed-smoke
```

PowerShell, from the verified checkout root:

```powershell
$r7Root = Join-Path $env:TEMP ('zti-r7-' + [guid]::NewGuid().ToString('N'))
py -3.12 -m venv (Join-Path $r7Root 'runtime')
$r7Python = Join-Path $r7Root 'runtime/Scripts/python.exe'
& $r7Python -m pip install -r successor/r7/REQUIREMENTS.txt
Copy-Item -LiteralPath successor/r7 -Destination (Join-Path $r7Root 'build-source') -Recurse
& $r7Python -m pip wheel --no-deps --no-build-isolation --wheel-dir (Join-Path $r7Root 'dist') (Join-Path $r7Root 'build-source')
$r7Wheel = Get-ChildItem -LiteralPath (Join-Path $r7Root 'dist') -Filter 'zti_r7_research-0.4.0-*.whl'
if (@($r7Wheel).Count -ne 1) { throw 'Exactly one built R7 wheel required' }
& $r7Python -m pip install --no-deps $r7Wheel.FullName
Set-Location -LiteralPath $r7Root
& $r7Python -I -m zti_r7 qualify --output qualification
& $r7Python -I -m zti_r7 instrument --output controls
& $r7Python -I -m zti_r7 export --run qualification --archive R7_PUBLIC_EVIDENCE.zip
& $r7Python -I -m zti_r7 audit --archive R7_PUBLIC_EVIDENCE.zip --output data-audit
& $r7Python -I -m zti_r7 smoke --output installed-smoke
```

Check every process exit and receipt before proceeding; PowerShell does not automatically stop after a native command's nonzero exit. `smoke` uses its declared selected cases and is not another 24-pair campaign. Source-checkout feasibility checks are separately available as `python successor/r7/tests/feasibility.py --output-dir <new-directory>` with the pinned environment; their temporary output contains private laboratory keys and must not be uploaded wholesale.

## Read the evidence

`SUMMARY.json` reports each controller execution and paired observed outcomes. Assess effects, useful completion, duplicates, false refusals, factual false `DONE`, unsupported `DONE`, justified and unnecessary `UNKNOWN`, and cost separately. A safe abstention is not useful completion. A difference needs a capability/information and causal explanation before attribution to the mechanism; an equal outcome does not establish universal equivalence.

The evaluator runs in a distinct process after controller writers exit. It reads committed SQLite backups and the observations actually delivered to the pilot. It does not import the messaging engine or either authorization checker as its truth definition. The instrument controls separately challenge omitted recipients, uncounted implicit mutations, duplicate obligations, false `DONE`, unsupported `DONE` despite a real effect, and accidental oracle information flow. The information-flow control invalidates isolation; it is not an extra blocked business attack.

The export command selects a closed allowlist of data and excludes private runtime/configuration/key directories. Its manifest hashes establish internal consistency. They do not establish provenance, outside reproduction or delivery. The audit uses the trusted installed reader against exported data; it does not execute captured code or create new provider effects. Release verification additionally requires actual anonymous downloads, matching bytes and an installed smoke from the downloaded package.

The repository workflow [research-r7.yml](../../.github/workflows/research-r7.yml) builds a wheel on the exact checked-out commit, records its tree and parents, and exercises an installed Ubuntu environment. Native Windows candidate evidence and merged-commit CI evidence keep their respective commit attribution; one is not relabeled as the other.

See [PROVENANCE.md](PROVENANCE.md), [CONTRACT.md](CONTRACT.md), the retained run receipts and the root license scope. No numerical success or superiority is claimed by this README in advance of those observations.
