# Noninteractive reproduction on Windows

This procedure runs only local verification and the harmless corpus. It does not create a GitHub repository, publish a release, send email or submit an Internet-Draft. Publication steps belong to the separate owner-authorized Codex handoff.

## Preconditions

Use a checkout of this repository, Python 3.12, and PowerShell. Python's `py` launcher is used by default; an explicit Python 3.12 executable can be supplied with `-PythonPath`. A first dependency installation needs access to the configured package index. No model download or model API is used.

The files are configured to keep LF line endings on checkout so frozen byte hashes remain portable. Do not edit or re-encode the frozen inputs to accommodate a mismatch; inspect checkout settings and the actual diff.

## One command after checkout

From the repository root, using PowerShell 7:

```powershell
pwsh -NoProfile -NonInteractive -File .\scripts\reproduce.ps1 -InstallDependencies
```

With Windows PowerShell 5.1:

```powershell
powershell.exe -NoProfile -NonInteractive -File .\scripts\reproduce.ps1 -InstallDependencies
```

To select an existing Python executable without relying on `py`:

```powershell
pwsh -NoProfile -NonInteractive -File .\scripts\reproduce.ps1 -PythonPath "C:\Python312\python.exe" -InstallDependencies
```

The path above is an illustrative installation path, not a required location. Use the actual installed interpreter. The procedure does not change the machine's execution policy. If local policy blocks script execution, use an approved execution method or run the explicit commands below; do not silently weaken policy.

The script checks every native command's exit code. It verifies the package, prepares `.venv`, optionally installs the pinned dependency with pip's `--no-input`, runs all forty scenarios and three mutant witnesses in a fresh directory, verifies the signed examples into a fresh report and verifies the resulting aggregate. It never overwrites an existing run.

Subsequent runs can omit `-InstallDependencies` once `.venv` is already prepared.

## Equivalent explicit commands

These are useful when Codex is operating an already approved PowerShell session. Stop on every nonzero exit code; never proceed to publication after a failed step.

```powershell
$ErrorActionPreference = "Stop"
py -3.12 -I scripts/verify_handoff.py
if ($LASTEXITCODE -ne 0) { throw "Package verification failed" }
py -3.12 -m venv .venv
if ($LASTEXITCODE -ne 0) { throw "Environment creation failed" }
& .\.venv\Scripts\python.exe -m pip install --disable-pip-version-check --no-input -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed" }
$RunDirectory = "work\run-" + [guid]::NewGuid().ToString("N")
& .\.venv\Scripts\python.exe -I reference/run_r4.py --output-dir $RunDirectory
if ($LASTEXITCODE -ne 0) { throw "Corpus failed; preserve results" }
& .\.venv\Scripts\python.exe -I reference/verify_examples.py --output ($RunDirectory + "-examples.json")
if ($LASTEXITCODE -ne 0) { throw "Example verification failed" }
& .\.venv\Scripts\python.exe -I scripts/verify_handoff.py --summary (Join-Path $RunDirectory "SUMMARY.json")
if ($LASTEXITCODE -ne 0) { throw "Aggregate verification failed" }
```

## Expected interpretation

The aggregate should report forty matching scenario observations, three detected mutant divergences and zero operational errors. The example verifier should report three valid ES256 signatures and consistent bindings. These counts describe the finite corpus, not universal safety or real MCP interoperability.

IDs, signatures, PIDs and the winner of a legitimate concurrent admission may change. A SQLite error, broken barrier or child crash is a failed run; it must not be relabeled as a successful policy refusal. Preserve any failure output and repair only the demonstrated issue, with an explicit diff and the relevant rerun.

This PowerShell procedure is prepared for the Windows handoff. It was not executed on a Windows host while packaging the Linux workspace; obtain that result in the target environment before reporting it as successful.
