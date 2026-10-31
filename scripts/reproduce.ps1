param(
    [string]$PythonPath = "",
    [switch]$InstallDependencies
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $RepoRoot

if ($PythonPath) {
    $BasePython = $PythonPath
    $BaseArgs = @()
} else {
    $BasePython = "py"
    $BaseArgs = @("-3.12")
}

& $BasePython @BaseArgs -I scripts/verify_handoff.py
if ($LASTEXITCODE -ne 0) { throw "Package verification failed." }

$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $VenvPython)) {
    & $BasePython @BaseArgs -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw "Virtual environment creation failed." }
}
if ($InstallDependencies) {
    & $VenvPython -m pip install --disable-pip-version-check --no-input -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }
}
& $VenvPython -c "import sys, cryptography; assert sys.version_info[:2] == (3, 12); assert cryptography.__version__ == '50.0.2'"
if ($LASTEXITCODE -ne 0) { throw "Python 3.12 / cryptography 50.0.2 is required. Prepare the environment or use -InstallDependencies." }

$RunName = "run-" + (Get-Date -Format "yyyyMMdd-HHmmss") + "-" + ([guid]::NewGuid().ToString("N").Substring(0,8))
$RunDirectory = Join-Path "work" $RunName
& $VenvPython -I reference/run_r4.py --output-dir $RunDirectory
if ($LASTEXITCODE -ne 0) { throw "Reference reproduction failed; preserve its output." }

$ExampleReport = Join-Path "work" ($RunName + "-examples.json")
& $VenvPython -I reference/verify_examples.py --output $ExampleReport
if ($LASTEXITCODE -ne 0) { throw "Signed-example verification failed." }

$SummaryPath = Join-Path $RunDirectory "SUMMARY.json"
$VerificationReport = Join-Path "work" ($RunName + "-handoff.json")
& $VenvPython -I scripts/verify_handoff.py --summary $SummaryPath --report $VerificationReport
if ($LASTEXITCODE -ne 0) { throw "Aggregate or package verification failed." }
Write-Output "Local reproduction completed. Results: $RunDirectory"
Write-Output "No repository, release, email or draft submission was published by this script."
