<#
.SYNOPSIS
  Scan a repo then run the OPA/Rego policy gate locally (Windows/PowerShell).
.EXAMPLE
  ./scripts/run-opa.ps1 -Repo . -Profile commercial
  Uses conftest/opa if installed, otherwise the built-in Python fallback.
#>
param(
  [string]$Repo = ".",
  [string]$Profile = "",
  [switch]$WarnAsError
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = (Join-Path $Root "src")

if (-not $Profile) {
  $pf = Join-Path $Repo ".sre/profile"
  if (Test-Path $pf) { $Profile = (Get-Content $pf -Raw).Trim() } else { $Profile = "commercial" }
}

$Out = Join-Path $Root "sre-reports"
Write-Host ">> Scanning $Repo with profile '$Profile'"
python -m sre_governance.cli scan --repo $Repo --profile $Profile --format json --out $Out --audit (Join-Path $Repo ".sre/audit.jsonl")

if (Get-Command opa -ErrorAction SilentlyContinue) {
  Write-Host ">> opa test policies/opa"
  opa test (Join-Path $Root "policies/opa") -v
}

Write-Host ">> Running policy gate"
$gateArgs = @("--report", (Join-Path $Out "sre-governance-report.json"))
if ($WarnAsError) { $gateArgs += "--warn-as-error" }
python (Join-Path $Root "scripts/opa_gate.py") @gateArgs
exit $LASTEXITCODE
