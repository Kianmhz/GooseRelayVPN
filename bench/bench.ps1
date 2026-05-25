param(
    [switch]$Smoke,
    [string]$Scenarios = "",
    [ValidateSet("direct_post", "direct_stream")]
    [string]$Transport = "direct_post",
    [switch]$VerboseRun
)

$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$BenchDir = Join-Path $Root "bench"
$BinDir = Join-Path $BenchDir "bin"
$ResultsDir = Join-Path $BenchDir "results"
$SmokeBin = Join-Path $BenchDir ".smoke_bin"

New-Item -ItemType Directory -Force -Path $BinDir, $ResultsDir | Out-Null

function Invoke-GoBuild {
    param(
        [string]$Output,
        [string]$Package
    )
    Push-Location $Root
    try {
        & go build -trimpath -o $Output $Package
        if ($LASTEXITCODE -ne 0) {
            throw "go build failed for $Package"
        }
    } finally {
        Pop-Location
    }
}

Write-Host "==> building bench tools"
Invoke-GoBuild (Join-Path $BinDir "sink.exe") "./bench/sink"
Invoke-GoBuild (Join-Path $BinDir "harness.exe") "./bench/harness"
Invoke-GoBuild (Join-Path $BinDir "diff.exe") "./bench/diff"

if (-not $Smoke) {
    Write-Host "bench.ps1 currently supports the Windows smoke path."
    Write-Host "Usage: powershell -ExecutionPolicy Bypass -File bench\bench.ps1 -Smoke [-Scenarios ttfb_p50_p95] [-Transport direct_stream] [-VerboseRun]"
    exit 2
}

if (Test-Path $SmokeBin) {
    Remove-Item -Recurse -Force $SmokeBin -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force -Path $SmokeBin | Out-Null

Write-Host "==> building current tree for smoke run"
Invoke-GoBuild (Join-Path $SmokeBin "goose-client.exe") "./cmd/client"
Invoke-GoBuild (Join-Path $SmokeBin "goose-server.exe") "./cmd/server"

if ([string]::IsNullOrWhiteSpace($Scenarios)) {
    $Scenarios = "ttfb_p50_p95"
}

$Out = Join-Path $ResultsDir "smoke.json"
$HarnessArgs = @(
    "--client-bin", (Join-Path $SmokeBin "goose-client.exe"),
    "--server-bin", (Join-Path $SmokeBin "goose-server.exe"),
    "--sink-bin", (Join-Path $BinDir "sink.exe"),
    "--out", $Out,
    "--ref", "smoke",
    "--transport", $Transport,
    "--scenarios", $Scenarios
)
if ($VerboseRun) {
    $HarnessArgs += "-v"
}

Write-Host "==> running harness smoke ($Scenarios, $Transport)"
& (Join-Path $BinDir "harness.exe") @HarnessArgs
if ($LASTEXITCODE -ne 0) {
    throw "benchmark smoke failed"
}

Write-Host ""
Write-Host "==> smoke results: $Out"
