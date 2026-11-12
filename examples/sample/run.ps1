# Runs the sample review on Windows and checks the result.
# Fails (non-zero exit) if the self-test, `analyze` or verify-log fails, if the exit code or the finding
# codes and status of any item differ from expected_findings.json, or if the tool's hash register
# (logs\<RUN-ID>\hashes.csv) differs from the independently computed expected_hashes.csv.
# Usage: .\examples\sample\run.ps1 [-Bin C:\path\to\rv-mailauth.exe]
# Output folder: examples\sample\out (or $env:RV_SAMPLE_OUT).
param([string]$Bin = "rv-mailauth")
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$out = if ($env:RV_SAMPLE_OUT) { $env:RV_SAMPLE_OUT } else { Join-Path $here "out" }
$expected = Get-Content -Raw -Encoding UTF8 (Join-Path $here "expected_findings.json") | ConvertFrom-Json
& $Bin self-test; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Bin keys show (Join-Path $here "dkim-keys.txt"); if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# The options of expected_findings.json ("args"): the sample public keys and "our" organisation's domain.
# Expected exit code 3: the sample set contains tampered messages (high findings); 0-3 are completed runs.
& $Bin analyze --input (Join-Path $here "evidence") --hash sha256,md5 --lang all --case DEMO-001 --actor "Sample" `
  --out $out --progress none --dkim-keys (Join-Path $here "dkim-keys.txt") --own-domain acme.example
if ($LASTEXITCODE -ne $expected.exit_code) {
  Write-Host "MISMATCH: analyze exited with $LASTEXITCODE, expected_findings.json says $($expected.exit_code)"
  exit 3
}
$run = Get-ChildItem (Join-Path $out "logs") | Sort-Object Name | Select-Object -Last 1
& $Bin verify-log $run.FullName; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$bad = 0
# Every item of statistics.json (findings, status) against expected_findings.json ("files", "status").
# mbox messages are <mbox>#<n>@<offset> in the report and <mbox>#<n> in the expectations.
$stats = Get-Content -Raw -Encoding UTF8 (Join-Path $out "reports\$($run.Name)\statistics.json") | ConvertFrom-Json
$names = @($expected.status.PSObject.Properties.Name)
if (@($stats.items).Count -ne $names.Count) {
  Write-Host "MISMATCH: the run has $(@($stats.items).Count) items, expected_findings.json lists $($names.Count)"
  $bad = 1
}
foreach ($item in $stats.items) {
  $name = (Split-Path -Leaf $item.path) -replace '@\d+$', ''
  if ($names -notcontains $name) { Write-Host "MISMATCH: $name is not in expected_findings.json"; $bad = 1; continue }
  $got = (@($item.findings) | Sort-Object -CaseSensitive) -join ' '
  $want = (@($expected.files.$name) | Sort-Object -CaseSensitive) -join ' '
  if ($got -cne $want -or $item.status -ne $expected.status.$name) {
    Write-Host "MISMATCH ${name}: tool [$got] $($item.status), expected [$want] $($expected.status.$name)"
    $bad = 1
  }
}
if (-not $bad) { Write-Host "findings and status match expected_findings.json ($($names.Count) items)" }
# Compare the tool's hash register (logs\<RUN-ID>\hashes.csv) with the independently computed
# expected_hashes.csv: same files, sizes, SHA-256 and MD5. Any difference fails the script (exit 3).
$hashes = Import-Csv (Join-Path $here "expected_hashes.csv")
# Messages of an mbox are listed after it as <mbox>#<n>@<offset> (parts of a file, not files): skipped here.
$register = Import-Csv (Join-Path $run.FullName "hashes.csv") | Where-Object { $_.path -notmatch '#\d+@\d+$' }
if ($register.Count -ne $hashes.Count) {
  Write-Host "MISMATCH: the tool hashed $($register.Count) files, expected_hashes.csv lists $($hashes.Count)"
  $bad = 1
}
foreach ($row in $hashes) {
  $got = $register | Where-Object { (Split-Path -Leaf $_.path) -eq $row.file }
  if ($null -eq $got -or @($got).Count -ne 1) { Write-Host "MISMATCH: $($row.file) not in hashes.csv"; $bad = 1; continue }
  if ($got.size -ne $row.size -or $got.sha256 -ne $row.sha256 -or $got.md5 -ne $row.md5) {
    Write-Host "MISMATCH $($row.file): tool $($got.size),$($got.sha256),$($got.md5), expected $($row.size),$($row.sha256),$($row.md5)"
    $bad = 1
  }
}
if ($bad) { exit 3 }
Write-Host "hashes.csv matches expected_hashes.csv ($($hashes.Count) files: size, SHA-256, MD5)"
Write-Host "Reports: $out\reports\$($run.Name)\statistics.en.html"
