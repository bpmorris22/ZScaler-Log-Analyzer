# run-tests.ps1 - regression fixtures for ZScaler-Engine.ps1 and the viewer's pure functions.
# Builds small synthetic CSVs under %TEMP%, runs the engine on each and asserts on the run JSON. Synthetic data only
# (documentation IP ranges, example.test users) - never point this at evidence. Run with Windows PowerShell 5.1:
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\run-tests.ps1
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$engine = Join-Path (Split-Path -Parent $here) 'ZScaler-Engine.ps1'
$work = Join-Path $env:TEMP ('zsl-tests-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force $work | Out-Null
$script:fail = 0; $script:pass = 0

$HDR = 'No.,Event Time,User,URL,Policy Action,URL Category,Threat Name,Department'
function Row($n, $time, $user, $url, $action = 'Allowed', $cat = 'Miscellaneous or Unknown') { "$n,""$time"",$user,$url,$action,$cat,None,Dept" }
function Fixture($name, [string[]]$rows, [string]$hdr = $HDR) {
  $d = Join-Path $work $name; New-Item -ItemType Directory -Force "$d\in" | Out-Null
  [IO.File]::WriteAllText("$d\in\input.csv", (@('Administrator,tester@example.test', $hdr) + $rows) -join "`r`n", (New-Object Text.UTF8Encoding($true)))
  return $d
}
function RunEngine($d, $tz = '', $inputPath = '') {
  if (-not $inputPath) { $inputPath = "$d\in" }
  Remove-Item "$d\out" -Recurse -Force -ErrorAction SilentlyContinue
  $args2 = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $engine, '-InputPath', $inputPath, '-OutDir', "$d\out", '-TargetHost', 'TEST', '-Stamp', '20000101_000000')
  if ($tz) { $args2 += @("-TzOverride:$tz") }   # colon binding, exactly as the HTA passes it (a "-07:00" value must not read as a parameter)
  $ErrorActionPreference = 'Continue'
  $log = & powershell.exe @args2 2>&1 | Out-String
  $ErrorActionPreference = 'Stop'
  $j = Get-ChildItem "$d\out" -Filter '*-ZScaler-*.json' -ErrorAction SilentlyContinue | Select-Object -First 1
  return @{ log = $log; json = $(if ($j) { Get-Content $j.FullName -Raw | ConvertFrom-Json } else { $null }) }
}
function Col($run, $table, $col) {
  $t = $run.json.tables.$table; $i = [array]::IndexOf([string[]]$t.cols, $col)
  return @($t.rows | ForEach-Object { $_[$i] })
}
function Check($name, $cond, $detail = '') {
  if ($cond) { $script:pass++; Write-Output "PASS  $name" } else { $script:fail++; Write-Output "FAIL  $name  $detail" }
}
function Minutes($start, $i) { ([datetime]$start).AddMinutes($i).ToString('MMMM d, yyyy h:mm:ss tt', [Globalization.CultureInfo]::InvariantCulture) + ' UTC' }

# 1. beacon timing keeps the first burst (int.MinValue overflow)
$d = Fixture 'beacon-eight' (0..7 | ForEach-Object { Row ($_ + 1) (Minutes '2026-10-20 10:00:00' $_) 'alice@example.test' '203.0.113.10/ping' })
$r = RunEngine $d
Check 'eight one-minute requests -> one beacon row with 8 bursts' ((Col $r 'beacons' 'Bursts') -contains 8) ($r.log)
Check 'beacon First_UTC is the earliest request' ((Col $r 'beacons' 'First_UTC') -contains '2026-10-20 10:00:00')
$d = Fixture 'beacon-twenty' (0..19 | ForEach-Object { Row ($_ + 1) (Minutes '2026-10-20 10:00:00' $_) 'alice@example.test' '203.0.113.11/ping' })
$r = RunEngine $d
Check 'twenty periodic requests -> 20 bursts, 100% regular' (((Col $r 'beacons' 'Bursts') -contains 20) -and ((Col $r 'beacons' 'RegularPct') -contains 100))

# 2. C2 paths are detected on every record, whatever their position or length
$benign = 1..6 | ForEach-Object { Row $_ (Minutes '2026-10-20 10:00:00' $_) 'alice@example.test' "203.0.113.20/benign$_" }
$r = RunEngine (Fixture 'seventh-path' ($benign + (Row 7 (Minutes '2026-10-20 10:00:00' 7) 'alice@example.test' '203.0.113.20/cmd/')))
Check 'C2 path after six benign paths is counted' ((Col $r 'hosts' 'C2PathHits') -contains 1)
Check 'C2Paths cites the record' ((Col $r 'hosts' 'C2Paths') -match '#row=9')
$r = RunEngine (Fixture 'first-path' (@(Row 1 (Minutes '2026-10-20 10:00:00' 0) 'alice@example.test' '203.0.113.20/cmd/') + $benign))
Check 'C2 path before six benign paths is counted' ((Col $r 'hosts' 'C2PathHits') -contains 1)
$r = RunEngine (Fixture 'long-path' @(Row 1 (Minutes '2026-10-20 10:00:00' 0) 'alice@example.test' ('203.0.113.21/' + ('a' * 300) + '/cmd/x')))
Check 'C2 path beyond the display truncation is counted' ((Col $r 'hosts' 'C2PathHits') -contains 1)

# 3. timezone policy applies to the fallback parser too
$r = RunEngine (Fixture 'zone-free-fallback' @(Row 1 '2026/10/20 10:00:00' 'alice@example.test' 'example.test/'))
Check 'zone-free fallback value stops the run' ($r.log -match 'ENGINE_FAIL.*timezone') ($r.log)
$r = RunEngine (Fixture 'zone-free-fallback-override' @(Row 1 '2026/10/20 10:00:00' 'alice@example.test' 'example.test/')) '+10:00'
Check 'zone-free fallback with override +10:00 -> 00:00 UTC' ($r.json.first -eq '2026-10-20 00:00:00') ($r.json.first)
$r = RunEngine (Fixture 'iso-override' @(Row 1 '2026-10-20T10:00:00Z' 'alice@example.test' 'example.test/')) '+10:00'
Check 'ISO Z value with override +10:00 -> 00:00 UTC (override wins)' ($r.json.first -eq '2026-10-20 00:00:00') ($r.json.first)
$r = RunEngine (Fixture 'iso-zoned' @(Row 1 '2026-10-20T10:00:00+10:00' 'alice@example.test' 'example.test/'))
Check 'ISO +10:00 value without override -> 00:00 UTC' ($r.json.first -eq '2026-10-20 00:00:00') ($r.json.first)
$r = RunEngine (Fixture 'iso-z' @(Row 1 '2026-10-20T10:00:00Z' 'alice@example.test' 'example.test/'))
Check 'ISO Z value without override -> 10:00 UTC' ($r.json.first -eq '2026-10-20 10:00:00') ($r.json.first)

# 5. offset sign applies to the whole value
foreach ($c in @(@('-00:30', '2026-10-20 10:30:00'), @('+00:30', '2026-10-20 09:30:00'), @('-07:00', '2026-10-20 17:00:00'), @('+05:30', '2026-10-20 04:30:00'))) {
  $r = RunEngine (Fixture ('offset' + $c[0].Replace(':', '')) @(Row 1 'October 20, 2026 10:00:00 AM PDT' 'alice@example.test' 'example.test/')) $c[0]
  Check "override $($c[0]) -> $($c[1])" ($r.json.first -eq $c[1]) ($r.json.first)
}
$r = RunEngine (Fixture 'record-offset' @(Row 1 '2026-10-20 10:00:00 -00:30' 'alice@example.test' 'example.test/'))
Check 'per-record -00:30 -> 10:30 UTC' ($r.json.first -eq '2026-10-20 10:30:00') ($r.json.first)

# 4. truncated / outcome-less records
$r = RunEngine (Fixture 'truncated-row' @('1,"October 20, 2026 10:00:00 AM UTC",alice@example.test,example.test/', (Row 2 'October 20, 2026 10:01:00 AM UTC' 'bob@example.test' 'example.test/')))
Check 'truncated record counted as incomplete' ($r.json.incomplete -eq 1) ($r.json.incomplete)
Check 'truncated record not counted as allowed' ($r.json.stats.allowed -eq 1) ("allowed=" + $r.json.stats.allowed)
Check 'files note cites the incomplete line' ((Col $r 'files' 'Note') -match 'line\(s\) 3') ((Col $r 'files' 'Note'))
$r = RunEngine (Fixture 'empty-action' @(Row 1 'October 20, 2026 10:00:00 AM UTC' 'alice@example.test' 'example.test/' ''))
Check 'empty Policy Action -> unknown outcome, not allowed' (($r.json.stats.unknownOutcome -eq 1) -and ($r.json.stats.allowed -eq 0)) ("unknown=" + $r.json.stats.unknownOutcome + " allowed=" + $r.json.stats.allowed)

$r = RunEngine (Fixture 'unknown-threat' @('1,"October 20, 2026 10:00:00 AM UTC",alice@example.test,remote.example.test/health,,Remote Access,Test.Threat,Dept'))
Check 'named threat with no action -> unknown, not blocked' (($r.json.stats.unknownOutcome -eq 1) -and ($r.json.stats.blocked -eq 0) -and ($r.json.stats.allowed -eq 0))
Check 'unknown threat still listed as a security event' ((Col $r 'security_events' 'ThreatName') -contains 'Test.Threat')

# user -> host membership is complete
$r = RunEngine (Fixture 'user-hosts' (1..9 | ForEach-Object { Row $_ (Minutes '2026-10-20 10:00:00' $_) ("u$_@example.test") '203.0.113.30/' }))
Check 'user_hosts lists every user of a host' (@(Col $r 'user_hosts' 'User').Count -eq 9)

# multi-file input: each file read once however it is reached; SourceFile unique and independent of how files were selected
$m = Join-Path $work 'multi-roots'; New-Item -ItemType Directory -Force "$m\in\tenant-a", "$m\in\tenant-b" | Out-Null
$enc = New-Object Text.UTF8Encoding($true)
[IO.File]::WriteAllText("$m\in\tenant-a\input.csv", (@($HDR, '1,"October 20, 2026 10:00:00 AM UTC",alpha@example.test,alpha.example.test/,Allowed,Business,Threat.Alpha,Dept') -join "`r`n"), $enc)
[IO.File]::WriteAllText("$m\in\tenant-b\input.csv", (@($HDR, '1,"October 20, 2026 10:00:00 AM UTC",beta@example.test,beta.example.test/,Malicious file Blocked,Business,Threat.Beta,Dept') -join "`r`n"), $enc)
$fa = "$m\in\tenant-a\input.csv"; $fb = "$m\in\tenant-b\input.csv"
$ctl = RunEngine $m '' "$m\in"
Check 'multi-root control: 2 files, 2 records, 1 allowed, 1 blocked' (($ctl.json.parsed -eq 2) -and ($ctl.json.filesRead -eq 2) -and ($ctl.json.stats.allowed -eq 1) -and ($ctl.json.stats.blocked -eq 1)) ($ctl.log)
$ctlSrc = (Col $ctl 'security_events' 'SourceFile' | Sort-Object) -join '|'
$r = RunEngine $m '' "$m\in|$m\in\tenant-a"
Check 'parent + child folder: totals equal the unique-file control' (($r.json.parsed -eq 2) -and ($r.json.filesRead -eq 2) -and ($r.json.stats.allowed -eq 1) -and ($r.json.stats.security -eq 2) -and ($r.json.duplicateInputs -eq 1)) ("parsed=" + $r.json.parsed + " files=" + $r.json.filesRead + " dup=" + $r.json.duplicateInputs)
$r = RunEngine $m '' "$m\in|$fa"
Check 'folder + one of its files: read once' (($r.json.parsed -eq 2) -and ($r.json.duplicateInputs -eq 1))
$r = RunEngine $m '' "$fa|$fa"
Check 'same file twice: read once' (($r.json.parsed -eq 1) -and ($r.json.filesRead -eq 1))
$short = (New-Object -ComObject Scripting.FileSystemObject).GetFile($fa).ShortPath
$r = RunEngine $m '' ("$fa|$m\in\tenant-b\..\tenant-a\INPUT.CSV|" + $short)
Check 'aliases (.., case, 8.3 short name) of one file: read once' (($r.json.parsed -eq 1) -and ($r.json.duplicateInputs -eq 2)) ("parsed=" + $r.json.parsed + " dup=" + $r.json.duplicateInputs + " short=" + $short)
$r = RunEngine $m '' "$m\in\tenant-a|$m\in\tenant-b"
$src = @(Col $r 'security_events' 'SourceFile' | Sort-Object)
Check 'separate roots: same-named files get distinct SourceFile ids' (($src.Count -eq 2) -and ($src[0] -ne $src[1])) ($src -join ' / ')
Check 'separate roots: ids equal the common-root selection' (($src -join '|') -eq $ctlSrc) (($src -join '|') + ' vs ' + $ctlSrc)
$r = RunEngine $m '' "$fa|$fb"
Check 'explicit files: ids equal the common-root selection' (((Col $r 'security_events' 'SourceFile' | Sort-Object) -join '|') -eq $ctlSrc)
$single = RunEngine $m '' $fa
Check 'single file: SourceFile is its name' ((Col $single 'security_events' 'SourceFile') -contains 'input.csv')

# 6. viewer: exact identity matching (needs node.js; the functions are extracted from the source unchanged)
$node = Get-Command node -ErrorAction SilentlyContinue
if ($node) {
  $out = & node (Join-Path $here 'viewer-tests.js') (Join-Path (Split-Path -Parent $here) 'ZScaler-Log-Analyzer.src.hta') 2>&1 | Out-String
  foreach ($l in ($out -split "`r?`n")) { if ($l -match '^PASS') { $script:pass++; Write-Output $l } elseif ($l -match '^FAIL') { $script:fail++; Write-Output $l } elseif ($l.Trim()) { Write-Output "      $l" } }
} else { Write-Output 'SKIP  viewer tests (node.js not found)' }

Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Output ''
Write-Output "$($script:pass) passed, $($script:fail) failed"
if ($script:fail) { exit 1 }
