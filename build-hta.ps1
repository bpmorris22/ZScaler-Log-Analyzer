# build-hta.ps1 - splice ZScaler-Engine.ps1 into ZScaler-Log-Analyzer.src.hta -> ZScaler-Log-Analyzer.hta
# Guards: the engine must not contain a closing script tag (it is embedded raw in a text/plain script block),
# both inputs must be pure ASCII (no em dashes or other non-ASCII), and the placeholder must appear exactly once.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = [IO.File]::ReadAllText((Join-Path $here 'ZScaler-Log-Analyzer.src.hta'))
$eng = [IO.File]::ReadAllText((Join-Path $here 'ZScaler-Engine.ps1'))
if ($eng -match '(?i)</script') { throw 'engine contains a closing script tag' }
foreach ($pair in @(@('src', $src), @('engine', $eng))) {
  $bad = [regex]::Matches($pair[1], '[^\x00-\x7F]')
  if ($bad.Count) { throw ("{0} has {1} non-ASCII char(s), first U+{2:X4}" -f $pair[0], $bad.Count, [int][char]$bad[0].Value) }
}
$ph = '@@ENGINE_PAYLOAD@@'
$n = ([regex]::Matches($src, [regex]::Escape($ph))).Count
if ($n -ne 1) { throw "placeholder count $n (expected 1)" }
$out = $src.Replace($ph, "`r`n" + ($eng -replace "`r?`n", "`r`n"))
$dst = Join-Path $here 'ZScaler-Log-Analyzer.hta'
[IO.File]::WriteAllText($dst, $out, (New-Object Text.UTF8Encoding($false)))
"built $dst ($((Get-Item $dst).Length) bytes)"
