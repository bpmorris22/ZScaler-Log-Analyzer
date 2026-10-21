# build-manual.ps1 - build docs\ZScaler-Log-Analyzer-Manual.html (in the publish repo) from manual-template.html,
# embedding every screenshot as a PNG data URI so the manual is one self-contained file.
# Screenshots in .\images are synthetic-data window captures from capture-shots.ps1 (sample from make-synthetic.py).
# Guards: every {{IMG:x}} placeholder filled, no placeholder left, pure ASCII output (no em / en dashes).
$ErrorActionPreference = 'Stop'
$app = Split-Path $PSScriptRoot -Parent
$html = [IO.File]::ReadAllText("$PSScriptRoot\manual-template.html")
$ver = ([regex]::Match([IO.File]::ReadAllText("$app\ZScaler-Log-Analyzer.src.hta"), 'var APP_VERSION = "([^"]+)"')).Groups[1].Value
$html = $html.Replace('@@APPVER@@', $ver).Replace('@@DATE@@', (Get-Date).ToString('yyyy-MM-dd'))
foreach ($m in [regex]::Matches($html, '\{\{IMG:([^}]+)\}\}')) {
  $k = $m.Groups[1].Value; $p = "$PSScriptRoot\images\$k.png"
  if (-not (Test-Path $p)) { throw "missing image for '$k': $p" }
  $html = $html.Replace($m.Value, 'data:image/png;base64,' + [Convert]::ToBase64String([IO.File]::ReadAllBytes($p)))
}
$left = [regex]::Matches($html, '\{\{IMG:[^}]+\}\}|@@[A-Z]+@@')
if ($left.Count) { throw ("unreplaced placeholders: " + (($left | ForEach-Object { $_.Value }) -join ', ')) }
$bad = [regex]::Matches($html, '[^\x00-\x7F]')
if ($bad.Count) { throw ("manual has {0} non-ASCII char(s), first U+{1:X4}" -f $bad.Count, [int][char]$bad[0].Value) }
# working copy: <app>\publish\docs ; inside the repo itself: <repo>\docs
$out = if (Test-Path "$app\publish\.git") { "$app\publish\docs\ZScaler-Log-Analyzer-Manual.html" } else { "$app\docs\ZScaler-Log-Analyzer-Manual.html" }
New-Item -ItemType Directory -Force (Split-Path $out) | Out-Null
[IO.File]::WriteAllText($out, $html, (New-Object Text.UTF8Encoding($false)))
"written {0} ({1:N2} MB, app v{2})" -f $out, ((Get-Item $out).Length / 1mb), $ver
