# capture-shots.ps1 - screenshots of the built HTA on the synthetic ACME-RETAIL sample, for the manual.
# Copies the HTA + sample to a clean path (C:\DFIR\zsl), patches a capture hook into the JScript block (after
# window.onload - never into the engine payload), launches mshta "<sample>" /auto per shot, waits for the results, runs
# the shot's script (view, sub-tab, filters, selected row, scroll), and grabs the window (DWM bounds + CopyFromScreen).
# Kills only the mshta it started. Synthetic data only: run manual\make-synthetic.py first.
param([string]$Only = '')
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;using System.Text;using System.Runtime.InteropServices;
public class ZsCap{
 [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
 [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
 [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h,int c);
 [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h,IntPtr after,int x,int y,int w,int ht,uint flags);
 [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr h,int a,out RECT r,int s);
 [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h,out RECT r);
 [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
 [DllImport("user32.dll")] public static extern int GetWindowTextLength(IntPtr h);
 public delegate bool EnumProc(IntPtr h, IntPtr l);
 [StructLayout(LayoutKind.Sequential)] public struct RECT{public int Left,Top,Right,Bottom;}
 static IntPtr _found; static uint _pid;
 static bool Cb(IntPtr h, IntPtr l){ uint pid; GetWindowThreadProcessId(h, out pid);
   if(pid==_pid && IsWindowVisible(h) && GetWindowTextLength(h)>0){ _found=h; return false; } return true; }
 public static IntPtr FindForPid(uint pid){ _found=IntPtr.Zero; _pid=pid; EnumWindows(new EnumProc(Cb), IntPtr.Zero); return _found; }
}
'@
[ZsCap]::SetProcessDPIAware() | Out-Null
$man = Split-Path -Parent $MyInvocation.MyCommand.Path
$app = Split-Path -Parent $man
$cap = 'C:\DFIR\zsl'
$shots = Join-Path $man 'images'
foreach ($d in @($cap, $shots)) { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force $d | Out-Null } }
$logs = Join-Path $cap 'ACME-RETAIL'
if (Test-Path $logs) { Remove-Item -Recurse -Force $logs }
Copy-Item -Recurse (Join-Path $man 'sample\ACME-RETAIL') $logs
if (Test-Path (Join-Path $cap '_Processed')) { Remove-Item -Recurse -Force (Join-Path $cap '_Processed') }
Set-Content -LiteralPath (Join-Path $cap 'IOC.txt') -Value @('# case IOCs', '203.0.113.77', 'files-transfer.example') -Encoding ascii
Remove-Item (Join-Path $cap 'ZScaler-Log-Analyzer.settings.json') -ErrorAction SilentlyContinue
$src = [IO.File]::ReadAllText((Join-Path $app 'ZScaler-Log-Analyzer.hta'))
$anchor = 'window.onload=function(){ init(); };'
if (([regex]::Matches($src, [regex]::Escape($anchor))).Count -ne 1) { throw 'capture anchor not found exactly once' }

# JS helpers available to every shot: pick(table, col, value) selects that row in the detail pane; card(n) scrolls an
# Activity card to the top; panel(false) hides the control panel
$helpers = @'
function pick(col, val){ var t=curTable(); if(!t) return; var i0=t.ix[col]; for(var i=0;i<t.rows.length;i++){ if(String(t.rows[i][i0])===val){ renderDetail(i);
  var trs=document.getElementById('tbl').getElementsByTagName('tr'); for(var z=0;z<trs.length;z++){ if(trs[z].getAttribute('data-i')===String(i)){ trs[z].className=(trs[z].className+' sel'); var sc=document.getElementById('tblScroll'); sc.scrollTop=Math.max(0, trs[z].offsetTop-80); sc.scrollLeft=0; applyFreeze(); } } flat(); return; } } }
function flat(){ try{ window.scrollTo(0,0); document.documentElement.scrollLeft=0; document.body.scrollLeft=0; var sc=document.getElementById('tblScroll'); if(sc) sc.scrollLeft=0; }catch(e){} }
function card(n){ var c=document.getElementById('actPanels').children; if(c[n]) c[n].scrollIntoView(true); }
function biz(m){ BIZOFF=m; try{ document.getElementById('bizTz').value=String(m); }catch(e){} updateOffBtn(); }
function panel(show){ document.getElementById('ctlCard').style.display=show?'':'none'; }
'@
$S = @(
  @{ n='ov';           js="panel(true); setViewTab('ov');" },
  @{ n='ov-full';      js="panel(false); setViewTab('ov');" },
  @{ n='coverage';     js="panel(false); setViewTab('ov'); document.getElementById('coverage').scrollIntoView(true);" },
  @{ n='activity';     js="panel(false); biz(600); setViewTab('act');" },
  @{ n='heatmaps';   js="panel(false); biz(600); setViewTab('act'); card(7);" },
  @{ n='users';        js="panel(false); SUB='users'; setViewTab('usr'); pick('User','c.diaz@acme-retail.example');" },
  @{ n='hosts_c2';     js="panel(false); SUB='hosts_c2'; setViewTab('dst'); pick('Host','203.0.113.77');" },
  @{ n='beacons';      js="panel(false); SUB='beacons'; SORTS.beacons={k:-2,dir:-1}; setViewTab('bcn'); pick('User','d.patel@acme-retail.example');" },
  @{ n='channels';     js="panel(false); SUB='channels'; setSev('flag'); setViewTab('chn'); flat();" },
  @{ n='security';     js="panel(false); SUB='security_events'; setViewTab('sec'); pick('ThreatName','HTML.Suspicious.Redirect');" },
  @{ n='userfilter';   js="panel(false); setUserFilter('k.berg@acme-retail.example'); HIDEINFRA=true; SUB='hosts'; setViewTab('dst'); flat();" },
  @{ n='pivot';        js="panel(false); setPivot('203.0.113.77'); setViewTab('ov');" },
  @{ n='unscannable';  js="panel(false); SUB='unscannable'; setViewTab('fil'); pick('User','c.diaz@acme-retail.example');" },
  @{ n='files';        js="panel(false); SUB='files'; setViewTab('src'); pick('RowCap','yes - exactly 100,000 records');" },
  @{ n='ioc';          js="panel(false); SUB='ioc_terms'; setViewTab('ioc'); flat();" }
)
function Capture($shot) {
  $name = $shot.n
  $mark = Join-Path $cap ("ready_" + $name + ".marker"); if (Test-Path $mark) { Remove-Item $mark -Force }
  $markJs = $mark.Replace('\', '\\')
  $hook = @"
$helpers
window.setTimeout(function capReady(){
  try{ var res=document.getElementById('results');
    if(res && !/\bhide\b/.test(res.className+'') && DATA){
      try{ window.moveTo(0,0); window.resizeTo(1500,1010); }catch(e){}
      try{ var lg=document.getElementById('log'); if(lg){ lg.style.display='none'; } }catch(e){}
      try{ $($shot.js) }catch(e){ bootLog('CAPTURE JS ERROR ${name}: '+e.message); }
      window.setTimeout(function(){ try{ var fso=new ActiveXObject('Scripting.FileSystemObject'); var f=fso.CreateTextFile('$markJs',true); f.Write('ready'); f.Close(); }catch(e){} }, 1500);
      return;
    }
  }catch(e){}
  window.setTimeout(capReady, 400);
}, 1500);
"@
  $phta = Join-Path $cap 'ZScaler-Log-Analyzer.hta'
  [IO.File]::WriteAllText($phta, $src.Replace($anchor, $anchor + "`r`n" + $hook), (New-Object Text.UTF8Encoding($false)))
  $proc = Start-Process mshta.exe -ArgumentList ('"' + $phta + '"'), ('"' + $logs + '"'), '/auto' -PassThru
  $mpid = [uint32]$proc.Id; $ok = $false
  for ($i = 0; $i -lt 120; $i++) { Start-Sleep -Milliseconds 700; if (Test-Path $mark) { $ok = $true; break } }
  if (-not $ok) { Write-Output ("FAIL " + $name + ": no ready marker"); try { Stop-Process -Id $mpid -Force } catch {}; return }
  Start-Sleep -Milliseconds 500
  $h = [ZsCap]::FindForPid($mpid)
  if ($h -eq [IntPtr]::Zero) { Write-Output ("FAIL " + $name + ": no window"); try { Stop-Process -Id $mpid -Force } catch {}; return }
  [ZsCap]::ShowWindow($h, 9) | Out-Null
  [ZsCap]::SetWindowPos($h, [IntPtr]-1, 0, 0, 0, 0, (0x0001 -bor 0x0002 -bor 0x0040)) | Out-Null
  [ZsCap]::SetForegroundWindow($h) | Out-Null
  Start-Sleep -Milliseconds 900
  $r = New-Object ZsCap+RECT; $sz = [Runtime.InteropServices.Marshal]::SizeOf([type]([ZsCap+RECT]))
  if ([ZsCap]::DwmGetWindowAttribute($h, 9, [ref]$r, $sz) -ne 0) { [ZsCap]::GetWindowRect($h, [ref]$r) | Out-Null }
  $w = $r.Right - $r.Left; $ht = $r.Bottom - $r.Top
  $bmp = New-Object Drawing.Bitmap($w, $ht); $g = [Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($r.Left, $r.Top, 0, 0, (New-Object Drawing.Size($w, $ht))); $g.Dispose()
  $png = Join-Path $shots ($name + '.png'); $bmp.Save($png, [Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
  try { Stop-Process -Id $mpid -Force } catch {}
  Write-Output ("OK " + $name + ": ${w}x${ht}")
}
foreach ($shot in $S) { if (-not $Only -or $shot.n -eq $Only) { Capture $shot } }
$bl = Join-Path $cap 'ZScaler-Log-Analyzer.boot.log'
if (Test-Path $bl) { Get-Content $bl | Where-Object { $_ -match 'CAPTURE JS ERROR|ONERROR' } }
