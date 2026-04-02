# Module: T1555.003-browser-db-lock
# Technique: T1555.003
# Description: Detect non-browser processes holding locks on browser credential DBs (Windows)
# Requires: handle.exe (Sysinternals) in PATH or same directory
param([ValidateSet('text','json')][string]$Format = $(if ($env:OUTPUT_FORMAT) { $env:OUTPUT_FORMAT } else { 'text' }))

$Technique = 'T1555.003'
function Emit($items) {
  if ($Format -eq 'json') { $items | ConvertTo-Json -Depth 4 -Compress; return }
  foreach ($i in @($items)) {
    Write-Host "[$($i.severity.ToUpper())] $($i.title)"
    if ($i.process) { Write-Host "Process: $($i.process) (PID: $($i.pid))" }
    if ($i.file) { Write-Host "File: $($i.file)" }
    if ($i.remediation) { Write-Host "Remediation: $($i.remediation)" }
  }
}

# Prefer a local Sysinternals binary, then PATH.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$handleExe = @('handle64.exe','handle.exe') | ForEach-Object {
  $local = Join-Path $scriptDir $_
  if (Test-Path $local) { $local } else { (Get-Command $_ -ErrorAction SilentlyContinue).Source }
} | Select-Object -First 1

if (-not $handleExe) {
  $skip = [pscustomobject]@{ technique_id=$Technique; title='handle.exe not found; check skipped'; severity='info'; file=''; process=''; pid=''; remediation='Install Sysinternals handle.exe or place it beside the script' }
  if ($Format -eq 'json') { Emit $skip } else { Write-Warning 'handle.exe/handle64.exe not found in PATH or script directory; skipping browser DB lock check.' }
  return
}

$allow = @('chrome.exe','firefox.exe','msedge.exe','brave.exe','opera.exe')
$targets = @(
  "$env:LOCALAPPDATA\Google\Chrome\User Data\*\Login Data", "$env:LOCALAPPDATA\Google\Chrome\User Data\*\Cookies", "$env:LOCALAPPDATA\Google\Chrome\User Data\*\Web Data", "$env:LOCALAPPDATA\Google\Chrome\User Data\*\History",
  "$env:APPDATA\Mozilla\Firefox\Profiles\*\logins.json", "$env:APPDATA\Mozilla\Firefox\Profiles\*\cookies.sqlite", "$env:APPDATA\Mozilla\Firefox\Profiles\*\key4.db",
  "$env:LOCALAPPDATA\Microsoft\Edge\User Data\*\Login Data", "$env:LOCALAPPDATA\Microsoft\Edge\User Data\*\Cookies", "$env:LOCALAPPDATA\Microsoft\Edge\User Data\*\Web Data", "$env:LOCALAPPDATA\Microsoft\Edge\User Data\*\History",
  "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\*\Login Data", "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\*\Cookies", "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\*\Web Data", "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\*\History"
)

$findings = @()
foreach ($pattern in $targets) {
  Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue | ForEach-Object {
    $dbFile = $_.FullName
    $results = & $handleExe -accepteula -nobanner "$dbFile" 2>$null
    foreach ($line in @($results)) {
      # Example: stealer.exe pid: 1234 type: File 1C4: C:\...\Login Data
      if ($line -match '^(?<process>\S+)\s+pid:\s+(?<pid>\d+)\s+type:\s+\S+\s+\S+:\s+(?<path>.+)$' -and $allow -notcontains $matches.process.ToLower()) {
        $findings += [pscustomobject]@{
          technique_id = $Technique
          title = 'Non-browser process accessing credential DB'
          severity = 'critical'
          process = $matches.process
          pid = $matches.pid
          file = $matches.path
          remediation = 'Investigate process, check VirusTotal, terminate if suspicious'
        }
      }
    }
  }
}

if ($findings.Count) { Emit $findings }
else {
  Emit ([pscustomobject]@{ technique_id=$Technique; title='No suspicious credential DB access found'; severity='info'; process=''; pid=''; file=''; remediation='' })
}
