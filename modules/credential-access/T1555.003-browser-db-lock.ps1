# Module: T1555.003-browser-db-lock
# Technique: T1555.003
# Description: Detect non-browser processes holding locks on browser credential DBs (Windows)
# Uses handle.exe when available and can auto-download the official Sysinternals build when missing
param([ValidateSet('text','json')][string]$Format = $(if ($env:OUTPUT_FORMAT) { $env:OUTPUT_FORMAT } else { 'text' }))

$Technique = 'T1555.003'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$handleTimeoutSeconds = 5

function Emit($items) {
  if ($Format -eq 'json') { $items | ConvertTo-Json -Depth 4 -Compress; return }
  foreach ($i in @($items)) {
    Write-Host "[$($i.severity.ToUpper())] $($i.title)"
    if ($i.process) { Write-Host "Process: $($i.process) (PID: $($i.pid))" }
    if ($i.file) { Write-Host "File: $($i.file)" }
    if ($i.remediation) { Write-Host "Remediation: $($i.remediation)" }
  }
}

function Resolve-HandleExecutable {
  $expectedHash = 'EXPECTED_SHA256_HASH_HERE' # Update with the real Sysinternals Handle SHA256 before enabling auto-download.
  $candidate = @('handle64.exe', 'handle.exe') | ForEach-Object {
    $local = Join-Path $scriptDir $_
    if (Test-Path $local) {
      $local
    } else {
      (Get-Command $_ -ErrorAction SilentlyContinue).Source
    }
  } | Select-Object -First 1

  if ($candidate) { return $candidate }
  if ($env:INFOSTEALER_CHECK_DISABLE_HANDLE_DOWNLOAD -eq '1') { return $null }

  $toolRoot = Join-Path $env:LOCALAPPDATA 'infostealer-check\tools\handle'
  $tempZipPath = Join-Path $env:TEMP ("handle-{0}.zip" -f ([guid]::NewGuid().ToString('N')))
  $preferredPaths = @(
    (Join-Path $toolRoot 'handle64.exe'),
    (Join-Path $toolRoot 'handle.exe')
  )

  foreach ($path in $preferredPaths) {
    if (Test-Path $path) { return $path }
  }

  try {
    New-Item -ItemType Directory -Path $toolRoot -Force | Out-Null
    Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Handle.zip' -OutFile $tempZipPath -UseBasicParsing
    Expand-Archive -Path $tempZipPath -DestinationPath $toolRoot -Force
  } catch {
    return $null
  } finally {
    Remove-Item $tempZipPath -Force -ErrorAction SilentlyContinue
  }

  foreach ($path in $preferredPaths) {
    if (Test-Path $path) {
      $handlePath = $path
      # Verify the downloaded executable to reduce supply chain risk before we trust and execute it.
      $actualHash = (Get-FileHash -Path $handlePath -Algorithm SHA256).Hash
      if ($actualHash -ne $expectedHash) {
        Remove-Item $handlePath -Force -ErrorAction SilentlyContinue
        throw "Downloaded Handle executable failed SHA256 verification. Update `$expectedHash with the real Sysinternals hash before enabling auto-download."
      }

      return $handlePath
    }
  }

  return $null
}

function Invoke-HandleQuery($HandlePath, $TargetPath) {
  $stdout = Join-Path $env:TEMP ("handle-{0}.out" -f ([guid]::NewGuid().ToString('N')))
  $stderr = Join-Path $env:TEMP ("handle-{0}.err" -f ([guid]::NewGuid().ToString('N')))

  try {
    $argLine = "-accepteula -nobanner `"$TargetPath`""
    $proc = Start-Process -FilePath $HandlePath -ArgumentList $argLine -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
    if (-not (Wait-Process -Id $proc.Id -Timeout $handleTimeoutSeconds -ErrorAction SilentlyContinue)) {
      Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
      return @()
    }

    if (Test-Path $stdout) {
      return @(Get-Content $stdout -ErrorAction SilentlyContinue)
    }

    return @()
  } finally {
    Remove-Item $stdout, $stderr -Force -ErrorAction SilentlyContinue
  }
}

$handleExe = Resolve-HandleExecutable
if (-not $handleExe) {
  $skip = [pscustomobject]@{
    technique_id = $Technique
    title = 'Browser DB lock check unavailable'
    severity = 'info'
    file = ''
    process = ''
    pid = ''
    remediation = 'Allow download of Sysinternals Handle or place handle64.exe beside the script'
  }
  Emit $skip
  return
}

$allow = @('chrome.exe', 'firefox.exe', 'msedge.exe', 'brave.exe', 'opera.exe')
$targets = @(
  "$env:LOCALAPPDATA\Google\Chrome\User Data\*\Login Data", "$env:LOCALAPPDATA\Google\Chrome\User Data\*\Cookies",
  "$env:APPDATA\Mozilla\Firefox\Profiles\*\logins.json", "$env:APPDATA\Mozilla\Firefox\Profiles\*\cookies.sqlite", "$env:APPDATA\Mozilla\Firefox\Profiles\*\key4.db",
  "$env:LOCALAPPDATA\Microsoft\Edge\User Data\*\Login Data", "$env:LOCALAPPDATA\Microsoft\Edge\User Data\*\Cookies",
  "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\*\Login Data", "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\*\Cookies"
)

$findings = @()
foreach ($pattern in $targets) {
  Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue | ForEach-Object {
    $dbFile = $_.FullName
    $results = Invoke-HandleQuery -HandlePath $handleExe -TargetPath $dbFile
    foreach ($line in @($results)) {
      # Example: stealer.exe pid: 1234 type: File 1C4: C:\...\Login Data
      if ($line -match '^(?<process>\S+)\s+pid:\s+(?<procId>\d+)\s+type:\s+\S+\s+\S+:\s+(?<path>.+)$' -and $allow -notcontains $matches.process.ToLower()) {
        $findings += [pscustomobject]@{
          technique_id = $Technique
          title = 'Non-browser process accessing credential DB'
          severity = 'critical'
          process = $matches.process
          pid = $matches.procId
          file = $matches.path
          remediation = 'Investigate process, check VirusTotal, terminate if suspicious'
        }
      }
    }
  }
}

$findings = @($findings | Sort-Object process, pid, file -Unique)

if ($findings.Count) {
  Emit $findings
} else {
  Emit ([pscustomobject]@{
    technique_id = $Technique
    title = 'No suspicious credential DB access found'
    severity = 'info'
    process = ''
    pid = ''
    file = ''
    remediation = ''
  })
}
