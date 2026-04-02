param(
    [int]$Iterations = 3,
    [int]$MaxMilliseconds = 3000
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $repoRoot 'modules\credential-access\T1555.003-browser-db-lock.ps1'

if (-not (Test-Path $modulePath)) {
    throw "Module not found: $modulePath"
}

$tempRoot = Join-Path $env:TEMP ("isc-t1555-bench-" + [guid]::NewGuid().ToString("N"))
$null = New-Item -ItemType Directory -Path $tempRoot -Force

$originalLocalAppData = $env:LOCALAPPDATA
$originalAppData = $env:APPDATA
$originalPath = $env:PATH
$originalDisableDownload = $env:INFOSTEALER_CHECK_DISABLE_HANDLE_DOWNLOAD

try {
    $localAppData = Join-Path $tempRoot 'LocalAppData'
    $appData = Join-Path $tempRoot 'AppData'
    $mockBin = Join-Path $tempRoot 'mockbin'

    $null = New-Item -ItemType Directory -Path $localAppData, $appData, $mockBin -Force

    $targets = @(
        "$localAppData\Google\Chrome\User Data\Default\Login Data",
        "$localAppData\Google\Chrome\User Data\Profile 1\Cookies",
        "$localAppData\Microsoft\Edge\User Data\Default\Login Data",
        "$localAppData\BraveSoftware\Brave-Browser\User Data\Default\Cookies",
        "$appData\Mozilla\Firefox\Profiles\abcd.default-release\logins.json",
        "$appData\Mozilla\Firefox\Profiles\abcd.default-release\cookies.sqlite",
        "$appData\Mozilla\Firefox\Profiles\abcd.default-release\key4.db"
    )

    foreach ($target in $targets) {
        $parent = Split-Path -Parent $target
        $null = New-Item -ItemType Directory -Path $parent -Force
        Set-Content -Path $target -Value 'test' -NoNewline
    }

    # Reuse a harmless Microsoft binary as a fast no-op stand-in for handle.exe.
    $handlePath = Join-Path $mockBin 'handle64.exe'
    Copy-Item "$env:SystemRoot\System32\where.exe" $handlePath -Force

    $env:LOCALAPPDATA = $localAppData
    $env:APPDATA = $appData
    $env:PATH = "$mockBin;$originalPath"
    $env:INFOSTEALER_CHECK_DISABLE_HANDLE_DOWNLOAD = '1'

    $samples = @()
    for ($i = 1; $i -le $Iterations; $i++) {
        $elapsed = Measure-Command {
            $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $modulePath -Format text 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "Module exited with code $LASTEXITCODE"
            }
            if (-not ($output -join "`n" | Select-String -SimpleMatch 'No suspicious credential DB access found')) {
                throw "Unexpected module output: $($output -join '; ')"
            }
        }
        $samples += [math]::Round($elapsed.TotalMilliseconds, 2)
    }

    $average = [math]::Round((($samples | Measure-Object -Average).Average), 2)
    $maximum = [math]::Round((($samples | Measure-Object -Maximum).Maximum), 2)

    [pscustomobject]@{
        iterations = $Iterations
        files_scanned = $targets.Count
        samples_ms = $samples
        average_ms = $average
        max_ms = $maximum
        threshold_ms = $MaxMilliseconds
        within_threshold = ($maximum -le $MaxMilliseconds)
    } | ConvertTo-Json -Depth 4

    if ($maximum -gt $MaxMilliseconds) {
        exit 1
    }
} finally {
    $env:LOCALAPPDATA = $originalLocalAppData
    $env:APPDATA = $originalAppData
    $env:PATH = $originalPath
    $env:INFOSTEALER_CHECK_DISABLE_HANDLE_DOWNLOAD = $originalDisableDownload
    Remove-Item -Recurse -Force $tempRoot -ErrorAction SilentlyContinue
}
