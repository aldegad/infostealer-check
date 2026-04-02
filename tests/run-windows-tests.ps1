$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[Console]::InputEncoding = $utf8NoBom
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom

$repoRoot = Split-Path -Parent $PSScriptRoot
$checkWindows = Join-Path $repoRoot 'check-windows.ps1'
$runner = Join-Path $repoRoot 'core\runner.ps1'
$bench = Join-Path $PSScriptRoot 'measure-T1555.003-browser-db-lock.ps1'
$powershellExe = (Get-Command powershell -ErrorAction Stop).Source

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Convert-JsonLine {
    param([string[]]$Lines)

    $startIndex = -1
    for ($i = 0; $i -lt @($Lines).Count; $i++) {
        $trimmed = @($Lines)[$i].Trim()
        if ($trimmed.StartsWith('{') -or $trimmed.StartsWith('[')) {
            $startIndex = $i
            break
        }
    }

    if ($startIndex -lt 0) {
        throw "Expected JSON output but received: $($Lines -join '; ')"
    }

    $jsonText = (@($Lines)[$startIndex..(@($Lines).Count - 1)] -join [Environment]::NewLine).Trim()
    return $jsonText | ConvertFrom-Json -ErrorAction Stop
}

function Invoke-PowerShellCapture {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$TempRoot
    )

    $stdoutPath = Join-Path $TempRoot ([guid]::NewGuid().ToString('N') + '.out')
    $stderrPath = Join-Path $TempRoot ([guid]::NewGuid().ToString('N') + '.err')

    try {
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $FilePath) + $Arguments
        $proc = Start-Process -FilePath $powershellExe `
            -ArgumentList $argList `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath `
            -Wait `
            -PassThru

        $lines = @()
        if (Test-Path $stdoutPath) {
            $lines += @(Get-Content -Path $stdoutPath -ErrorAction SilentlyContinue)
        }
        if (Test-Path $stderrPath) {
            $lines += @(Get-Content -Path $stderrPath -ErrorAction SilentlyContinue)
        }

        return [pscustomobject]@{
            ExitCode = $proc.ExitCode
            Lines = $lines
        }
    } finally {
        Remove-Item $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
    }
}

$originalLocalAppData = $env:LOCALAPPDATA
$originalAppData = $env:APPDATA
$originalPath = $env:PATH
$originalDisableDownload = $env:INFOSTEALER_CHECK_DISABLE_HANDLE_DOWNLOAD
$tempRoot = Join-Path $env:TEMP ("isc-windows-tests-" + [guid]::NewGuid().ToString('N'))

try {
    Write-Host 'Running Windows runtime smoke tests...'

    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

    $benchCapture = Invoke-PowerShellCapture -FilePath $bench -Arguments @() -TempRoot $tempRoot
    Assert-True ($benchCapture.ExitCode -eq 0) "Browser DB lock benchmark failed: $($benchCapture.Lines -join '; ')"
    $benchResult = Convert-JsonLine -Lines $benchCapture.Lines
    Assert-True ($benchResult.within_threshold -eq $true) 'Browser DB lock benchmark exceeded the allowed threshold.'

    $tempLocalAppData = Join-Path $tempRoot 'LocalAppData'
    $tempAppData = Join-Path $tempRoot 'AppData'
    New-Item -ItemType Directory -Path $tempLocalAppData, $tempAppData -Force | Out-Null

    $env:LOCALAPPDATA = $tempLocalAppData
    $env:APPDATA = $tempAppData
    $env:PATH = $originalPath
    $env:INFOSTEALER_CHECK_DISABLE_HANDLE_DOWNLOAD = '1'

    $runnerReportDir = Join-Path $tempRoot 'runner-report'
    $runnerCapture = Invoke-PowerShellCapture -FilePath $runner -Arguments @('-Module', 'T1555.003', '-Format', 'json', '-ReportDir', $runnerReportDir) -TempRoot $tempRoot
    Assert-True ($runnerCapture.ExitCode -eq 0) "runner.ps1 smoke test failed: $($runnerCapture.Lines -join '; ')"
    $runnerJsonPath = Join-Path $runnerReportDir 'findings.json'
    Assert-True (Test-Path $runnerJsonPath) 'runner.ps1 did not produce findings.json.'
    $runnerResult = Get-Content -Path $runnerJsonPath -Raw | ConvertFrom-Json -ErrorAction Stop
    Assert-True ($runnerResult.platform -eq 'Windows') 'runner.ps1 did not report the Windows platform.'
    Assert-True ($runnerResult.modules_run -eq 1) 'runner.ps1 did not execute exactly one module.'

    $wrapperReportDir = Join-Path $tempRoot 'wrapper-report'
    $wrapperCapture = Invoke-PowerShellCapture -FilePath $checkWindows -Arguments @('-Mode', 'modular', '-Module', 'T1555.003', '-Format', 'json', '-ReportDir', $wrapperReportDir) -TempRoot $tempRoot
    Assert-True ($wrapperCapture.ExitCode -eq 0) "check-windows.ps1 modular smoke test failed: $($wrapperCapture.Lines -join '; ')"
    $wrapperJsonPath = Join-Path $wrapperReportDir 'findings.json'
    Assert-True (Test-Path $wrapperJsonPath) 'check-windows.ps1 did not produce findings.json.'
    $wrapperResult = Get-Content -Path $wrapperJsonPath -Raw | ConvertFrom-Json -ErrorAction Stop
    Assert-True ($wrapperResult.modules_run -eq 1) 'check-windows.ps1 did not forward the module selection correctly.'
    Assert-True ($null -ne $wrapperResult.PSObject.Properties['findings']) 'check-windows.ps1 output did not include a findings key.'
} finally {
    $env:LOCALAPPDATA = $originalLocalAppData
    $env:APPDATA = $originalAppData
    $env:PATH = $originalPath
    $env:INFOSTEALER_CHECK_DISABLE_HANDLE_DOWNLOAD = $originalDisableDownload
    Remove-Item -Recurse -Force $tempRoot -ErrorAction SilentlyContinue
}

Write-Host 'Windows runtime smoke tests passed.'
