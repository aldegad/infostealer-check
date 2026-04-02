#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Module,
    [ValidateSet('text', 'json')][string]$Format = 'text',
    [string]$ReportDir
)

$ErrorActionPreference = 'Stop'

$runnerDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $runnerDir

function Get-ModuleScripts {
    param([string]$Filter)

    $scripts = Get-ChildItem -Path (Join-Path $projectRoot 'modules') -Recurse -Filter *.ps1 -File |
        Sort-Object FullName

    if ($Filter) {
        $scripts = $scripts | Where-Object { $_.BaseName -like "*$Filter*" }
    }

    if (-not $scripts) {
        throw "No Windows modules found" + $(if ($Filter) { " matching '$Filter'" } else { '' })
    }

    return @($scripts)
}

function Convert-ModuleOutput {
    param([string[]]$Lines)

    $items = @()
    foreach ($line in @($Lines)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $trimmed = $line.Trim()
        if (-not ($trimmed.StartsWith('{') -or $trimmed.StartsWith('['))) { continue }

        try {
            $parsed = $trimmed | ConvertFrom-Json -ErrorAction Stop
        } catch {
            continue
        }

        if ($parsed -is [System.Collections.IEnumerable] -and -not ($parsed -is [string]) -and -not ($parsed -is [pscustomobject])) {
            foreach ($entry in $parsed) {
                if ($entry) { $items += $entry }
            }
        } else {
            $items += $parsed
        }
    }

    return @($items)
}

function Write-TextFinding {
    param($Finding)

    $severity = [string]$Finding.severity
    $technique = [string]$Finding.technique_id
    $title = [string]$Finding.title
    $evidence = $Finding.evidence
    $remediation = $Finding.remediation

    switch ($severity.ToLowerInvariant()) {
        'critical' { $label = '[CRITICAL]' }
        'high' { $label = '[HIGH]' }
        'medium' { $label = '[MEDIUM]' }
        'low' { $label = '[LOW]' }
        default { $label = '[INFO]' }
    }

    Write-Host "$label $technique $title"
    if ($null -ne $evidence -and -not [string]::IsNullOrWhiteSpace(($evidence | Out-String).Trim())) {
        Write-Host "  evidence: $(($evidence | Out-String).Trim())"
    }
    if ($null -ne $remediation -and -not [string]::IsNullOrWhiteSpace(($remediation | Out-String).Trim())) {
        Write-Host "  remediation: $(($remediation | Out-String).Trim())"
    }
}

if (-not $ReportDir) {
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $ReportDir = Join-Path $projectRoot "reports\windows-$timestamp"
}
New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null

$scripts = Get-ModuleScripts -Filter $Module
$allFindings = @()

foreach ($script in $scripts) {
    if ($Format -eq 'text') {
        Write-Host ""
        Write-Host "==> $($script.Directory.Name)/$($script.BaseName)"
    }

    $raw = & powershell -NoProfile -ExecutionPolicy Bypass -File $script.FullName -Format json 2>&1
    if ($LASTEXITCODE -ne 0) {
        $allFindings += [pscustomobject]@{
            technique_id = $script.BaseName
            title = 'Module execution failed'
            severity = 'high'
            evidence = ($raw | Out-String).Trim()
            remediation = 'Review the module output and fix the failing PowerShell script.'
        }
        continue
    }

    $parsed = Convert-ModuleOutput -Lines $raw
    if (-not $parsed) {
        $allFindings += [pscustomobject]@{
            technique_id = $script.BaseName
            title = 'Module returned no structured output'
            severity = 'medium'
            evidence = ($raw | Out-String).Trim()
            remediation = 'Ensure the module emits JSON objects when Format=json is requested.'
        }
        continue
    }

    $allFindings += $parsed

    if ($Format -eq 'text') {
        foreach ($finding in $parsed) {
            Write-TextFinding -Finding $finding
        }
    }
}

$counts = @{
    critical = @($allFindings | Where-Object { $_.severity -eq 'critical' }).Count
    high     = @($allFindings | Where-Object { $_.severity -eq 'high' }).Count
    medium   = @($allFindings | Where-Object { $_.severity -eq 'medium' }).Count
    low      = @($allFindings | Where-Object { $_.severity -eq 'low' }).Count
    info     = @($allFindings | Where-Object { $_.severity -eq 'info' }).Count
}
$counts.total = @($allFindings).Count

$report = [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    platform = 'Windows'
    modules_run = $scripts.Count
    report_dir = $ReportDir
    findings = $allFindings
    summary = $counts
}

$jsonPath = Join-Path $ReportDir 'findings.json'
$textPath = Join-Path $ReportDir 'findings.txt'
$reportJson = $report | ConvertTo-Json -Depth 6
Set-Content -Path $jsonPath -Value $reportJson

if ($Format -eq 'text') {
    "" | Set-Content -Path $textPath
    foreach ($finding in $allFindings) {
        $block = @(
            "[$($finding.severity.ToString().ToUpper())] $($finding.technique_id) $($finding.title)"
            $(if ($finding.evidence) { "  evidence: $(($finding.evidence | Out-String).Trim())" })
            $(if ($finding.remediation) { "  remediation: $(($finding.remediation | Out-String).Trim())" })
        ) | Where-Object { $_ }
        Add-Content -Path $textPath -Value ($block -join [Environment]::NewLine)
        Add-Content -Path $textPath -Value ''
    }

    Write-Host ""
    Write-Host "Summary: critical=$($counts.critical) high=$($counts.high) medium=$($counts.medium) low=$($counts.low) info=$($counts.info) total=$($counts.total)"
    Write-Host "Report:  $ReportDir"
} else {
    $report | ConvertTo-Json -Depth 6 -Compress
}

exit ([Math]::Min(125, ($counts.critical + $counts.high)))
