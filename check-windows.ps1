#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('auto', 'legacy', 'modular', 'both')][string]$Mode = 'auto',
    [ValidateSet('text', 'json')][string]$Format = 'text',
    [string]$Module,
    [string]$ReportDir
)

$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$legacyScript = Join-Path $scriptRoot 'check-windows-legacy.ps1'
$modularRunner = Join-Path $scriptRoot 'core\runner.ps1'

function Invoke-ModularRunner {
    if (-not (Test-Path $modularRunner)) {
        throw "Modular runner not found: $modularRunner"
    }

    $args = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $modularRunner,
        '-Format', $Format
    )

    if ($Module) {
        $args += @('-Module', $Module)
    }

    if ($ReportDir) {
        $args += @('-ReportDir', $ReportDir)
    }

    Write-Host "[i] Running modular Windows checks via core/runner.ps1"
    & powershell @args
    return $LASTEXITCODE
}

function Invoke-LegacyRunner {
    if (-not (Test-Path $legacyScript)) {
        throw "Legacy Windows script not found: $legacyScript"
    }

    if ($Format -eq 'json' -or $Module) {
        Write-Warning 'Legacy Windows script does not support -Format json or -Module filtering. Skipping legacy mode.'
        return 0
    }

    Write-Host "[i] Running legacy Windows compatibility checks via check-windows-legacy.ps1"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $legacyScript
    return $LASTEXITCODE
}

switch ($Mode) {
    'legacy' {
        exit (Invoke-LegacyRunner)
    }
    'modular' {
        exit (Invoke-ModularRunner)
    }
    'both' {
        $modularExit = Invoke-ModularRunner
        $legacyExit = Invoke-LegacyRunner
        exit ([Math]::Max($modularExit, $legacyExit))
    }
    default {
        if ($Format -eq 'json' -or $Module) {
            exit (Invoke-ModularRunner)
        }

        Write-Host "[i] Auto mode selected. Using legacy checks for broad Windows coverage."
        Write-Host "[i] Use -Mode modular to run the new module-based Windows pipeline."
        exit (Invoke-LegacyRunner)
    }
}
