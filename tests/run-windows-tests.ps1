Import-Module Pester -MinimumVersion 3.4.0

$testPath = Join-Path $PSScriptRoot 'windows\WindowsScanner.Tests.ps1'
Invoke-Pester -Script $testPath
