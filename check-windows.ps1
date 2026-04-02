$modulePath = Join-Path $PSScriptRoot 'modules\WindowsInfostealerCheck.psm1'
Import-Module $modulePath -Force

Invoke-WindowsInfostealerCheck
