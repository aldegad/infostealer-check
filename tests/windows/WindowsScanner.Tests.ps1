$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$modulePath = Join-Path $repoRoot 'modules\WindowsInfostealerCheck.psm1'
$fixtureRoot = Join-Path $repoRoot 'tests\fixtures\windows'

Import-Module $modulePath -Force

Describe 'Windows scanner heuristics' {
    Context 'Scheduled task assessment' {
        $cases = Get-Content (Join-Path $fixtureRoot 'scheduled-tasks.json') -Raw | ConvertFrom-Json

        foreach ($case in $cases) {
            It $case.name {
                $actions = @($case.actions | ForEach-Object {
                    $_.Replace('__APPDATA__', $env:APPDATA)
                })

                $assessment = Get-WindowsScheduledTaskAssessment -TaskName $case.taskName -Actions $actions -Author $case.author
                $assessment.Severity | Should Be $case.expectedSeverity
            }
        }
    }

    Context 'Chrome extension assessment' {
        $cases = Get-Content (Join-Path $fixtureRoot 'extensions.json') -Raw | ConvertFrom-Json

        foreach ($case in $cases) {
            It $case.name {
                $assessment = Get-WindowsChromeExtensionAssessment `
                    -ExtensionId $case.extensionId `
                    -ExtensionName $case.extensionName `
                    -Permissions @($case.permissions) `
                    -UpdateUrl $case.updateUrl

                $assessment.Severity | Should Be $case.expectedSeverity
            }
        }
    }

    Context 'Defender detection assessment' {
        $cases = Get-Content (Join-Path $fixtureRoot 'defender-detections.json') -Raw | ConvertFrom-Json

        foreach ($case in $cases) {
            It $case.name {
                $tempArtifact = Join-Path $env:TEMP 'infostealer-check-test-artifact.tmp'
                Set-Content -Path $tempArtifact -Value 'marker'
                $resources = @($case.resources | ForEach-Object {
                    $_.Replace('__TEMP_FILE__', $tempArtifact)
                })

                $assessment = Get-WindowsDefenderDetectionAssessment `
                    -ThreatName $case.threatName `
                    -InitialDetectionTime ([datetime]'2026-04-02T12:00:00') `
                    -ActionSuccess ([bool]$case.actionSuccess) `
                    -Resources $resources

                $assessment.Severity | Should Be $case.expectedSeverity
                Remove-Item $tempArtifact -Force
            }
        }

        It 'extracts file paths from resource text' {
            $tempArtifact = Join-Path $env:TEMP 'infostealer-check-test-artifact.tmp'
            Set-Content -Path $tempArtifact -Value 'marker'
            $paths = Get-DetectionResourcePaths "File:_$tempArtifact"
            $paths.Count | Should Be 1
            $paths[0] | Should Be $tempArtifact
            Remove-Item $tempArtifact -Force
        }
    }
}
