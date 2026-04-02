#Requires -Version 5.1
$MODULE_ID = "dll-sideload"
$MODULE_TECHNIQUE = "T1574.002"
$MODULE_DESCRIPTION = "Detect DLL sideloading in legitimate application directories"

function Emit-Finding($Title, $Severity, $Evidence, $Remediation) {
    $obj = [ordered]@{ technique_id=$MODULE_TECHNIQUE; title=$Title; severity=$Severity; evidence=$Evidence; remediation=$Remediation }
    if ($env:OUTPUT_FORMAT -eq "json") { Write-Output ($obj | ConvertTo-Json -Compress) }
    else { Write-Host "[$Severity] $MODULE_TECHNIQUE $Title"; Write-Host "  evidence: $Evidence"; Write-Host "  remediation: $Remediation" }
}

function run_checks {
    $findings = 0
    $sysDll = "$env:SystemRoot\System32"
    $lummaNames = @("version.dll","winhttp.dll","dbghelp.dll")

    # 1. Unsigned DLLs next to signed EXEs in Program Files
    foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ -and (Test-Path $_) }) {
        Get-ChildItem -Path $pf -Recurse -Filter *.dll -ErrorAction SilentlyContinue | Select-Object -First 200 | ForEach-Object {
            $dll = $_; $dir = $dll.DirectoryName
            $exe = Get-ChildItem -Path $dir -Filter *.exe -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($exe) {
                $sig = Get-AuthenticodeSignature $dll.FullName -ErrorAction SilentlyContinue
                if ($sig -and $sig.Status -ne 'Valid') {
                    Emit-Finding "Unsigned DLL next to signed EXE" "high" "$($dll.FullName) beside $($exe.FullName)" "Verify DLL origin and replace with vendor-signed copy"
                    $script:findings++
                }
            }
        }
    }

    # 2. DLLs in user-writable locations loaded by legitimate processes
    $writablePaths = @($env:APPDATA, $env:LOCALAPPDATA, $env:TEMP, "$env:USERPROFILE\Downloads") | Where-Object { $_ -and (Test-Path $_) }
    foreach ($wp in $writablePaths) {
        Get-ChildItem -Path $wp -Recurse -Filter *.dll -ErrorAction SilentlyContinue | Select-Object -First 100 | ForEach-Object {
            $dll = $_
            $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { try { $_.Modules.FileName -contains $dll.FullName } catch { $false } }
            if ($procs) {
                Emit-Finding "DLL in writable path loaded by process" "high" "$($dll.FullName) loaded by $($procs.Name -join ',')" "Remove DLL and investigate loading process"
                $script:findings++
            }
        }
    }

    # 3. Recently modified DLLs in system directories (last 7 days)
    $cutoff = (Get-Date).AddDays(-7)
    Get-ChildItem -Path $sysDll -Filter *.dll -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $cutoff } | Select-Object -First 50 | ForEach-Object {
        $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -ne 'Valid') {
            Emit-Finding "Recently modified unsigned DLL in System32" "critical" "$($_.FullName) modified $($_.LastWriteTime)" "Compare hash with vendor baseline and restore from trusted source"
            $script:findings++
        }
    }

    # 4. Known Lumma DLL names in non-system paths
    $drives = @($env:SystemDrive)
    $searchRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:APPDATA, $env:LOCALAPPDATA, $env:TEMP, "$env:USERPROFILE\Downloads") | Where-Object { $_ -and (Test-Path $_) }
    foreach ($root in $searchRoots) {
        foreach ($name in $lummaNames) {
            Get-ChildItem -Path $root -Recurse -Filter $name -ErrorAction SilentlyContinue | Where-Object {
                $_.DirectoryName -notlike "$sysDll*"
            } | Select-Object -First 10 | ForEach-Object {
                Emit-Finding "Known Lumma sideload DLL name in non-system path" "critical" "$($_.FullName)" "Quarantine file, scan with AV, and audit the hosting application"
                $script:findings++
            }
        }
    }

    if ($findings -eq 0) {
        $obj = [ordered]@{ technique_id=$MODULE_TECHNIQUE; title="No DLL sideloading indicators found"; severity="info"; evidence=""; remediation="" }
        if ($env:OUTPUT_FORMAT -eq "json") { Write-Output ($obj | ConvertTo-Json -Compress) }
        else { Write-Host "[OK] $MODULE_TECHNIQUE No DLL sideloading indicators found" }
    }
}

run_checks
