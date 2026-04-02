$ErrorActionPreference = "SilentlyContinue"

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$desktop = [Environment]::GetFolderPath("Desktop")
$reportDir = Join-Path $desktop "infostealer-check-$timestamp"
$reportFile = Join-Path $reportDir "report.txt"
$networkCsv = Join-Path $reportDir "network_connections.csv"
$psHistoryCopy = Join-Path $reportDir "powershell_history.txt"

New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

function Write-Report {
    param(
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    Write-Host $Message -ForegroundColor $Color
    Add-Content -Path $reportFile -Value $Message
}

function Log($Message)  { Write-Report $Message }
function Good($Message) { Write-Report "[OK] $Message" Green }
function Warn($Message) { Write-Report "[!] $Message" Yellow }
function Bad($Message)  { Write-Report "[X] $Message" Red }
function Info($Message) { Write-Report "[i] $Message" Cyan }
function Sep()          { Log "------------------------------------------------------------" }

$foundIssues = 0
$highConfidenceFindings = 0
$warningFindings = 0
$userWritableRoots = @(
    $env:TEMP,
    (Join-Path $env:LOCALAPPDATA "Temp"),
    $env:APPDATA,
    $env:LOCALAPPDATA,
    (Join-Path $env:USERPROFILE "Downloads"),
    (Join-Path $env:USERPROFILE "Desktop"),
    "$env:SystemDrive\Users\Public",
    $env:ProgramData
)
$trustedTaskPathPatterns = @(
    '^C:\\Program Files( \(x86\))?\\Adobe\\',
    '^C:\\Program Files( \(x86\))?\\Common Files\\Adobe\\',
    '^C:\\Program Files( \(x86\))?\\AMD\\',
    '^C:\\Program Files( \(x86\))?\\GIGABYTE\\',
    '^C:\\Program Files( \(x86\))?\\Logitech\\',
    '^C:\\Program Files( \(x86\))?\\Microsoft OneDrive\\',
    '^C:\\Program Files( \(x86\))?\\NVIDIA Corporation\\',
    '^C:\\Windows\\'
)
$trustedTaskAuthors = @(
    'Adobe',
    'Advanced Micro Devices',
    'AMD',
    'GIGABYTE',
    'Logitech',
    'Microsoft',
    'NVIDIA'
)
$trustedExtensionIds = @{
    "fcoeoabgfenejglbffodgkkbkcdhcgfn" = "Claude"
    "inomeogfingihgjfjlpeplalcfajhgai" = "Chrome Remote Desktop"
}
$trustedExtensionUpdateUrls = @(
    "https://clients2.google.com/service/update2/crx",
    "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
)

function Add-Issue {
    param([string]$Level, [string]$Message)

    switch ($Level) {
        "bad" {
            Bad $Message
            $script:foundIssues++
            $script:highConfidenceFindings++
        }
        "warn" {
            Warn $Message
            $script:foundIssues++
            $script:warningFindings++
        }
        default {
            Info $Message
        }
    }
}

function Format-Preview {
    param(
        [string]$Text,
        [int]$MaxLength = 140
    )

    if (-not $Text) {
        return ""
    }

    $singleLine = ($Text -replace "\s+", " ").Trim()
    if ($singleLine.Length -le $MaxLength) {
        return $singleLine
    }

    return "$($singleLine.Substring(0, $MaxLength - 3))..."
}

function Resolve-ScanPath {
    param([string]$Path)

    if (-not $Path) {
        return $null
    }

    return [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
}

function Test-UserWritablePath {
    param([string]$Path)

    $resolved = Resolve-ScanPath $Path
    if (-not $resolved) {
        return $false
    }

    foreach ($root in $userWritableRoots) {
        $expandedRoot = Resolve-ScanPath $root
        if ($expandedRoot -and $resolved.StartsWith($expandedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Get-CommandExecutablePath {
    param([string]$CommandLine)

    if (-not $CommandLine) {
        return $null
    }

    if ($CommandLine -match '(?i)"([^"]+\.(exe|cmd|bat|ps1|vbs|js|msi))"') {
        return Resolve-ScanPath $matches[1]
    }

    if ($CommandLine -match '(?i)^([^\s]+\.(exe|cmd|bat|ps1|vbs|js|msi))') {
        return Resolve-ScanPath $matches[1]
    }

    return $null
}

function Test-TrustedSignedFile {
    param([string]$Path)

    $resolved = Resolve-ScanPath $Path
    if (-not $resolved -or -not (Test-Path $resolved)) {
        return $false
    }

    $signature = Get-AuthenticodeSignature $resolved
    return $signature.Status -eq "Valid"
}

function Get-DetectionResourcePaths {
    param([string]$Text)

    $matches = New-Object System.Collections.Generic.List[string]
    if (-not $Text) {
        return @()
    }

    foreach ($match in [regex]::Matches($Text, '(?i)[A-Za-z]:\\[^"\r\n]+?\.(exe|dll|cmd|bat|ps1|msi|js|vbs|zip|rar|7z|tmp|dat|db|sqlite|json|lnk)')) {
        $candidate = Resolve-ScanPath $match.Value
        if ($candidate -and -not $matches.Contains($candidate)) {
            [void]$matches.Add($candidate)
        }
    }

    return $matches.ToArray()
}

Log ""
Log "============================================================"
Log "  Infostealer Infection Check - Windows"
Log "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Log "============================================================"
Log ""

Sep
Log "[1/10] System info"
Sep

$os = Get-CimInstance Win32_OperatingSystem
Info "Computer: $env:COMPUTERNAME"
Info "User: $env:USERNAME"
Info "Windows: $($os.Caption) ($($os.Version))"
Info "Architecture: $($os.OSArchitecture)"
Info "Last boot: $($os.LastBootUpTime)"
Log ""

Sep
Log "[2/10] Suspicious processes"
Sep

$suspiciousNames = @(
    "stealer", "keylog", "spyware", "miner", "cryptojack",
    "redline", "raccoon", "vidar", "lumma", "stealc",
    "metastealer", "amatera", "acrstealer", "risepro",
    "mystic", "rhadamanthys", "installfix", "clickfix", "macsync"
)

$processes = Get-CimInstance Win32_Process | Select-Object Name, ProcessId, ExecutablePath, CommandLine
$matchedProcess = $false

foreach ($proc in $processes) {
    $name = [string]$proc.Name
    $path = [string]$proc.ExecutablePath
    foreach ($pattern in $suspiciousNames) {
        if ($name -match $pattern -or $path -match $pattern) {
            Add-Issue "bad" "Suspicious process: $name (PID: $($proc.ProcessId)) - $path"
            $matchedProcess = $true
            break
        }
    }
}

if (-not $matchedProcess) {
    Good "No process names matched common infostealer patterns"
}

$unusualProcRoots = @("\Temp\", "\AppData\Local\Temp\", "\Downloads\", "\Users\Public\")
$unusualProcs = $processes | Where-Object {
    $path = [string]$_.ExecutablePath
    $path -and ($unusualProcRoots | Where-Object { $path -like "*$_*" })
}

if ($unusualProcs) {
    foreach ($proc in $unusualProcs) {
        Add-Issue "warn" "Process running from unusual path: $($proc.Name) -> $($proc.ExecutablePath)"
    }
} else {
    Good "No processes running from Temp, Downloads, or Public paths"
}
Log ""

Sep
Log "[3/10] Startup entries"
Sep

$runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $entries = Get-ItemProperty $key
        foreach ($prop in $entries.PSObject.Properties) {
            if ($prop.Name -match "^PS") { continue }
            $value = [string]$prop.Value
            if ($value -match "\\Temp\\|\\AppData\\Local\\Temp\\|powershell.*-enc|cmd.*/c.*curl|mshta|wscript|cscript.*http") {
                Add-Issue "bad" "Suspicious Run key in ${key}: $($prop.Name) = $value"
            } else {
                Info "$key :: $($prop.Name) = $value"
            }
        }
    }
}

$startupFolder = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"
if (Test-Path $startupFolder) {
    $startupItems = Get-ChildItem $startupFolder -File
    if ($startupItems) {
        foreach ($item in $startupItems) {
            $ageDays = ((Get-Date) - $item.CreationTime).TotalDays
            if ($ageDays -lt 30) {
                Add-Issue "warn" "Recent startup item: $($item.Name) ($($item.CreationTime.ToString('yyyy-MM-dd')))"
            } else {
                Info "Startup item: $($item.Name)"
            }
        }
    } else {
        Good "Startup folder is empty"
    }
}
Log ""

Sep
Log "[4/10] Scheduled tasks"
Sep

$tasks = Get-ScheduledTask | Where-Object {
    $_.State -ne "Disabled" -and
    $_.TaskPath -notlike "\Microsoft\*"
}

if ($tasks) {
    foreach ($task in $tasks) {
        $actions = @($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() } | Where-Object { $_ })
        if (-not $actions) {
            Info "Scheduled task without executable action: $($task.TaskName)"
            continue
        }

        $taskActionText = $actions -join "; "
        $executablePath = Get-CommandExecutablePath $taskActionText
        $resolvedExecutable = Resolve-ScanPath $executablePath
        $author = [string]$task.Author
        $usesScriptEngine = $taskActionText -match '(^|[\\/"\s])(powershell|pwsh|cmd|wscript|cscript|mshta|curl|rundll32|regsvr32)(\.exe)?([\\/"\s]|$)'
        $usesRemoteContent = $taskActionText -match 'https?://'
        $usesEncodedPayload = $taskActionText -match '(?i)-enc(odedcommand)?\b|frombase64string|invoke-expression|\biex\b'
        $runsFromUserWritablePath = (Test-UserWritablePath $resolvedExecutable) -or $taskActionText -match '\\Temp\\|\\AppData\\|\\Downloads\\|\\ProgramData\\'
        $trustedPath = $false
        foreach ($pattern in $trustedTaskPathPatterns) {
            if ($resolvedExecutable -match $pattern) {
                $trustedPath = $true
                break
            }
        }
        $trustedAuthor = $false
        foreach ($pattern in $trustedTaskAuthors) {
            if ($author -match $pattern) {
                $trustedAuthor = $true
                break
            }
        }
        $trustedSignature = Test-TrustedSignedFile $resolvedExecutable

        if ($usesScriptEngine -and ($usesRemoteContent -or $usesEncodedPayload -or $runsFromUserWritablePath)) {
            Add-Issue "bad" "Suspicious scheduled task: $($task.TaskName) -> $taskActionText"
        } elseif ($resolvedExecutable -and -not (Test-Path $resolvedExecutable) -and -not ($taskActionText -match '^%')) {
            Add-Issue "warn" "Scheduled task references a missing executable: $($task.TaskName) -> $taskActionText"
        } elseif ($runsFromUserWritablePath) {
            Add-Issue "warn" "Scheduled task runs from a user-writable path: $($task.TaskName) -> $taskActionText"
        } elseif ($usesScriptEngine -or $usesRemoteContent) {
            Add-Issue "warn" "Script-driven scheduled task: $($task.TaskName) -> $taskActionText"
        } elseif ($trustedPath -or $trustedAuthor -or $trustedSignature) {
            Info "Trusted vendor scheduled task: $($task.TaskName) -> $taskActionText"
        } else {
            Info "Scheduled task: $($task.TaskName) -> $taskActionText"
        }
    }
} else {
    Good "No non-Microsoft scheduled tasks found"
}
Log ""

Sep
Log "[5/10] Recently installed software and recent downloads"
Sep

$recentApps = Get-ItemProperty `
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", `
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Where-Object {
        $_.InstallDate -and $_.InstallDate -gt (Get-Date).AddDays(-7).ToString("yyyyMMdd")
    } |
    Select-Object DisplayName, Publisher, InstallDate

if ($recentApps) {
    foreach ($app in $recentApps) {
        Info "Recent install: $($app.DisplayName) by $($app.Publisher) ($($app.InstallDate))"
    }
} else {
    Good "No installed applications recorded in the last 7 days"
}

$downloads = Join-Path $env:USERPROFILE "Downloads"
if (Test-Path $downloads) {
    $recentExecutables = Get-ChildItem $downloads -Recurse -Include "*.exe","*.msi","*.bat","*.cmd","*.ps1" -File |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }

    if ($recentExecutables) {
        foreach ($file in $recentExecutables) {
            $sig = Get-AuthenticodeSignature $file.FullName
            if ($sig.Status -ne "Valid") {
                Add-Issue "warn" "Recent unsigned or untrusted file in Downloads: $($file.FullName)"
            } else {
                Info "Signed recent download: $($file.FullName)"
            }
        }
    } else {
        Good "No recent executable/script downloads found"
    }
}
Log ""

Sep
Log "[6/10] Chrome extensions"
Sep

$chromeProfilesRoot = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data"
$riskyPermissions = @("cookies", "webRequest", "webRequestBlocking", "<all_urls>", "clipboardRead", "nativeMessaging")

if (Test-Path $chromeProfilesRoot) {
    $profiles = Get-ChildItem $chromeProfilesRoot -Directory | Where-Object {
        $_.Name -eq "Default" -or $_.Name -like "Profile*"
    }

    foreach ($profile in $profiles) {
        $extensionsDir = Join-Path $profile.FullName "Extensions"
        if (-not (Test-Path $extensionsDir)) { continue }

        Info "Inspecting Chrome profile: $($profile.Name)"
        $extensionRoots = Get-ChildItem $extensionsDir -Directory
        foreach ($extRoot in $extensionRoots) {
            $manifest = Get-ChildItem $extRoot.FullName -Recurse -Filter "manifest.json" | Select-Object -First 1
            if (-not $manifest) { continue }

            try {
                $json = Get-Content $manifest.FullName -Raw | ConvertFrom-Json
                $permissions = @($json.permissions) + @($json.host_permissions)
                $permissions = $permissions | Where-Object { $_ } | Select-Object -Unique
                $extName = if ($json.name) { [string]$json.name } else { $extRoot.Name }
                $hit = $permissions | Where-Object { $_ -in $riskyPermissions }
                $storeUpdateUrl = [string]$json.update_url
                $trustedStoreSource = $trustedExtensionUpdateUrls -contains $storeUpdateUrl
                $trustedHighPrivilegeExtension = $trustedExtensionIds.ContainsKey($extRoot.Name)
                $criticalPermissions = @($hit | Where-Object { $_ -in @("nativeMessaging", "<all_urls>", "cookies", "webRequest", "webRequestBlocking") })

                if ($hit) {
                    if ($trustedHighPrivilegeExtension -and $trustedStoreSource) {
                        Info "Trusted high-privilege extension: $extName ($($extRoot.Name)) -> $($hit -join ', ')"
                    } elseif (-not $trustedStoreSource -and $criticalPermissions.Count -ge 2) {
                        Add-Issue "bad" "Extension with high-risk permissions from an untrusted update source: $extName ($($extRoot.Name)) -> $($hit -join ', ')"
                    } else {
                        Add-Issue "warn" "Extension with high-risk permissions: $extName ($($extRoot.Name)) -> $($hit -join ', ')"
                    }
                }
            } catch {
                Warn "Could not parse manifest: $($manifest.FullName)"
            }
        }
    }
} else {
    Info "Chrome user data path not found"
}
Log ""

Sep
Log "[7/10] Network connections"
Sep

$connections = Get-NetTCPConnection -State Established | Where-Object {
    $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0)"
}
$suspiciousPorts = @(4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345, 54321)

if ($connections) {
    $suspiciousConnections = $connections | Where-Object { $_.RemotePort -in $suspiciousPorts }
    if ($suspiciousConnections) {
        foreach ($conn in $suspiciousConnections) {
            $procName = (Get-Process -Id $conn.OwningProcess).ProcessName
            Add-Issue "bad" "Connection on suspicious port: $procName -> $($conn.RemoteAddress):$($conn.RemotePort)"
        }
    } else {
        Good "No established TCP connections on the suspicious port list"
    }

    $connections |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
            @{Name = "Process"; Expression = { (Get-Process -Id $_.OwningProcess).ProcessName }} |
        Export-Csv -Path $networkCsv -NoTypeInformation

    Info "Saved network connection log: $networkCsv"
} else {
    Info "No established TCP connections found or command unavailable"
}
Log ""

Sep
Log "[8/10] Chrome credential store metadata"
Sep

if (Test-Path $chromeProfilesRoot) {
    foreach ($profile in $profiles) {
        $loginDb = Join-Path $profile.FullName "Login Data"
        $cookiesDb = Join-Path $profile.FullName "Cookies"

        if (Test-Path $loginDb) {
            Info "$($profile.Name) Login Data last modified: $((Get-Item $loginDb).LastWriteTime)"
        }
        if (Test-Path $cookiesDb) {
            Info "$($profile.Name) Cookies last modified: $((Get-Item $cookiesDb).LastWriteTime)"
        }
    }

    $chromeRunning = Get-Process chrome
    if (-not $chromeRunning) {
        Info "Chrome is not running; recent DB writes should be reviewed in context"
    }
} else {
    Info "Chrome profile not found"
}
Log ""

Sep
Log "[9/10] Windows Defender status and threat history"
Sep

try {
    $threats = Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 10
    if ($threats) {
        foreach ($t in $threats) {
            $threatInfo = Get-MpThreat -ThreatID $t.ThreatID
            $threatName = if ($threatInfo.ThreatName) { $threatInfo.ThreatName } else { "Unknown threat" }
            $resources = @($t.Resources | ForEach-Object { [string]$_ } | Where-Object { $_ })
            $resourceTypes = @()
            $existingResourcePaths = New-Object System.Collections.Generic.List[string]
            $resourcePreviews = New-Object System.Collections.Generic.List[string]

            foreach ($resource in $resources) {
                $resourceText = $resource.Trim()
                $resourceParts = $resourceText.Split(':', 2)
                if ($resourceParts.Count -eq 2 -and $resourceParts[0] -match '^[A-Za-z]+$') {
                    $resourceType = $resourceParts[0]
                    $resourceBody = $resourceParts[1].TrimStart('_')
                } else {
                    $resourceType = "Resource"
                    $resourceBody = $resourceText
                }

                if ($resourceTypes -notcontains $resourceType) {
                    $resourceTypes += $resourceType
                }

                if ($resourcePreviews.Count -lt 2) {
                    [void]$resourcePreviews.Add("${resourceType}: $(Format-Preview $resourceBody)")
                }

                if ($resourceType -ne "CmdLine") {
                    foreach ($candidatePath in Get-DetectionResourcePaths $resourceBody) {
                        if ((Test-Path $candidatePath) -and (Test-UserWritablePath $candidatePath) -and -not $existingResourcePaths.Contains($candidatePath)) {
                            [void]$existingResourcePaths.Add($candidatePath)
                        }
                    }
                }
            }

            $remediationSucceeded = [bool]$t.ActionSuccess
            if ($existingResourcePaths.Count -gt 0) {
                Add-Issue "bad" "Defender detection with residual artifacts still present: $threatName at $($t.InitialDetectionTime)"
                foreach ($path in $existingResourcePaths) {
                    Warn "  Residual artifact: $path"
                }
            } elseif (-not $remediationSucceeded) {
                Add-Issue "bad" "Defender detection without confirmed remediation: $threatName at $($t.InitialDetectionTime)"
            } else {
                Add-Issue "warn" "Historical Defender detection with no current file residue found: $threatName at $($t.InitialDetectionTime)"
            }

            $resourceTypeSummary = if ($resourceTypes) { $resourceTypes -join ", " } else { "none" }
            Info "Threat resource types: $resourceTypeSummary"
            foreach ($preview in $resourcePreviews) {
                Info "  Resource preview: $preview"
            }
            Info "Remediation success: $remediationSucceeded"
            Info "Remediation time: $($t.RemediationTime)"
        }
    } else {
        Good "No recent Windows Defender detections found"
    }
} catch {
    Info "Could not read Windows Defender threat history"
}

try {
    $mpStatus = Get-MpComputerStatus
    if ($mpStatus.RealTimeProtectionEnabled) {
        Good "Windows Defender real-time protection: enabled"
    } else {
        Add-Issue "bad" "Windows Defender real-time protection: disabled"
    }
    Info "Last full scan: $($mpStatus.FullScanEndTime)"
    Info "Engine version: $($mpStatus.AMEngineVersion)"
} catch {
    Warn "Could not read Windows Defender status"
}
Log ""

Sep
Log "[10/10] PowerShell history"
Sep

$psHistoryFile = Join-Path $env:APPDATA "Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $psHistoryFile) {
    $recentCmds = Get-Content $psHistoryFile -Tail 200
    $suspiciousCmds = $recentCmds | Where-Object {
        $_ -match "Invoke-WebRequest|IWR|curl|wget|DownloadString|DownloadFile|Start-BitsTransfer|Invoke-Expression|IEX|bypass|encodedcommand|-enc |base64"
    }

    if ($suspiciousCmds) {
        Add-Issue "warn" "Suspicious PowerShell commands found in recent history"
        foreach ($cmd in ($suspiciousCmds | Select-Object -First 10)) {
            Warn "  $cmd"
        }
    } else {
        Good "No suspicious PowerShell command patterns found"
    }

    Copy-Item $psHistoryFile $psHistoryCopy -Force
    Info "Saved PowerShell history copy: $psHistoryCopy"
} else {
    Info "PowerShell history file not found"
}
Log ""

Sep
Sep
Log ""

if ($foundIssues -gt 0) {
    if ($highConfidenceFindings -gt 0) {
        Bad "Scan complete: $highConfidenceFindings high-confidence finding(s), $warningFindings warning(s)"
    } else {
        Warn "Scan complete: $warningFindings warning(s), no high-confidence hits"
    }
    Log "Recommended next steps:"
    Log "1. Run a reputable secondary scanner such as Microsoft Defender Offline or Malwarebytes."
    Log "2. Review warning entries, Defender detections, recent downloads, and any user-writable persistence locations."
    Log "3. Rotate browser passwords and sign out of important web sessions if compromise is possible."
    Log "4. Review the generated report and network log with your security owner if this is a work machine."
} else {
    Good "Scan complete: no high-confidence infostealer indicators were found"
    Log "Lower-signal anomalies can still exist, so a secondary malware scan is still a good idea."
}

Log ""
Log "Detailed report: $reportFile"
Log "Network log: $networkCsv"
Log ""
Sep

Invoke-Item $reportDir
