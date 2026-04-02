# ============================================================
#  Infostealer Infection Check Script — Windows
#  ANTTIME 침해사고 대응용
#  사용법: 관리자 권한 PowerShell에서 실행
#  Set-ExecutionPolicy Bypass -Scope Process -Force
#  .\infostealer-check-windows.ps1
# ============================================================

$ErrorActionPreference = "SilentlyContinue"

# 보고서 설정
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportDir = "$env:USERPROFILE\Desktop\infostealer-check-$timestamp"
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
$acl = Get-Acl $reportDir
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $reportDir $acl 2>$null
$reportFile = "$reportDir\report.txt"

function Log($msg)  { Write-Host $msg; Add-Content $reportFile $msg }
function Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow; Add-Content $reportFile "[!] $msg" }
function Bad($msg)  { Write-Host "[X] $msg" -ForegroundColor Red; Add-Content $reportFile "[X] $msg" }
function Good($msg) { Write-Host "[OK] $msg" -ForegroundColor Green; Add-Content $reportFile "[OK] $msg" }
function Info($msg) { Write-Host "[i] $msg" -ForegroundColor Cyan; Add-Content $reportFile "[i] $msg" }
function Sep()      { Log "------------------------------------------------------------" }
function Flag-Issue($severity, $msg) {
    if ($severity -eq "High") {
        Bad $msg
    } else {
        Warn $msg
    }
    $script:foundIssues++
}

$foundIssues = 0

Log ""
Log "============================================================"
Log "  Infostealer Infection Check - Windows"
Log "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Log "============================================================"
Log ""

# == 1. 시스템 정보 ==
Sep
Log "[1/10] 시스템 정보"
Sep
Info "호스트명: $env:COMPUTERNAME"
Info "사용자: $env:USERNAME"
$os = (Get-CimInstance Win32_OperatingSystem)
Info "Windows: $($os.Caption) ($($os.Version))"
Info "아키텍처: $($os.OSArchitecture)"
Info "마지막 부팅: $($os.LastBootUpTime)"
Log ""

# == 2. 의심 프로세스 점검 ==
Sep
Log "[2/10] 의심스러운 프로세스 점검"
Sep

$suspiciousNames = @(
    "stealer", "keylog", "spyware", "miner", "cryptojack",
    "RedLine", "Raccoon", "Vidar", "Lumma", "StealC",
    "MetaStealer", "Amatera", "ACRStealer", "RisePro",
    "Mystic", "Stealc", "Rhadamanthys", "installfix",
    "clickfix", "MacSync"
)

$processes = Get-Process | Select-Object Name, Id, Path, Company
$suspFound = $false

foreach ($proc in $processes) {
    foreach ($pattern in $suspiciousNames) {
        if ($proc.Name -match $pattern -or ($proc.Path -and $proc.Path -match $pattern)) {
            Bad "의심 프로세스: $($proc.Name) (PID: $($proc.Id)) - $($proc.Path)"
            $suspFound = $true
            $foundIssues++
        }
    }
}

if (-not $suspFound) {
    Good "알려진 인포스틸러 프로세스 없음"
}

# 비정상 경로 프로세스
Info "비정상 경로 프로세스 확인 중..."
$unusualProcs = $processes | Where-Object {
    $_.Path -and (
        $_.Path -match "\\Temp\\" -or
        $_.Path -match "\\AppData\\Local\\Temp\\" -or
        $_.Path -match "\\Downloads\\" -or
        $_.Path -match "\\Public\\"
    ) -and $_.Company -ne "Microsoft Corporation"
}

if ($unusualProcs) {
    foreach ($p in $unusualProcs) {
        Warn "비정상 경로: $($p.Name) -> $($p.Path)"
        $foundIssues++
    }
} else {
    Good "비정상 경로 프로세스 없음"
}
Log ""

# == 3. 시작 프로그램 점검 ==
Sep
Log "[3/10] 시작 프로그램 (Startup) 점검"
Sep

# Registry Run keys
$runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $entries = Get-ItemProperty $key 2>$null
        $props = $entries.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }
        foreach ($prop in $props) {
            $val = $prop.Value
            if ($val -match "\\Temp\\|\\AppData\\Local\\Temp\\|powershell.*-enc|cmd.*/c.*curl|mshta|wscript|cscript.*http") {
                Bad "의심 시작프로그램: $($prop.Name) = $val"
                $foundIssues++
            } else {
                Info "  $($prop.Name): $val"
            }
        }
    }
}

# Startup 폴더
$startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
if (Test-Path $startupFolder) {
    $startupItems = Get-ChildItem $startupFolder -File
    foreach ($item in $startupItems) {
        $age = (Get-Date) - $item.CreationTime
        if ($age.TotalDays -lt 30) {
            Warn "최근 추가된 시작프로그램: $($item.Name) ($(($item.CreationTime).ToString('yyyy-MM-dd')))"
            $foundIssues++
        }
    }
}
Log ""

# == 4. 예약 작업 점검 ==
Sep
Log "[4/10] 예약 작업 (Scheduled Tasks) 점검"
Sep

$tasks = Get-ScheduledTask | Where-Object {
    $_.State -ne "Disabled" -and
    $_.TaskPath -notmatch "\\Microsoft\\" -and
    $_.Author -ne "Microsoft Corporation"
}

foreach ($task in $tasks) {
    $actions = $task | Get-ScheduledTaskInfo 2>$null
    $taskActions = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "

    if ($taskActions -match "powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|curl") {
        Bad "의심 예약작업: $($task.TaskName) -> $taskActions"
        $foundIssues++
    } elseif ($taskActions -match "https?://|\\Temp\\|\\AppData\\Local\\Temp\\") {
        Warn "주의 예약작업: $($task.TaskName) -> $taskActions"
        $foundIssues++
    } else {
        Info "  $($task.TaskName): $taskActions"
    }
}
Log ""

# == 5. 최근 설치 프로그램 ==
Sep
Log "[5/10] 최근 7일 내 설치된 프로그램"
Sep

$recentApps = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" 2>$null |
    Where-Object { $_.InstallDate -and $_.InstallDate -gt (Get-Date).AddDays(-7).ToString("yyyyMMdd") } |
    Select-Object DisplayName, Publisher, InstallDate

if ($recentApps) {
    foreach ($app in $recentApps) {
        Info "  $($app.DisplayName) by $($app.Publisher) ($($app.InstallDate))"
    }
} else {
    Info "최근 7일 내 설치된 프로그램 없음"
}

# 서명 안 된 실행파일 (Downloads)
Info "Downloads 폴더 미서명 실행파일 확인 중..."
$unsignedExes = Get-ChildItem "$env:USERPROFILE\Downloads" -Recurse -Include "*.exe","*.msi","*.bat","*.cmd","*.ps1" -File 2>$null |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }

foreach ($exe in $unsignedExes) {
    $sig = Get-AuthenticodeSignature $exe.FullName 2>$null
    if ($sig.Status -ne "Valid") {
        Warn "미서명/만료 실행파일: $($exe.Name)"
        $foundIssues++
    }
}
Log ""

# == 6. Chrome 확장 프로그램 감사 ==
Sep
Log "[6/10] Chrome 확장 프로그램 감사"
Sep

$chromeExtDir = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
if (Test-Path $chromeExtDir) {
    $extDirs = Get-ChildItem $chromeExtDir -Directory
    Info "설치된 확장 프로그램 수: $($extDirs.Count)"

    foreach ($extDir in $extDirs) {
        $manifests = Get-ChildItem $extDir.FullName -Recurse -Filter "manifest.json" | Select-Object -First 1
        if ($manifests) {
            try {
                $manifest = Get-Content $manifests.FullName -Raw | ConvertFrom-Json
                $extName = $manifest.name
                $perms = ($manifest.permissions -join ",")

                if ($perms -match "cookies|webRequest|webRequestBlocking|<all_urls>|clipboardRead|nativeMessaging") {
                    Warn "고위험 권한 확장: $extName"
                    Info "  권한: $perms"
                }
            } catch {
                Flag-Issue "Medium" "manifest.json 파싱 실패: $($manifests.FullName)"
            }
        }
    }
} else {
    Info "Chrome 확장 폴더 없음"
}
Log ""

# == 7. 네트워크 연결 점검 ==
Sep
Log "[7/10] 의심스러운 네트워크 연결"
Sep

$connections = Get-NetTCPConnection -State Established 2>$null |
    Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0)" }

# 의심 포트
$suspPorts = @(4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345, 54321)
$suspConns = $connections | Where-Object { $_.RemotePort -in $suspPorts }

if ($suspConns) {
    Bad "의심스러운 포트 연결:"
    foreach ($c in $suspConns) {
        $proc = Get-Process -Id $c.OwningProcess 2>$null
        Bad "  $($proc.Name) -> $($c.RemoteAddress):$($c.RemotePort)"
        $foundIssues++
    }
} else {
    Good "의심 포트 연결 없음"
}

# 전체 연결 저장
$connections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, @{N="Process";E={(Get-Process -Id $_.OwningProcess 2>$null).Name}} |
    Export-Csv "$reportDir\network_connections.csv" -NoTypeInformation
Info "전체 네트워크 연결: $reportDir\network_connections.csv"
Log ""

# == 8. Chrome 자격 증명 접근 점검 ==
Sep
Log "[8/10] Chrome 자격 증명 접근 흔적"
Sep

$chromeProfile = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"

if (Test-Path $chromeProfile) {
    $loginDb = "$chromeProfile\Login Data"
    $cookieDb = "$chromeProfile\Cookies"

    if (Test-Path $loginDb) {
        $loginMod = (Get-Item $loginDb).LastWriteTime.ToString("yyyy-MM-dd HH:mm")
        Info "Chrome Login Data 마지막 수정: $loginMod"
    }
    if (Test-Path $cookieDb) {
        $cookieMod = (Get-Item $cookieDb).LastWriteTime.ToString("yyyy-MM-dd HH:mm")
        Info "Chrome Cookies 마지막 수정: $cookieMod"
    }

    # DB 파일을 열고 있는 프로세스 확인
    $handles = Get-Process | ForEach-Object {
        try {
            $_.Modules | Where-Object { $_.FileName -match "Login Data|Cookies" }
        } catch {}
    }

    if ($handles | Where-Object { $_ }) {
        Warn "Chrome DB에 접근 중인 비정상 프로세스 있을 수 있음"
    } else {
        Good "Chrome DB 접근 이상 없음"
    }
} else {
    Info "Chrome 프로필 없음"
}
Log ""

# == 9. Windows Defender 위협 기록 ==
Sep
Log "[9/10] Windows Defender 최근 위협 기록"
Sep

try {
    $threats = Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 10
    if ($threats) {
        foreach ($t in $threats) {
            $threatInfo = Get-MpThreat -ThreatID $t.ThreatID 2>$null
            Bad "위협 감지: $($threatInfo.ThreatName) ($($t.InitialDetectionTime))"
            Info "  상태: $($t.CurrentThreatExecutionStatusName)"
            $foundIssues++
        }
    } else {
        Good "최근 감지된 위협 없음"
    }
} catch {
    Info "Windows Defender 기록 조회 실패 (관리자 권한 필요)"
}

# Defender 실시간 보호 상태
try {
    $mpStatus = Get-MpComputerStatus
    if ($mpStatus.RealTimeProtectionEnabled) {
        Good "실시간 보호: 활성화"
    } else {
        Bad "실시간 보호: 비활성화 (매우 위험!)"
        $foundIssues++
    }
    Info "마지막 전체 스캔: $($mpStatus.FullScanEndTime)"
    Info "엔진 버전: $($mpStatus.AMEngineVersion)"
} catch {
    Warn "Windows Defender 상태 확인 실패"
}
Log ""

# == 10. PowerShell 실행 기록 ==
Sep
Log "[10/10] PowerShell 실행 기록 점검"
Sep

$psHistoryFile = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $psHistoryFile) {
    $recentCmds = Get-Content $psHistoryFile -Tail 100
    $suspCmds = $recentCmds | Where-Object {
        $_ -match "Invoke-WebRequest|IWR|curl|wget|DownloadString|DownloadFile|Start-BitsTransfer|Invoke-Expression|IEX|bypass|encodedcommand|-enc |base64"
    }

    if ($suspCmds) {
        Warn "의심스러운 PowerShell 명령 기록:"
        foreach ($cmd in $suspCmds | Select-Object -First 10) {
            Warn "  $cmd"
            $foundIssues++
        }
    } else {
        Good "의심 PowerShell 명령 없음"
    }

    # 전체 기록 복사
    Copy-Item $psHistoryFile "$reportDir\powershell_history.txt" -Force
    Info "PowerShell 기록: $reportDir\powershell_history.txt"
} else {
    Info "PowerShell 기록 파일 없음"
}
Log ""

# == 결과 요약 ==
Sep
Sep
Log ""
if ($foundIssues -gt 0) {
    Log ""
    Bad "  경고: $foundIssues 개의 의심 항목이 발견되었습니다!"
    Log ""
    Log "  다음 조치를 권장합니다:"
    Log "  1. Malwarebytes 무료 버전으로 전체 스캔 실행"
    Log "  2. 의심 프로세스/앱 즉시 종료 및 삭제"
    Log "  3. Chrome 비밀번호 전체 변경"
    Log "  4. Google 계정 세션 전체 로그아웃"
    Log "  5. 이 보고서를 보안 담당자에게 전달"
} else {
    Log ""
    Good "  점검 완료: 명확한 감염 징후는 발견되지 않았습니다."
    Log ""
    Log "  그러나 고급 인포스틸러는 흔적을 지울 수 있으므로:"
    Log "  1. Malwarebytes로 추가 스캔 권장"
    Log "  2. Chrome 저장 비밀번호 변경 권장"
    Log "  3. Google 계정 보안 점검 실행"
}
Log ""
Log "  상세 보고서: $reportFile"
Log "  네트워크 로그: $reportDir\network_connections.csv"
Log ""
Sep

# 보고서 열기
Invoke-Item $reportDir
