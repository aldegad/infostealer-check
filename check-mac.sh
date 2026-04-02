#!/bin/bash
# ============================================================
#  Infostealer Infection Check Script — macOS
#  ANTTIME 침해사고 대응용
#  사용법: chmod +x infostealer-check-mac.sh && ./infostealer-check-mac.sh
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -f "$SCRIPT_DIR/core/runner.sh" ]]; then
  echo "infostealer-check v2 detected. Running modular scanner..."
  exec "$SCRIPT_DIR/core/runner.sh" --format text "$@"
fi

set -uo pipefail

RED='\033[0;31m'
YEL='\033[0;33m'
GRN='\033[0;32m'
BLU='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

REPORT_DIR="$HOME/Desktop/infostealer-check-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"
REPORT="$REPORT_DIR/report.txt"

log()  { echo -e "$1" | tee -a "$REPORT"; }
warn() { echo -e "${YEL}[!] $1${NC}" | tee -a "$REPORT"; }
bad()  { echo -e "${RED}[X] $1${NC}" | tee -a "$REPORT"; }
good() { echo -e "${GRN}[OK] $1${NC}" | tee -a "$REPORT"; }
info() { echo -e "${BLU}[i] $1${NC}" | tee -a "$REPORT"; }
sep()  { log "────────────────────────────────────────────────────────"; }

FOUND_ISSUES=0
flag_issue() { FOUND_ISSUES=$((FOUND_ISSUES + 1)); }

log ""
log "${BOLD}============================================================${NC}"
log "${BOLD}  Infostealer Infection Check — macOS${NC}"
log "${BOLD}  $(date '+%Y-%m-%d %H:%M:%S')${NC}"
log "${BOLD}============================================================${NC}"
log ""

# ── 1. 시스템 정보 ──
sep
log "${BOLD}[1/10] 시스템 정보${NC}"
sep
info "호스트명: $(hostname)"
info "사용자: $(whoami)"
info "macOS: $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
info "아키텍처: $(uname -m)"
info "가동 시간: $(uptime | sed 's/.*up/up/')"
log ""

# ── 2. 의심 프로세스 점검 ──
sep
log "${BOLD}[2/10] 의심스러운 프로세스 점검${NC}"
sep

SUSPICIOUS_PROCS=(
  "stealer" "keylog" "spyware" "miner" "cryptojack"
  "MacStealer" "AtomicStealer" "Amos" "Poseidon" "Banshee"
  "RealStealer" "MetaStealer" "Pureland" "MacSync"
  "amatera" "acr_stealer" "clickfix" "installfix"
  "osascript.*password" "osascript.*keychain"
  "curl.*pastebin" "curl.*discord" "curl.*telegram"
)

PROC_LIST=$(ps aux 2>/dev/null || true)
SUSP_FOUND=0

for pattern in "${SUSPICIOUS_PROCS[@]}"; do
  matches=$(echo "$PROC_LIST" | grep -i "$pattern" | grep -v "grep" | grep -v "infostealer-check" || true)
  if [ -n "$matches" ]; then
    bad "의심 프로세스 발견: $pattern"
    echo "$matches" >> "$REPORT"
    SUSP_FOUND=1
    flag_issue
  fi
done

if [ $SUSP_FOUND -eq 0 ]; then
  good "알려진 인포스틸러 프로세스 없음"
fi

# 비정상적인 위치에서 실행 중인 프로세스
info "비정상 경로 프로세스 확인 중..."
UNUSUAL_PATHS=$(ps aux | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}' | grep -iE '/tmp/|/var/tmp/|/private/tmp.*[^/]$|\.hidden|/Users/.*/\.' | grep -v "grep" | grep -v "com.apple" | grep -v "infostealer-check" | grep -v "claude" | grep -v "codex" | grep -v "node_modules" | grep -v "\.nvm/" | grep -v "vite" | grep -v "bun" | grep -v "broker\.mjs" | head -20 || true)
if [ -n "$UNUSUAL_PATHS" ]; then
  warn "비정상 경로에서 실행 중인 프로세스:"
  echo "$UNUSUAL_PATHS" | tee -a "$REPORT"
  flag_issue
else
  good "비정상 경로 프로세스 없음"
fi
log ""

# ── 3. Launch Agents / Daemons (자동실행 점검) ──
sep
log "${BOLD}[3/10] Launch Agents / Daemons 점검${NC}"
sep

LAUNCH_DIRS=(
  "$HOME/Library/LaunchAgents"
  "/Library/LaunchAgents"
  "/Library/LaunchDaemons"
)

KNOWN_GOOD_PREFIXES="com.apple|com.google|com.microsoft|com.adobe|com.docker|com.dropbox|com.spotify|com.1password|com.jetbrains|org.mozilla"

for dir in "${LAUNCH_DIRS[@]}"; do
  if [ -d "$dir" ]; then
    info "검사 중: $dir"
    while IFS= read -r plist; do
      basename_plist=$(basename "$plist")
      if ! echo "$basename_plist" | grep -qE "^($KNOWN_GOOD_PREFIXES)"; then
        # 최근 30일 이내 생성된 것만 경고
        if find "$plist" -mtime -30 -print 2>/dev/null | grep -q .; then
          warn "최근 추가된 비표준 LaunchAgent: $basename_plist"
          # 실행 파일 경로 확인
          prog=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$plist" 2>/dev/null || /usr/libexec/PlistBuddy -c "Print :Program" "$plist" 2>/dev/null || echo "unknown")
          info "  → 실행 파일: $prog"
          flag_issue
        fi
      fi
    done < <(find "$dir" -name "*.plist" 2>/dev/null)
  fi
done
log ""

# ── 4. 로그인 항목 점검 ──
sep
log "${BOLD}[4/10] 로그인 항목 (Login Items) 점검${NC}"
sep

LOGIN_ITEMS=$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null || echo "조회 실패")
info "등록된 로그인 항목: $LOGIN_ITEMS"

# SMAppService 기반 로그인 항목 (macOS 13+)
if command -v sfltool &>/dev/null; then
  info "Background Items:"
  sfltool dumpbtm 2>/dev/null | head -30 >> "$REPORT" || true
fi
log ""

# ── 5. 최근 설치/수정된 앱 점검 ──
sep
log "${BOLD}[5/10] 최근 7일 내 설치/수정된 앱${NC}"
sep

info "Applications 폴더:"
find /Applications -maxdepth 1 -mtime -7 -type d 2>/dev/null | while read -r app; do
  appname=$(basename "$app")
  codesign_status=$(codesign -v "$app" 2>&1 || true)
  if echo "$codesign_status" | grep -q "invalid\|not signed\|explicit requirement"; then
    bad "서명 문제 있는 최근 앱: $appname"
    flag_issue
  else
    info "  $appname (서명 정상)"
  fi
done

# 사용자 다운로드 폴더
info "Downloads 폴더 (최근 7일):"
find "$HOME/Downloads" -maxdepth 2 -mtime -7 \( -name "*.dmg" -o -name "*.pkg" -o -name "*.app" -o -name "*.command" -o -name "*.sh" \) 2>/dev/null | while read -r dl; do
  warn "최근 다운로드: $(basename "$dl")"
done
log ""

# ── 6. 브라우저 확장 프로그램 감사 ──
sep
log "${BOLD}[6/10] Chrome 확장 프로그램 감사${NC}"
sep

CHROME_EXT_DIR="$HOME/Library/Application Support/Google/Chrome/Default/Extensions"
if [ -d "$CHROME_EXT_DIR" ]; then
  EXT_COUNT=$(find "$CHROME_EXT_DIR" -maxdepth 1 -type d | wc -l | tr -d ' ')
  info "설치된 확장 프로그램 수: $((EXT_COUNT - 1))"

  find "$CHROME_EXT_DIR" -maxdepth 3 -name "manifest.json" 2>/dev/null | while read -r manifest; do
    ext_name=$(python3 -c "import json; d=json.load(open('$manifest')); print(d.get('name','unknown'))" 2>/dev/null || echo "unknown")
    ext_perms=$(python3 -c "import json; d=json.load(open('$manifest')); print(','.join(d.get('permissions',[])))" 2>/dev/null || echo "")

    # 위험 권한 체크
    if echo "$ext_perms" | grep -qiE "cookies|webRequest|webRequestBlocking|<all_urls>|clipboardRead|nativeMessaging"; then
      warn "고위험 권한 확장: $ext_name"
      info "  권한: $ext_perms"
      # __MSG_ 로 시작하면 정상적인 i18n, 아니면 수상
      if echo "$ext_name" | grep -q "^__MSG_"; then
        info "  (i18n 이름 — 정상적인 패턴)"
      fi
    fi
  done
else
  info "Chrome 확장 폴더 없음"
fi
log ""

# ── 7. 네트워크 연결 점검 ──
sep
log "${BOLD}[7/10] 의심스러운 네트워크 연결${NC}"
sep

# 외부 연결 목록
NETSTAT_OUT=$(netstat -an 2>/dev/null | grep ESTABLISHED || true)
LSOF_NET=$(lsof -i -nP 2>/dev/null | grep ESTABLISHED || true)

# 알려진 C2/악성 IP 대역 (예시)
SUSPICIOUS_PORTS="4444|5555|6666|7777|8888|9999|1337|31337|12345|54321"
SUSP_NET=$(echo "$LSOF_NET" | grep -E ":($SUSPICIOUS_PORTS)" | grep -v "localhost" || true)

if [ -n "$SUSP_NET" ]; then
  bad "의심스러운 포트 연결 발견:"
  echo "$SUSP_NET" | tee -a "$REPORT"
  flag_issue
else
  good "의심 포트 연결 없음"
fi

# Discord/Telegram webhook (인포스틸러 데이터 전송용)
WEBHOOK_CONN=$(echo "$LSOF_NET" | grep -iE "discord|telegram|pastebin" || true)
if [ -n "$WEBHOOK_CONN" ]; then
  warn "Discord/Telegram/Pastebin 연결 감지 (인포스틸러 데이터 전송 가능):"
  echo "$WEBHOOK_CONN" | head -10 | tee -a "$REPORT"
fi

# 전체 외부 연결 저장
echo "$LSOF_NET" > "$REPORT_DIR/network_connections.txt" 2>/dev/null || true
info "전체 네트워크 연결 목록: $REPORT_DIR/network_connections.txt"
log ""

# ── 8. Chrome 프로필 / 쿠키 접근 점검 ──
sep
log "${BOLD}[8/10] Chrome 자격 증명 접근 흔적${NC}"
sep

CHROME_PROFILE="$HOME/Library/Application Support/Google/Chrome/Default"

if [ -d "$CHROME_PROFILE" ]; then
  # Login Data (저장된 비밀번호 DB) 최근 접근 확인
  LOGIN_DB="$CHROME_PROFILE/Login Data"
  if [ -f "$LOGIN_DB" ]; then
    login_mod=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$LOGIN_DB" 2>/dev/null || echo "unknown")
    info "Chrome Login Data 마지막 수정: $login_mod"
  fi

  # Cookies DB
  COOKIE_DB="$CHROME_PROFILE/Cookies"
  if [ -f "$COOKIE_DB" ]; then
    cookie_mod=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$COOKIE_DB" 2>/dev/null || echo "unknown")
    info "Chrome Cookies 마지막 수정: $cookie_mod"
  fi

  # 비정상 접근 — Chrome이 아닌 프로세스가 DB 파일을 열고 있는지
  CHROME_DB_ACCESS=$(lsof "$LOGIN_DB" "$COOKIE_DB" 2>/dev/null | grep -v "Google Chrome" | grep -v "^Google " | grep -v "COMMAND" || true)
  if [ -n "$CHROME_DB_ACCESS" ]; then
    bad "Chrome 외 프로세스가 자격증명 DB 접근 중!"
    echo "$CHROME_DB_ACCESS" | tee -a "$REPORT"
    flag_issue
  else
    good "Chrome DB에 비정상 접근 없음"
  fi
else
  info "Chrome 프로필 없음"
fi

# Keychain 접근 로그
info "최근 Keychain 접근 이벤트 확인 중..."
KEYCHAIN_LOG=$(log show --predicate 'subsystem == "com.apple.securityd"' --last 24h --style compact 2>/dev/null | grep -iE "Chrome|unlock|authorize" | tail -10 || true)
if [ -n "$KEYCHAIN_LOG" ]; then
  info "최근 24시간 Keychain 접근 (Chrome 관련):"
  echo "$KEYCHAIN_LOG" >> "$REPORT"
fi
log ""

# ── 9. 최근 cron / periodic 작업 ──
sep
log "${BOLD}[9/10] 예약 작업 (cron / at) 점검${NC}"
sep

CRON_JOBS=$(crontab -l 2>/dev/null || echo "없음")
info "현재 사용자 crontab: $CRON_JOBS"

# /etc/periodic 변조 체크
for period_dir in /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly; do
  if [ -d "$period_dir" ]; then
    find "$period_dir" -mtime -30 -type f 2>/dev/null | while read -r f; do
      warn "최근 수정된 periodic 스크립트: $f"
      flag_issue
    done
  fi
done
log ""

# ── 10. TCC / 권한 점검 ──
sep
log "${BOLD}[10/10] 개인정보 접근 권한 (TCC) 점검${NC}"
sep

TCC_DB="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
if [ -f "$TCC_DB" ]; then
  info "전체 디스크 접근 권한이 부여된 앱:"
  sqlite3 "$TCC_DB" "SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND allowed=1;" 2>/dev/null | while read -r app; do
    info "  → $app"
  done

  info "접근성(Accessibility) 권한 앱:"
  sqlite3 "$TCC_DB" "SELECT client FROM access WHERE service='kTCCServiceAccessibility' AND allowed=1;" 2>/dev/null | while read -r app; do
    info "  → $app"
  done
else
  info "TCC DB 접근 불가 (정상 — SIP 보호)"
fi
log ""

# ── 결과 요약 ──
sep
sep
log ""
if [ $FOUND_ISSUES -gt 0 ]; then
  log "${RED}${BOLD}  경고: $FOUND_ISSUES 개의 의심 항목이 발견되었습니다!${NC}"
  log ""
  log "  다음 조치를 권장합니다:"
  log "  1. Malwarebytes 무료 버전으로 전체 스캔 실행"
  log "  2. 의심 프로세스/앱 즉시 종료 및 삭제"
  log "  3. Chrome 비밀번호 전체 변경"
  log "  4. Google 계정 세션 전체 로그아웃"
  log "  5. 이 보고서를 보안 담당자에게 전달"
else
  log "${GRN}${BOLD}  점검 완료: 명확한 감염 징후는 발견되지 않았습니다.${NC}"
  log ""
  log "  그러나 고급 인포스틸러는 흔적을 지울 수 있으므로:"
  log "  1. Malwarebytes로 추가 스캔 권장"
  log "  2. Chrome 저장 비밀번호 변경 권장"
  log "  3. Google 계정 보안 점검 실행"
fi
log ""
log "  상세 보고서: $REPORT"
log "  네트워크 로그: $REPORT_DIR/network_connections.txt"
log ""
sep
