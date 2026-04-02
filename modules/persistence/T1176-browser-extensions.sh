#!/usr/bin/env bash

MODULE_ID="browser-extensions"
MODULE_TECHNIQUE="T1176"
MODULE_DESCRIPTION="Audit browser extensions for suspicious permissions across all browsers"
cd "$(dirname "$0")" || exit 1
CORE_DIR=../../core
source "${CORE_DIR}/output.sh"

scan_root() {
    local browser="$1" root="$2" mf meta name perms flags rel extdir recent
    [ -d "$root" ] || return
    while IFS= read -r mf; do
        meta=$(/usr/bin/python3 - "$mf" <<'PY'
import json,sys
bad={"cookies","webRequest","webRequestBlocking","nativeMessaging","debugger","clipboardRead","clipboardWrite","tabs","history","bookmarks","downloads","management","proxy","privacy"}
try: d=json.load(open(sys.argv[1]))
except Exception: print("||"); raise SystemExit
name=d.get("name","unknown")
perms=sorted({p for p in d.get("permissions",[]) if isinstance(p,str) and p in bad})
patterns=(d.get("host_permissions") or [])+[m for c in d.get("content_scripts",[]) if isinstance(c,dict) for m in (c.get("matches") or [])]
broad=any(p in ("<all_urls>","*://*/*") for p in patterns if isinstance(p,str))
print(f"{name}|{','.join(perms)}|{'broad-hosts' if broad else ''}")
PY
)
        IFS='|' read -r name perms flags <<<"$meta"
        [ -n "$perms$flags" ] || continue
        rel=${mf#"$root"/}; extdir="$root/${rel%%/*}"; [ "$rel" = "$mf" ] && extdir="$(dirname "$mf")"
        recent=$(find "$extdir" -prune -mtime -7 -print 2>/dev/null)
        [ -n "$recent" ] && flags="${flags:+$flags,}recent-install"
        emit_finding "$MODULE_TECHNIQUE" "Suspicious browser extension" "medium" \
            "browser=$browser name=$name permissions=${perms:-none} indicators=${flags:-permissions-only} path=$mf" \
            "Review the publisher and requested access, remove unauthorized extensions, and rotate browser sessions if compromise is suspected."
        FOUND=1
    done < <(find "$root" -name manifest.json 2>/dev/null)
}

run_checks() {
    local FOUND=0 d
    scan_root "Chrome" "$HOME/Library/Application Support/Google/Chrome/Default/Extensions"
    for d in "$HOME"/Library/Application\ Support/Firefox/Profiles/*/extensions; do scan_root "Firefox" "$d"; done
    scan_root "Safari" "$HOME/Library/Containers/com.apple.Safari/Data/Library/Safari/AppExtensions"
    scan_root "Safari" "$HOME/Library/Containers/com.apple.Safari/Data/Library/Safari/WebExtensions"
    scan_root "Edge" "$HOME/Library/Application Support/Microsoft Edge/Default/Extensions"
    scan_root "Brave" "$HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions"
    scan_root "Arc" "$HOME/Library/Application Support/Arc/User Data/Default/Extensions"
    [ "$FOUND" -eq 0 ] && emit_clean "$MODULE_TECHNIQUE" "$MODULE_DESCRIPTION"
}

run_checks
