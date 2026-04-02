#!/usr/bin/env bash

MODULE_ID="dns-analysis"
MODULE_TECHNIQUE="T1071.004"
MODULE_DESCRIPTION="Analyze DNS cache for DGA domains and suspicious resolutions"

source "$(dirname "$0")/../../core/output.sh"

entropy() {
    awk -v s="$1" 'BEGIN{n=split(s,a,"");for(i=1;i<=n;i++)c[a[i]]++;for(k in c){p=c[k]/n;h-=p*(log(p)/log(2))}printf "%.2f",h}'
}

run_checks() {
    local findings=0 dns_dump syslog_hits domains suspicious="" doh nxdomain_count d label h

    dns_dump=$(scutil --dns 2>/dev/null || true)
    syslog_hits=$(grep -Ei 'mDNSResponder|dns|query|nxdomain|no such host' /var/log/system.log 2>/dev/null || true)
    domains=$(printf '%s\n%s\n' "$dns_dump" "$syslog_hits" | grep -Eo '([A-Za-z0-9-]+\.)+[A-Za-z]{2,}' | tr '[:upper:]' '[:lower:]' | sort -u)

    while IFS= read -r d; do
        [ -z "$d" ] && continue
        label=${d//./}
        h=$(entropy "$label")
        if [ "${#label}" -gt 15 ] && awk -v h="$h" 'BEGIN{exit !(h>3.5)}'; then
            suspicious="${suspicious}${d} entropy=${h}"$'\n'
        fi
    done <<< "$domains"

    if [ -n "$suspicious" ]; then
        emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "high" \
            "High-entropy domains from scutil/system.log"$'\n'"$(printf '%s' "$suspicious" | head -10)" \
            "Inspect processes generating these lookups and block suspected DGA traffic."
        findings=$((findings + 1))
    fi

    doh=$(lsof -i 2>/dev/null | grep -Ei 'dns.google|cloudflare-dns|dns.quad9' | grep -Evi 'Safari|Chrome|Firefox|Brave|Arc|Edge|Opera' || true)
    if [ -n "$doh" ]; then
        emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "high" \
            "Suspicious DNS-over-HTTPS connections from non-browser processes"$'\n'"$(printf '%s' "$doh" | head -10)" \
            "Review the owning process and restrict unauthorized DoH endpoints."
        findings=$((findings + 1))
    fi

    nxdomain_count=$(printf '%s\n' "$syslog_hits" | grep -Eic 'nxdomain|no such host' || true)
    if [ "${nxdomain_count:-0}" -gt 20 ]; then
        emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "medium" \
            "High NXDOMAIN volume detected in /var/log/system.log"$'\n'"count=${nxdomain_count}" \
            "Investigate for DGA-driven lookup failures or misconfigured DNS beacons."
        findings=$((findings + 1))
    fi

    [ "$findings" -eq 0 ] && emit_clean "$MODULE_ID" "$MODULE_TECHNIQUE"
}

run_checks
