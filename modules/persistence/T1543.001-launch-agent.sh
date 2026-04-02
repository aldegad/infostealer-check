#!/bin/bash

MODULE_ID="T1543.001"
MODULE_TECHNIQUE="Create or Modify System Process: Launch Agent"
MODULE_DESCRIPTION="Enumerate LaunchAgents and LaunchDaemons and flag recently modified non-standard plist entries using the v1 macOS scanner logic."

source "$(dirname "$0")/../../core/output.sh"

run_checks() {
    local findings=0
    local launch_dirs
    local known_good_prefixes
    local dir
    local plist
    local basename_plist
    local program_path

    launch_dirs=(
        "$HOME/Library/LaunchAgents"
        "/Library/LaunchAgents"
        "/Library/LaunchDaemons"
    )
    known_good_prefixes="com.apple|com.google|com.microsoft|com.adobe|com.docker|com.dropbox|com.spotify|com.1password|com.jetbrains|org.mozilla"

    for dir in "${launch_dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            emit_info "$MODULE_ID" "Launch directory not present: $dir"
            continue
        fi

        emit_info "$MODULE_ID" "Enumerating launch items in $dir"
        while IFS= read -r plist; do
            basename_plist=$(basename "$plist")

            if echo "$basename_plist" | grep -qE "^($known_good_prefixes)"; then
                continue
            fi

            if find "$plist" -mtime -30 -print 2>/dev/null | grep -q .; then
                program_path=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$plist" 2>/dev/null || /usr/libexec/PlistBuddy -c "Print :Program" "$plist" 2>/dev/null || echo "unknown")
                emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "medium" \
                    "Recently modified non-standard launch item" \
                    "plist=$plist program=$program_path" \
                    "Review the plist owner and binary, then remove the item if it is unauthorized."
                findings=$((findings + 1))
            fi
        done < <(find "$dir" -name "*.plist" 2>/dev/null)
    done

    # TODO: v1 enumerated launch items but did not explicitly detect hidden filenames or obfuscated plist/program values.
    emit_info "$MODULE_ID" "TODO: Hidden or obfuscated launch item heuristics were not present in v1."

    if [ "$findings" -eq 0 ]; then
        emit_clean "$MODULE_ID" "$MODULE_TECHNIQUE"
    fi
}

run_checks
