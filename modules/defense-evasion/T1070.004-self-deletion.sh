#!/usr/bin/env bash
MODULE_ID="self-deletion-residue"
MODULE_TECHNIQUE="T1070.004"
MODULE_DESCRIPTION="Detect traces left by self-deleting infostealers"
CORE_DIR=../../core
source "${CORE_DIR}/output.sh"

run_checks() {
  local findings=0 now p
  now=$(date +%s)
  hit() { emit_finding "$MODULE_TECHNIQUE" "$1" "medium" "$2" "Inspect and remove unauthorized residue."; findings=$((findings+1)); }

  # 1. Orphaned LaunchAgent plists pointing to non-existent executables
  for d in "$HOME/Library/LaunchAgents" /Library/LaunchAgents; do
    [ -d "$d" ] || continue
    while IFS= read -r f; do
      p=$(/usr/libexec/PlistBuddy -c 'Print :Program' "$f" 2>/dev/null || \
          /usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$f" 2>/dev/null)
      [ -n "$p" ] && [ ! -e "$p" ] && hit "Orphaned LaunchAgent" "plist=$f target=$p"
    done < <(find "$d" -name '*.plist' 2>/dev/null)
  done

  # 2. Empty staging directories in /tmp, ~/Library/Caches with recent creation
  while IFS= read -r d; do
    local b; b=$(stat -f %B "$d" 2>/dev/null || echo 0)
    [ "$b" -ge $((now - 172800)) ] && hit "Empty staging directory" "path=$d created=$b"
  done < <(find /tmp "$HOME/Library/Caches" -type d -empty 2>/dev/null)

  # 3. Dangling symlinks in /usr/local/bin, ~/Library/
  while IFS= read -r l; do
    hit "Dangling symlink" "path=$l target=$(readlink "$l")"
  done < <(find /usr/local/bin "$HOME/Library" -type l ! -exec test -e {} \; -print 2>/dev/null)

  # 4. Trash entries matching known stealer patterns (last 7 days)
  while IFS= read -r t; do
    hit "Trash residue matching stealer patterns" "path=$t"
  done < <(find "$HOME/.Trash" -maxdepth 1 -mtime -7 \
    \( -iname '*steal*' -o -iname '*amos*' -o -iname '*poseidon*' \
       -o -iname '*wallet*' -o -iname '*keychain*' -o -iname '*cookie*' \
       -o -iname '*browser*' \) 2>/dev/null)

  # 5. Unified log: process launches from paths that no longer exist (last 24h)
  while IFS= read -r p; do
    [ -e "$p" ] || hit "Unified log launch from deleted path" "path=$p"
  done < <(log show --last 24h --style compact \
    --predicate 'eventMessage CONTAINS[c] "exec" OR eventMessage CONTAINS[c] "posix_spawn"' 2>/dev/null \
    | grep -Eo '/(private/tmp|tmp|var/folders|Users)/[^ "'"'"'(),:#]+' | sort -u)

  # 6. Summary
  [ "$findings" -eq 0 ] && emit_clean "$MODULE_TECHNIQUE" "$MODULE_DESCRIPTION"
}

run_checks
