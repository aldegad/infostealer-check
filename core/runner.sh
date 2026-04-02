#!/bin/bash
# core/runner.sh — Module runner for infostealer-check v2 (macOS)
# Discovers and runs all .sh scripts in modules/*/ directories.
# Usage: ./core/runner.sh [--module T1555.003] [--format json|text]

set -euo pipefail

RUNNER_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd "$RUNNER_DIR/.." && pwd)

# ── defaults ──────────────────────────────────────────────────────
OUTPUT_FORMAT="${OUTPUT_FORMAT:-text}"
TARGET_MODULE=""
REPORT_DIR=""

# ── argument parsing ─────────────────────────────────────────────
usage() {
    cat <<'USAGE'
Usage: runner.sh [OPTIONS]

Options:
  --module ID      Run only the module whose filename contains ID
                   (e.g. --module T1555.003)
  --format FMT     Output format: json | text  (default: text)
  --report-dir DIR Custom report directory (default: reports/<timestamp>)
  -h, --help       Show this help
USAGE
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --module)
            TARGET_MODULE="$2"
            shift 2
            ;;
        --format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --report-dir)
            REPORT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            ;;
    esac
done

export OUTPUT_FORMAT

# ── report directory ─────────────────────────────────────────────
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
if [ -z "$REPORT_DIR" ]; then
    REPORT_DIR="${PROJECT_ROOT}/reports/${TIMESTAMP}"
fi
mkdir -p "$REPORT_DIR"

export REPORT_NDJSON_FILE="${REPORT_DIR}/findings.ndjson"
export REPORT_TEXT_FILE="${REPORT_DIR}/findings.txt"
export REPORT_FINDINGS_FILE="${REPORT_DIR}/findings.tsv"

# ── source output library ───────────────────────────────────────
source "$RUNNER_DIR/output.sh"

# ── discover modules ────────────────────────────────────────────
discover_modules() {
    local modules_dir="${PROJECT_ROOT}/modules"
    local scripts=()

    if [ ! -d "$modules_dir" ]; then
        echo "ERROR: modules/ directory not found at $modules_dir" >&2
        exit 1
    fi

    while IFS= read -r script; do
        [ -f "$script" ] || continue

        if [ -n "$TARGET_MODULE" ]; then
            local basename
            basename=$(basename "$script")
            if [[ "$basename" != *"$TARGET_MODULE"* ]]; then
                continue
            fi
        fi

        scripts+=("$script")
    done < <(find "$modules_dir" -mindepth 2 -maxdepth 2 -name '*.sh' -type f | sort)

    if [ ${#scripts[@]} -eq 0 ]; then
        if [ -n "$TARGET_MODULE" ]; then
            echo "ERROR: No module matching '$TARGET_MODULE' found" >&2
            exit 1
        else
            echo "ERROR: No modules found in $modules_dir" >&2
            exit 1
        fi
    fi

    printf '%s\n' "${scripts[@]}"
}

# ── run a single module ─────────────────────────────────────────
run_module() {
    local script="$1"
    local module_basename
    module_basename=$(basename "$script" .sh)
    local category
    category=$(basename "$(dirname "$script")")

    export RUNNER_MODULE_NAME="${category}/${module_basename}"

    if [ "$OUTPUT_FORMAT" = "text" ]; then
        printf '\n━━━ %s/%s ━━━\n' "$category" "$module_basename"
    fi

    # Run in a subshell so module failures don't kill the runner
    (
        cd "$PROJECT_ROOT"
        bash "$script"
    ) || true
}

# ── main ─────────────────────────────────────────────────────────
main() {
    local modules
    modules=$(discover_modules)

    local module_count=0
    while IFS= read -r m; do
        module_count=$((module_count + 1))
    done <<< "$modules"

    if [ "$OUTPUT_FORMAT" = "text" ]; then
        echo "╔══════════════════════════════════════════════════════╗"
        echo "║  infostealer-check v2 — macOS Security Scanner     ║"
        echo "╚══════════════════════════════════════════════════════╝"
        printf 'Host:     %s\n' "$(__infostealer_hostname)"
        printf 'OS:       %s\n' "$(__infostealer_os_version)"
        printf 'Time:     %s\n' "$(__infostealer_timestamp)"
        printf 'Modules:  %d\n' "$module_count"
        printf 'Report:   %s\n' "$REPORT_DIR"
    fi

    # Run each module
    while IFS= read -r script; do
        run_module "$script"
    done <<< "$modules"

    # ── summary ──────────────────────────────────────────────────
    local critical=0 high=0 medium=0 low=0 info_count=0 total=0

    if [ -f "$REPORT_FINDINGS_FILE" ]; then
        while IFS=$'\t' read -r severity _technique _title; do
            total=$((total + 1))
            case "$severity" in
                critical) critical=$((critical + 1)) ;;
                high)     high=$((high + 1)) ;;
                medium)   medium=$((medium + 1)) ;;
                low)      low=$((low + 1)) ;;
                info)     info_count=$((info_count + 1)) ;;
            esac
        done < "$REPORT_FINDINGS_FILE"
    fi

    if [ "$OUTPUT_FORMAT" = "text" ]; then
        echo ""
        echo "┌──────────────────────────────────────────────────────┐"
        echo "│  SUMMARY                                             │"
        echo "├──────────────────────────────────────────────────────┤"
        printf '│  Critical: %-3d  High: %-3d  Medium: %-3d             │\n' "$critical" "$high" "$medium"
        printf '│  Low:      %-3d  Info: %-3d  Total:  %-3d             │\n' "$low" "$info_count" "$total"
        echo "├──────────────────────────────────────────────────────┤"
        printf '│  Report: %-43s│\n' "$REPORT_DIR"
        echo "└──────────────────────────────────────────────────────┘"
    fi

    if [ "$OUTPUT_FORMAT" = "json" ]; then
        local summary
        summary="{"
        summary="${summary}\"timestamp\":\"$(__infostealer_timestamp)\""
        summary="${summary},\"hostname\":\"$(__infostealer_hostname)\""
        summary="${summary},\"os_version\":\"$(__infostealer_os_version)\""
        summary="${summary},\"event\":\"summary\""
        summary="${summary},\"modules_run\":${module_count}"
        summary="${summary},\"findings\":{\"critical\":${critical},\"high\":${high},\"medium\":${medium},\"low\":${low},\"info\":${info_count},\"total\":${total}}"
        summary="${summary},\"report_dir\":\"$REPORT_DIR\""
        summary="${summary}}"
        printf '%s\n' "$summary"
    fi

    # Exit code = min(critical + high, 125)
    local exit_code=$((critical + high))
    if [ "$exit_code" -gt 125 ]; then
        exit_code=125
    fi
    exit "$exit_code"
}

main
