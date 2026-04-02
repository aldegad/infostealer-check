#!/bin/bash

if [ -z "${INFOSTEALER_OUTPUT_SH_LOADED:-}" ]; then
    INFOSTEALER_OUTPUT_SH_LOADED=1

    __infostealer_output_format() {
        printf '%s' "${OUTPUT_FORMAT:-text}"
    }

    __infostealer_color_enabled() {
        if [ "${NO_COLOR:-}" = "1" ]; then
            return 1
        fi

        [ -t 1 ]
    }

    __infostealer_hostname() {
        if [ -n "${INFOSTEALER_HOSTNAME:-}" ]; then
            printf '%s' "$INFOSTEALER_HOSTNAME"
            return
        fi

        INFOSTEALER_HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
        printf '%s' "$INFOSTEALER_HOSTNAME"
    }

    __infostealer_os_version() {
        if [ -n "${INFOSTEALER_OS_VERSION:-}" ]; then
            printf '%s' "$INFOSTEALER_OS_VERSION"
            return
        fi

        local product build
        product=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
        build=$(sw_vers -buildVersion 2>/dev/null || echo "")

        if [ -n "$build" ]; then
            INFOSTEALER_OS_VERSION="${product} (${build})"
        else
            INFOSTEALER_OS_VERSION="$product"
        fi

        printf '%s' "$INFOSTEALER_OS_VERSION"
    }

    __infostealer_timestamp() {
        date -u +"%Y-%m-%dT%H:%M:%SZ"
    }

    __infostealer_module_name() {
        if [ -n "${RUNNER_MODULE_NAME:-}" ]; then
            printf '%s' "$RUNNER_MODULE_NAME"
            return
        fi

        if [ -n "${MODULE_ID:-}" ]; then
            printf '%s' "$MODULE_ID"
            return
        fi

        printf '%s' "unknown"
    }

    __infostealer_json_escape() {
        local value
        value=${1:-}
        value=${value//\\/\\\\}
        value=${value//\"/\\\"}
        value=${value//$'\n'/\\n}
        value=${value//$'\r'/\\r}
        value=${value//$'\t'/\\t}
        printf '%s' "$value"
    }

    __infostealer_print_text() {
        local event="$1"
        local severity="$2"
        local technique_id="$3"
        local title="$4"
        local message="$5"
        local evidence="$6"
        local remediation="$7"
        local color_reset="" color="" label="" prefix=""
        local line

        if __infostealer_color_enabled; then
            color_reset=$'\033[0m'
            case "$severity" in
                critical) color=$'\033[1;31m' ;;
                high) color=$'\033[0;31m' ;;
                medium) color=$'\033[0;33m' ;;
                low) color=$'\033[0;32m' ;;
                info) color=$'\033[0;34m' ;;
                *) color="" ;;
            esac
        fi

        case "$event" in
            finding)
                case "$severity" in
                    critical) label="[!!]" ;;
                    high) label="[X]" ;;
                    medium) label="[!]" ;;
                    low) label="[-]" ;;
                    *) label="[?]" ;;
                esac
                prefix="${label} ${technique_id} ${title}"
                ;;
            clean)
                label="[OK]"
                prefix="${label} ${technique_id} ${title}"
                ;;
            info)
                label="[i]"
                prefix="${label} ${technique_id} ${title}"
                ;;
            *)
                label="[?]"
                prefix="${label} ${technique_id} ${title}"
                ;;
        esac

        line="$prefix"
        if [ -n "$message" ]; then
            line="${line}: ${message}"
        fi

        if [ -n "$color" ]; then
            printf '%b%s%b\n' "$color" "$line" "$color_reset"
        else
            printf '%s\n' "$line"
        fi

        if [ -n "$evidence" ]; then
            printf '    evidence: %s\n' "$evidence"
        fi

        if [ -n "$remediation" ]; then
            printf '    remediation: %s\n' "$remediation"
        fi
    }

    __infostealer_append_text_report() {
        local event="$1"
        local severity="$2"
        local technique_id="$3"
        local title="$4"
        local message="$5"
        local evidence="$6"
        local remediation="$7"
        local report_file="${REPORT_TEXT_FILE:-}"
        local prefix

        [ -n "$report_file" ] || return 0

        mkdir -p "$(dirname "$report_file")"

        case "$event" in
            finding)
                case "$severity" in
                    critical) prefix="[!!]" ;;
                    high) prefix="[X]" ;;
                    medium) prefix="[!]" ;;
                    low) prefix="[-]" ;;
                    *) prefix="[?]" ;;
                esac
                ;;
            clean) prefix="[OK]" ;;
            info) prefix="[i]" ;;
            *) prefix="[?]" ;;
        esac

        {
            if [ -n "$message" ]; then
                printf '%s %s %s: %s\n' "$prefix" "$technique_id" "$title" "$message"
            else
                printf '%s %s %s\n' "$prefix" "$technique_id" "$title"
            fi

            if [ -n "$evidence" ]; then
                printf '    evidence: %s\n' "$evidence"
            fi

            if [ -n "$remediation" ]; then
                printf '    remediation: %s\n' "$remediation"
            fi
        } >> "$report_file"
    }

    __infostealer_emit_json() {
        local event="$1"
        local severity="$2"
        local technique_id="$3"
        local title="$4"
        local message="$5"
        local evidence="$6"
        local remediation="$7"
        local timestamp hostname os_version module json_line

        timestamp=$(__infostealer_timestamp)
        hostname=$(__infostealer_hostname)
        os_version=$(__infostealer_os_version)
        module=$(__infostealer_module_name)

        json_line="{"
        json_line="${json_line}\"timestamp\":\"$(__infostealer_json_escape "$timestamp")\""
        json_line="${json_line},\"hostname\":\"$(__infostealer_json_escape "$hostname")\""
        json_line="${json_line},\"os_version\":\"$(__infostealer_json_escape "$os_version")\""
        json_line="${json_line},\"module\":\"$(__infostealer_json_escape "$module")\""
        json_line="${json_line},\"technique_id\":\"$(__infostealer_json_escape "$technique_id")\""
        json_line="${json_line},\"event\":\"$(__infostealer_json_escape "$event")\""
        json_line="${json_line},\"severity\":\"$(__infostealer_json_escape "$severity")\""
        json_line="${json_line},\"title\":\"$(__infostealer_json_escape "$title")\""

        if [ -n "$message" ]; then
            json_line="${json_line},\"details\":\"$(__infostealer_json_escape "$message")\""
        fi

        if [ -n "$evidence" ]; then
            json_line="${json_line},\"evidence\":\"$(__infostealer_json_escape "$evidence")\""
        fi

        if [ -n "$remediation" ]; then
            json_line="${json_line},\"remediation\":\"$(__infostealer_json_escape "$remediation")\""
        fi

        json_line="${json_line}}"

        if [ "$(__infostealer_output_format)" = "json" ]; then
            printf '%s\n' "$json_line"
        fi

        if [ -n "${REPORT_NDJSON_FILE:-}" ]; then
            mkdir -p "$(dirname "$REPORT_NDJSON_FILE")"
            printf '%s\n' "$json_line" >> "$REPORT_NDJSON_FILE"
        fi
    }

    __infostealer_record_finding() {
        local severity="$1"
        local technique_id="$2"
        local title="$3"

        if [ -n "${REPORT_FINDINGS_FILE:-}" ]; then
            mkdir -p "$(dirname "$REPORT_FINDINGS_FILE")"
            printf '%s\t%s\t%s\n' "$severity" "$technique_id" "$title" >> "$REPORT_FINDINGS_FILE"
        fi
    }

    __infostealer_emit() {
        local event="$1"
        local severity="$2"
        local technique_id="$3"
        local title="$4"
        local message="$5"
        local evidence="$6"
        local remediation="$7"

        __infostealer_emit_json "$event" "$severity" "$technique_id" "$title" "$message" "$evidence" "$remediation"
        __infostealer_append_text_report "$event" "$severity" "$technique_id" "$title" "$message" "$evidence" "$remediation"

        if [ "$(__infostealer_output_format)" = "text" ]; then
            __infostealer_print_text "$event" "$severity" "$technique_id" "$title" "$message" "$evidence" "$remediation"
        fi

        if [ "$event" = "finding" ]; then
            __infostealer_record_finding "$severity" "$technique_id" "$title"
        fi
    }

    emit_finding() {
        local technique_id="$1"
        local title="$2"
        local severity="$3"
        local evidence="$4"
        local remediation="$5"

        __infostealer_emit "finding" "$severity" "$technique_id" "$title" "" "$evidence" "$remediation"
    }

    emit_clean() {
        local technique_id="$1"
        local title="$2"

        __infostealer_emit "clean" "info" "$technique_id" "$title" "" "" ""
    }

    emit_info() {
        local technique_id="$1"
        local title="$2"
        local details="${3:-}"

        if [ $# -lt 3 ]; then
            details="$title"
            title="Info"
        fi

        __infostealer_emit "info" "info" "$technique_id" "$title" "$details" "" ""
    }
fi
