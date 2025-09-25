#!/bin/bash
# ===========================================
# PASSIVE OSINT SUITE MONITORING
# ===========================================
# System health monitoring and alerting

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
LOG_FILE="logs/monitoring.log"
ALERT_FILE="logs/alerts.log"
CHECK_INTERVAL=300  # 5 minutes

# Logging functions
log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1" >> "$LOG_FILE"
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warning() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARNING] $1" >> "$LOG_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARNING] $1" >> "$ALERT_FILE"
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$LOG_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$ALERT_FILE"
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $1" >> "$LOG_FILE"
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Create log directories
mkdir -p logs

# System health checks
check_disk_space() {
    local threshold=90
    local usage
    usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')

    if (( usage > threshold )); then
        log_warning "Disk usage is ${usage}% (threshold: ${threshold}%)"
        return 1
    else
        log_info "Disk usage: ${usage}%"
        return 0
    fi
}

check_memory() {
    local threshold=90
    local usage
    usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')

    if (( usage > threshold )); then
        log_warning "Memory usage is ${usage}% (threshold: ${threshold}%)"
        return 1
    else
        log_info "Memory usage: ${usage}%"
        return 0
    fi
}

check_python_processes() {
    local python_procs
    python_procs=$(pgrep -f python3 | wc -l)

    if (( python_procs > 10 )); then
        log_warning "High number of Python processes: ${python_procs}"
        return 1
    elif (( python_procs == 0 )); then
        log_info "No Python processes running (OSINT Suite not active)"
        return 0
    else
        log_info "Python processes running: ${python_procs}"
        return 0
    fi
}

check_network_connectivity() {
    if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
        log_info "Network connectivity: OK"
        return 0
    else
        log_warning "Network connectivity: FAILED"
        return 1
    fi
}

check_tor_status() {
    if command -v tor >/dev/null 2>&1; then
        if pgrep -f tor >/dev/null 2>&1; then
            log_info "Tor service: RUNNING"
            return 0
        else
            log_info "Tor service: INSTALLED but not running"
            return 0
        fi
    else
        log_info "Tor service: NOT INSTALLED"
        return 0
    fi
}

check_osint_suite_health() {
    if [[ -d ".venv" ]]; then
        if source .venv/bin/activate 2>/dev/null && python3 -c "
import sys
try:
    import requests, bs4
    from secrets_manager import secrets_manager
    from audit_trail import audit_trail
    print('Core components OK')
except ImportError as e:
    print(f'Import error: {e}')
    sys.exit(1)
" >/dev/null 2>&1; then
            log_info "OSINT Suite core components: HEALTHY"
            return 0
        else
            log_error "OSINT Suite core components: FAILED"
            return 1
        fi
    else
        log_warning "OSINT Suite virtual environment not found"
        return 1
    fi
}

check_log_sizes() {
    local max_size=$((100*1024*1024))  # 100MB

    for log_file in logs/*.log; do
        if [[ -f "$log_file" ]]; then
            local size
            size=$(stat -f%z "$log_file" 2>/dev/null || stat -c%s "$log_file" 2>/dev/null || echo "0")

            if (( size > max_size )); then
                log_warning "Log file $log_file is $(numfmt --to=iec-i --suffix=B $size) (consider rotation)"
            fi
        fi
    done
}

# Run all checks
run_all_checks() {
    log_info "Starting system health monitoring"

    local issues=0

    check_disk_space || ((issues++))
    check_memory || ((issues++))
    check_python_processes || ((issues++))
    check_network_connectivity || ((issues++))
    check_tor_status || ((issues++))
    check_osint_suite_health || ((issues++))
    check_log_sizes

    if (( issues > 0 )); then
        log_warning "Health check completed with $issues issue(s)"
        return 1
    else
        log_success "All health checks passed"
        return 0
    fi
}

# Generate report
generate_report() {
    echo ""
    echo "========================================"
    echo "PASSIVE OSINT SUITE HEALTH REPORT"
    echo "========================================"
    echo "Generated: $(date)"
    echo ""

    echo "RECENT LOG ENTRIES:"
    echo "-------------------"
    if [[ -f "$LOG_FILE" ]]; then
        tail -10 "$LOG_FILE" | while read -r line; do
            echo "  $line"
        done
    else
        echo "  No log file found"
    fi

    echo ""
    echo "ACTIVE ALERTS:"
    echo "--------------"
    if [[ -f "$ALERT_FILE" ]]; then
        tail -5 "$ALERT_FILE" | while read -r line; do
            echo "  $line"
        done
    else
        echo "  No active alerts"
    fi

    echo ""
    echo "SYSTEM RESOURCES:"
    echo "-----------------"
    echo "  Disk Usage: $(df -h / | tail -1 | awk '{print $5}')"
    echo "  Memory Usage: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
    echo "  Load Average: $(uptime | awk -F'load average:' '{print $2}')"

    echo ""
    echo "OSINT SUITE STATUS:"
    echo "-------------------"
    if [[ -d ".venv" ]]; then
        echo "  Virtual Environment: ✅ Present"
    else
        echo "  Virtual Environment: ❌ Missing"
    fi

    if [[ -f "config.ini" ]]; then
        echo "  Configuration: ✅ Present"
    else
        echo "  Configuration: ❌ Missing"
    fi

    if pgrep -f "python3 main.py" >/dev/null 2>&1; then
        echo "  Suite Running: ✅ Active"
    else
        echo "  Suite Running: ❌ Not running"
    fi
}

# Main function
main() {
    cd "$SCRIPT_DIR"

    case "${1:-}" in
        --daemon)
            log_info "Starting monitoring daemon (interval: ${CHECK_INTERVAL}s)"
            while true; do
                run_all_checks
                sleep "$CHECK_INTERVAL"
            done
            ;;
        --report)
            generate_report
            ;;
        --alerts)
            echo "Recent Alerts:"
            echo "--------------"
            if [[ -f "$ALERT_FILE" ]]; then
                cat "$ALERT_FILE"
            else
                echo "No alerts found"
            fi
            ;;
        --help|-h)
            echo "Passive OSINT Suite Monitoring"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --daemon     Run continuous monitoring"
            echo "  --report     Generate health report"
            echo "  --alerts     Show recent alerts"
            echo "  --help       Show this help"
            echo ""
            echo "Without options, runs a single health check."
            ;;
        *)
            run_all_checks
            ;;
    esac
}

# Run main function
main "$@"