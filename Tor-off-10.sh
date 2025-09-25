#!/bin/bash
#
# Tor Transparent Proxy Router - OFF Script
# Safely reverts all changes made by the ON script.
# MUST be run with sudo.

set -euo pipefail

# --- CONFIGURATION ---
readonly BACKUP_DIR="/etc/tor-router-backup"
readonly NM_CONF_DIR="/etc/NetworkManager/conf.d"
readonly NM_CONF_FILE="${NM_CONF_DIR}/99-tor-router-dns.conf"
readonly LOCK_FILE="/var/run/tor-router.lock"

# --- FUNCTIONS ---
die() {
    echo -e "\n[!] ERROR: $1" >&2
    exit 1
}

log() {
    echo "[+] $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (use sudo)."
    fi
}

check_lock() {
    if [[ ! -f "$LOCK_FILE" ]]; then
        log "No active lock found. Proceeding with cleanup anyway..."
    elif [[ "$(cat "$LOCK_FILE" 2>/dev/null)" != "$$" ]]; then
        die "Lock file exists for a different process. Please check if another instance is running."
    fi
}

restore_iptables() {
    log "Restoring firewall rules..."
    # Flush all rules and set default policies to ACCEPT
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -F
    iptables -t nat -F
    iptables -X
    iptables -t nat -X

    ip6tables -P INPUT ACCEPT
    ip6tables -P OUTPUT ACCEPT
    ip6tables -P FORWARD ACCEPT
    ip6tables -F
    ip6tables -X

    # Restore from backup if available
    if [[ -f "${BACKUP_DIR}/iptables.rules" ]]; then
        iptables-restore < "${BACKUP_DIR}/iptables.rules" 2>/dev/null || true
    fi
    if [[ -f "${BACKUP_DIR}/ip6tables.rules" ]]; then
        ip6tables-restore < "${BACKUP_DIR}/ip6tables.rules" 2>/dev/null || true
    fi
}

restore_dns() {
    log "Restoring DNS settings..."
    rm -f "$NM_CONF_FILE"
    systemctl try-restart NetworkManager.service || true

    if [[ -f "${BACKUP_DIR}/resolv.conf" ]]; then
        cp -f "${BACKUP_DIR}/resolv.conf" /etc/resolv.conf
    else
        # Fallback: Use a known good DNS
        echo "nameserver 1.1.1.1" > /etc/resolv.conf
        echo "nameserver 8.8.8.8" >> /etc/resolv.conf
    fi
}

restore_sysctl() {
    log "Restoring system settings..."
    if [[ -f "${BACKUP_DIR}/ip_forward" ]]; then
        local ip_forward
        ip_forward=$(cat "${BACKUP_DIR}/ip_forward")
        echo "$ip_forward" > /proc/sys/net/ipv4/ip_forward
    else
        echo 0 > /proc/sys/net/ipv4/ip_forward
    fi
}

cleanup_backups() {
    # Keep backups for debugging, but remove old lock file
    rm -f "$LOCK_FILE"
    log "Backups preserved in: $BACKUP_DIR"
}

# --- MAIN EXECUTION ---
main() {
    echo "=== Tor Transparent Router Deactivation ==="
    
    check_root
    check_lock

    restore_iptables
    restore_dns
    restore_sysctl
    cleanup_backups

    echo -e "\n[✓] SUCCESS: All changes reverted. Normal network restored."
    echo "    You may need to restart your applications."
}

main "$@"