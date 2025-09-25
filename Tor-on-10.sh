#!/bin/bash
#
# Tor Transparent Proxy Router - ON Script
# Hardens the system and routes all traffic through Tor.
# Includes DNS leak protection and comprehensive error handling.
# MUST be run with sudo.

set -euo pipefail  # Exit on any error, undefined variable, or pipe failure

# --- CONFIGURATION ---
readonly TOR_USER="debian-tor"
readonly TORRC="/etc/tor/torrc"
readonly NM_CONF_DIR="/etc/NetworkManager/conf.d"
readonly NM_CONF_FILE="${NM_CONF_DIR}/99-tor-router-dns.conf"
readonly BACKUP_DIR="/etc/tor-router-backup"
readonly LOCK_FILE="/var/run/tor-router.lock"

# --- FUNCTIONS ---
die() {
    echo -e "\n[!] FATAL ERROR: $1" >&2
    echo "[*] Attempting automatic cleanup..."
    cleanup
    exit 1
}

log() {
    echo "[+] $1"
}

cleanup() {
    # Remove lock file if it exists and we own it
    if [[ -f "$LOCK_FILE" && "$(cat "$LOCK_FILE" 2>/dev/null)" == "$$" ]]; then
        rm -f "$LOCK_FILE"
    fi
    return 0
}

check_dependencies() {
    local deps=("tor" "iptables" "ip6tables" "systemctl" "id")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            die "Missing required dependency: $dep"
        fi
    done
}

check_tor_uid() {
    if ! TOR_UID=$(id -u "$TOR_USER" 2>/dev/null); then
        die "Tor user '$TOR_USER' does not exist. Please install Tor."
    fi
    readonly TOR_UID
}

sanity_checks() {
    # Must be root
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (use sudo)."
    fi

    # Prevent concurrent execution
    if [[ -f "$LOCK_FILE" ]]; then
        die "Lock file exists. Is another instance running? If not, delete $LOCK_FILE"
    fi
    echo "$$" > "$LOCK_FILE"

    # Check if we're in a remote session

}

create_backup() {
    mkdir -p "$BACKUP_DIR"
    cp -f /etc/resolv.conf "${BACKUP_DIR}/resolv.conf" || die "Failed to backup resolv.conf"
    iptables-save > "${BACKUP_DIR}/iptables.rules" 2>/dev/null || true
    ip6tables-save > "${BACKUP_DIR}/ip6tables.rules" 2>/dev/null || true
    sysctl -n net.ipv4.ip_forward > "${BACKUP_DIR}/ip_forward" 2>/dev/null || true
}

configure_tor() {
    log "Configuring Tor..."
    # Ensure required lines exist in torrc
    local torrc_lines=(
        "DNSPort 5353"
        "TransPort 9040"
        "AutomapHostsOnResolve 1"
    )

    for line in "${torrc_lines[@]}"; do
        if ! grep -q "^${line}" "$TORRC"; then
            echo "$line" | tee -a "$TORRC" > /dev/null
        fi
    done

    log "Restarting Tor service..."
    if ! systemctl restart tor; then
        die "Failed to restart Tor. Check journalctl -u tor for details."
    fi
    # Give Tor time to bind to ports
    sleep 2
}

configure_iptables() {
    log "Setting up firewall rules..."

    # Flush all rules and set default policies to DROP
    iptables -F
    iptables -t nat -F
    iptables -X
    iptables -t nat -X
    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
    iptables -P FORWARD DROP

    ip6tables -F
    ip6tables -X
    ip6tables -P INPUT DROP
    ip6tables -P OUTPUT DROP
    ip6tables -P FORWARD DROP

    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward

    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A OUTPUT -o lo -j ACCEPT

    # Allow established connections (critical for stability)
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow Tor daemon output
    iptables -A OUTPUT -m owner --uid-owner "$TOR_UID" -j ACCEPT

    # CRITICAL: Allow traffic TO Tor's ports
    iptables -A OUTPUT -p tcp -m tcp --dport 9040 -j ACCEPT
    iptables -A OUTPUT -p udp -m udp --dport 5353 -j ACCEPT

    # CRITICAL: Exclude Tor's traffic from being redirected
    iptables -t nat -A OUTPUT -p udp --dport 53 -m owner --uid-owner "$TOR_UID" -j RETURN
    iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353

    iptables -t nat -A OUTPUT -p tcp --syn -m owner --uid-owner "$TOR_UID" -j RETURN
    iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports 9040

    # Log any dropped packets (helpful for debugging)
    iptables -A OUTPUT -j LOG --log-prefix "TorRouter-Dropped: " --log-level 4
}

configure_dns() {
    log "Configuring DNS..."
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    chmod 644 /etc/resolv.conf

    mkdir -p "$NM_CONF_DIR"
    echo -e "[main]\ndns=none" > "$NM_CONF_FILE"
    systemctl try-restart NetworkManager.service || true
}

verify_connection() {
    log "Verifying Tor connection..."
    sleep 3  # Give things a moment to settle

    if ! timeout 30 curl -s --socks5-hostname 127.0.0.1:9050 \
         "https://check.torproject.org/api/ip" | grep -q "true"; then
        die "Tor connection verification failed. Check your setup."
    fi

    log "Tor connection successfully verified!"
}

# --- MAIN EXECUTION ---
main() {
    echo "=== Tor Transparent Router Activation ==="
    trap cleanup EXIT INT TERM  # Ensure cleanup on any exit

    sanity_checks
    check_dependencies
    check_tor_uid
    create_backup
    configure_tor
    configure_iptables
    configure_dns
    verify_connection

    echo -e "\n[✓] SUCCESS: All traffic is now routed through Tor."
    echo "    DNS leak protection is active."
    echo "    Run $(basename "$0" | sed 's/on/off/') to revert changes."
}

main "$@"
