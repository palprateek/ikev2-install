#!/bin/bash

# Secure IKEv2 VPN server installer for Ubuntu 22.04 and later
# Configures strongSwan for IKEv2 with EAP-MSCHAPv2 authentication

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

function isRoot() {
    if [ "${EUID}" -ne 0 ]; then
        echo "You need to run this script as root"
        exit 1
    fi
}

function checkVirt() {
    if ! command -v systemd-detect-virt &>/dev/null; then
        apt-get update
        apt-get install -y systemd || {
            echo "Failed to install systemd for virtualization detection"
            exit 1
        }
    fi
    if [ "$(systemd-detect-virt)" == "openvz" ]; then
        echo "OpenVZ is not supported"
        exit 1
    fi
    if [ "$(systemd-detect-virt)" == "lxc" ]; then
        echo "LXC is not supported"
        exit 1
    fi
}

function checkOS() {
    source /etc/os-release
    if [[ "${ID}" != "ubuntu" ]]; then
        echo "This script only supports Ubuntu"
        exit 1
    fi
    # Convert VERSION_ID (e.g., "22.04") to a numerical value (2204) for comparison
    VERSION_NUM=$(echo "${VERSION_ID}" | tr -d '.' | sed 's/^0*//')
    if [[ -z "${VERSION_NUM}" || "${VERSION_NUM}" -lt 2204 ]]; then
        echo "This script requires Ubuntu 22.04 or later"
        exit 1
    fi
    if [[ "${VERSION_NUM}" -gt 2204 ]]; then
        echo "Warning: This script was tested on Ubuntu 22.04. Newer versions (${VERSION_ID}) may have compatibility issues."
        echo "Proceed with caution and test thoroughly."
        echo "Press any key to continue or Ctrl+C to cancel..."
        read -r
    fi
}

function checkSystem() {
    # Check internet connectivity
    if ! ping -c 1 archive.ubuntu.com &>/dev/null; then
        echo "No internet connectivity. Please check your network."
        exit 1
    fi
    # Check disk space (minimum 500MB)
    if [[ $(df -m / | tail -1 | awk '{print $4}') -lt 500 ]]; then
        echo "Insufficient disk space. At least 500MB required."
        exit 1
    fi
}

function initialCheck() {
    isRoot
    checkOS
    checkVirt
    checkSystem
}

function installQuestions() {
    echo "Welcome to the IKEv2 VPN installer!"
    echo ""
    echo "I need to ask you a few questions before starting the setup."
    echo "Please provide the required information."
    echo ""

    # Manual IPv4 public address
    SERVER_PUB_IP=""
    until [[ ${SERVER_PUB_IP} =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; do
        read -rp "IPv4 public address: " SERVER_PUB_IP
        if ! ip addr show | grep -q "${SERVER_PUB_IP}"; then
            echo "Warning: ${SERVER_PUB_IP} not found on this server. Ensure it is correct."
        fi
    done

    # Manual public interface
    SERVER_NIC=""
    echo "Available network interfaces:"
    ip link show | awk '/^[0-9]+:/ {print $2}' | tr -d ':'
    until [[ -n ${SERVER_NIC} && -d /sys/class/net/${SERVER_NIC} ]]; do
        read -rp "Public interface: " SERVER_NIC
        if [[ ! -d /sys/class/net/${SERVER_NIC} ]]; then
            echo "Invalid interface. Please select a valid network interface."
        fi
    done

    # VPN server address (IP or DNS)
    read -rp "VPN server address (IP or DNS name): " -e -i "${SERVER_PUB_IP}" SERVER_ADDRESS
    if ! ping -c 1 "${SERVER_ADDRESS}" &>/dev/null; then
        echo "Warning: ${SERVER_ADDRESS} does not resolve. Ensure it is correct."
    fi

    # VPN username
    until [[ ${VPN_USERNAME} =~ ^[a-zA-Z0-9_-]+$ ]]; do
        read -rp "VPN username: " -e -i "vpnuser" VPN_USERNAME
    done

    # VPN password
    until [[ -n ${VPN_PASSWORD} ]]; do
        read -rp "VPN password: " VPN_PASSWORD
        if [[ -z ${VPN_PASSWORD} ]]; then
            echo "Password cannot be empty."
        fi
    done

    # Client name (for configuration naming)
    until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ ]]; do
        read -rp "First client name: " -e -i "client1" CLIENT_NAME
    done

    echo ""
    echo "Okay, that was all I needed. We are ready to set up your IKEv2 VPN server now."
    echo "Note: If using a cloud provider (e.g., AWS, GCP), ensure source/destination checks are disabled."
    echo "Press any key to continue..."
    read -r
}

function installStrongSwan() {
    echo "Installing strongSwan and dependencies..."
    apt-get update
    apt-get install -y strongswan strongswan-pki libcharon-extra-plugins rng-tools || {
        echo "Failed to install strongSwan packages. Check /var/log/apt/term.log for details."
        exit 1
    }
    # Start rngd for better entropy
    rngd -r /dev/urandom
}

function generateCertificates() {
    echo "Generating CA and server certificates..."
    for dir in cacerts certs private; do
        mkdir -p /etc/ipsec.d/${dir}
        chown root:root /etc/ipsec.d/${dir}
        chmod 700 /etc/ipsec.d/${dir}
    done
    
    # Generate CA key and certificate
    ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/ca-key.pem
    ipsec pki --self --ca --lifetime 3650 --in /etc/ipsec.d/private/ca-key.pem \
        --type rsa --dn "CN=VPN CA" --outform pem > /etc/ipsec.d/cacerts/ca-cert.pem

    # Generate server key and certificate
    ipsec pki --gen --type rsa --size 4096 --outform pem | tee /etc/ipsec.d/private/server-key.pem
    ipsec pki --pub --in /etc/ipsec.d/private/server-key.pem --type rsa | \
        ipsec pki --issue --lifetime 1825 --cacert /etc/ipsec.d/cacerts/ca-cert.pem \
        --cakey /etc/ipsec.d/private/ca-key.pem --dn "CN=${SERVER_ADDRESS}" \
        --san "${SERVER_ADDRESS}" --flag serverAuth --flag ikeIntermediate --outform pem \
        > /etc/ipsec.d/certs/server-cert.pem

    chown root:root /etc/ipsec.d/*/*
    chmod 600 /etc/ipsec.d/private/*
}

function configureStrongSwan() {
    echo "Configuring strongSwan..."
    
    # Backup existing configs
    mv /etc/ipsec.conf /etc/ipsec.conf.bak 2>/dev/null || true
    mv /etc/strongswan.conf /etc/strongswan.conf.bak 2>/dev/null || true

    # Write ipsec.conf
    cat > /etc/ipsec.conf << EOF
config setup
    charondebug="ike 2, knl 1, cfg 0"
    uniqueids=no

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    ike=aes256-sha256-modp2048,3des-sha1-modp2048!
    esp=aes256-sha256,3des-sha1!
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=${SERVER_ADDRESS}
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%identity
EOF

    # Write ipsec.secrets
    cat > /etc/ipsec.secrets << EOF
: RSA server-key.pem
${VPN_USERNAME} : EAP "${VPN_PASSWORD}"
EOF

    # Write strongswan.conf
    cat > /etc/strongswan.conf << EOF
charon {
    load_modular = yes
    duplicheck.enable = no
    compress = yes
    plugins {
        include /etc/strongswan.d/charon/*.conf
    }
    dns1 = 8.8.8.8
    dns2 = 8.8.4.4
}

include /etc/strongswan.d/*.conf
EOF

    # Validate configuration
    if ! ipsec rereadall &>/dev/null; then
        echo "Error in strongSwan configuration. Check /etc/ipsec.conf and /etc/ipsec.secrets."
        exit 1
    fi
}

function configureFirewall() {
    echo "Configuring firewall..."
    # Check for ufw and disable if active
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        echo "UFW is active and may conflict. Disabling UFW..."
        ufw disable
    fi

    apt-get install -y iptables-persistent || {
        echo "Failed to install iptables-persistent"
        exit 1
    }
    if ! dpkg -l | grep -q iptables-persistent; then
        echo "iptables-persistent installation failed."
        exit 1
    fi

    iptables -A INPUT -i "${SERVER_NIC}" -p udp --dport 500 -j ACCEPT
    iptables -A INPUT -i "${SERVER_NIC}" -p udp --dport 4500 -j ACCEPT
    iptables -A FORWARD -i "${SERVER_NIC}" -o "${SERVER_NIC}" -p esp -j ACCEPT
    iptables -A FORWARD -i "${SERVER_NIC}" -o "${SERVER_NIC}" -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o "${SERVER_NIC}" -j MASQUERADE

    # Save iptables rules
    iptables-save > /etc/iptables/rules.v4
}

function enableIPForwarding() {
    echo "Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-ipforward.conf
    sysctl --system
}

function generateClientConfig() {
    local CLIENT_NAME=$1
    echo "Generating configuration for client ${CLIENT_NAME}..."

    # Create client configuration instructions
    CLIENT_DIR="/root/ikev2-clients"
    mkdir -p "${CLIENT_DIR}"
    cat > "${CLIENT_DIR}/${CLIENT_NAME}-instructions.txt" << EOF
IKEv2 VPN Client Configuration for ${CLIENT_NAME}

1. Copy the CA certificate to your client device (e.g., Windows):
   - Run the following command on the server to display the CA certificate:
     cat /etc/ipsec.d/cacerts/ca-cert.pem
   - Copy the output to a file named ca-cert.pem on your client device.
2. Securely transfer the CA certificate using SCP if needed:
   scp root@${SERVER_ADDRESS}:/etc/ipsec.d/cacerts/ca-cert.pem .
3. Configure your client with:
   - Server address: ${SERVER_ADDRESS}
   - Username: ${VPN_USERNAME}
   - Password: [Your chosen password]
4. For Windows:
   - Import the CA certificate into the Trusted Root Certification Authorities store.
   - Set up an IKEv2 VPN connection using the server address and credentials.
5. For detailed client setup instructions (Windows, macOS, Android), refer to your client documentation or online guides.
EOF

    echo "Client ${CLIENT_NAME} configuration saved to ${CLIENT_DIR}/${CLIENT_NAME}-instructions.txt"
    echo "Displaying CA certificate for manual copying..."
    cat /etc/ipsec.d/cacerts/ca-cert.pem
}

function newClient() {
    echo "Adding a new client..."
    until [[ ${NEW_CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ ]]; do
        read -rp "Client name: " -e -i "client$(date +%s)" NEW_CLIENT_NAME
    done
    until [[ ${NEW_VPN_USERNAME} =~ ^[a-zA-Z0-9_-]+$ ]]; do
        read -rp "VPN username: " -e -i "vpnuser${NEW_CLIENT_NAME}" NEW_VPN_USERNAME
    done
    until [[ -n ${NEW_VPN_PASSWORD} ]]; do
        read -rp "VPN password: " NEW_VPN_PASSWORD
        if [[ -z ${NEW_VPN_PASSWORD} ]]; then
            echo "Password cannot be empty."
        fi
    done
    echo "${NEW_VPN_USERNAME} : EAP \"${NEW_VPN_PASSWORD}\"" >> /etc/ipsec.secrets
    generateClientConfig "${NEW_CLIENT_NAME}"
    systemctl restart strongswan-starter
    if ! systemctl is-active --quiet strongswan-starter; then
        echo "strongSwan failed to start. Check logs with 'journalctl -u strongswan-starter'."
        exit 1
    fi
    echo "Client ${NEW_CLIENT_NAME} added successfully."
}

function listClients() {
    echo "Listing all clients..."
    grep -v ": RSA" /etc/ipsec.secrets | awk '{print $1}' | sort -u
}

function revokeClient() {
    echo "Revoking a client..."
    listClients
    until [[ ${REVOKE_CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ ]]; do
        read -rp "VPN username to revoke: " REVOKE_CLIENT_NAME
    done
    if grep -q "^${REVOKE_CLIENT_NAME} : EAP" /etc/ipsec.secrets; then
        sed -i "/^${REVOKE_CLIENT_NAME} : EAP/d" /etc/ipsec.secrets
        rm -f "/root/ikev2-clients/${REVOKE_CLIENT_NAME}-instructions.txt"
        systemctl restart strongswan-starter
        if ! systemctl is-active --quiet strongswan-starter; then
            echo "strongSwan failed to start after revocation. Check logs with 'journalctl -u strongswan-starter'."
            exit 1
        fi
        echo "Client ${REVOKE_CLIENT_NAME} revoked successfully."
    else
        echo "Client ${REVOKE_CLIENT_NAME} does not exist."
    fi
}

function uninstallVpn() {
    echo "Uninstalling IKEv2 VPN..."
    read -rp "Are you sure you want to remove strongSwan and all configurations? [y/N]: " -e -i "N" REMOVE
    if [[ "${REMOVE}" =~ ^[yY]$ ]]; then
        apt-get purge -y strongswan strongswan-pki libcharon-extra-plugins iptables-persistent rng-tools
        apt-get autoremove -y
        rm -rf /etc/ipsec.d /etc/iptables /etc/sysctl.d/99-ipforward.conf /root/ikev2-clients
        mv /etc/ipsec.conf.bak /etc/ipsec.conf 2>/dev/null || true
        mv /etc/strongswan.conf.bak /etc/strongswan.conf 2>/dev/null || true
        sysctl -w net.ipv4.ip_forward=0
        sysctl --system
        if systemctl is-active --quiet strongswan-starter; then
            echo "Failed to uninstall strongSwan properly."
            exit 1
        else
            echo "IKEv2 VPN uninstalled successfully."
            exit 0
        fi
    else
        echo "Removal aborted!"
    fi
}

function manageMenu() {
    echo "Welcome to IKEv2 VPN installer!"
    echo "It looks like the IKEv2 VPN is already installed."
    echo ""
    echo "What do you want to do?"
    echo "   1) Add a new client"
    echo "   2) List all clients"
    echo "   3) Revoke existing client"
    echo "   4) Uninstall IKEv2 VPN"
    echo "   5) Exit"
    until [[ ${MENU_OPTION} =~ ^[1-5]$ ]]; do
        read -rp "Select an option [1-5]: " MENU_OPTION
    done
    case "${MENU_OPTION}" in
        1) newClient ;;
        2) listClients ;;
        3) revokeClient ;;
        4) uninstallVpn ;;
        5) exit 0 ;;
    esac
}

function installVpn() {
    initialCheck
    installQuestions
    installStrongSwan
    generateCertificates
    configureStrongSwan
    configureFirewall
    enableIPForwarding
    generateClientConfig "${CLIENT_NAME}"
    systemctl enable strongswan-starter
    systemctl restart strongswan-starter
    if ! systemctl is-active --quiet strongswan-starter; then
        echo "strongSwan failed to start. Check logs with 'journalctl -u strongswan-starter'."
        exit 1
    fi
    echo "IKEv2 VPN server installed successfully!"
    echo "Client configuration saved to /root/ikev2-clients/${CLIENT_NAME}-instructions.txt"
}

# Main logic
if [ -f /etc/ipsec.conf ] && grep -q "conn ikev2-vpn" /etc/ipsec.conf; then
    manageMenu
else
    installVpn
fi