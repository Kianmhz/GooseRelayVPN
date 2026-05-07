#!/bin/bash

# GooseRelayVPN Server Installer & Manager
# Repository: https://github.com/Kianmhz/GooseRelayVPN

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

INSTALL_DIR="/root/goose"
SERVICE_NAME="goose-relay"
REPO="Kianmhz/GooseRelayVPN"
BINARY_NAME="goose-server"
CONFIG_NAME="server_config.json"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Function to display the menu
show_menu() {
    echo -e "${GREEN}GooseRelayVPN Server Management Script${NC}"
    echo "1) Install GooseRelayVPN"
    echo "2) Update GooseRelayVPN"
    echo "3) Uninstall GooseRelayVPN"
    echo "4) Reconfigure GooseRelayVPN"
    echo "5) Exit"
}

# Function to check dependencies
check_dependencies() {
    echo -e "${YELLOW}Checking dependencies...${NC}"
    DEPS=("curl" "tar" "openssl" "jq")
    MISSING_DEPS=()
    for dep in "${DEPS[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            MISSING_DEPS+=("$dep")
        fi
    done

    if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
        echo -e "${YELLOW}Installing missing dependencies: ${MISSING_DEPS[*]}...${NC}"
        apt-get update
        apt-get install -y "${MISSING_DEPS[@]}"
    fi
}

# Function to get latest version from GitHub
get_latest_version() {
    curl -s "https://api.github.com/repos/$REPO/releases/latest" | jq -r .tag_name
}

# Function to get version of a binary
get_bin_version() {
    local bin_path=$1
    if [ ! -f "$bin_path" ]; then echo "none"; return; fi
    
    # 1. Try -version flag
    local ver=$("$bin_path" -version 2>/dev/null | grep -E "^v[0-9]+\.[0-9]+\.[0-9]+$" || echo "")
    if [ -n "$ver" ]; then echo "$ver"; return; fi
    
    # 2. Try strings extraction
    ver=$(strings "$bin_path" | grep -E "^v[0-9]+\.[0-9]+\.[0-9]+$" | head -n 1 || echo "")
    if [ -n "$ver" ]; then echo "$ver"; return; fi
    
    echo "unknown"
}

# Function to discover existing installation
discover_existing() {
    # Check our standard path first
    if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        EXISTING_BIN="$INSTALL_DIR/$BINARY_NAME"
        EXISTING_DIR="$INSTALL_DIR"
        return
    fi

    echo -e "${YELLOW}Checking for existing GooseRelayVPN installations...${NC}"
    
    # Check running processes
    local p_path=$(pgrep -af "$BINARY_NAME" | grep -v "$0" | awk '{print $2}' | head -n 1 || echo "")
    if [ -n "$p_path" ] && [ -f "$p_path" ]; then
        EXISTING_BIN="$p_path"
        EXISTING_DIR=$(dirname "$p_path")
        return
    fi

    # Check systemd services
    local s_path=$(systemctl show -p FragmentPath "$SERVICE_NAME" 2>/dev/null | cut -d= -f2)
    if [ -n "$s_path" ] && [ -f "$s_path" ]; then
        local exec_line=$(grep "ExecStart=" "$s_path" | cut -d= -f2 | awk '{print $1}')
        if [ -n "$exec_line" ] && [ -f "$exec_line" ]; then
            EXISTING_BIN="$exec_line"
            EXISTING_DIR=$(dirname "$exec_line")
            return
        fi
    fi

    # Common locations
    LOCATIONS=("/usr/local/bin/$BINARY_NAME" "/usr/bin/$BINARY_NAME" "/root/$BINARY_NAME")
    for loc in "${LOCATIONS[@]}"; do
        if [ -f "$loc" ]; then
            EXISTING_BIN="$loc"
            EXISTING_DIR=$(dirname "$loc")
            return
        fi
    done
}

# Function to detect platform
get_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l) ARCH="armv7" ;;
        *) echo -e "${RED}Unsupported architecture: $ARCH${NC}"; exit 1 ;;
    esac
    echo "${OS}-${ARCH}"
}

# Function to install/update the server
install_or_update() {
    local is_update=$1
    discover_existing
    
    LATEST_VERSION=$(get_latest_version)
    
    if [ -n "$EXISTING_BIN" ]; then
        CURRENT_VERSION=$(get_bin_version "$EXISTING_BIN")
        echo -e "Found existing installation at ${YELLOW}$EXISTING_BIN${NC} (Version: ${GREEN}$CURRENT_VERSION${NC})"
        
        if [ "$CURRENT_VERSION" == "$LATEST_VERSION" ] && [ "$is_update" == "true" ]; then
            echo -e "${GREEN}GooseRelayVPN is already up to date.${NC}"
            read -p "Force update anyway? (y/n): " force
            if [[ "$force" != "y" ]]; then return; fi
        fi

        if [ "$EXISTING_DIR" != "$INSTALL_DIR" ]; then
            echo -e "${YELLOW}Migration needed:${NC} Existing installation is in $EXISTING_DIR. Will move to $INSTALL_DIR."
            read -p "Proceed with migration and update? (y/n): " proceed
            if [[ "$proceed" != "y" ]]; then return; fi
        fi
    else
        if [ "$is_update" == "true" ]; then
            echo -e "${RED}No existing installation found to update.${NC}"
            return
        fi
        echo -e "${YELLOW}Installing GooseRelayVPN $LATEST_VERSION...${NC}"
    fi

    check_dependencies
    
    # 1. Shutdown if running
    echo -e "${YELLOW}Stopping service...${NC}"
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    # Also kill any orphaned processes
    pkill -f "$BINARY_NAME" || true

    # 2. Prepare directory
    mkdir -p "$INSTALL_DIR"
    
    # 3. Handle config migration/creation
    if [ -n "$EXISTING_DIR" ] && [ -f "$EXISTING_DIR/$CONFIG_NAME" ] && [ "$EXISTING_DIR" != "$INSTALL_DIR" ]; then
        echo -e "${YELLOW}Migrating configuration from $EXISTING_DIR...${NC}"
        cp "$EXISTING_DIR/$CONFIG_NAME" "$INSTALL_DIR/$CONFIG_NAME"
    elif [ ! -f "$INSTALL_DIR/$CONFIG_NAME" ]; then
        echo -e "${YELLOW}Creating fresh configuration...${NC}"
        curl -s "https://raw.githubusercontent.com/$REPO/main/server_config.example.json" -o "$INSTALL_DIR/$CONFIG_NAME"
        TUNNEL_KEY=$(openssl rand -hex 32)
        jq --arg key "$TUNNEL_KEY" '.tunnel_key = $key' "$INSTALL_DIR/$CONFIG_NAME" > "$INSTALL_DIR/$CONFIG_NAME.tmp" && mv "$INSTALL_DIR/$CONFIG_NAME.tmp" "$INSTALL_DIR/$CONFIG_NAME"
        echo -e "${GREEN}Generated tunnel_key: $TUNNEL_KEY${NC}"
        
        echo -e "\nRoute all outbound connections through a local SOCKS5 proxy? (Cloudflare WARP)"
        read -p "Activate upstream_proxy? (y/n): " use_proxy
        if [[ "$use_proxy" == "y" ]]; then
            jq '.upstream_proxy = "socks5://127.0.0.1:40000"' "$INSTALL_DIR/$CONFIG_NAME" > "$INSTALL_DIR/$CONFIG_NAME.tmp" && mv "$INSTALL_DIR/$CONFIG_NAME.tmp" "$INSTALL_DIR/$CONFIG_NAME"
        else
            jq 'del(.upstream_proxy)' "$INSTALL_DIR/$CONFIG_NAME" > "$INSTALL_DIR/$CONFIG_NAME.tmp" && mv "$INSTALL_DIR/$CONFIG_NAME.tmp" "$INSTALL_DIR/$CONFIG_NAME"
        fi
    fi

    # 4. Download and Install Binary
    PLATFORM=$(get_platform)
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST_VERSION/GooseRelayVPN-server-$LATEST_VERSION-$PLATFORM.tar.gz"
    echo -e "${YELLOW}Downloading $LATEST_VERSION for $PLATFORM...${NC}"
    curl -L "$DOWNLOAD_URL" -o "/tmp/goose.tar.gz"
    tar -xzf "/tmp/goose.tar.gz" -C "$INSTALL_DIR"
    rm "/tmp/goose.tar.gz"
    echo "$LATEST_VERSION" > "$INSTALL_DIR/.version"

    if [ ! -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        FIND_BIN=$(find "$INSTALL_DIR" -name "$BINARY_NAME" -type f | head -n 1)
        [ -n "$FIND_BIN" ] && mv "$FIND_BIN" "$INSTALL_DIR/$BINARY_NAME"
    fi
    chmod +x "$INSTALL_DIR/$BINARY_NAME"

    # 5. Setup/Update Service
    create_service
    
    # 6. Firewall
    configure_firewall

    echo -e "${GREEN}GooseRelayVPN is now running from $INSTALL_DIR!${NC}"
    systemctl status "$SERVICE_NAME" --no-pager
}

create_service() {
    echo -e "${YELLOW}Configuring systemd service...${NC}"
    cat <<EOF > /etc/systemd/system/$SERVICE_NAME.service
[Unit]
Description=GooseRelayVPN exit server
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$BINARY_NAME -config $INSTALL_DIR/$CONFIG_NAME
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"
}

configure_firewall() {
    PORT=$(jq -r '.server_port // 8443' "$INSTALL_DIR/$CONFIG_NAME")
    if command -v ufw &> /dev/null; then
        ufw allow "$PORT"/tcp
    elif command -v iptables &> /dev/null; then
        iptables -A INPUT -p tcp --dport "$PORT" -j ACCEPT
    fi
}

uninstall_server() {
    discover_existing
    if [ -z "$EXISTING_BIN" ]; then
        echo -e "${RED}GooseRelayVPN is not installed.${NC}"
        return
    fi
    read -p "Uninstall GooseRelayVPN from $EXISTING_DIR? (y/n): " choice
    if [[ "$choice" == "y" ]]; then
        systemctl stop "$SERVICE_NAME" || true
        systemctl disable "$SERVICE_NAME" || true
        rm -f /etc/systemd/system/$SERVICE_NAME.service
        systemctl daemon-reload
        rm -rf "$INSTALL_DIR"
        # If it was elsewhere, we don't necessarily want to rm -rf that entire dir
        # but we should remove the binary
        [ "$EXISTING_DIR" != "$INSTALL_DIR" ] && rm -f "$EXISTING_BIN"
        echo -e "${GREEN}Uninstalled successfully.${NC}"
    fi
}

reconfigure_server() {
    if [ ! -f "$INSTALL_DIR/$CONFIG_NAME" ]; then
        echo -e "${RED}Configuration not found at $INSTALL_DIR/$CONFIG_NAME${NC}"
        return
    fi
    echo "1) Regenerate tunnel_key"
    echo "2) Toggle upstream_proxy"
    read -p "Choice: " choice
    case $choice in
        1)
            NEW_KEY=$(openssl rand -hex 32)
            jq --arg key "$NEW_KEY" '.tunnel_key = $key' "$INSTALL_DIR/$CONFIG_NAME" > "$INSTALL_DIR/$CONFIG_NAME.tmp" && mv "$INSTALL_DIR/$CONFIG_NAME.tmp" "$INSTALL_DIR/$CONFIG_NAME"
            echo -e "${GREEN}New tunnel_key: $NEW_KEY${NC}"
            systemctl restart "$SERVICE_NAME"
            ;;
        2)
            HAS_PROXY=$(jq '.upstream_proxy' "$INSTALL_DIR/$CONFIG_NAME")
            if [ "$HAS_PROXY" != "null" ]; then
                jq 'del(.upstream_proxy)' "$INSTALL_DIR/$CONFIG_NAME" > "$INSTALL_DIR/$CONFIG_NAME.tmp" && mv "$INSTALL_DIR/$CONFIG_NAME.tmp" "$INSTALL_DIR/$CONFIG_NAME"
                echo "Upstream proxy disabled."
            else
                jq '.upstream_proxy = "socks5://127.0.0.1:40000"' "$INSTALL_DIR/$CONFIG_NAME" > "$INSTALL_DIR/$CONFIG_NAME.tmp" && mv "$INSTALL_DIR/$CONFIG_NAME.tmp" "$INSTALL_DIR/$CONFIG_NAME"
                echo "Upstream proxy enabled."
            fi
            systemctl restart "$SERVICE_NAME"
            ;;
    esac
}

if [ "$#" -gt 0 ]; then
    case $1 in
        install) install_or_update "false" ;;
        update) install_or_update "true" ;;
        uninstall) uninstall_server ;;
        *) show_menu ;;
    esac
else
    while true; do
        show_menu
        read -p "Enter choice [1-5]: " choice
        case $choice in
            1) install_or_update "false" ;;
            2) install_or_update "true" ;;
            3) uninstall_server ;;
            4) reconfigure_server ;;
            5) exit 0 ;;
        esac
        echo ""
    done
fi
