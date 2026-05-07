#!/bin/bash

# GooseRelayVPN Server Installer
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

# Function to get installed version
get_installed_version() {
    if [ -f "$INSTALL_DIR/.version" ]; then
        cat "$INSTALL_DIR/.version"
    else
        echo "unknown"
    fi
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

# Function to install the server
install_server() {
    if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        echo -e "${YELLOW}GooseRelayVPN is already installed.${NC}"
        read -p "Do you want to reinstall? (y/n): " choice
        if [[ "$choice" != "y" ]]; then return; fi
    fi

    check_dependencies
    
    VERSION=$(get_latest_version)
    PLATFORM=$(get_platform)
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/GooseRelayVPN-server-$VERSION-$PLATFORM.tar.gz"
    
    echo -e "${YELLOW}Downloading GooseRelayVPN $VERSION for $PLATFORM...${NC}"
    mkdir -p "$INSTALL_DIR"
    curl -L "$DOWNLOAD_URL" -o "/tmp/goose.tar.gz"
    tar -xzf "/tmp/goose.tar.gz" -C "$INSTALL_DIR"
    rm "/tmp/goose.tar.gz"
    echo "$VERSION" > "$INSTALL_DIR/.version"
    
    # Check if we got the binary (sometimes it's inside a folder in the tar)
    if [ ! -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        # Try to find it
        FIND_BIN=$(find "$INSTALL_DIR" -name "$BINARY_NAME" -type f | head -n 1)
        if [ -n "$FIND_BIN" ]; then
            mv "$FIND_BIN" "$INSTALL_DIR/$BINARY_NAME"
        else
            echo -e "${RED}Error: Binary not found after extraction.${NC}"
            exit 1
        fi
    fi
    chmod +x "$INSTALL_DIR/$BINARY_NAME"

    # Configuration
    if [ ! -f "$INSTALL_DIR/$CONFIG_NAME" ]; then
        echo -e "${YELLOW}Creating configuration...${NC}"
        # Fetch example config if not exists
        curl -s "https://raw.githubusercontent.com/$REPO/main/server_config.example.json" -o "$INSTALL_DIR/$CONFIG_NAME"
        
        TUNNEL_KEY=$(openssl rand -hex 32)
        
        # Use jq for more robust JSON manipulation
        jq --arg key "$TUNNEL_KEY" '.tunnel_key = $key' "$INSTALL_DIR/$CONFIG_NAME" > "$INSTALL_DIR/$CONFIG_NAME.tmp" && mv "$INSTALL_DIR/$CONFIG_NAME.tmp" "$INSTALL_DIR/$CONFIG_NAME"
        
        echo -e "${GREEN}Generated tunnel_key: $TUNNEL_KEY${NC}"
        echo -e "${YELLOW}PLEASE COPY AND SAVE THIS KEY FOR CLIENT CONFIGURATION!${NC}"
        
        echo -e "\nRoute all outbound connections through a local SOCKS5 proxy? (Useful for Cloudflare WARP)"
        read -p "Activate upstream_proxy? (y/n): " use_proxy
        if [[ "$use_proxy" == "y" ]]; then
            jq '.upstream_proxy = "socks5://127.0.0.1:40000"' "$INSTALL_DIR/$CONFIG_NAME" > "$INSTALL_DIR/$CONFIG_NAME.tmp" && mv "$INSTALL_DIR/$CONFIG_NAME.tmp" "$INSTALL_DIR/$CONFIG_NAME"
        else
            jq 'del(.upstream_proxy)' "$INSTALL_DIR/$CONFIG_NAME" > "$INSTALL_DIR/$CONFIG_NAME.tmp" && mv "$INSTALL_DIR/$CONFIG_NAME.tmp" "$INSTALL_DIR/$CONFIG_NAME"
        fi
    fi

    # Systemd Service
    create_service
    
    # Firewall
    configure_firewall

    echo -e "${GREEN}GooseRelayVPN installation complete!${NC}"
    systemctl status "$SERVICE_NAME" --no-pager
}

# Function to create/update systemd service
create_service() {
    echo -e "${YELLOW}Setting up systemd service...${NC}"
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

# Function to configure firewall
configure_firewall() {
    PORT=$(jq -r '.server_port // 8443' "$INSTALL_DIR/$CONFIG_NAME")
    echo -e "${YELLOW}Opening port $PORT...${NC}"
    if command -v ufw &> /dev/null; then
        ufw allow "$PORT"/tcp
    elif command -v iptables &> /dev/null; then
        iptables -A INPUT -p tcp --dport "$PORT" -j ACCEPT
    else
        echo -e "${YELLOW}No ufw or iptables found. Please open port $PORT manually.${NC}"
    fi
}

# Function to update the server
update_server() {
    if [ ! -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        echo -e "${RED}GooseRelayVPN is not installed. Use install option instead.${NC}"
        return
    fi

    check_dependencies
    CURRENT_VERSION=$(get_installed_version)
    LATEST_VERSION=$(get_latest_version)

    if [ "$CURRENT_VERSION" == "$LATEST_VERSION" ]; then
        echo -e "${GREEN}GooseRelayVPN is already up to date ($CURRENT_VERSION).${NC}"
        read -p "Do you want to force update anyway? (y/n): " choice
        if [[ "$choice" != "y" ]]; then return; fi
    else
        echo -e "${YELLOW}A new version is available: $LATEST_VERSION (Current: $CURRENT_VERSION)${NC}"
        read -p "Do you want to update? (y/n): " choice
        if [[ "$choice" != "y" ]]; then return; fi
    fi

    PLATFORM=$(get_platform)
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST_VERSION/GooseRelayVPN-server-$LATEST_VERSION-$PLATFORM.tar.gz"
    
    echo -e "${YELLOW}Downloading update $LATEST_VERSION...${NC}"
    curl -L "$DOWNLOAD_URL" -o "/tmp/goose.tar.gz"
    
    # Stop service before updating
    systemctl stop "$SERVICE_NAME" || true
    
    tar -xzf "/tmp/goose.tar.gz" -C "$INSTALL_DIR"
    rm "/tmp/goose.tar.gz"
    echo "$LATEST_VERSION" > "$INSTALL_DIR/.version"
    
    # Binary placement check again
    if [ ! -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        FIND_BIN=$(find "$INSTALL_DIR" -name "$BINARY_NAME" -type f | head -n 1)
        if [ -n "$FIND_BIN" ]; then
            mv "$FIND_BIN" "$INSTALL_DIR/$BINARY_NAME"
        fi
    fi
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
    
    systemctl start "$SERVICE_NAME"
    echo -e "${GREEN}Update complete!${NC}"
}

# Function to uninstall
uninstall_server() {
    read -p "Are you sure you want to uninstall GooseRelayVPN? (y/n): " choice
    if [[ "$choice" == "y" ]]; then
        echo -e "${YELLOW}Uninstalling...${NC}"
        systemctl stop "$SERVICE_NAME" || true
        systemctl disable "$SERVICE_NAME" || true
        rm -f /etc/systemd/system/$SERVICE_NAME.service
        systemctl daemon-reload
        
        rm -rf "$INSTALL_DIR"
        echo -e "${GREEN}GooseRelayVPN uninstalled successfully.${NC}"
    fi
}

# Function to reconfigure
reconfigure_server() {
    if [ ! -f "$INSTALL_DIR/$CONFIG_NAME" ]; then
        echo -e "${RED}Configuration file not found.${NC}"
        return
    fi
    
    echo "1) Regenerate tunnel_key"
    echo "2) Enable/Disable upstream_proxy"
    read -p "Select an option: " choice
    
    case $choice in
        1)
            NEW_KEY=$(openssl rand -hex 32)
            jq --arg key "$NEW_KEY" '.tunnel_key = $key' "$INSTALL_DIR/$CONFIG_NAME" > "$INSTALL_DIR/$CONFIG_NAME.tmp" && mv "$INSTALL_DIR/$CONFIG_NAME.tmp" "$INSTALL_DIR/$CONFIG_NAME"
            echo -e "${GREEN}New tunnel_key generated: $NEW_KEY${NC}"
            echo -e "${YELLOW}Remember to update your client config!${NC}"
            systemctl restart "$SERVICE_NAME"
            ;;
        2)
            HAS_PROXY=$(jq '.upstream_proxy' "$INSTALL_DIR/$CONFIG_NAME")
            if [ "$HAS_PROXY" != "null" ]; then
                echo "Upstream proxy is currently enabled ($HAS_PROXY)."
                read -p "Disable it? (y/n): " dis
                if [[ "$dis" == "y" ]]; then
                    jq 'del(.upstream_proxy)' "$INSTALL_DIR/$CONFIG_NAME" > "$INSTALL_DIR/$CONFIG_NAME.tmp" && mv "$INSTALL_DIR/$CONFIG_NAME.tmp" "$INSTALL_DIR/$CONFIG_NAME"
                    echo "Upstream proxy disabled."
                fi
            else
                echo "Upstream proxy is currently disabled."
                read -p "Enable it? (y/n): " en
                if [[ "$en" == "y" ]]; then
                    jq '.upstream_proxy = "socks5://127.0.0.1:40000"' "$INSTALL_DIR/$CONFIG_NAME" > "$INSTALL_DIR/$CONFIG_NAME.tmp" && mv "$INSTALL_DIR/$CONFIG_NAME.tmp" "$INSTALL_DIR/$CONFIG_NAME"
                    echo "Upstream proxy enabled."
                fi
            fi
            systemctl restart "$SERVICE_NAME"
            ;;
        *) echo "Invalid option";;
    esac
}

# Main execution loop
if [ "$#" -gt 0 ]; then
    # Non-interactive mode if needed
    case $1 in
        install) install_server ;;
        update) update_server ;;
        uninstall) uninstall_server ;;
        *) show_menu ;;
    esac
else
    while true; do
        show_menu
        read -p "Enter choice [1-5]: " choice
        case $choice in
            1) install_server ;;
            2) update_server ;;
            3) uninstall_server ;;
            4) reconfigure_server ;;
            5) exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}" ;;
        esac
        echo ""
    done
fi
