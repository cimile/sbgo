#!/bin/bash
#
# Filename: install.sh
# Description: This script sets up the Go language environment and necessary tools.
# It DOES NOT compile or manage the sb.go program.
#
# Usage:
#   1. Save this content as install.sh.
#   2. Grant execute permission: chmod +x install.sh
#   3. Run the script with sudo: sudo ./install.sh

set -e

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

clear
echo -e "${CYAN}--- Go Language Environment Automated Setup ---${NC}"
echo -e "${CYAN}--- Script Version: 3.0 (Manual sb.go) ---${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root. Please use 'sudo ./install.sh'${NC}"
   exit 1
fi

echo -e "${YELLOW}Updating system packages and upgrading...${NC}"
sudo apt update && sudo apt upgrade -y
echo -e "${GREEN}System update completed. ${NC}"

# Install dos2unix and vim for manual sb.go cleaning if needed
echo -e "${YELLOW}Installing essential tools (dos2unix, vim)...${NC}"
sudo apt install -y dos2unix vim
echo -e "${GREEN}Essential tools installed.${NC}"


if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}Go language not found, downloading and installing latest stable Go...${NC}"

    ARCH=$(dpkg --print-architecture)
    case "$ARCH" in
        amd64) GO_ARCH="amd64" ;;
        arm64) GO_ARCH="arm64" ;;
        *) echo -e "${RED}Unsupported architecture: ${ARCH}. Please install Go manually.${NC}"; exit 1 ;;
    esac

    GO_URL=$(wget -qO- https://go.dev/dl/ | grep -oP "go[0-9\.]+\.linux-${GO_ARCH}\.tar\.gz" | head -n 1)
    if [ -z "$GO_URL" ]; then
        echo -e "${RED}Error: Failed to fetch latest Go download URL. Please check go.dev/dl${NC}"
        exit 1
    fi
    GO_FULL_URL="https://go.dev/dl/${GO_URL}"

    echo -e "${YELLOW}Downloading Go (${GO_FULL_URL})...${NC}"
    mkdir -p /tmp/go_install
    wget -O /tmp/go_install/go.tar.gz "$GO_FULL_URL"

    echo -e "${YELLOW}Installing Go...${NC}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go_install/go.tar.gz

    GO_PROFILE_PATH="/etc/profile.d/go_env.sh"
    echo "export PATH=\$PATH:/usr/local/go/bin" | sudo tee "$GO_PROFILE_PATH" > /dev/null
    echo "export GOPATH=\$HOME/go" | sudo tee -a "$GO_PROFILE_PATH" > /dev/null
    echo "export PATH=\$PATH:\$GOPATH/bin" | sudo tee -a "$GO_PROFILE_PATH" > /dev/null

    source "$GO_PROFILE_PATH" > /dev/null 2>&1 || true
    export PATH="$PATH:/usr/local/go/bin"
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin"

    echo -e "${GREEN}Go language installation completed: $(go version)${NC}"
    rm -rf /tmp/go_install
else
    echo -e "${GREEN}Go language is already installed: $(go version)${NC}"
    GO_PROFILE_PATH="/etc/profile.d/go_env.sh"
    if [ -f "$GO_PROFILE_PATH" ]; then
        source "$GO_PROFILE_PATH" > /dev/null 2>&1 || true
        export PATH="$PATH:/usr/local/go/bin"
        export GOPATH="$HOME/go"
        export PATH="$PATH:$GOPATH/bin"
    fi
fi

echo -e "${GREEN}--- Go environment setup finished. ---${NC}"
echo -e "${YELLOW}IMPORTANT: You might need to log out and log back in (or restart SSH session) for Go environment variables to be fully persistent in your main shell.${NC}"
echo ""
echo -e "${CYAN}--- Next Steps: Compiling and Running Your Sing-box Manager ---${NC}"
echo -e "${CYAN}1. Create a new directory for your project (e.g., /home/your_user/sb_manager_go/):${NC}"
echo -e "${CYAN}   mkdir -p ~/sb_manager_go && cd ~/sb_manager_go${NC}"
echo -e "${CYAN}2. Create 'sb.go' file and paste the Go source code. This step is CRUCIAL:${NC}"
echo -e "${CYAN}   nano sb.go${NC}"
echo -e "${CYAN}   (Paste the entire sb.go content provided below into nano. Save (Ctrl+O) and Exit (Ctrl+X).)${NC}"
echo -e "${CYAN}3. Initialize Go module and download dependencies (in the same directory as sb.go):${NC}"
echo -e "${CYAN}   go mod init singbox_manager_go${NC}"
echo -e "${CYAN}   go mod tidy${NC}"
echo -e "${CYAN}4. Compile your 'sb.go' program:${NC}"
echo -e "${CYAN}   go build -o sb sb.go${NC}"
echo -e "${CYAN}5. Run the compiled program (requires root privileges for Sing-box manager operations):${NC}"
echo -e "${CYAN}   sudo ./sb${NC}"
echo -e "${CYAN}6. (Optional) Create a symlink for easier global access:${NC}"
echo -e "${CYAN}   sudo ln -sf \$(pwd)/sb /usr/local/bin/sb${NC}"
echo -e "${CYAN}   Then you can just run: sudo sb${NC}"
echo -e "${NC}"