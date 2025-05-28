#!/bin/bash
#
# Filename: install_sb.sh
# Description: One-click script to set up Go environment, compile, and run Sing-box manager (sb.go).
#
# Usage:
#   1. Save this content as install_sb.sh
#   2. Grant execute permission: chmod +x install_sb.sh
#   3. Run the script: sudo ./install_sb.sh

set -e # Exit immediately if a command exits with a non-zero status

# --- Color Definitions ---
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'
WHITE='\033[0;37m'

clear
echo -e "${CYAN}${BOLD}--- Sing-box Manager (Go) Automated Installation Script ---${NC}"
echo -e "${CYAN}--- https://github.com/SagerNet/sing-box ---${NC}"
echo -e "${CYAN}--- Script Version: 3.9.5 (Improved Sing-box Version Parsing) ---${NC}"
echo ""

# Function to display progress messages
log_info() {
    echo -e "${CYAN}INFO: ${1}${NC}"
}

log_success() {
    echo -e "${GREEN}SUCCESS: ${1}${NC}"
}

log_warn() {
    echo -e "${YELLOW}WARN: ${1}${NC}"
}

log_error() {
    echo -e "${RED}ERROR: ${1}${NC}" >&2
}

# --- 1. Check for Root Privileges ---
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root. Please use: sudo ./install_sb.sh"
   exit 1
fi

log_info "Starting system update and upgrade..."
if apt update -y && apt upgrade -y; then
    log_success "System update and upgrade completed successfully."
else
    log_error "System update/upgrade failed. Check internet connection and apt sources."
    exit 1
fi

# --- 2. Check and Install Go Language Environment ---
log_info "Checking Go Language Environment..."
if command -v go &> /dev/null; then
    log_success "Go language is already installed: $(go version)"
else
    log_warn "Go language not found. Downloading and installing latest stable Go..."

    ARCH=$(dpkg --print-architecture)
    GO_ARCH=""
    case "$ARCH" in
        amd64) GO_ARCH="amd64" ;;
        arm64) GO_ARCH="arm64" ;;
        *) log_error "Unsupported architecture: ${ARCH}. Please install Go manually."; exit 1 ;;
    esac

    GO_URL=$(curl -s https://go.dev/dl/ | grep -oP "go[0-9\.]+\.linux-${GO_ARCH}\.tar\.gz" | head -n 1)
    if [ -z "$GO_URL" ]; then
        log_error "Could not retrieve latest Go language download link. Check go.dev/dl manually."
        exit 1
    fi
    GO_FULL_URL="https://go.dev/dl/${GO_URL}"
    GO_VERSION=$(echo "$GO_URL" | grep -oP "go[0-9\.]+" | sed 's/go//')

    log_info "Downloading Go ${GO_VERSION} for ${ARCH} from ${GO_FULL_URL}..."
    mkdir -p /tmp/go_install
    if command -v curl &> /dev/null && command -v pv &> /dev/null; then
        CONTENT_LENGTH=$(curl -sLI "$GO_FULL_URL" | grep -i Content-Length | awk '{print $2}' | tr -d '\r\n')
        curl -L "$GO_FULL_URL" | pv -pefs "${CONTENT_LENGTH:-0}" > /tmp/go_install/go.tar.gz || { log_error "Go download failed (curl+pv)."; exit 1; }
    elif command -v wget &> /dev/null; then
        wget --show-progress -O /tmp/go_install/go.tar.gz "$GO_FULL_URL" || { log_error "Go download failed (wget)."; exit 1; }
    else
        log_error "Neither curl nor wget found. Install one to proceed or download Go manually."
        exit 1
    fi
    log_success "Go download complete."

    log_info "Installing Go to /usr/local..."
    rm -rf /usr/local/go
    if ! tar -C /usr/local -xzf /tmp/go_install/go.tar.gz; then
        log_error "Go extraction failed."
        exit 1
    fi

    GO_PROFILE_PATH="/etc/profile.d/go_env.sh"
    echo "export PATH=\$PATH:/usr/local/go/bin" | tee "$GO_PROFILE_PATH" > /dev/null
    echo "export GOPATH=\$HOME/go" | tee -a "$GO_PROFILE_PATH" > /dev/null
    echo "export PATH=\$PATH:\$GOPATH/bin" | tee -a "$GO_PROFILE_PATH" > /dev/null

    # shellcheck source=/dev/null
    source "$GO_PROFILE_PATH"
    export PATH="$PATH:/usr/local/go/bin"
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin"

    log_success "Go language installation complete: $(go version)"
    rm -rf /tmp/go_install
fi

# --- 3. Prepare Go Project Directory and Write sb.go File ---
log_info "Setting up Sing-box Manager Project..."
PROJECT_DIR="/opt/sb_manager_go"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

log_info "Writing sb.go script content..."
cat << 'EOF_GO_CODE' > sb.go
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	qrcode "github.com/skip2/go-qrcode"
)

const (
	singBoxDir         = "/etc/s-box"
	singBoxBinary      = "/etc/s-box/sing-box"
	singBoxConfig      = "/etc/s-box/sb.json"
	selfSignedCert     = "/etc/s-box/self_signed_cert.pem"
	selfSignedKey      = "/etc/s-box/self_signed_key.pem"
	systemdServiceFile = "/etc/systemd/system/sing-box.service"
	defaultSNI         = "www.bing.com"
	realitySNI         = "www.bing.com"
	defaultUserAgent   = "sb-manager-go/3.9.5" // User agent for HTTP requests
	installConfigFile  = "/etc/s-box/install_data.json"
	acmeBaseDir        = "/etc/s-box/acme"
	cliCommandName     = "sb"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
)

func logInfo(format string, a ...interface{}) {
	fmt.Printf(ColorCyan+"INFO: "+format+ColorReset+"\n", a...)
}

func logSuccess(format string, a ...interface{}) {
	fmt.Printf(ColorGreen+"SUCCESS: "+format+ColorReset+"\n", a...)
}

func logWarn(format string, a ...interface{}) {
	fmt.Printf(ColorYellow+"WARN: "+format+ColorReset+"\n", a...)
}

func logError(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, ColorRed+"ERROR: "+format+ColorReset+"\n", a...)
}

type SingBoxLogConfig struct {
	Disabled  bool   `json:"disabled"`
	Level     string `json:"level"`
	Timestamp bool   `json:"timestamp"`
}

type SingBoxUser struct {
	UUID     string `json:"uuid,omitempty"`
	Flow     string `json:"flow,omitempty"`
	AlterID  int    `json:"alterId,omitempty"`
	Password string `json:"password,omitempty"`
	Method   string `json:"method,omitempty"`
	Username string `json:"username,omitempty"`
}

type SingBoxRealityHandshake struct {
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
}

type SingBoxRealityConfig struct {
	Enabled    bool                    `json:"enabled"`
	Handshake  SingBoxRealityHandshake `json:"handshake"`
	PrivateKey string                  `json:"private_key"`
	ShortID    []string                `json:"short_id"`
}

type SingBoxTLSConfig struct {
	Enabled         bool                  `json:"enabled"`
	ServerName      string                `json:"server_name,omitempty"`
	CertificatePath string                `json:"certificate_path,omitempty"`
	KeyPath         string                `json:"key_path,omitempty"`
	Reality         *SingBoxRealityConfig `json:"reality,omitempty"`
	ALPN            []string              `json:"alpn,omitempty"`
}

type SingBoxTransportConfig struct {
	Type                string `json:"type"`
	Path                string `json:"path,omitempty"`
	MaxEarlyData        int    `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string `json:"early_data_header_name,omitempty"`
}

type SingBoxInbound struct {
	Type                     string                  `json:"type"`
	Tag                      string                  `json:"tag"`
	Listen                   string                  `json:"listen"`
	ListenPort               uint16                  `json:"listen_port"`
	Sniff                    bool                    `json:"sniff"`
	SniffOverrideDestination bool                    `json:"sniff_override_destination"`
	Users                    []SingBoxUser           `json:"users,omitempty"`
	TLS                      *SingBoxTLSConfig       `json:"tls,omitempty"`
	Transport                *SingBoxTransportConfig `json:"transport,omitempty"`
	CongestionControl        string                  `json:"congestion_control,omitempty"`
	IgnoreClientBandwidth    bool                    `json:"ignore_client_bandwidth,omitempty"`
	Method                   string                  `json:"method,omitempty"`
}

type SingBoxOutbound struct {
	Type           string `json:"type"`
	Tag            string `json:"tag"`
	DomainStrategy string `json:"domain_strategy,omitempty"`
}

type SingBoxRouteRule struct {
	Protocol []string `json:"protocol,omitempty"`
	Network  string   `json:"network,omitempty"`
	Outbound string   `json:"outbound"`
}

type SingBoxRouteConfig struct {
	Rules []SingBoxRouteRule `json:"rules"`
}

type SingBoxServerConfig struct {
	Log       SingBoxLogConfig   `json:"log"`
	Inbounds  []SingBoxInbound   `json:"inbounds"`
	Outbounds []SingBoxOutbound  `json:"outbounds"`
	Route     SingBoxRouteConfig `json:"route"`
}

type InstallData struct {
	ServerIP          string            `json:"server_ip"`
	Hostname          string            `json:"hostname"`
	Ports             map[string]uint16 `json:"ports"`
	MainUUID          string            `json:"main_uuid"`
	RealityPrivateKey string            `json:"reality_private_key"`
	RealityPublicKey  string            `json:"reality_public_key"`
	RealityShortID    string            `json:"reality_short_id"`
	Domain            string            `json:"domain,omitempty"`
	VmessPath         string            `json:"vmess_path"`
	UseAcmeCert       bool              `json:"use_acme_cert"`
	AcmeEmail         string            `json:"acme_email,omitempty"`
	UseSocks5Auth     bool              `json:"use_socks5_auth"`
	Socks5Username    string            `json:"socks5_username"`
	Socks5Password    string            `json:"socks5_password"`
}

var currentInstallData InstallData

func main() {
	loadInstallData()

	for {
		printMainMenu()
		choice := getUserInput(ColorYellow + "Enter your choice: " + ColorReset)
		clearScreen()
		switch choice {
		case "1":
			installInteractive()
		case "2":
			uninstall()
		case "3":
			manageNodes()
		case "4":
			manageCertificates()
		case "5":
			manageSocks5Auth()
		case "6":
			generateAndShowSubscription()
		case "7":
			restartSingBoxServiceInteractive()
		case "8":
			stopSingBoxServiceInteractive()
		case "9":
			startSingBoxServiceInteractive()
		case "10":
			viewSingBoxLogs()
		case "11":
			updateSingBoxBinaryAndRestartInteractive()
		case "0":
			logSuccess("Exiting.")
			os.Exit(0)
		default:
			logError("Invalid choice. Please try again.")
		}
		if choice != "0" && choice != "10" {
			fmt.Printf("\n%sPress Enter to continue...%s", ColorYellow, ColorReset)
			_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')
		}
	}
}

func clearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	_ = cmd.Run()
}

func getSingBoxStatus() (string, bool) {
	if _, err := os.Stat(systemdServiceFile); os.IsNotExist(err) {
		return "Not Installed", false
	} else if err != nil {
		return fmt.Sprintf("Error stating service file: %v", err), false
	}

	cmd := exec.Command("systemctl", "is-active", "sing-box")
	output, err := cmd.Output()
	status := strings.TrimSpace(string(output))

	if err != nil {
		failCmd := exec.Command("systemctl", "is-failed", "sing-box")
		failOutput, _ := failCmd.Output()
		failStatus := strings.TrimSpace(string(failOutput))
		if failStatus == "failed" {
			return "Failed", false
		}
		return "Inactive/Stopped", false
	}

	if status == "active" {
		return "Active (Running)", true
	}
	return strings.ToTitle(status), false
}

func printMainMenu() {
	clearScreen()
	statusText, isRunning := getSingBoxStatus()
	statusColor := ColorYellow
	if isRunning {
		statusColor = ColorGreen
	} else if statusText == "Failed" || statusText == "Not Installed" {
		statusColor = ColorRed
	}

	managerTitle := fmt.Sprintf("%sSing-box Manager (%s)%s", ColorCyan, cliCommandName, ColorReset)
	statusLine := fmt.Sprintf("%sStatus: %s%s", statusColor, statusText, ColorReset)
	fmt.Printf("\n%s--- %s --- %s ---\n%s", ColorBold, managerTitle, statusLine, ColorReset)

	fmt.Printf("\n%s--- Key File Locations ---%s\n", ColorBlue, ColorReset)
	fmt.Printf("  %sBinary: %s%s\n", ColorGreen, singBoxBinary, ColorReset)
	fmt.Printf("  %sConfig: %s%s\n", ColorGreen, singBoxConfig, ColorReset)
	fmt.Printf("  %sService: %s%s\n", ColorGreen, systemdServiceFile, ColorReset)
	fmt.Printf("  %sInstall Data: %s%s\n", ColorGreen, installConfigFile, ColorReset)
	fmt.Printf(strings.Repeat("-", 60) + "\n")

	fmt.Printf("%s1. Install/Reinstall Sing-box%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s2. Uninstall Sing-box%s\n", ColorRed, ColorReset)
	fmt.Printf("%s3. Show Nodes%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s--- Configuration Management ---%s\n", ColorBlue, ColorReset)
	fmt.Printf("%s4. Manage Certificates (Self-signed/ACME)%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s5. Manage Socks5 Authentication%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s6. Generate & Show Subscription Link%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s--- Service Management ---%s\n", ColorBlue, ColorReset)
	fmt.Printf("%s7. Restart Sing-box%s\n", ColorYellow, ColorReset)
	fmt.Printf("%s8. Stop Sing-box%s\n", ColorYellow, ColorReset)
	fmt.Printf("%s9. Start Sing-box%s\n", ColorYellow, ColorReset)
	fmt.Printf("%s10. View Sing-box Logs%s\n", ColorYellow, ColorReset)
	fmt.Printf("%s11. Update Sing-box Binary%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s0. Exit%s\n", ColorYellow, ColorReset)
	fmt.Println(strings.Repeat("-", 60))
}

func getUserInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	inputRaw, _ := reader.ReadString('\n')
	return strings.TrimSpace(inputRaw)
}

func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("command '%s %s' failed: %w\nStdout: %s\nStderr: %s", name, strings.Join(args, " "), err, strings.ToValidUTF8(stdout.String(), ""), strings.ToValidUTF8(stderr.String(), ""))
	}
	return stdout.String(), nil
}

func checkRoot() {
	if os.Geteuid() != 0 {
		logError("Root privileges required for this operation.")
		os.Exit(1)
	}
}

func checkOS() {
	logInfo("Performing OS check...")
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		logSuccess("OS check OK (Debian-based).")
		return
	}

	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		logWarn("OS check failed to read /etc/os-release: %v", err)
		if strings.ToLower(getUserInput(ColorYellow+"Is this a Debian-based system? (y/N): "+ColorReset)) != "y" {
			logError("OS not confirmed as Debian-based. Aborting.")
			os.Exit(1)
		}
		logSuccess("OS check manually confirmed as Debian-based.")
		return
	}
	s := string(b)
	if !strings.Contains(s, "ID_LIKE=debian") && !strings.Contains(s, "ID=debian") && !strings.Contains(s, "ID=ubuntu") {
		logError("Unsupported OS. This script is primarily for Debian/Ubuntu based systems.")
		os.Exit(1)
	}
	logSuccess("OS check OK (Debian-based).")
}

func installDependencies() {
	logInfo("Updating apt package lists...")
	if _, err := runCommand("apt-get", "update", "-y"); err != nil {
		logError("Apt update failed: %v", err)
		os.Exit(1)
	}
	dependencies := []string{"curl", "wget", "jq", "qrencode", "openssl", "iproute2", "iptables", "ca-certificates", "certbot"}
	logInfo("Installing dependencies: %v", dependencies)

	installArgs := []string{"install", "-y"}
	installArgs = append(installArgs, dependencies...)
	installCmd := exec.Command("apt-get", installArgs...)
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr

	if err := installCmd.Run(); err != nil {
		if strings.Contains(err.Error(), "certbot") {
			logWarn("apt install certbot failed. Attempting to install via snapd...")
			if _, snapdErr := runCommand("apt-get", "install", "-y", "snapd"); snapdErr != nil {
				 logWarn("Failed to install snapd: %v. Certbot might need manual installation.", snapdErr)
			} else {
				if _, certbotSnapErr := runCommand("snap", "install", "--classic", "certbot"); certbotSnapErr != nil {
					logWarn("Snap install certbot failed: %v. Manual certbot installation might be required.", certbotSnapErr)
				} else {
					_ , linkErr := runCommand("ln", "-sf", "/snap/bin/certbot", "/usr/bin/certbot")
					if linkErr == nil {
						logSuccess("Certbot installed via Snap and symlinked.")
					} else {
						logWarn("Failed to symlink snap certbot: %v", linkErr)
					}
				}
			}
		} else {
			logError("Dependency installation failed: %v", err)
			os.Exit(1)
		}
	}
	logSuccess("Dependencies installation attempted.")
	if _, err := exec.LookPath("certbot"); err != nil {
		logWarn("Certbot command still not found. ACME certificate features may not work. Please install Certbot manually.")
	} else {
		logSuccess("Certbot found and accessible.")
	}
}

func getCPUArch() string {
	arch := runtime.GOARCH
	if arch == "amd64" || arch == "arm64" {
		return arch
	}
	logError("CPU architecture %s is unsupported by this script's automated download.", arch)
	os.Exit(1)
	return ""
}

func getSingBoxVersion() (string, error) {
	if _, err := os.Stat(singBoxBinary); os.IsNotExist(err) {
		return "", fmt.Errorf("sing-box binary not found at %s", singBoxBinary)
	}
	rawOutput, err := runCommand(singBoxBinary, "version")
	if err != nil {
		return "", fmt.Errorf("failed to get sing-box version: %w. Output: %s", err, rawOutput)
	}

	lines := strings.Split(rawOutput, "\n")
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "sing-box version ") {
			versionPart := strings.TrimPrefix(trimmedLine, "sing-box version ")
			if firstSpace := strings.Index(versionPart, " "); firstSpace != -1 {
				return versionPart[:firstSpace], nil
			}
			return versionPart, nil 
		} else if strings.HasPrefix(trimmedLine, "version ") { 
			versionPart := strings.TrimPrefix(trimmedLine, "version ")
			if firstSpace := strings.Index(versionPart, " "); firstSpace != -1 {
				return versionPart[:firstSpace], nil
			}
			return versionPart, nil
		}
	}
	
	if len(lines) > 0 {
		firstLine := strings.TrimSpace(lines[0])
		re := regexp.MustCompile(`v?([0-9]+\.[0-9]+\.[0-9]+)`)
		match := re.FindStringSubmatch(firstLine)
		if len(match) > 1 {
			return match[1], nil 
		}
	}
	
	return "unknown", fmt.Errorf("failed to parse sing-box version from output: %s", rawOutput)
}


func isSingBoxVersionAtLeast(major, minor, patch int) bool {
	versionStr, err := getSingBoxVersion()
	if err != nil {
		logWarn("Could not get Sing-box version for feature check: %v. Assuming feature not supported.", err)
		return false
	}
	if versionStr == "unknown" {
		logWarn("Sing-box version is 'unknown'. Assuming feature not supported.")
		return false
	}

	parts := strings.Split(strings.TrimPrefix(versionStr, "v"), ".")
	if len(parts) < 3 {
		logWarn("Malformed Sing-box version string '%s' (expected X.Y.Z). Assuming feature not supported.", versionStr)
		return false
	}
	vMajor, majErr := strconv.Atoi(parts[0])
	vMinor, minErr := strconv.Atoi(parts[1])
	vPatch, patErr := strconv.Atoi(parts[2])

	if majErr != nil || minErr != nil || patErr != nil {
		logWarn("Error parsing Sing-box version parts from '%s'. Assuming feature not supported.", versionStr)
		return false
	}

	if vMajor > major { return true }
	if vMajor < major { return false }
	if vMinor > minor { return true }
	if vMinor < minor { return false }
	return vPatch >= patch
}


func downloadAndInstallSingBox() {
	logInfo("Downloading and installing latest Sing-box...")
	arch := getCPUArch()
	client := &http.Client{Timeout: 60 * time.Second}

	req, err := http.NewRequest("GET", "https://api.github.com/repos/SagerNet/sing-box/releases/latest", nil)
	if err != nil {
		logError("Failed to create request for GitHub releases: %v", err)
		os.Exit(1)
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	res, err := client.Do(req)
	if err != nil {
		logError("Failed to fetch release information from GitHub: %v", err)
		os.Exit(1)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(res.Body)
		logError("GitHub API request failed (Status %d): %s", res.StatusCode, string(bodyBytes))
		os.Exit(1)
	}

	var releaseInfo struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(res.Body).Decode(&releaseInfo); err != nil {
		logError("Failed to parse GitHub release JSON: %v", err)
		os.Exit(1)
	}

	var downloadURL string
	suffix := fmt.Sprintf("linux-%s.tar.gz", arch)
	for _, asset := range releaseInfo.Assets {
		if strings.HasPrefix(asset.Name, "sing-box-") && strings.HasSuffix(asset.Name, suffix) {
			downloadURL = asset.URL
			logInfo("Found Sing-box asset: %s", asset.Name)
			break
		}
	}

	if downloadURL == "" {
		logError("No download URL found for %s architecture in %s release. Check GitHub releases page.", arch, releaseInfo.TagName)
		os.Exit(1)
	}

	logInfo("Downloading Sing-box from: %s", downloadURL)
	if err := os.MkdirAll(singBoxDir, 0755); err != nil {
		logError("Failed to create Sing-box directory %s: %v", singBoxDir, err)
		os.Exit(1)
	}

	downloadPath := filepath.Join(os.TempDir(), filepath.Base(downloadURL))
	outputFile, err := os.Create(downloadPath)
	if err != nil {
		logError("Failed to create temporary download file %s: %v", downloadPath, err)
		os.Exit(1)
	}

	downloadResponse, err := client.Get(downloadURL)
	if err != nil {
		_ = outputFile.Close()
		_ = os.Remove(downloadPath)
		logError("Download request failed: %v", err)
		os.Exit(1)
	}
	defer downloadResponse.Body.Close()

	if downloadResponse.StatusCode != http.StatusOK {
		_ = outputFile.Close()
		_ = os.Remove(downloadPath)
		logError("Download failed with HTTP status %d", downloadResponse.StatusCode)
		os.Exit(1)
	}

	fmt.Printf("%sDownloading Sing-box binary...%s", ColorYellow, ColorReset)
	bytesWritten, err := io.Copy(outputFile, downloadResponse.Body)
	fmt.Printf("\n")
	_ = outputFile.Close()
	if err != nil {
		_ = os.Remove(downloadPath)
		logError("Failed to save downloaded content: %v", err)
		os.Exit(1)
	}
	logSuccess("Downloaded %d bytes to %s.", bytesWritten, downloadPath)

	logInfo("Extracting Sing-box archive...")
	extractDir := filepath.Join(os.TempDir(), "sb-extract")
	_ = os.RemoveAll(extractDir)
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		logError("Failed to create extraction directory %s: %v", extractDir, err)
		_ = os.Remove(downloadPath)
		os.Exit(1)
	}

	if _, err := runCommand("tar", "-xzf", downloadPath, "-C", extractDir, "--strip-components=1"); err != nil {
		logWarn("Failed to extract with --strip-components=1 (%v), trying without...", err)
		_ = os.RemoveAll(extractDir)
		if err := os.MkdirAll(extractDir, 0755); err != nil {
			logError("Failed to re-create extraction directory %s: %v", extractDir, err)
			_ = os.Remove(downloadPath)
			os.Exit(1)
		}
		if _, err := runCommand("tar", "-xzf", downloadPath, "-C", extractDir); err != nil {
			logError("Failed to extract Sing-box archive (second attempt): %v", err)
			_ = os.Remove(downloadPath)
			_ = os.RemoveAll(extractDir)
			os.Exit(1)
		}
	}

	var binaryPath string
	err = filepath.Walk(extractDir, func(p string, info os.FileInfo, walkErr error) error {
		if walkErr != nil { return walkErr }
		if !info.IsDir() && info.Name() == "sing-box" {
			binaryPath = p
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		logError("Error walking extracted files: %v", err)
	}

	if binaryPath == "" {
		logError("Sing-box binary not found in extracted archive at %s.", extractDir)
		_ = os.Remove(downloadPath)
		_ = os.RemoveAll(extractDir)
		os.Exit(1)
	}

	sourceFile, err := os.Open(binaryPath)
	if err != nil {
		logError("Failed to open source binary %s: %v", binaryPath, err)
		os.Exit(1)
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(singBoxBinary)
	if err != nil {
		logError("Failed to create destination binary %s: %v", singBoxBinary, err)
		os.Exit(1)
	}
	defer destinationFile.Close()

	_, err = io.Copy(destinationFile, sourceFile)
	if err != nil {
		logError("Failed to copy binary to %s: %v", singBoxBinary, err)
		os.Exit(1)
	}

	if err := os.Chmod(singBoxBinary, 0755); err != nil {
		logWarn("Failed to set executable permission on %s: %v", singBoxBinary, err)
	}

	_ = os.Remove(downloadPath)
	_ = os.RemoveAll(extractDir)

	versionOutput, versionErr := getSingBoxVersion()
	if versionErr != nil {
		logWarn("After installation, failed to get Sing-box version: %v", versionErr)
	}
	logSuccess("Sing-box installed. Version: %s", strings.TrimSpace(versionOutput))
}

func generateSelfSignedCert() {
	logInfo("Generating self-signed certificate for fallback/default TLS...")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logError("Failed to generate ECDSA private key: %v", err)
		os.Exit(1)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject: pkix.Name{
			CommonName:   defaultSNI,
			Organization: []string{"Sing-box Manager SelfSigned"},
		},
		NotBefore: now,
		NotAfter:  now.AddDate(10, 0, 0),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{defaultSNI},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		logError("Failed to create certificate: %v", err)
		os.Exit(1)
	}

	certOut, err := os.Create(selfSignedCert)
	if err != nil {
		logError("Failed to open %s for writing: %v", selfSignedCert, err)
		os.Exit(1)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		logError("Failed to write certificate PEM data: %v", err)
		os.Exit(1)
	}

	keyOut, err := os.Create(selfSignedKey)
	if err != nil {
		logError("Failed to open %s for writing: %v", selfSignedKey, err)
		os.Exit(1)
	}
	defer keyOut.Close()
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		logError("Failed to marshal EC private key: %v", err)
		os.Exit(1)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		logError("Failed to write key PEM data: %v", err)
		os.Exit(1)
	}
	logSuccess("Self-signed certificate and key generated and saved.")
}

func generateRandomPort() uint16 {
	logInfo("Attempting to generate a random available port...")
	const minPort = 10000
	const maxPort = 65535
	const maxAttempts = 50

	for i := 0; i < maxAttempts; i++ {
		nBig, err := rand.Int(rand.Reader, big.NewInt(int64(maxPort-minPort+1)))
		if err != nil {
			logWarn("crypto/rand.Int failed: %v. Retrying... (%d/%d)", err, i+1, maxAttempts)
			continue
		}
		p := uint16(nBig.Int64() + int64(minPort))

		tcpAddr := fmt.Sprintf(":%d", p)
		listener, tcpErr := net.Listen("tcp", tcpAddr)
		if tcpErr == nil {
			_ = listener.Close()
			udpAddr := fmt.Sprintf(":%d", p)
			packetListener, udpErr := net.ListenPacket("udp", udpAddr)
			if udpErr == nil {
				_ = packetListener.Close()
				logSuccess("Generated random available port: %d", p)
				return p
			}
		}
	}
	logWarn("Failed to generate a random available port after %d attempts. Please provide one manually.", maxAttempts)
	return 0
}

func getPort(protocol string, suggestedPort uint16) uint16 {
	reader := bufio.NewReader(os.Stdin)
	for {
		defaultHint := "random"
		if suggestedPort > 0 {
			defaultHint = fmt.Sprintf("%d (previous) or 'random'", suggestedPort)
		}
		fmt.Printf("%sEnter %s port (default: %s, range 10000-65535): %s", ColorYellow, protocol, defaultHint, ColorReset)
		inputRaw, _ := reader.ReadString('\n')
		input := strings.TrimSpace(strings.ToLower(inputRaw))

		if input == "" {
			if suggestedPort > 0 {
				logSuccess("Using previous port for %s: %d", protocol, suggestedPort)
				return suggestedPort
			}
			input = "random"
		}

		if input == "random" {
            randomPort := generateRandomPort()
            if randomPort != 0 {
                return randomPort
            }
			logError("Failed to find a random available port automatically. Please enter a port number manually.")
			continue
		}

		portNum, err := strconv.Atoi(input)
		if err == nil && portNum >= 10000 && portNum <= 65535 {
			return uint16(portNum)
		}
		logError("Invalid port. Please enter a number between 10000 and 65535, 'random', or leave empty for default.")
	}
}

func generateSingBoxUUID() string {
	return uuid.NewString()
}

func generateRealityKeyPair() (privateKey, publicKey, shortID string, err error) {
	if _, statErr := os.Stat(singBoxBinary); os.IsNotExist(statErr) {
		return "", "", "", fmt.Errorf("sing-box binary not found at %s, cannot generate Reality keys", singBoxBinary)
	}

	logInfo("Generating Sing-box Reality key pair...")
	output, err := runCommand(singBoxBinary, "generate", "reality-keypair")
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate reality keypair using sing-box: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			switch key {
			case "PrivateKey":
				privateKey = value
			case "PublicKey":
				publicKey = value
			}
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return "", "", "", fmt.Errorf("error scanning reality keypair output: %w", scanErr)
	}
	if privateKey == "" || publicKey == "" {
		return "", "", "", fmt.Errorf("failed to parse private/public keys from sing-box output: %s", output)
	}

	logInfo("Generating Reality Short ID (4 hex chars)...")
	shortIDOutput, err := runCommand(singBoxBinary, "generate", "rand", "--hex", "4")
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate reality short ID using sing-box: %w", err)
	}
	shortID = strings.TrimSpace(shortIDOutput)

	logSuccess("Reality key pair and Short ID generated successfully.")
	return privateKey, publicKey, shortID, nil
}

func saveInstallData() {
	logInfo("Saving installation data...")
	data, err := json.MarshalIndent(currentInstallData, "", "  ")
	if err != nil {
		logWarn("Failed to marshal install_data to JSON: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(installConfigFile), 0755); err != nil {
		logWarn("Failed to ensure directory for %s: %v", installConfigFile, err)
	}
	if err := os.WriteFile(installConfigFile, data, 0600); err != nil {
		logWarn("Failed to save %s: %v", installConfigFile, err)
	} else {
		logSuccess("Installation data saved to %s", installConfigFile)
	}
}

func loadInstallData() {
	logInfo("Loading existing installation data (if any)...")
	if err := os.MkdirAll(singBoxDir, 0755); err != nil && !os.IsExist(err) {
		logWarn("Failed to create base directory %s: %v. This might cause issues.", singBoxDir, err)
	}

	data, err := os.ReadFile(installConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			logInfo("No existing installation config found (%s). Initializing with defaults.", installConfigFile)
		} else {
			logWarn("Failed to read %s: %v. Initializing with defaults.", installConfigFile, err)
		}
		currentInstallData = InstallData{
			Ports:    make(map[string]uint16),
			ServerIP: getPublicIP(),
			Hostname: func() string {
				name, _ := os.Hostname()
				if name == "" { name = "sb-server" }
				return name
			}(),
			UseAcmeCert:    false,
			UseSocks5Auth:  false,
		}
		return
	}

	if err := json.Unmarshal(data, &currentInstallData); err != nil {
		logWarn("Failed to unmarshal %s: %v. Content: <%s>. Initializing with defaults.", installConfigFile, err, string(data))
		currentInstallData = InstallData{
			Ports:    make(map[string]uint16),
			ServerIP: getPublicIP(),
			Hostname: func() string { name, _ := os.Hostname(); if name == "" { name = "sb-server" }; return name }(),
		}
		return
	}

	if currentInstallData.Ports == nil {
		currentInstallData.Ports = make(map[string]uint16)
	}
	if currentInstallData.ServerIP == "" {
		currentInstallData.ServerIP = getPublicIP()
	}
	if currentInstallData.Hostname == "" {
		currentInstallData.Hostname, _ = os.Hostname()
		if currentInstallData.Hostname == "" {
			currentInstallData.Hostname = "sb-server"
		}
	}
	if currentInstallData.UseAcmeCert && currentInstallData.AcmeEmail == "" {
		logWarn("ACME certificate usage enabled but ACME email is missing in config. Disabling ACME. Reconfigure if needed.")
		currentInstallData.UseAcmeCert = false
		currentInstallData.Domain = ""
	}
	if currentInstallData.UseSocks5Auth {
		if currentInstallData.Socks5Username == "" {
			currentInstallData.Socks5Username = "sb_socks_user"
		}
		if currentInstallData.Socks5Password == "" {
			currentInstallData.Socks5Password = generateSingBoxUUID()
			logInfo("Generated new random password for SOCKS5 user %s due to missing one in config.", currentInstallData.Socks5Username)
		}
	}
	logSuccess("Installation data loaded successfully from %s.", installConfigFile)
}

func buildSingBoxServerConfig() SingBoxServerConfig {
	cfg := currentInstallData
	certPath, keyPath := selfSignedCert, selfSignedKey

	vmessServerSNI, hysteria2ServerSNI, tuicServerSNI := defaultSNI, defaultSNI, defaultSNI

	if !isSingBoxVersionAtLeast(1, 7, 0) {
		logWarn("Sing-box version appears older than 1.7.0 (or version check failed). Some UDP/network features might be handled by defaults or client-side settings.")
	}


	if cfg.UseAcmeCert && cfg.Domain != "" {
		domainAcmeDir := filepath.Join(acmeBaseDir, cfg.Domain)
		acmeCertPath := filepath.Join(domainAcmeDir, "fullchain.pem")
		acmeKeyPath := filepath.Join(domainAcmeDir, "privkey.pem")

		var acmeFilesExist bool
		if _, certErr := os.Stat(acmeCertPath); certErr == nil {
			if _, keyErr := os.Stat(acmeKeyPath); keyErr == nil {
				acmeFilesExist = true
			}
		}

		if acmeFilesExist {
			certPath = acmeCertPath
			keyPath = acmeKeyPath
			vmessServerSNI, hysteria2ServerSNI, tuicServerSNI = cfg.Domain, cfg.Domain, cfg.Domain
			logInfo("Server config: Using ACME certificate for domain '%s' (files found).", cfg.Domain)
		} else {
			logError("CRITICAL WARNING: Server config is set to use ACME for '%s', but certificate files were NOT FOUND.", cfg.Domain)
			logError("  Expected cert: %s", acmeCertPath)
			logError("  Expected key:  %s", acmeKeyPath)
			logError("  Sing-box will LIKELY FAIL TO START or serve TLS correctly. It will fall back to self-signed certs with default SNI (%s) for now.", defaultSNI)
			certPath = selfSignedCert
			keyPath = selfSignedKey
		}
	} else {
		_, selfCertStatErr := os.Stat(selfSignedCert)
		_, selfKeyStatErr := os.Stat(selfSignedKey)
		if os.IsNotExist(selfCertStatErr) || os.IsNotExist(selfKeyStatErr) {
			logInfo("Self-signed cert/key not found. Generating now...")
			generateSelfSignedCert()
		}
		logInfo("Server config: Using self-signed certificate (SNI for TLS non-VLESS: %s).", defaultSNI)
	}

	if cfg.VmessPath == "" {
		cfg.VmessPath = fmt.Sprintf("/%s-vm", cfg.MainUUID)
	}

	inbounds := []SingBoxInbound{
		{
			Type:                     "vless",
			Tag:                      "vless-in",
			Listen:                   "::",
			ListenPort:               cfg.Ports["vless"],
			Sniff:                    false,
			SniffOverrideDestination: false,
			Users:                    []SingBoxUser{{UUID: cfg.MainUUID, Flow: "xtls-rprx-vision"}},
			TLS: &SingBoxTLSConfig{
				Enabled:    true,
				ServerName: realitySNI,
				Reality: &SingBoxRealityConfig{
					Enabled:    true,
					Handshake:  SingBoxRealityHandshake{Server: realitySNI, ServerPort: 443},
					PrivateKey: cfg.RealityPrivateKey,
					ShortID:    []string{cfg.RealityShortID},
				},
			},
		},
		{
			Type:                     "vmess",
			Tag:                      "vmess-in",
			Listen:                   "::",
			ListenPort:               cfg.Ports["vmess"],
			Sniff:                    false,
			SniffOverrideDestination: false,
			Users:                    []SingBoxUser{{UUID: cfg.MainUUID, AlterID: 0}},
			Transport: &SingBoxTransportConfig{
				Type:                "ws",
				Path:                cfg.VmessPath,
				MaxEarlyData:        2048,
				EarlyDataHeaderName: "Sec-WebSocket-Protocol",
			},
			TLS: &SingBoxTLSConfig{
				Enabled:         true,
				ServerName:      vmessServerSNI,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
		{
			Type:                     "hysteria2",
			Tag:                      "hy2-in",
			Listen:                   "::",
			ListenPort:               cfg.Ports["hysteria2"],
			Sniff:                    false,
			SniffOverrideDestination: false,
			Users:                    []SingBoxUser{{Password: cfg.MainUUID}},
			IgnoreClientBandwidth:    false,
			TLS: &SingBoxTLSConfig{
				Enabled:         true,
				ALPN:            []string{"h3"},
				CertificatePath: certPath,
				KeyPath:         keyPath,
				ServerName:      hysteria2ServerSNI,
			},
		},
		{
			Type:                     "tuic",
			Tag:                      "tuic5-in",
			Listen:                   "::",
			ListenPort:               cfg.Ports["tuic"],
			Sniff:                    false,
			SniffOverrideDestination: false,
			Users:                    []SingBoxUser{{UUID: cfg.MainUUID, Password: cfg.MainUUID}},
			CongestionControl:        "bbr",
			TLS: &SingBoxTLSConfig{
				Enabled:         true,
				ALPN:            []string{"h3"},
				CertificatePath: certPath,
				KeyPath:         keyPath,
				ServerName:      tuicServerSNI,
			},
		},
		{
			Type:       "shadowsocks",
			Tag:        "ss-in",
			Listen:     "::",
			ListenPort: cfg.Ports["shadowsocks"],
			Users:      []SingBoxUser{{Password: cfg.MainUUID}},
			Method:     "aes-128-gcm",
			Sniff:      false,
		},
	}

	var socks5Users []SingBoxUser
	if cfg.UseSocks5Auth {
		socks5Users = append(socks5Users, SingBoxUser{
			Username: cfg.Socks5Username,
			Password: cfg.Socks5Password,
		})
	}
	socks5Inbound := SingBoxInbound{
		Type:       "socks",
		Tag:        "socks5-in",
		Listen:     "::",
		ListenPort: cfg.Ports["socks5"],
		Sniff:      false,
		Users:      socks5Users,
	}
	inbounds = append(inbounds, socks5Inbound)

	return SingBoxServerConfig{
		Log:       SingBoxLogConfig{Level: "info", Timestamp: true},
		Inbounds:  inbounds,
		Outbounds: []SingBoxOutbound{
			{Type: "direct", Tag: "direct", DomainStrategy: "prefer_ipv4"},
			{Type: "block", Tag: "block"},
		},
		Route: SingBoxRouteConfig{
			Rules: []SingBoxRouteRule{
				{Protocol: []string{"quic", "stun"}, Outbound: "block"},
				{Network: "udp,tcp", Outbound: "direct"},
			},
		},
	}
}

func writeSingBoxJSON(serverConfig SingBoxServerConfig) {
	logInfo("Writing Sing-box JSON configuration file (%s)...", singBoxConfig)
	data, err := json.MarshalIndent(serverConfig, "", "  ")
	if err != nil {
		logError("Failed to marshal Sing-box config to JSON: %v", err)
		os.Exit(1)
	}
	if err := os.WriteFile(singBoxConfig, data, 0644); err != nil {
		logError("Failed to write Sing-box config file %s: %v", singBoxConfig, err)
		os.Exit(1)
	}
	logSuccess("Sing-box configuration written to %s.", singBoxConfig)
}

func setupSystemdService() {
	logInfo("Setting up systemd service for Sing-box (%s)...", systemdServiceFile)
	serviceContent := `[Unit]
Description=Sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/etc/s-box
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/etc/s-box/sing-box run -c /etc/s-box/sb.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile(systemdServiceFile, []byte(serviceContent), 0644); err != nil {
		logError("Failed to write systemd service file %s: %v", systemdServiceFile, err)
		os.Exit(1)
	}

	logInfo("Reloading systemd daemon, enabling and attempting to restart Sing-box service...")
	if _, err := runCommand("systemctl", "daemon-reload"); err != nil {
		logWarn("systemctl daemon-reload failed: %v (might not be critical)", err)
	}
	if _, err := runCommand("systemctl", "enable", "sing-box"); err != nil {
		logWarn("systemctl enable sing-box failed: %v", err)
	}
	restartSingBoxService()
}

func restartSingBoxService() {
	logInfo("Restarting Sing-box service...")
	if _, err := runCommand(singBoxBinary, "check", "-c", singBoxConfig); err != nil {
		logError("Sing-box configuration check failed: %v", err)
		logError("Service will not be restarted due to invalid configuration. Please fix the config or reinstall.")
		return
	}
	logSuccess("Sing-box configuration check passed.")

	if _, err := runCommand("systemctl", "restart", "sing-box"); err != nil {
		logWarn("Sing-box service restart command failed: %v", err)
		statusOutput, _ := runCommand("systemctl", "status", "sing-box")
		logWarn("Current service status:\n%s", statusOutput)
	} else {
		logSuccess("Sing-box service restarted successfully.")
	}
}

func getPublicIP() string {
	client := http.Client{Timeout: 5 * time.Second}
	ipServices := []string{
		"https://api.ipify.org",
		"https://api64.ipify.org",
		"https://icanhazip.com",
		"https://ipinfo.io/ip",
	}

	for i, serviceURL := range ipServices {
		resp, err := client.Get(serviceURL)
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr == nil {
				ipStr := strings.TrimSpace(string(body))
				if net.ParseIP(ipStr) != nil {
					return ipStr
				}
				logWarn("Service %s returned invalid IP: %s", serviceURL, ipStr)
			} else {
				logWarn("Failed to read response body from %s: %v", serviceURL, readErr)
			}
		} else {
			logWarn("Failed to get IP from %s: %v (attempt %d/%d)", serviceURL, err, i+1, len(ipServices))
		}
	}
	logWarn("Failed to get public IP address from all services. Using placeholder.")
	return "YOUR_SERVER_IP"
}

func generateNodeLinks() []string {
	if currentInstallData.MainUUID == "" {
		logWarn("No installation data (UUID) found. Please install/reinstall Sing-box first (Option 1).")
		return nil
	}

	cfg := currentInstallData
	var links []string
	nodeHostTag := cfg.Hostname
	if nodeHostTag == "" {
		nodeHostTag = "sb-server"
	}

	serverAddressForLinks := cfg.ServerIP
	if serverAddressForLinks == "" || serverAddressForLinks == "YOUR_SERVER_IP" {
		serverAddressForLinks = getPublicIP()
	}

	clientSNIForTLSLinks := defaultSNI
	clientAddressForTLSLinks := serverAddressForLinks // This is the address the client will connect to (IP or domain)
	clientInsecureTLSFlag := 1 
	clientAllowInsecureBoolForJSON := true 

	acmeCertsEffectivelyUsed := false
	if cfg.UseAcmeCert && cfg.Domain != "" {
		domainAcmeDir := filepath.Join(acmeBaseDir, cfg.Domain)
		acmeCertPath := filepath.Join(domainAcmeDir, "fullchain.pem")
		acmeKeyPath := filepath.Join(domainAcmeDir, "privkey.pem")
		if _, certErr := os.Stat(acmeCertPath); certErr == nil {
			if _, keyErr := os.Stat(acmeKeyPath); keyErr == nil {
				acmeCertsEffectivelyUsed = true
			}
		}
	}

	if acmeCertsEffectivelyUsed {
		clientSNIForTLSLinks = cfg.Domain
		clientAddressForTLSLinks = cfg.Domain // When ACME is used, client connects to domain
		clientInsecureTLSFlag = 0      
		clientAllowInsecureBoolForJSON = false 
		logInfo("Generating links: ACME cert for '%s' is active. All TLS services (VMess, Hy2, TUIC) will use domain SNI and secure mode.", cfg.Domain)
	} else {
		if cfg.UseAcmeCert && cfg.Domain != "" { // ACME intended but files missing
			logWarn("Generating links: ACME for '%s' intended, but cert files NOT FOUND. Links will use IP/default SNI and insecure mode for TLS.", cfg.Domain)
		} else { // Self-signed mode
			logInfo("Generating links: Using Self-Signed certs. Links will use IP/default SNI and insecure mode for TLS.")
		}
		// Defaults are already set for this case
	}

	// Helper to format address for URI (wrap IPv6 in brackets)
	// This should be used for host part of URI, not for "add" field in VMess JSON if "add" is a domain.
	formatUriHost := func(addr string) string {
		ip := net.ParseIP(addr)
		if ip != nil && ip.To4() == nil && ip.To16() != nil { 
			return fmt.Sprintf("[%s]", addr)
		}
		return addr
	}
	
	// VLESS Reality: connects to serverAddressForLinks (IP or domain directly, SNI is specific realitySNI)
	vlessFormattedUriHost := formatUriHost(serverAddressForLinks)
	vlessLink := fmt.Sprintf("vless://%s@%s:%d?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&pbk=%s&sid=%s&type=tcp#%s-VLESS-Reality",
		cfg.MainUUID, vlessFormattedUriHost, cfg.Ports["vless"],
		realitySNI, cfg.RealityPublicKey, cfg.RealityShortID, nodeHostTag)
	links = append(links, vlessLink)

	// VMess:
	// "add" field in JSON is the address client connects to. If it's a domain, it's unformatted.
	// "host" field is WebSocket host header.
	// "sni" field is TLS SNI.
	vmessPathForLink := cfg.VmessPath
	if !strings.HasPrefix(vmessPathForLink, "/") { vmessPathForLink = "/" + vmessPathForLink }
	vmessObj := map[string]interface{}{
		"v":    "2",
		"ps":   fmt.Sprintf("%s-VMESS-WS-TLS", nodeHostTag),
		"add":  clientAddressForTLSLinks, // This is the connection address (IP or domain)
		"port": strconv.Itoa(int(cfg.Ports["vmess"])),
		"id":   cfg.MainUUID,
		"aid":  "0",
		"net":  "ws",
		"type": "none",
		"host": clientSNIForTLSLinks, // WebSocket host should match SNI
		"path": vmessPathForLink,
		"tls":  "tls",
		"sni":  clientSNIForTLSLinks, 
		"allowInsecure": clientAllowInsecureBoolForJSON, 
	}
	vmessJsonBytes, _ := json.Marshal(vmessObj)
	links = append(links, "vmess://"+base64.RawURLEncoding.EncodeToString(vmessJsonBytes))

	// Hysteria2 & TUIC: connect to clientAddressForTLSLinks, SNI is clientSNIForTLSLinks
	hy2FormattedUriHost := formatUriHost(clientAddressForTLSLinks)
	hysteria2Link := fmt.Sprintf("hysteria2://%s@%s:%d?sni=%s&insecure=%d&alpn=h3#%s-HY2",
		cfg.MainUUID, hy2FormattedUriHost, cfg.Ports["hysteria2"],
		clientSNIForTLSLinks, clientInsecureTLSFlag, nodeHostTag)
	links = append(links, hysteria2Link)

	tuicFormattedUriHost := formatUriHost(clientAddressForTLSLinks)
	tuicLink := fmt.Sprintf("tuic://%s:%s@%s:%d?sni=%s&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=%d#%s-TUIC",
		cfg.MainUUID, cfg.MainUUID, tuicFormattedUriHost, cfg.Ports["tuic"],
		clientSNIForTLSLinks, clientInsecureTLSFlag, nodeHostTag)
	links = append(links, tuicLink)

	// Shadowsocks & SOCKS5: connect to serverAddressForLinks (IP or domain directly)
	ssFormattedUriHost := formatUriHost(serverAddressForLinks)
	ssCipherMethod := "aes-128-gcm"
	ssPassword := cfg.MainUUID
	ssUserInfo := fmt.Sprintf("%s:%s", ssCipherMethod, ssPassword)
	ssEncodedUserInfo := base64.RawURLEncoding.EncodeToString([]byte(ssUserInfo))
	ssLink := fmt.Sprintf("ss://%s@%s:%d#%s-SS-%s",
		ssEncodedUserInfo, ssFormattedUriHost, cfg.Ports["shadowsocks"],
		nodeHostTag, strings.ToUpper(ssCipherMethod))
	links = append(links, ssLink)

	socks5AuthPart := ""
	if cfg.UseSocks5Auth && cfg.Socks5Username != "" && cfg.Socks5Password != "" {
		socks5AuthPart = fmt.Sprintf("%s:%s@", cfg.Socks5Username, cfg.Socks5Password)
	}
	socks5FormattedUriHost := formatUriHost(serverAddressForLinks)
	socks5Link := fmt.Sprintf("socks5://%s%s:%d#%s-SOCKS5",
		socks5AuthPart, socks5FormattedUriHost, cfg.Ports["socks5"], nodeHostTag)
	links = append(links, socks5Link)

	return links
}


func displayNodeInformationFromLinks(links []string) {
	fmt.Printf("\n%s--- Node Information & Links ---%s\n", ColorCyan, ColorReset)
	if len(links) == 0 {
		logWarn("No node links to display. Configuration might be incomplete.")
		return
	}
	for _, link := range links {
		var nodeType string
		switch {
		case strings.HasPrefix(link, "vless://"):   nodeType = "VLESS-Reality"
		case strings.HasPrefix(link, "vmess://"):   nodeType = "VMess-WS-TLS"
		case strings.HasPrefix(link, "hysteria2://"): nodeType = "Hysteria2"
		case strings.HasPrefix(link, "tuic://"):    nodeType = "TUICv5"
		case strings.HasPrefix(link, "ss://"):      nodeType = "Shadowsocks"
		case strings.HasPrefix(link, "socks5://"):  nodeType = "Socks5"
		default:                                  nodeType = "Unknown"
		}

		fmt.Printf("\n%s[%s]%s\n", ColorPurple, nodeType, ColorReset)
		fmt.Printf("  %sLink: %s%s%s\n", ColorGreen, ColorYellow, link, ColorReset)

		qr, err := qrcode.New(link, qrcode.Medium)
		if err == nil {
			fmt.Printf("  %sQR Code:%s\n", ColorGreen, ColorReset)
			fmt.Println(qr.ToSmallString(true))
		} else {
			logWarn("Failed to generate QR code for %s link: %v", nodeType, err)
		}
	}
}

func runAcmeCertbotSetup() bool {
	fmt.Printf("\n%s--- ACME Certificate Automation (Certbot) ---%s\n", ColorCyan, ColorReset)

	domainRegex := regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	var domain string
	for {
		domain = getUserInput(ColorYellow + "Enter your Fully Qualified Domain Name (e.g., sub.example.com): " + ColorReset)
		if domain == "" {
			if strings.ToLower(getUserInput(ColorYellow+"Domain cannot be empty. Cancel ACME setup? (y/N): "+ColorReset)) == "y" {
				logWarn("ACME setup cancelled by user (empty domain).")
				return false
			}
			continue
		}
		if !domainRegex.MatchString(domain) {
			logError("Invalid domain name format. Please enter a valid FQDN.")
			continue
		}
		break
	}
	currentInstallData.Domain = domain

	var email string
	for {
		email = getUserInput(ColorYellow + "Enter your email address for Certbot notifications (e.g., your@example.com): " + ColorReset)
		if email == "" {
			if strings.ToLower(getUserInput(ColorYellow+"Email cannot be empty. Cancel ACME setup? (y/N): "+ColorReset)) == "y" {
				logWarn("ACME setup cancelled by user (empty email).")
				return false
			}
			continue
		}
		if !emailRegex.MatchString(email) {
			logError("Invalid email address format. Please enter a valid email.")
			continue
		}
		break
	}
	currentInstallData.AcmeEmail = email

	currentIP := getPublicIP()
	fmt.Printf("\n%sIMPORTANT: Before proceeding, ensure the following:%s\n", ColorYellow, ColorReset)
	fmt.Printf("  %s1. DNS A (and/or AAAA) record for '%s%s%s' MUST point to this server's public IP: %s%s%s%s\n", ColorCyan, ColorYellow, domain, ColorCyan, ColorYellow, currentIP, ColorCyan, ColorReset)
	fmt.Printf("  %s2. Port 80 (TCP) on this server must be OPEN (firewall & not used by another service) for Certbot's HTTP-01 challenge.%s\n", ColorCyan, ColorReset)

	for {
		dnsCheckConfirm := getUserInput(ColorYellow + "Have you verified DNS and opened port 80 in your firewall? (y/N): " + ColorReset)
		if strings.ToLower(dnsCheckConfirm) == "y" {
			break
		}
		if strings.ToLower(getUserInput(ColorYellow+"DNS/Firewall not confirmed. Cancel ACME setup? (y/N): "+ColorReset)) == "y" {
			logWarn("ACME setup cancelled by user (DNS/firewall not confirmed).")
			return false
		}
	}

	logInfo("Checking if port 80 is currently in use (for Certbot's '--standalone' mode)...")
	listener, err := net.Listen("tcp", ":80")
	if err != nil {
		logError("Port 80 is likely in use by another application: %v", err)
		logError("Please stop the conflicting service (e.g., Nginx, Apache) and retry. Check with: sudo ss -tulnp | grep ':80'")
		logError("ACME setup aborted due to port 80 conflict.")
		return false
	}
	_ = listener.Close()
	logSuccess("Port 80 appears to be free for Certbot.")

	if _, err := exec.LookPath("certbot"); err != nil {
		logError("Certbot command is not found in PATH. Please ensure it's installed and accessible.")
		logError("  Try: sudo apt install certbot -y OR (if using snap) sudo snap install --classic certbot && sudo ln -s /snap/bin/certbot /usr/bin/certbot")
		logError("ACME setup aborted.")
		return false
	}

	logInfo("Attempting to obtain certificate for %s using Certbot (standalone)...", domain)
	certbotArgs := []string{"certonly", "--standalone", "--non-interactive", "--preferred-challenges", "http", "--email", email, "--agree-tos", "-d", domain, "--keep-until-expiring"}
	certbotOutput, certbotErr := runCommand("certbot", certbotArgs...)

	if certbotErr != nil {
		logError("Certbot failed to obtain certificate for %s: %v", domain, certbotErr)
		logError("Certbot Output:\n%s", certbotOutput)
		logError("Common issues: DNS not propagated, port 80 blocked by firewall/ISP, or another service using port 80. ACME setup aborted.")
		return false
	}
	logSuccess("Certbot successfully obtained certificate for %s.", domain)

	domainAcmeDir := filepath.Join(acmeBaseDir, domain)
	destCertPath := filepath.Join(domainAcmeDir, "fullchain.pem")
	destKeyPath := filepath.Join(domainAcmeDir, "privkey.pem")

	if err := os.MkdirAll(domainAcmeDir, 0755); err != nil {
		logError("Could not create ACME destination directory %s: %v", domainAcmeDir, err)
		return false
	}

	sourceCertPath := filepath.Join("/etc/letsencrypt/live", domain, "fullchain.pem")
	sourceKeyPath := filepath.Join("/etc/letsencrypt/live", domain, "privkey.pem")

	logInfo("Copying certificate files to Sing-box directory: %s", domainAcmeDir)
	if _, err := runCommand("cp", "-L", sourceCertPath, destCertPath); err != nil {
		logError("Failed to copy fullchain.pem from %s to %s: %v", sourceCertPath, destCertPath, err)
		return false
	}
	if _, err := runCommand("cp", "-L", sourceKeyPath, destKeyPath); err != nil {
		logError("Failed to copy privkey.pem from %s to %s: %v", sourceKeyPath, destKeyPath, err)
		return false
	}

	if _, err := runCommand("chmod", "644", destCertPath); err != nil {
		logWarn("Failed to set 644 permissions on %s: %v", destCertPath, err)
	}
	if _, err := runCommand("chmod", "600", destKeyPath); err != nil {
		logWarn("Failed to set 600 permissions on %s: %v", destKeyPath, err)
	}
	if _, err := runCommand("chown", "root:root", destCertPath, destKeyPath); err != nil {
		logWarn("Failed to set root ownership on certificate files in %s: %v", domainAcmeDir, err)
	}

	_, certStatErr := os.Stat(destCertPath)
	_, keyStatErr := os.Stat(destKeyPath)
	if os.IsNotExist(certStatErr) || os.IsNotExist(keyStatErr) {
		logError("ACME certificate files were not found at destination after copying attempt.")
		if os.IsNotExist(certStatErr) { logError("  Missing: %s", destCertPath) }
		if os.IsNotExist(keyStatErr) { logError("  Missing: %s", destKeyPath) }
		logError("ACME certificate setup failed. Sing-box may use self-signed certificates as fallback.")
		return false
	}

	logSuccess("ACME certificate automation complete for '%s'. Files copied to %s.", domain, domainAcmeDir)
	logInfo("Sing-box will be configured to use these certificates.")
	return true
}

func installInteractive() {
	fmt.Printf("\n%s--- Starting Sing-box Installation / Reinstallation ---%s\n", ColorYellow, ColorReset)
	checkRoot()
	checkOS()
	installDependencies()

	_ = os.MkdirAll(singBoxDir, 0755)
	_ = os.MkdirAll(acmeBaseDir, 0755)

	downloadAndInstallSingBox()

	installedVersion, versionErr := getSingBoxVersion()
	if versionErr != nil {
		logError("CRITICAL: Failed to confirm Sing-box version after download: %v", versionErr)
		logError("This could mean the binary was not installed correctly or is corrupted. Aborting installation.")
		os.Exit(1)
	}
	logSuccess("Confirmed Installed Sing-box Binary Version: %s", installedVersion)

	if !isSingBoxVersionAtLeast(1, 7, 0) {
		logWarn("Sing-box version appears older than 1.7.0 (or version check failed). Some UDP/network features might be handled by defaults or client-side settings.")
	} else {
		logInfo("Sing-box version %s is 1.7.0 or newer. Default configuration should be suitable.", installedVersion)
	}

	logInfo("Generating base self-signed certificates (as a fallback or default)...")
	generateSelfSignedCert()

	loadInstallData()

	fmt.Printf("\n%s--- Port Configuration ---%s\n", ColorCyan, ColorReset)
	if currentInstallData.Ports == nil {
		currentInstallData.Ports = make(map[string]uint16)
	}
	currentInstallData.Ports["vless"]       = getPort("VLESS", currentInstallData.Ports["vless"])
	currentInstallData.Ports["vmess"]       = getPort("VMess", currentInstallData.Ports["vmess"])
	currentInstallData.Ports["hysteria2"]   = getPort("Hysteria2", currentInstallData.Ports["hysteria2"])
	currentInstallData.Ports["tuic"]        = getPort("TUIC", currentInstallData.Ports["tuic"])
	currentInstallData.Ports["shadowsocks"] = getPort("Shadowsocks", currentInstallData.Ports["shadowsocks"])
	currentInstallData.Ports["socks5"]      = getPort("Socks5", currentInstallData.Ports["socks5"])

	currentInstallData.MainUUID = generateSingBoxUUID()
	logSuccess("Generated Main UUID for services: %s", currentInstallData.MainUUID)

	currentInstallData.VmessPath = fmt.Sprintf("/%s-vm", currentInstallData.MainUUID)

	privKey, pubKey, shortID, realityErr := generateRealityKeyPair()
	if realityErr != nil {
		logError("Failed to generate Reality key pair: %v. Aborting installation.", realityErr)
		os.Exit(1)
	}
	currentInstallData.RealityPrivateKey = privKey
	currentInstallData.RealityPublicKey = pubKey
	currentInstallData.RealityShortID = shortID
	logSuccess("Reality Public Key: %s", pubKey)
	logSuccess("Reality Short ID: %s", shortID)

	fmt.Printf("\n%s--- Socks5 Authentication Configuration ---%s\n", ColorCyan, ColorReset)
	socks5AuthChoice := getUserInput(ColorYellow + "Enable username/password authentication for Socks5 inbound? (y/N): " + ColorReset)
	if strings.ToLower(socks5AuthChoice) == "y" {
		currentInstallData.UseSocks5Auth = true
		for {
			username := getUserInput(ColorYellow + "Enter Socks5 username (default: sb_socks_user): " + ColorReset)
			if username == "" { username = "sb_socks_user" }
			currentInstallData.Socks5Username = username
			if currentInstallData.Socks5Username != "" { break }
			logError("Socks5 username cannot be empty. Please try again.")
		}
		for {
			password := getUserInput(ColorYellow + "Enter Socks5 password (leave empty for random, strong password recommended): " + ColorReset)
			if password == "" {
				password = generateSingBoxUUID()
				logSuccess("Generated random Socks5 password: %s", password)
			}
			currentInstallData.Socks5Password = password
			if currentInstallData.Socks5Password != "" { break }
			logError("Socks5 password cannot be empty. Please try again.")
		}
		logSuccess("Socks5 authentication enabled. User: %s", currentInstallData.Socks5Username)
	} else {
		currentInstallData.UseSocks5Auth = false
		currentInstallData.Socks5Username = ""
		currentInstallData.Socks5Password = ""
		logInfo("Socks5 inbound will be unauthenticated (open access).")
	}

	fmt.Printf("\n%s--- Certificate Configuration (for VMess, Hysteria2, TUIC) ---%s\n", ColorCyan, ColorReset)
	certChoice := getUserInput(ColorYellow + "Use ACME (Let's Encrypt) certificate for a domain? (y/N, N=Self-Signed): " + ColorReset)
	if strings.ToLower(certChoice) == "y" {
		if runAcmeCertbotSetup() {
			currentInstallData.UseAcmeCert = true
		} else {
			logWarn("ACME certificate setup failed or was cancelled. Reverting to self-signed certificates.")
			currentInstallData.UseAcmeCert = false
			currentInstallData.Domain = ""
			currentInstallData.AcmeEmail = ""
		}
	} else {
		logInfo("Using self-signed certificates for TLS-enabled services (VMess, Hysteria2, TUIC).")
		currentInstallData.UseAcmeCert = false
		currentInstallData.Domain = ""
		currentInstallData.AcmeEmail = ""
	}

	currentInstallData.ServerIP = getPublicIP()
	currentInstallData.Hostname, _ = os.Hostname()
	if currentInstallData.Hostname == "" { currentInstallData.Hostname = "sb-server" }

	saveInstallData()

	serverConfig := buildSingBoxServerConfig()
	writeSingBoxJSON(serverConfig)
	setupSystemdService()

	time.Sleep(1 * time.Second)
	statusText, isRunning := getSingBoxStatus()

	if !isRunning && currentInstallData.UseAcmeCert && currentInstallData.Domain != "" {
		domainAcmeDir := filepath.Join(acmeBaseDir, currentInstallData.Domain)
		certPath := filepath.Join(domainAcmeDir, "fullchain.pem")
		keyPath := filepath.Join(domainAcmeDir, "privkey.pem")
		_, certErr := os.Stat(certPath)
		_, keyErr := os.Stat(keyPath)
		if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
			logError("\nIMPORTANT WARNING:")
			logError("Sing-box service is %s. This is LIKELY because ACME certificates for '%s' are MISSING at:", statusText, currentInstallData.Domain)
			logError("  Cert: %s (exists: %v)", certPath, !os.IsNotExist(certErr))
			logError("  Key:  %s (exists: %v)", keyPath, !os.IsNotExist(keyErr))
			logError("Please ensure these files exist, or switch to Self-Signed (Option 4) and restart Sing-box.")
		}
	} else if !isRunning {
		logWarn("Sing-box service is %s. Check logs (Option 10) for details if issues persist.", statusText)
	}

	displayNodeInformationFromLinks(generateNodeLinks())
	cleanupInstallationFiles()

	logSuccess("Sing-box installation/reinstallation process completed.")
}

func uninstall() {
	checkRoot()
	logInfo("Uninstalling Sing-box and related configurations...")

	symlinkPath := filepath.Join("/usr/local/bin", cliCommandName)
	if err := os.Remove(symlinkPath); err == nil {
		logSuccess("Removed command symlink: %s", symlinkPath)
	} else if !os.IsNotExist(err) {
		logWarn("Could not remove symlink %s: %v (might be already removed or never created)", symlinkPath, err)
	}

	logInfo("Stopping and disabling Sing-box systemd service...")
	_, _ = runCommand("systemctl", "stop", "sing-box")
	_, _ = runCommand("systemctl", "disable", "sing-box")

	if err := os.Remove(systemdServiceFile); err == nil {
		logSuccess("Removed systemd service file: %s", systemdServiceFile)
	} else if !os.IsNotExist(err) {
		logWarn("Could not remove systemd service file %s: %v", systemdServiceFile, err)
	}

	logInfo("Removing Sing-box configuration directory: %s...", singBoxDir)
	if err := os.RemoveAll(singBoxDir); err != nil {
		logWarn("Failed to remove Sing-box directory %s: %v", singBoxDir, err)
	} else {
		logSuccess("Removed Sing-box directory %s.", singBoxDir)
	}

	logInfo("Reloading systemd daemon...")
	_, _ = runCommand("systemctl", "daemon-reload")

	logSuccess("Sing-box uninstallation complete.")
	logInfo("If you also want to remove Go, you'll need to do that manually (e.g., 'sudo rm -rf /usr/local/go /etc/profile.d/go_env.sh').")
}

func manageNodes() {
	if _, err := os.Stat(installConfigFile); os.IsNotExist(err) {
		logWarn("Sing-box is not installed or configuration data (%s) is missing. Please install first (Option 1).", installConfigFile)
		return
	}
	displayNodeInformationFromLinks(generateNodeLinks())
}

func manageCertificates() {
	checkRoot()
	if _, err := os.Stat(installConfigFile); os.IsNotExist(err) {
		logWarn("Sing-box is not installed or config data is missing. Please install first.")
		return
	}

	loadInstallData()

	fmt.Printf("\n%s--- Manage Certificates (for VMess, Hysteria2, TUIC) ---%s\n", ColorCyan, ColorReset)
	fmt.Printf("Current setting: Use ACME (Let's Encrypt) Certificate = %s%v%s", ColorYellow, currentInstallData.UseAcmeCert, ColorReset)
	if currentInstallData.UseAcmeCert {
		fmt.Printf(" (Domain: %s%s%s, Email: %s%s%s)\n", ColorYellow, currentInstallData.Domain, ColorReset, ColorYellow, currentInstallData.AcmeEmail, ColorReset)
	} else {
		fmt.Printf(" %s(Using Self-Signed Certificates)%s\n", ColorYellow, ColorReset)
	}
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("%s1. Switch to/Reconfigure ACME (Domain) Certificate%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s2. Switch to Self-Signed Certificate%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s0. Back to Main Menu%s\n", ColorYellow, ColorReset)

	choice := getUserInput(ColorYellow + "Your choice: " + ColorReset)
	configChanged := false

	switch choice {
	case "1":
		originalDomain, originalUseAcme, originalEmail := currentInstallData.Domain, currentInstallData.UseAcmeCert, currentInstallData.AcmeEmail
		if currentInstallData.UseAcmeCert {
			logInfo("Currently configured to use ACME for domain: %s", currentInstallData.Domain)
			if strings.ToLower(getUserInput(ColorYellow+"Reconfigure/renew for this domain or set up a new one? (y/N): "+ColorReset)) != "y" {
				logInfo("No changes made to ACME configuration.")
				return
			}
		}
		if runAcmeCertbotSetup() {
			currentInstallData.UseAcmeCert = true
			configChanged = true
			logSuccess("Sing-box is now configured to use ACME for domain: %s", currentInstallData.Domain)
		} else {
			logWarn("ACME setup failed or was cancelled. Reverting to previous certificate settings.")
			currentInstallData.Domain = originalDomain
			currentInstallData.AcmeEmail = originalEmail
			currentInstallData.UseAcmeCert = originalUseAcme
			if originalUseAcme {
				logWarn("Reverted to previous ACME settings for domain: %s (if any).", originalDomain)
			} else {
				logWarn("Reverted to Self-Signed certificate settings.")
			}
		}
	case "2":
		if !currentInstallData.UseAcmeCert {
			logInfo("Already using self-signed certificates. No change made.")
			return
		}
		logInfo("Switching to self-signed certificates...")
		generateSelfSignedCert()
		currentInstallData.UseAcmeCert = false
		currentInstallData.Domain = ""
		currentInstallData.AcmeEmail = ""
		configChanged = true
		logSuccess("Successfully switched to self-signed certificates.")
	case "0":
		return
	default:
		logError("Invalid choice. Please try again.")
		return
	}

	if configChanged {
		saveInstallData()
		logInfo("Rebuilding Sing-box server configuration due to certificate change...")
		serverCfg := buildSingBoxServerConfig()
		writeSingBoxJSON(serverCfg)
		restartSingBoxService()
		logSuccess("Sing-box configuration updated and service restarted.")
		displayNodeInformationFromLinks(generateNodeLinks())
	}
}

func manageSocks5Auth() {
	checkRoot()
	if _, err := os.Stat(installConfigFile); os.IsNotExist(err) {
		logWarn("Sing-box is not installed or configuration data is missing. Please install first.")
		return
	}
	loadInstallData()

	fmt.Printf("\n%s--- Manage Socks5 Authentication ---%s\n", ColorCyan, ColorReset)
	currentStatus := "Disabled (Open Access)"
	if currentInstallData.UseSocks5Auth {
		currentStatus = fmt.Sprintf("Enabled (User: %s%s%s, Pass: [hidden])", ColorYellow, currentInstallData.Socks5Username, ColorReset)
	}
	fmt.Printf("Current Socks5 authentication status: %s%s%s\n", ColorYellow, currentStatus, ColorReset)
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("%s1. Enable/Reconfigure Socks5 Authentication%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s2. Disable Socks5 Authentication%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s0. Back to Main Menu%s\n", ColorYellow, ColorReset)

	choice := getUserInput(ColorYellow + "Your choice: " + ColorReset)
	configChanged := false

	switch choice {
	case "1":
		if currentInstallData.UseSocks5Auth {
			logInfo("Socks5 authentication is already enabled. Reconfiguring...")
		} else {
			logInfo("Enabling Socks5 authentication.")
		}
		currentInstallData.UseSocks5Auth = true

		defaultUsernameHint := "sb_socks_user"
		if currentInstallData.Socks5Username != "" {
			defaultUsernameHint = currentInstallData.Socks5Username
		}
		for {
			username := getUserInput(ColorYellow + fmt.Sprintf("Enter Socks5 username (default: %s): ", defaultUsernameHint) + ColorReset)
			if username == "" { username = defaultUsernameHint }
			if username != "" {
				currentInstallData.Socks5Username = username
				break
			}
			logError("Socks5 username cannot be empty. Please enter a value or accept default.")
		}

		for {
			password := getUserInput(ColorYellow + "Enter Socks5 password (leave empty for random, strong password recommended): " + ColorReset)
			if password == "" {
				password = generateSingBoxUUID()
				logSuccess("Generated random Socks5 password: %s", password)
			}
			if password != "" {
				currentInstallData.Socks5Password = password
				break
			}
			logError("Socks5 password cannot be empty. Please enter a value or let one be generated.")
		}
		logSuccess("Socks5 authentication configured. Username: %s", currentInstallData.Socks5Username)
		configChanged = true

	case "2":
		if !currentInstallData.UseSocks5Auth {
			logInfo("Socks5 authentication is already disabled. No change made.")
			return
		}
		logInfo("Disabling Socks5 authentication.")
		currentInstallData.UseSocks5Auth = false
		currentInstallData.Socks5Username = ""
		currentInstallData.Socks5Password = ""
		logSuccess("Socks5 authentication disabled. Socks5 inbound will now allow open access.")
		configChanged = true

	case "0":
		return
	default:
		logError("Invalid choice. Please try again.")
		return
	}

	if configChanged {
		saveInstallData()
		logInfo("Rebuilding Sing-box server configuration due to Socks5 auth change...")
		serverCfg := buildSingBoxServerConfig()
		writeSingBoxJSON(serverCfg)
		restartSingBoxService()
		logSuccess("Sing-box configuration updated and service restarted.")
	}
}

func updateSingBoxBinaryAndRestartInteractive() {
	logInfo("Attempting to update Sing-box binary to the latest version...")
	checkRoot()

	oldVersion, errOld := getSingBoxVersion()
	if errOld != nil {
		logWarn("Could not determine current Sing-box version before update: %v", errOld)
		oldVersion = "unknown"
	}

	downloadAndInstallSingBox()

	newVersion, errNew := getSingBoxVersion()
	if errNew != nil {
		logWarn("Failed to get new Sing-box version after update attempt: %v", errNew)
		newVersion = "unknown"
	}

	if oldVersion != "unknown" && newVersion != "unknown" && oldVersion == newVersion {
		logInfo("Sing-box is already at the latest version (%s).", newVersion)
	} else {
		logSuccess("Sing-box updated from version '%s' to '%s'.", oldVersion, newVersion)
	}

	fmt.Printf("\n%sIMPORTANT: The Sing-box binary has been updated.%s\n", ColorYellow, ColorReset)
	fmt.Printf("%s  - A service restart is needed for the new binary to take effect.%s\n", ColorYellow, ColorReset)
	fmt.Printf("%s  - If the new version includes features requiring config changes, you might need to re-run '1. Install/Reinstall Sing-box' to regenerate the config.%s\n", ColorYellow, ColorReset)

	confirmRestart := getUserInput(ColorYellow + "Restart Sing-box service now to apply the updated binary? (y/N): " + ColorReset)
	if strings.ToLower(confirmRestart) == "y" {
		restartSingBoxService()
	} else {
		logWarn("Sing-box service not restarted. Please restart it manually (Option 7) for the update to take effect.")
	}
}

func generateAndShowSubscription() {
	if _, err := os.Stat(installConfigFile); os.IsNotExist(err) {
		logWarn("Sing-box is not installed or configuration data is missing. Please install first (Option 1).")
		return
	}
	links := generateNodeLinks()
	if len(links) == 0 {
		logWarn("No nodes configured to generate a subscription link.")
		return
	}

	var sbS strings.Builder
	for _, l := range links {
		sbS.WriteString(l + "\n")
	}
	b64s := base64.StdEncoding.EncodeToString([]byte(sbS.String()))

	fmt.Printf("\n%s--- Subscription Link (Base64 Encoded) ---%s\n", ColorCyan, ColorReset)
	fmt.Println(ColorYellow + b64s + ColorReset)
	fmt.Printf("\n%sCopy this link and import it into your Sing-box compatible client.%s\n", ColorGreen, ColorReset)
}

func cleanupInstallationFiles() {
	tempDir := os.TempDir()
	patterns := []string{"sing-box-*.tar.gz", "sb-extract*"}
	logInfo("Cleaning up temporary installation files from %s...", tempDir)

	cleanedCount := 0
	for _, pattern := range patterns {
		items, _ := filepath.Glob(filepath.Join(tempDir, pattern))
		for _, item := range items {
			info, err := os.Stat(item)
			if err == nil {
				if info.IsDir() {
					if err := os.RemoveAll(item); err == nil {
						cleanedCount++
					} else {
						logWarn("Failed to remove directory: %s - %v", item, err)
					}
				} else {
					if err := os.Remove(item); err == nil {
						cleanedCount++
					} else {
						logWarn("Failed to remove file: %s - %v", item, err)
					}
				}
			}
		}
	}
	if cleanedCount > 0 {
		logInfo("Temporary installation files cleaned up (%d items).", cleanedCount)
	} else {
		logInfo("No temporary installation files found to clean up.")
	}
}

func restartSingBoxServiceInteractive() {
	checkRoot()
	restartSingBoxService()
}

func stopSingBoxServiceInteractive() {
	checkRoot()
	logInfo("Stopping Sing-box service...")
	if _, err := runCommand("systemctl", "stop", "sing-box"); err != nil {
		logWarn("Sing-box service stop command failed: %v", err)
	} else {
		logSuccess("Sing-box service stopped successfully.")
	}
}

func startSingBoxServiceInteractive() {
	checkRoot()
	logInfo("Starting Sing-box service...")
	if _, err := runCommand("systemctl", "enable", "sing-box"); err != nil {
		logWarn("systemctl enable sing-box failed: %v (service might not start on boot)", err)
	}
	if _, err := runCommand("systemctl", "start", "sing-box"); err != nil {
		logWarn("Sing-box service start command failed: %v", err)
	} else {
		logSuccess("Sing-box service started successfully.")
	}
}

func viewSingBoxLogs() {
	logInfo("Displaying Sing-box logs (use Ctrl+C to exit)...")
	cmd := exec.Command("journalctl", "-u", "sing-box", "-f", "-e", "--no-pager")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			fmt.Printf("\n%sLog viewing ended (exit code: %d).%s\n", ColorYellow, exitError.ExitCode(), ColorReset)
			return
		}
		logError("Error viewing logs with journalctl: %v", err)
	}
}
EOF_GO_CODE
log_success "sb.go script content written to ${PROJECT_DIR}/sb.go"

# --- 4. Initialize Go Module and Download Dependencies ---
log_info "Initializing Go Module in ${PROJECT_DIR}..."
if [ ! -f "$PROJECT_DIR/go.mod" ]; then
    if go mod init sb_manager; then
        log_success "Go module initialized."
    else
        log_error "'go mod init' failed. Check Go installation and permissions in ${PROJECT_DIR}."
        exit 1
    fi
else
    log_warn "Go module (go.mod) already exists. Skipping 'go mod init'."
fi

log_info "Synchronizing Go module dependencies (go mod tidy)..."
if go mod tidy; then
    log_success "Go module dependencies synchronized."
else
    log_error "'go mod tidy' failed. Check internet connection or module paths."
    exit 1
fi

# --- 5. Compile Go Script ---
log_info "Compiling Sing-box Manager Executable (sb)..."
if go build -ldflags="-s -w" -o sb sb.go; then
    chmod +x sb
    log_success "Compilation complete. Executable: ${PROJECT_DIR}/sb"
else
    log_error "Go compilation failed. Check sb.go for errors or Go environment."
    exit 1
fi

# --- 6. Create Symlink to /usr/local/bin ---
log_info "Creating command symlink '/usr/local/bin/sb'..."
TARGET_CLI_NAME="sb"
if ln -sf "${PROJECT_DIR}/sb" "/usr/local/bin/${TARGET_CLI_NAME}"; then
    log_success "You can now run the manager using: sudo ${TARGET_CLI_NAME}"
else
    log_error "Failed to create symlink. Check permissions for /usr/local/bin."
fi

# --- 7. Final Instructions ---
echo ""
echo -e "${CYAN}${BOLD}--- Installation Script Finished ---${NC}"
echo -e "${CYAN}Sing-box Manager has been compiled to: ${GREEN}${PROJECT_DIR}/sb${NC}"
if [ -L "/usr/local/bin/${TARGET_CLI_NAME}" ] && [ -x "/usr/local/bin/${TARGET_CLI_NAME}" ]; then
    echo -e "${CYAN}You can start it by typing: ${GREEN}sudo ${TARGET_CLI_NAME}${NC}"
else
    echo -e "${YELLOW}Symlink creation failed or not verified.${NC}"
    echo -e "${CYAN}You can run the manager directly using: ${GREEN}sudo ${PROJECT_DIR}/sb${NC}"
fi
echo -e "${CYAN}Follow the manager's prompts to install Sing-box and configure nodes.${NC}"
echo -e "${YELLOW}If any errors occurred, please review the output above.${NC}"
echo ""

log_success "Script execution finished."
