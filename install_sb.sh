#!/bin/bash
#
# Filename: install_sb.sh
# Description: One-click script to set up Go environment, compile, and run Sing-box manager (sb.go).
#
# Usage:
#   1. Save this content as install_sb.sh.
#   2. Grant execute permission: chmod +x install_sb.sh
#   3. Run the script: sudo ./install_sb.sh

set -e # Exit immediately if a command exits with a non-zero status

# --- Color Definitions ---
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

clear
echo -e "${CYAN}--- Sing-box Manager (Go) Automated Installation Script ---${NC}"
echo -e "${CYAN}--- https://github.com/SagerNet/sing-box ---${NC}"
echo -e "${CYAN}--- Script Version: 1.0 ---${NC}"
echo ""

# --- 1. Check for Root Privileges ---
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root. Please use sudo ./install_sb.sh${NC}"
   exit 1
fi

echo -e "${YELLOW}Updating system package list and upgrading...${NC}"
apt update && apt upgrade -y
echo -e "${GREEN}System update completed.${NC}"

# --- 2. Check and Install Go Language Environment ---
if command -v go &> /dev/null; then
    echo -e "${GREEN}Go language is already installed: $(go version)${NC}"
else
    echo -e "${YELLOW}Go language not found, downloading and installing latest stable Go...${NC}"

    # Get system architecture
    ARCH=$(dpkg --print-architecture)
    case "$ARCH" in
        amd64) GO_ARCH="amd64" ;;
        arm64) GO_ARCH="arm64" ;;
        *) echo -e "${RED}Unsupported architecture: ${ARCH}. Please install Go manually.${NC}"; exit 1 ;;
    esac

    # Get latest Go version download link
    GO_URL=$(wget -qO- https://go.dev/dl/ | grep -oP "go[0-9\.]+\.linux-${GO_ARCH}\.tar\.gz" | head -n 1)
    if [ -z "$GO_URL" ]; then
        echo -e "${RED}Error: Could not retrieve latest Go language download link. Please check go.dev/dl manually.${NC}"
        exit 1
    fi
    GO_FULL_URL="https://go.dev/dl/${GO_URL}"
    GO_VERSION=$(echo "$GO_URL" | grep -oP "go[0-9\.]+" | sed 's/go//')

    echo -e "${YELLOW}Downloading Go ${GO_VERSION} (${GO_FULL_URL})...${NC}"
    mkdir -p /tmp/go_install
    wget -O /tmp/go_install/go.tar.gz "$GO_FULL_URL"

    echo -e "${YELLOW}Installing Go...${NC}"
    rm -rf /usr/local/go # Remove old Go installation
    tar -C /usr/local -xzf /tmp/go_install/go.tar.gz

    # Configure Go environment variables (persist to /etc/profile.d/)
    GO_PROFILE_PATH="/etc/profile.d/go_env.sh"
    echo "export PATH=\$PATH:/usr/local/go/bin" | tee "$GO_PROFILE_PATH" > /dev/null
    echo "export GOPATH=\$HOME/go" | tee -a "$GO_PROFILE_PATH" > /dev/null
    echo "export PATH=\$PATH:\$GOPATH/bin" | tee -a "$GO_PROFILE_PATH" > /dev/null

    # Make environment variables effective immediately for current shell
    source "$GO_PROFILE_PATH"
    export PATH="$PATH:/usr/local/go/bin"
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin"

    echo -e "${GREEN}Go language installation complete: $(go version)${NC}"
    rm -rf /tmp/go_install
fi

# --- 3. Prepare Go Project Directory and Write sb.go File ---
echo -e "${YELLOW}Creating Sing-box manager project directory...${NC}"
PROJECT_DIR="/home/sb_manager_go" # Place under /home for easier management
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

echo -e "${YELLOW}Writing sb.go script content...${NC}"
# --- START OF SB.GO CONTENT ---
# Using 'EOF_GO_CODE' with single quotes to prevent shell interpretation of Go code content.
cat << 'EOF_GO_CODE' > sb.go
// sb.go
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
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
	defaultUserAgent   = "sb-manager-go/3.9"
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
)

// SingBoxLogConfig defines the log configuration for Sing-box.
type SingBoxLogConfig struct {
	Disabled  bool   `json:"disabled"`
	Level     string `json:"level"`
	Timestamp bool   `json:"timestamp"`
}

// SingBoxUser defines a user for Sing-box inbounds.
type SingBoxUser struct {
	UUID     string `json:"uuid,omitempty"`
	Flow     string `json:"flow,omitempty"`
	AlterID  int    `json:"alterId,omitempty"`
	Password string `json:"password,omitempty"`
}

// SingBoxRealityHandshake defines the handshake configuration for VLESS Reality.
type SingBoxRealityHandshake struct {
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
}

// SingBoxRealityConfig defines the Reality configuration for VLESS.
type SingBoxRealityConfig struct {
	Enabled    bool                    `json:"enabled"`
	Handshake  SingBoxRealityHandshake `json:"handshake"`
	PrivateKey string                  `json:"private_key"`
	ShortID    []string                `json:"short_id"`
}

// SingBoxTLSConfig defines TLS settings for inbounds.
type SingBoxTLSConfig struct {
	Enabled         bool                  `json:"enabled"`
	ServerName      string                `json:"server_name,omitempty"`
	CertificatePath string                `json:"certificate_path,omitempty"`
	KeyPath         string                `json:"key_path,omitempty"`
	Reality         *SingBoxRealityConfig `json:"reality,omitempty"`
	ALPN            []string              `json:"alpn,omitempty"`
}

// SingBoxTransportConfig defines transport settings (e.g., WebSocket).
type SingBoxTransportConfig struct {
	Type                string `json:"type"`
	Path                string `json:"path,omitempty"`
	MaxEarlyData        int    `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string `json:"early_data_header_name,omitempty"`
}

// SingBoxInbound defines an inbound listener.
type SingBoxInbound struct {
	Type                     string                  `json:"type"`
	Tag                      string                  `json:"tag"`
	Listen                   string                  `json:"listen"`
	ListenPort               uint16                  `json:"listen_port"`
	Sniff                    bool                    `json:"sniff"`
	SniffOverrideDestination bool                    `json:"sniff_override_destination"`
	Users                    []SingBoxUser           `json:"users"`
	TLS                      *SingBoxTLSConfig       `json:"tls,omitempty"`
	Transport                *SingBoxTransportConfig `json:"transport,omitempty"`
	CongestionControl        string                  `json:"congestion_control,omitempty"`
	IgnoreClientBandwidth    bool                    `json:"ignore_client_bandwidth,omitempty"`
}

// SingBoxOutbound defines an outbound proxy.
type SingBoxOutbound struct {
	Type           string `json:"type"`
	Tag            string `json:"tag"`
	DomainStrategy string `json:"domain_strategy,omitempty"`
}

// SingBoxRouteRule defines a routing rule.
type SingBoxRouteRule struct {
	Protocol []string `json:"protocol,omitempty"`
	Network  string   `json:"network,omitempty"`
	Outbound string   `json:"outbound"`
}

// SingBoxRouteConfig defines routing settings.
type SingBoxRouteConfig struct {
	Rules []SingBoxRouteRule `json:"rules"`
}

// SingBoxServerConfig is the root configuration for Sing-box.
type SingBoxServerConfig struct {
	Log       SingBoxLogConfig   `json:"log"`
	Inbounds  []SingBoxInbound   `json:"inbounds"`
	Outbounds []SingBoxOutbound  `json:"outbounds"`
	Route     SingBoxRouteConfig `json:"route"`
}

// InstallData stores persistent configuration data for the manager.
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
			generateAndShowSubscription()
		case "6":
			restartSingBoxServiceInteractive()
		case "7":
			stopSingBoxServiceInteractive()
		case "8":
			startSingBoxServiceInteractive()
		case "9":
			viewSingBoxLogs()
		case "10":
			checkSingBoxStatusInteractive()
		case "0":
			fmt.Println(ColorGreen + "Exiting." + ColorReset)
			os.Exit(0)
		default:
			fmt.Printf("%sInvalid choice. Please try again.%s\n", ColorRed, ColorReset)
		}
		if choice != "0" && choice != "9" && choice != "10" {
			fmt.Printf("\n%sPress Enter to continue...%s", ColorYellow, ColorReset)
			bufio.NewReader(os.Stdin).ReadBytes('\n')
		}
	}
}

// clearScreen clears the terminal screen.
func clearScreen() {
	cmd := exec.Command("clear")
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

// getSingBoxStatus checks the status of the sing-box systemd service.
func getSingBoxStatus() (string, bool) {
	var err error // Declare err once at the top of the function scope

	// Check service file existence
	if _, err = os.Stat(systemdServiceFile); os.IsNotExist(err) {
		return "Not Installed", false
	}
	if err != nil {
		return fmt.Sprintf("Error stating service file: %v", err), false
	}

	// Check active status
	cmd := exec.Command("systemctl", "is-active", "sing-box")
	var output []byte // Declare output explicitly
	output, err = cmd.Output() // Assign to existing 'err'
	status := strings.TrimSpace(string(output))

	if err != nil {
		// If is-active fails, check if it's in a failed state
		failCmd := exec.Command("systemctl", "is-failed", "sing-box")
		var failOutput []byte
		failOutput, _ = failCmd.Output() // No 'err' variable from here, _ is used.
		failStatus := strings.TrimSpace(string(failOutput))
		if failStatus == "failed" {
			return "Failed", false
		}
		return "Inactive/Stopped", false
	}

	if status == "active" {
		return "Active (Running)", true
	}
	return strings.Title(status), false
}

// printMainMenu displays the main menu options.
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
	fmt.Printf("\n--- %s --- %s ---\n", managerTitle, statusLine)
	fmt.Printf("%s1. Install/Reinstall Sing-box%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s2. Uninstall Sing-box%s\n", ColorRed, ColorReset)
	fmt.Printf("%s3. Show Nodes%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s4. Manage Certificates (Switch Self-signed/ACME)%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s5. Generate & Show Subscription Link%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s--- Service Management ---%s\n", ColorBlue, ColorReset)
	fmt.Printf("%s6. Restart Sing-box%s\n", ColorYellow, ColorReset)
	fmt.Printf("%s7. Stop Sing-box%s\n", ColorYellow, ColorReset)
	fmt.Printf("%s8. Start Sing-box%s\n", ColorYellow, ColorReset)
	fmt.Printf("%s9. View Sing-box Logs%s\n", ColorYellow, ColorReset)
	fmt.Printf("%s10. Check Sing-box Status%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s0. Exit%s\n", ColorYellow, ColorReset)
	fmt.Println(strings.Repeat("-", 50))
}

// checkSingBoxStatusInteractive displays the current Sing-box service status.
func checkSingBoxStatusInteractive() {
	fmt.Printf("%sChecking Sing-box service status...%s\n", ColorYellow, ColorReset)
	statusText, isRunning := getSingBoxStatus()
	statusColor := ColorYellow
	if isRunning {
		statusColor = ColorGreen
	} else if statusText == "Failed" || statusText == "Not Installed" {
		statusColor = ColorRed
	}
	fmt.Printf("Sing-box Service Status: %s%s%s\n", statusColor, statusText, ColorReset)
	if !isRunning && statusText != "Not Installed" {
		fmt.Printf("%sUse option '9' for detailed logs if service failed.%s\n", ColorYellow, ColorReset)
	}
}

// getUserInput prompts the user for input and returns the trimmed string.
func getUserInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// runCommand executes a shell command and returns its stdout or an error.
func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("command %s %v failed: %w\nStdout: %s\nStderr: %s", name, args, err, strings.ToValidUTF8(stdout.String(), ""), strings.ToValidUTF8(stderr.String(), ""))
	}
	return stdout.String(), nil
}

// checkRoot ensures the script is run with root privileges.
func checkRoot() {
	if os.Geteuid() != 0 {
		log.Fatalf("%sRoot privileges required.%s", ColorRed, ColorReset)
	}
}

// checkOS verifies the operating system is Debian-based.
func checkOS() {
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		fmt.Printf("%sOS check OK (Debian-based).%s\n", ColorGreen, ColorReset)
		return
	}

	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		fmt.Printf("%sWarning: OS check failed: %v%s\n", ColorYellow, err, ColorReset)
		if strings.ToLower(getUserInput(ColorYellow + "Is this Debian-based? (y/N): " + ColorReset)) != "y" {
			log.Fatalf("%sOS not confirmed Debian-based.%s", ColorRed, ColorReset)
		}
		return
	}
	s := string(b)
	if !strings.Contains(s, "ID_LIKE=debian") && !strings.Contains(s, "ID=debian") && !strings.Contains(s, "ID=ubuntu") {
		log.Fatalf("%sUnsupported OS.%s", ColorRed, ColorReset)
	}
	fmt.Printf("%sOS check OK.%s\n", ColorGreen, ColorReset)
}

// installDependencies installs necessary system packages.
func installDependencies() {
	fmt.Printf("%sUpdating apt...%s\n", ColorYellow, ColorReset)
	if _, err := runCommand("apt-get", "update", "-y"); err != nil {
		log.Fatalf("%sApt update failed: %v%s", ColorRed, err, ColorReset)
	}
	dependencies := []string{"curl", "wget", "jq", "qrencode", "openssl", "iproute2", "iptables", "ca-certificates", "certbot"}
	fmt.Printf("%sInstalling dependencies: %v%s\n", ColorYellow, dependencies, ColorReset)
	installArgs := []string{"install", "-y"}
	installArgs = append(installArgs, dependencies...)
	if _, err := runCommand("apt-get", installArgs...); err != nil {
		if strings.Contains(err.Error(), "certbot") {
			fmt.Printf("%sWARN: apt install certbot failed. Try snap: sudo apt install snapd && sudo snap install --classic certbot && sudo ln -s /snap/bin/certbot /usr/bin/certbot%s\n", ColorYellow, ColorReset)
		} else {
			log.Fatalf("%sDependency installation failed: %v%s", ColorRed, err, ColorReset)
		}
	}
	fmt.Printf("%sDependencies installation attempted.%s\n", ColorGreen, ColorReset)
	if _, err := exec.LookPath("certbot"); err != nil {
		fmt.Printf("%sWARN: certbot still not found. Manual install needed for ACME features.%s\n", ColorYellow, ColorReset)
	} else {
		fmt.Printf("%sCertbot found and accessible.%s\n", ColorGreen, ColorReset)
	}
}

// getCPUArch determines the CPU architecture for Sing-box download.
func getCPUArch() string {
	arch := runtime.GOARCH
	if arch == "amd64" || arch == "arm64" {
		return arch
	}
	log.Fatalf("%sArchitecture %s is unsupported.%s", ColorRed, arch, ColorReset)
	return "" // Should not reach here
}

// downloadAndInstallSingBox downloads and installs the latest Sing-box binary.
func downloadAndInstallSingBox() {
	fmt.Printf("%sDownloading and installing Sing-box...%s\n", ColorYellow, ColorReset)
	arch := getCPUArch()
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/repos/SagerNet/sing-box/releases/latest", nil)
	if err != nil {
		log.Fatalf("Failed to create request for releases: %v", err)
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Accept", "application/vnd.github.com.v3+json") // Corrected Accept header
	res, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to fetch release information: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		log.Fatalf("Failed to fetch release status %d: %s", res.StatusCode, string(body))
	}

	var releaseInfo struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(res.Body).Decode(&releaseInfo); err != nil {
		log.Fatalf("Failed to parse release JSON: %v", err)
	}

	var downloadURL string
	suffix := fmt.Sprintf("linux-%s.tar.gz", arch)
	for _, asset := range releaseInfo.Assets {
		if strings.HasPrefix(asset.Name, "sing-box-") && strings.HasSuffix(asset.Name, suffix) {
			downloadURL = asset.URL
			fmt.Printf("%sFound Sing-box asset: %s%s\n", ColorGreen, asset.Name, ColorReset)
			break
		}
	}

	if downloadURL == "" {
		log.Fatalf("No download URL found for %s architecture in %s release.", arch, releaseInfo.TagName)
	}

	fmt.Printf("%sDownloading from %s%s\n", ColorYellow, downloadURL, ColorReset)
	os.MkdirAll(singBoxDir, 0755)
	downloadPath := filepath.Join(os.TempDir(), filepath.Base(downloadURL))

	outputFile, err := os.Create(downloadPath)
	if err != nil {
		log.Fatalf("Failed to create download file: %v", err)
	}

	downloadResponse, err := client.Get(downloadURL)
	if err != nil {
		outputFile.Close()
		os.Remove(downloadPath)
		log.Fatalf("Download failed: %v", err)
	}
	defer downloadResponse.Body.Close()

	if downloadResponse.StatusCode != http.StatusOK {
		outputFile.Close()
		os.Remove(downloadPath)
		log.Fatalf("Download failed with status %d", downloadResponse.StatusCode)
	}

	_, err = io.Copy(outputFile, downloadResponse.Body)
	outputFile.Close()
	if err != nil {
		os.Remove(downloadPath)
		log.Fatalf("Failed to save downloaded content: %v", err)
	}

	fmt.Printf("%sExtracting Sing-box...%s\n", ColorYellow, ColorReset)
	extractDir := filepath.Join(os.TempDir(), "sb-extract")
	os.RemoveAll(extractDir)
	os.MkdirAll(extractDir, 0755)

	if _, err := runCommand("tar", "-xzf", downloadPath, "-C", extractDir); err != nil {
		log.Fatalf("Failed to extract Sing-box archive: %v", err)
	}

	var binaryPath string
	filepath.Walk(extractDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == "sing-box" {
			binaryPath = p
			return filepath.SkipDir // Found the binary, stop walking
		}
		return nil
	})

	if binaryPath == "" {
		log.Fatalf("Sing-box binary not found in extracted archive.")
	}

	sourceFile, err := os.Open(binaryPath)
	if err != nil {
		log.Fatalf("Failed to open source binary: %v", err)
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(singBoxBinary)
	if err != nil {
		log.Fatalf("Failed to create destination binary: %v", err)
	}
	defer destinationFile.Close()

	_, err = io.Copy(destinationFile, sourceFile)
	if err != nil {
		log.Fatalf("Failed to copy binary to destination: %v", err)
	}

	os.Chmod(singBoxBinary, 0755) // Make executable

	if err := os.Remove(binaryPath); err != nil {
		fmt.Printf("%sWARN: Could not remove temporary binary file: %v%s\n", ColorYellow, err, ColorReset)
	}
	os.Remove(downloadPath)
	os.RemoveAll(extractDir)

	versionOutput, _ := runCommand(singBoxBinary, "version")
	fmt.Printf("%sSing-box installed: %s%s\n", ColorGreen, strings.TrimSpace(versionOutput), ColorReset)
}

// generateSelfSignedCert generates and saves a self-signed TLS certificate and key.
func generateSelfSignedCert() {
	fmt.Printf("%sGenerating self-signed certificate...%s\n", ColorYellow, ColorReset)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate ECDSA private key: %v", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject: pkix.Name{
			CommonName: defaultSNI,
		},
		NotBefore: now,
		NotAfter:  now.AddDate(10, 0, 0), // Valid for 10 years

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{defaultSNI},
		BasicConstraintsValid: true,
		IsCA:                  true, // Mark as CA for self-signed
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	certOut, err := os.Create(selfSignedCert)
	if err != nil {
		log.Fatalf("Failed to open self-signed certificate file for writing: %v", err)
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut, err := os.Create(selfSignedKey)
	if err != nil {
		log.Fatalf("Failed to open self-signed key file for writing: %v", err)
	}
	defer keyOut.Close()
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Failed to marshal private key: %v", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes})

	fmt.Printf("%sSelf-signed certificate generated and saved.%s\n", ColorGreen, ColorReset)
}

// getPort prompts the user for a port number, validating its range.
func getPort(protocol string, suggestedPort uint16) uint16 {
	reader := bufio.NewReader(os.Stdin)
	defaultHint := "random"
	if suggestedPort > 0 {
		defaultHint = fmt.Sprintf("%d or random", suggestedPort)
	}
	for {
		fmt.Printf("%s %s port (default:%s, 10000-65535): ", ColorYellow, protocol, defaultHint)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" {
			if suggestedPort > 0 {
				fmt.Printf("Using previous/default: %d\n", suggestedPort)
				return suggestedPort
			}
			return generateRandomPort(uint16(20000 + time.Now().Nanosecond()%10000)) // Fallback if no suggested port
		}

		port, err := strconv.Atoi(input)
		if err == nil && port >= 10000 && port <= 65535 {
			return uint16(port)
		}
		fmt.Printf("%sInvalid port. Please enter a number between 10000 and 65535.%s\n", ColorRed, ColorReset)
	}
}

// generateRandomPort finds an available random port.
func generateRandomPort(fallback uint16) uint16 {
	for i := 0; i < 20; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(55536)) // 65535 - 10000 = 55535
		if err != nil {
			continue
		}
		p := uint16(n.Int64() + 10000) // Port between 10000 and 65535

		// Check if TCP port is available
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
		if err == nil {
			listener.Close()
			// Check if UDP port is available (less critical, but good practice)
			packetListener, err := net.ListenPacket("udp", fmt.Sprintf(":%d", p))
			if err == nil {
				packetListener.Close()
				fmt.Printf("%sGenerated random port: %d%s\n", ColorGreen, p, ColorReset)
				return p
			}
		}
	}
	fmt.Printf("%sWARN: Failed to generate a random available port after multiple attempts, using fallback %d%s\n", ColorYellow, fallback, ColorReset)
	return fallback
}

// generateSingBoxUUID generates a new UUID for Sing-box user.
func generateSingBoxUUID() string {
	return uuid.NewString()
}

// generateRealityKeyPair generates Reality private key, public key, and short ID using Sing-box.
func generateRealityKeyPair() (privateKey, publicKey, shortID string, err error) {
	if _, err := os.Stat(singBoxBinary); os.IsNotExist(err) {
		return "", "", "", fmt.Errorf("sing-box binary not found at %s", singBoxBinary)
	}

	output, err := runCommand(singBoxBinary, "generate", "reality-keypair")
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate reality keypair: %w", err)
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
	if scanner.Err() != nil {
		return "", "", "", fmt.Errorf("failed to scan reality keypair output: %w", scanner.Err())
	}
	if privateKey == "" || publicKey == "" {
		return "", "", "", fmt.Errorf("failed to parse private/public keys from sing-box output: %s", output)
	}

	shortIDOutput, err := runCommand(singBoxBinary, "generate", "rand", "--hex", "4")
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate short ID: %w", err)
	}
	shortID = strings.TrimSpace(shortIDOutput)

	return privateKey, publicKey, shortID, nil
}

// saveInstallData saves the current installation data to a JSON file.
func saveInstallData() {
	data, err := json.MarshalIndent(currentInstallData, "", "  ")
	if err != nil {
		fmt.Printf("%sWARN: Failed to marshal install_data.json: %v%s\n", ColorYellow, err, ColorReset)
		return
	}
	if err := os.WriteFile(installConfigFile, data, 0600); err != nil {
		fmt.Printf("%sWARN: Failed to save install_data.json: %v%s\n", ColorYellow, err, ColorReset)
	}
}

// loadInstallData loads installation data from a JSON file, or initializes defaults.
func loadInstallData() {
	if err := os.MkdirAll(singBoxDir, 0755); err != nil && !os.IsExist(err) {
		fmt.Printf("%sWARN: Failed to create directory %s: %v%s\n", ColorYellow, singBoxDir, err, ColorReset)
	}

	data, err := os.ReadFile(installConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("%sNo existing install config found. Initializing with defaults.%s\n", ColorYellow, ColorReset)
		} else {
			fmt.Printf("%sWARN: Failed to read %s: %v. Initializing with defaults.%s\n", ColorYellow, installConfigFile, err, ColorReset)
		}
		currentInstallData.Ports = make(map[string]uint16)
		currentInstallData.ServerIP = getPublicIP()
		currentInstallData.Hostname, _ = os.Hostname()
		if currentInstallData.Hostname == "" {
			currentInstallData.Hostname = "sb-server"
		}
		currentInstallData.UseAcmeCert = false
		currentInstallData.Domain = ""
		currentInstallData.AcmeEmail = ""
		return
	}

	if err := json.Unmarshal(data, &currentInstallData); err != nil {
		fmt.Printf("%sWARN: Failed to unmarshal %s: %v. Content: <%s>. Initializing with defaults.%s\n", ColorYellow, installConfigFile, err, string(data), ColorReset)
		currentInstallData.Ports = make(map[string]uint16)
		currentInstallData.ServerIP = getPublicIP()
		currentInstallData.Hostname, _ = os.Hostname()
		if currentInstallData.Hostname == "" {
			currentInstallData.Hostname = "sb-server"
		}
		currentInstallData.MainUUID = ""
		currentInstallData.RealityPrivateKey = ""
		currentInstallData.RealityPublicKey = ""
		currentInstallData.RealityShortID = ""
		currentInstallData.VmessPath = ""
		currentInstallData.UseAcmeCert = false
		currentInstallData.Domain = ""
		currentInstallData.AcmeEmail = ""
		return
	}

	// Ensure maps and string fields are initialized if loaded from an older/partial config
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
	if currentInstallData.AcmeEmail == "" && currentInstallData.UseAcmeCert {
		// If ACME was enabled but email was missing (e.g. from older version), clear domain to avoid broken state
		currentInstallData.Domain = ""
		currentInstallData.UseAcmeCert = false
		fmt.Printf("%sWARN: ACME certs enabled but email missing in config. Reverting to self-signed. Please reconfigure ACME if desired.%s\n", ColorYellow, ColorReset)
	}

	fmt.Printf("%sInstall data loaded from %s%s\n", ColorGreen, installConfigFile, ColorReset)
}

// buildSingBoxServerConfig constructs the Sing-box server configuration based on currentInstallData.
func buildSingBoxServerConfig() SingBoxServerConfig {
	cfg := currentInstallData
	certPath, keyPath := selfSignedCert, selfSignedKey
	vmSNI, h2SNI, tSNI := defaultSNI, defaultSNI, defaultSNI
	isAcmeEffective := false

	if cfg.UseAcmeCert && cfg.Domain != "" {
		domainAcmeDir := filepath.Join(acmeBaseDir, cfg.Domain)
		acmeCertPath := filepath.Join(domainAcmeDir, "fullchain.pem")
		acmeKeyPath := filepath.Join(domainAcmeDir, "privkey.pem")

		// Check if ACME certificate files actually exist
		if _, certErr := os.Stat(acmeCertPath); certErr == nil {
			if _, keyErr := os.Stat(acmeKeyPath); keyErr == nil {
				isAcmeEffective = true
			}
		}

		if isAcmeEffective {
			certPath = acmeCertPath
			keyPath = acmeKeyPath
			vmSNI, h2SNI, tSNI = cfg.Domain, cfg.Domain, cfg.Domain
			fmt.Printf("%sServer config: Using ACME certificate for domain: %s (files found).%s\n", ColorGreen, cfg.Domain, ColorReset)
		} else {
			// ACME was intended, but files not found. Fallback to self-signed behavior for config, but warn.
			fmt.Printf("%sCRITICAL WARN: Server config set to use ACME for '%s', but certificate files NOT FOUND at expected paths.%s\n", ColorRed, cfg.Domain, ColorReset)
			fmt.Printf("%s  Expected cert: %s\n", ColorRed, acmeCertPath, ColorReset)
			fmt.Printf("%s  Expected key:  %s\n", ColorRed, acmeKeyPath, ColorReset)
			fmt.Printf("%s  Sing-box will LIKELY FAIL TO START or serve TLS correctly until these files are placed! Default SNI will be used.%s\n", ColorRed, ColorReset)
			certPath = selfSignedCert
			keyPath = selfSignedKey
		}
	} else {
		// Ensure self-signed certs exist if ACME is not used or failed
		_, selfCertStatErr := os.Stat(selfSignedCert)
		_, selfKeyStatErr := os.Stat(selfSignedKey)
		if os.IsNotExist(selfCertStatErr) || os.IsNotExist(selfKeyStatErr) {
			fmt.Printf("%sSelf-signed cert/key not found (default mode), generating now...%s\n", ColorYellow, ColorReset)
			generateSelfSignedCert()
		}
		fmt.Printf("%sServer config: Using self-signed certificate (SNI for non-VLESS: %s)%s\n", ColorGreen, defaultSNI, ColorReset)
	}

	if cfg.VmessPath == "" {
		cfg.VmessPath = fmt.Sprintf("/%s-vm", cfg.MainUUID)
	}

	return SingBoxServerConfig{
		Log: SingBoxLogConfig{Level: "info", Timestamp: true},
		Inbounds: []SingBoxInbound{
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
					ServerName: realitySNI, // Reality SNI is fixed
					Reality: &SingBoxRealityConfig{
						Enabled:   true,
						Handshake: SingBoxRealityHandshake{Server: realitySNI, ServerPort: 443},
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
					ServerName:      vmSNI,
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
				Users:                    []SingBoxUser{{Password: cfg.MainUUID}}, // Hysteria2 uses password
				IgnoreClientBandwidth:    false,
				TLS: &SingBoxTLSConfig{
					Enabled:         true,
					ALPN:            []string{"h3"},
					CertificatePath: certPath,
					KeyPath:         keyPath,
					ServerName:      h2SNI,
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
					ServerName:      tSNI,
				},
			},
		},
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

// writeSingBoxJSON writes the Sing-box server configuration to sb.json.
func writeSingBoxJSON(serverConfig SingBoxServerConfig) {
	fmt.Printf("%sWriting sb.json...%s\n", ColorYellow, ColorReset)
	data, err := json.MarshalIndent(serverConfig, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal Sing-box config to JSON: %v", err)
	}
	if err := os.WriteFile(singBoxConfig, data, 0644); err != nil {
		log.Fatalf("Failed to write Sing-box config file: %v", err)
	}
	fmt.Printf("%sConfig written to %s%s\n", ColorGreen, singBoxConfig, ColorReset)
}

// setupSystemdService creates and enables the systemd service for Sing-box.
func setupSystemdService() {
	fmt.Printf("%sSetting up systemd service...%s\n", ColorYellow, ColorReset)
	serviceContent := `[Unit]
Description=Sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/etc/s-box
# CapabilityBoundingSet and AmbientCapabilities are for advanced network operations
# such as binding to privileged ports, raw sockets for TPROXY, etc.
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
		log.Fatalf("Failed to write systemd service file: %v", err)
	}

	// Reload systemd daemon, enable and restart service
	if _, err := runCommand("systemctl", "daemon-reload"); err != nil {
		fmt.Printf("%sWARN: systemctl daemon-reload failed: %v%s\n", ColorYellow, err, ColorReset)
	}
	if _, err := runCommand("systemctl", "enable", "sing-box"); err != nil {
		fmt.Printf("%sWARN: systemctl enable sing-box failed: %v%s\n", ColorYellow, err, ColorReset)
	}
	restartSingBoxService()
}

// restartSingBoxService restarts the Sing-box systemd service.
func restartSingBoxService() {
	fmt.Printf("%sRestarting Sing-box service...%s\n", ColorYellow, ColorReset)
	if _, err := runCommand("systemctl", "restart", "sing-box"); err != nil {
		fmt.Printf("%sWARN: Sing-box service restart failed: %v%s\n", ColorYellow, err, ColorReset)
	} else {
		fmt.Printf("%sSing-box service restarted successfully.%s\n", ColorGreen, ColorReset)
	}
}

// getPublicIP attempts to retrieve the server's public IPv4 or IPv6 address.
func getPublicIP() string {
	client := http.Client{Timeout: 5 * time.Second}
	ipServices := []string{"https://api.ipify.org", "https://api6.ipify.org", "https://icanhazip.com"}

	for i, serviceURL := range ipServices {
		resp, err := client.Get(serviceURL)
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr == nil {
				ip := strings.TrimSpace(string(body))
				if net.ParseIP(ip) != nil {
					return ip
				}
			}
		}
		if i == len(ipServices)-1 {
			fmt.Printf("%sWARN: Failed to get public IP address from all services: %v%s\n", ColorYellow, err, ColorReset)
		}
	}
	return "YOUR_SERVER_IP" // Fallback placeholder
}

// Btoi converts a boolean to an integer (0 for true, 1 for false). Used for 'insecure' flags.
func Btoi(isSecure bool) int {
	if isSecure {
		return 0
	}
	return 1
}

// generateNodeLinks generates client configuration links based on the current setup.
func generateNodeLinks() []string {
	if currentInstallData.MainUUID == "" {
		fmt.Printf("%sNo installation data found. Please install Sing-box first.%s\n", ColorYellow, ColorReset)
		return nil
	}

	cfg := currentInstallData
	var links []string
	nodeHost := cfg.Hostname
	if nodeHost == "" {
		nodeHost = "sb-server"
	}

	serverIPForLink := cfg.ServerIP
	if serverIPForLink == "" || serverIPForLink == "YOUR_SERVER_IP" {
		serverIPForLink = getPublicIP()
	}

	isAcmeEffectivelyUsed, linkSNIForNonVLESS, addressForNonVLESSLinks := false, defaultSNI, serverIPForLink

	if cfg.UseAcmeCert && cfg.Domain != "" {
		addressForNonVLESSLinks = cfg.Domain
		linkSNIForNonVLESS = cfg.Domain
		domainAcmeDir := filepath.Join(acmeBaseDir, cfg.Domain)
		certPath, keyPath := filepath.Join(domainAcmeDir, "fullchain.pem"), filepath.Join(domainAcmeDir, "privkey.pem")
		if _, certErr := os.Stat(certPath); certErr == nil {
			if _, keyErr := os.Stat(keyPath); keyErr == nil {
				isAcmeEffectivelyUsed = true
			}
		}
	}

	if isAcmeEffectivelyUsed {
		fmt.Printf("%sLinks using ACME domain: %s (certificates found, insecure=0 for VMess/Hy2/TUIC).%s\n", ColorCyan, cfg.Domain, ColorReset)
	} else if cfg.UseAcmeCert {
		fmt.Printf("%sWARN: Links use ACME domain: %s, but certificate files NOT found. insecure=1 will be set for VMess/Hy2/TUIC.%s\n", ColorYellow, cfg.Domain, ColorReset)
	} else {
		fmt.Printf("%sLinks using IP/default SNI for non-VLESS (Self-Signed mode, insecure=1 for VMess/Hy2/TUIC).%s\n", ColorCyan, ColorReset)
	}

	// Format IP addresses for links (IPv6 needs brackets)
	formatAddress := func(addr string) string {
		ip := net.ParseIP(addr)
		if ip != nil && ip.To4() == nil && ip.To16() != nil {
			return fmt.Sprintf("[%s]", addr)
		}
		return addr
	}

	// VLESS Reality
	vlessActualConnectionAddress := serverIPForLink
	vlessDisplayAddress := formatAddress(vlessActualConnectionAddress)
	vlessLink := fmt.Sprintf("vless://%s@%s:%d?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp#%s-VLESS-Reality",
		cfg.MainUUID, vlessDisplayAddress, cfg.Ports["vless"], realitySNI, cfg.RealityPublicKey, cfg.RealityShortID, nodeHost)
	links = append(links, vlessLink)

	// VMess WebSocket TLS
	displayAddressNonVLESS := formatAddress(addressForNonVLESSLinks)
	vmessObj := map[string]interface{}{
		"v":    "2",
		"ps":   fmt.Sprintf("%s-VMESS-WS-TLS", nodeHost),
		"add":  addressForNonVLESSLinks,
		"port": strconv.Itoa(int(cfg.Ports["vmess"])),
		"id":   cfg.MainUUID,
		"aid":  "0", // AlterID for VMess
		"net":  "ws",
		"type": "none",
		"host": linkSNIForNonVLESS, // SNI for VMess
		"path": cfg.VmessPath,
		"tls":  "tls",
		"sni":  linkSNIForNonVLESS, // SNI for VMess
	}
	vmessB, _ := json.Marshal(vmessObj)
	links = append(links, "vmess://"+base64.RawURLEncoding.EncodeToString(vmessB))

	// Hysteria2
	insecureFlagValue := Btoi(isAcmeEffectivelyUsed && cfg.UseAcmeCert)
	hysteria2Link := fmt.Sprintf("hysteria2://%s@%s:%d?sni=%s&insecure=%d&alpn=h3#%s-HY2",
		cfg.MainUUID, displayAddressNonVLESS, cfg.Ports["hysteria2"], linkSNIForNonVLESS, insecureFlagValue, nodeHost)
	links = append(links, hysteria2Link)

	// TUIC v5
	tuicLink := fmt.Sprintf("tuic://%s:%s@%s:%d?sni=%s&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=%d#%s-TUIC",
		cfg.MainUUID, cfg.MainUUID, displayAddressNonVLESS, cfg.Ports["tuic"], linkSNIForNonVLESS, insecureFlagValue, nodeHost)
	links = append(links, tuicLink)

	return links
}

// displayNodeInformationFromLinks prints the generated node links and QR codes.
func displayNodeInformationFromLinks(links []string) {
	fmt.Printf("\n%s--- Nodes ---%s\n", ColorCyan, ColorReset)
	if len(links) == 0 {
		fmt.Printf("%sNo links to display.%s\n", ColorYellow, ColorReset)
		return
	}
	for _, link := range links {
		var nodeType string
		if strings.HasPrefix(link, "vless://") {
			nodeType = "VLESS-Reality"
		} else if strings.HasPrefix(link, "vmess://") {
			nodeType = "VMess-WS-TLS"
		} else if strings.HasPrefix(link, "hysteria2://") {
			nodeType = "Hysteria2"
		} else if strings.HasPrefix(link, "tuic://") {
			nodeType = "TUICv5"
		}
		fmt.Printf("\n%s[%s]%s\n", ColorPurple, nodeType, ColorReset)
		fmt.Printf("  %sLink: %s%s%s\n", ColorGreen, ColorYellow, link, ColorReset)

		qr, err := qrcode.New(link, qrcode.Medium)
		if err == nil {
			fmt.Printf("  %sQR Code:%s\n", ColorGreen, ColorReset)
			fmt.Println(qr.ToSmallString(true))
		} else {
			fmt.Printf("  %sWARN: Failed to generate QR code: %v%s\n", ColorYellow, err, ColorReset)
		}
	}
}

// runAcmeCertbotSetup automates obtaining and setting up ACME certificates using Certbot.
func runAcmeCertbotSetup() bool {
	fmt.Printf("\n%s--- ACME Certificate Automation ---%s\n", ColorCyan, ColorReset)

	// 1. Prompt for Domain
	domain := getUserInput(ColorYellow + "Enter your Fully Qualified Domain Name (e.g., sub.example.com): " + ColorReset)
	if domain == "" || !strings.Contains(domain, ".") {
		fmt.Printf("%sInvalid domain name. ACME setup aborted.%s\n", ColorRed, ColorReset)
		return false
	}
	currentInstallData.Domain = domain // Store it even if setup fails, for user convenience

	// 2. Prompt for Email
	email := getUserInput(ColorYellow + "Enter your email address for Certbot (e.g., your@example.com): " + ColorReset)
	if email == "" || !strings.Contains(email, "@") {
		fmt.Printf("%sInvalid email address. ACME setup aborted.%s\n", ColorRed, ColorReset)
		return false
	}
	currentInstallData.AcmeEmail = email // Store it

	currentIP := getPublicIP()
	fmt.Printf("%sIMPORTANT: Before proceeding, ensure the following:%s\n", ColorYellow, ColorReset)
	fmt.Printf("  %s1. DNS A (and/or AAAA) record for '%s%s%s' MUST point to this server's public IP: %s%s%s%s\n", ColorCyan, ColorYellow, domain, ColorCyan, ColorYellow, currentIP, ColorCyan, ColorReset)
	fmt.Printf("  %s2. Port 80 on this server must be OPEN (firewall & not in use by another service) for Certbot's HTTP-01 challenge.%s\n", ColorCyan, ColorReset)

	dnsCheckConfirm := getUserInput(ColorYellow + "Have you verified the DNS record and ensured port 80 is open in your firewall? (y/N): " + ColorReset)
	if strings.ToLower(dnsCheckConfirm) != "y" {
		fmt.Printf("%sDNS/Firewall verification not confirmed. ACME setup aborted.%s\n", ColorRed, ColorReset)
		return false
	}

	// Check if port 80 is free
	fmt.Printf("%sChecking if port 80 is currently in use (for Certbot's '--standalone' mode)...%s\n", ColorYellow, ColorReset)
	listener, err := net.Listen("tcp", ":80")
	if err != nil {
		fmt.Printf("%sError: Port 80 is likely in use by another application: %v%s\n", ColorRed, err, ColorReset)
		fmt.Printf("%sPlease stop the conflicting service (e.g., Nginx, Apache) and retry. You can check with: sudo ss -tulnp | grep ':80'%s\n", ColorRed, ColorReset)
		fmt.Printf("%sACME setup aborted due to port 80 issue.%s\n", ColorRed, ColorReset)
		return false
	}
	listener.Close() // Release port 80
	fmt.Printf("%sPort 80 appears to be free for Certbot's '--standalone' mode.%s\n", ColorGreen, ColorReset)

	// Check if certbot is installed
	if _, err := exec.LookPath("certbot"); err != nil {
		fmt.Printf("%sERROR: Certbot is not found in your system's PATH. Please install it manually or check installation:%s\n", ColorRed, ColorReset)
		fmt.Printf("%s  sudo apt install certbot -y OR sudo snap install --classic certbot && sudo ln -s /snap/bin/certbot /usr/bin/certbot%s\n", ColorCyan, ColorReset)
		fmt.Printf("%sACME setup aborted.%s\n", ColorRed, ColorReset)
		return false
	}

	fmt.Printf("\n%sAttempting to obtain certificate for %s%s%s using Certbot...%s\n", ColorYellow, ColorCyan, domain, ColorYellow, ColorReset)
	certbotArgs := []string{"certonly", "--standalone", "--noninteractive", "--email", email, "--agree-tos", "-d", domain}
	certbotOutput, certbotErr := runCommand("certbot", certbotArgs...)

	if certbotErr != nil {
		fmt.Printf("%sCertbot failed to obtain certificate:%s\n", ColorRed, ColorReset)
		fmt.Printf("%sError: %v%s\n", ColorRed, certbotErr, ColorReset)
		fmt.Printf("%sOutput: %s%s\n", ColorRed, certbotOutput, ColorReset)
		fmt.Printf("%sPlease check your DNS settings, firewall, and ensure port 80 is truly free. ACME setup aborted.%s\n", ColorRed, ColorReset)
		return false
	}

	fmt.Printf("%sCertbot successfully obtained certificate.%s\n", ColorGreen, ColorReset)

	// Copy/Symlink certificates
	domainAcmeDir := filepath.Join(acmeBaseDir, domain)
	destCertPath := filepath.Join(domainAcmeDir, "fullchain.pem")
	destKeyPath := filepath.Join(domainAcmeDir, "privkey.pem")

	// Ensure destination directory exists
	if err := os.MkdirAll(domainAcmeDir, 0755); err != nil {
		fmt.Printf("%sERROR: Could not create ACME destination directory %s: %v%s\n", ColorRed, domainAcmeDir, err, ColorReset)
		return false
	}

	// Paths where Certbot places them
	sourceCertPath := filepath.Join("/etc/letsencrypt/live", domain, "fullchain.pem")
	sourceKeyPath := filepath.Join("/etc/letsencrypt/live", domain, "privkey.pem")

	fmt.Printf("%sCopying certificate files to Sing-box directory...%s\n", ColorYellow, ColorReset)

	// Copy fullchain.pem
	if _, err := runCommand("cp", sourceCertPath, destCertPath); err != nil {
		fmt.Printf("%sERROR: Failed to copy fullchain.pem: %v%s\n", ColorRed, err, ColorReset)
		return false
	}
	// Copy privkey.pem
	if _, err := runCommand("cp", sourceKeyPath, destKeyPath); err != nil {
		fmt.Printf("%sERROR: Failed to copy privkey.pem: %v%s\n", ColorRed, err, ColorReset)
		return false
	}

	// Set permissions
	if _, err := runCommand("chmod", "644", destCertPath); err != nil {
		fmt.Printf("%sWARN: Failed to set permissions on %s: %v%s\n", ColorYellow, destCertPath, err, ColorReset)
	}
	if _, err := runCommand("chmod", "600", destKeyPath); err != nil {
		fmt.Printf("%sWARN: Failed to set permissions on %s: %v%s\n", ColorYellow, destKeyPath, err, ColorReset)
	}
	if _, err := runCommand("chown", "root:root", destCertPath, destKeyPath); err != nil {
		fmt.Printf("%sWARN: Failed to set ownership on certificate files: %v%s\n", ColorYellow, err, ColorReset)
	}

	// Final check for files
	_, certErr := os.Stat(destCertPath)
	_, keyErr := os.Stat(destKeyPath)
	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		fmt.Printf("%sERROR: Certificates were not found at the destination after copying:%s\n", ColorRed, ColorReset)
		if os.IsNotExist(certErr) {
			fmt.Printf("  Missing: %s%s%s\n", ColorRed, destCertPath, ColorReset)
		}
		if os.IsNotExist(keyErr) {
			fmt.Printf("  Missing: %s%s%s\n", ColorRed, destKeyPath, ColorReset)
		}
		fmt.Printf("%sACME certificate setup failed after Certbot run. Sing-box will use self-signed certificates.%s\n", ColorRed, ColorReset)
		return false
	}

	fmt.Printf("%sACME certificate automation complete for '%s'. Files are in %s%s%s. Sing-box will be configured to use them.%s\n", ColorGreen, ColorCyan, domain, ColorGreen, domainAcmeDir, ColorReset)
	return true
}

// installInteractive guides the user through the Sing-box installation process.
func installInteractive() {
	fmt.Printf("%sStarting Sing-box installation/reinstallation...%s\n", ColorYellow, ColorReset)
	checkRoot()
	checkOS()
	installDependencies()

	os.MkdirAll(singBoxDir, 0755)
	os.MkdirAll(acmeBaseDir, 0755)

	downloadAndInstallSingBox()

	fmt.Printf("%sGenerating base self-signed certificates as a fallback...%s\n", ColorYellow, ColorReset)
	generateSelfSignedCert()

	loadInstallData()

	fmt.Printf("\n%s--- Port Configuration ---%s\n", ColorCyan, ColorReset)
	if currentInstallData.Ports == nil {
		currentInstallData.Ports = make(map[string]uint16)
	}
	currentInstallData.Ports["vless"] = getPort("VLESS", currentInstallData.Ports["vless"])
	currentInstallData.Ports["vmess"] = getPort("VMess", currentInstallData.Ports["vmess"])
	currentInstallData.Ports["hysteria2"] = getPort("Hysteria2", currentInstallData.Ports["hysteria2"])
	currentInstallData.Ports["tuic"] = getPort("TUIC", currentInstallData.Ports["tuic"])

	currentInstallData.MainUUID = generateSingBoxUUID()
	fmt.Printf("%sGenerated UUID: %s%s%s\n", ColorGreen, ColorYellow, currentInstallData.MainUUID, ColorReset)

	currentInstallData.VmessPath = fmt.Sprintf("/%s-vm", currentInstallData.MainUUID)

	privKey, pubKey, shortID, err := generateRealityKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate Reality key pair: %v", err)
	}
	currentInstallData.RealityPrivateKey, currentInstallData.RealityPublicKey, currentInstallData.RealityShortID = privKey, pubKey, shortID
	fmt.Printf("%sReality Public Key: %s%s%s\n", ColorGreen, ColorYellow, pubKey, ColorReset)
	fmt.Printf("%sReality Short ID: %s%s%s\n", ColorGreen, ColorYellow, shortID, ColorReset)

	fmt.Printf("\n%s--- Certificate Configuration ---%s\n", ColorCyan, ColorReset)
	certChoice := getUserInput(ColorYellow + "Use ACME (domain) certificate for VMess/Hysteria2/TUIC? (y/N): " + ColorReset)
	if strings.ToLower(certChoice) == "y" {
		if runAcmeCertbotSetup() { // Call the new automation function
			currentInstallData.UseAcmeCert = true
			// Domain and Email are already stored by runAcmeCertbotSetup()
		} else {
			fmt.Printf("%sACME setup failed. Reverting to self-signed certificates.%s\n", ColorYellow, ColorReset)
			currentInstallData.UseAcmeCert = false
			currentInstallData.Domain = ""    // Clear domain if ACME failed
			currentInstallData.AcmeEmail = "" // Clear email if ACME failed
		}
	} else {
		fmt.Printf("%sUsing self-signed certificates.%s\n", ColorGreen, ColorReset)
		currentInstallData.UseAcmeCert = false
		currentInstallData.Domain = ""
		currentInstallData.AcmeEmail = ""
	}

	currentInstallData.ServerIP = getPublicIP()
	currentInstallData.Hostname, _ = os.Hostname()
	if currentInstallData.Hostname == "" {
		currentInstallData.Hostname = "sb-server"
	}

	saveInstallData()

	serverConfig := buildSingBoxServerConfig()
	writeSingBoxJSON(serverConfig)
	setupSystemdService()

	time.Sleep(1 * time.Second) // Give service a moment to start
	statusText, isRunning := getSingBoxStatus()

	// Specific warning if ACME was chosen but service failed, likely due to missing certs
	if !isRunning && currentInstallData.UseAcmeCert && currentInstallData.Domain != "" {
		domainAcmeDir := filepath.Join(acmeBaseDir, currentInstallData.Domain)
		certPath := filepath.Join(domainAcmeDir, "fullchain.pem")
		keyPath := filepath.Join(domainAcmeDir, "privkey.pem")
		_, certErr := os.Stat(certPath)
		_, keyErr := os.Stat(keyPath)
		if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
			fmt.Printf("\n%sIMPORTANT WARNING:%s\n%sSing-box service is %s%s%s. This is highly likely because ACME certificates for '%s%s%s' are missing at:\n  Cert: %s\n  Key:  %s\nPlease ensure these files are in place, or switch to self-signed via option '4' in the main menu, then restart Sing-box.%s\n", ColorRed, ColorReset, ColorRed, statusText, ColorReset, ColorYellow, ColorCyan, currentInstallData.Domain, ColorYellow, certPath, keyPath, ColorReset)
		}
	} else if !isRunning {
		fmt.Printf("\n%sWARN: Sing-box service is %s%s%s. Check logs using option '9' for details.%s\n", ColorRed, statusText, ColorReset, ColorYellow, ColorReset)
	}

	displayNodeInformationFromLinks(generateNodeLinks())
	cleanupInstallationFiles()

	fmt.Printf("\n%sInstallation completed successfully.%s\n", ColorGreen, ColorReset)
}

// uninstall removes all Sing-box related files and services.
func uninstall() {
	checkRoot()
	fmt.Printf("%sUninstalling Sing-box...%s\n", ColorYellow, ColorReset)

	// Remove CLI symlink if it exists
	symlinkPath := filepath.Join("/usr/local/bin", cliCommandName)
	if err := os.Remove(symlinkPath); err == nil {
		fmt.Printf("%sRemoved command symlink: %s%s\n", ColorGreen, symlinkPath, ColorReset)
	} else if !os.IsNotExist(err) {
		fmt.Printf("%sWARN: Could not remove symlink %s: %v%s\n", ColorYellow, symlinkPath, err, ColorReset)
	}

	// Stop and disable systemd service
	runCommand("systemctl", "stop", "sing-box")
	runCommand("systemctl", "disable", "sing-box")
	os.Remove(systemdServiceFile)

	// Remove Sing-box configuration directory
	if err := os.RemoveAll(singBoxDir); err != nil {
		fmt.Printf("%sWARN: Failed to remove Sing-box directory %s: %v%s\n", ColorYellow, singBoxDir, err, ColorReset)
	}

	runCommand("systemctl", "daemon-reload") // Reload systemd to reflect changes

	fmt.Printf("%sSing-box uninstallation complete.%s\n", ColorGreen, ColorReset)
}

// manageNodes displays the current Sing-box node information (links and QR codes).
func manageNodes() {
	if _, err := os.Stat(installConfigFile); os.IsNotExist(err) {
		fmt.Printf("%sSing-box is not installed or configuration data is missing. Please install first.%s\n", ColorYellow, ColorReset)
		return
	}
	displayNodeInformationFromLinks(generateNodeLinks())
}

// manageCertificates allows switching between ACME and self-signed certificates.
func manageCertificates() {
	checkRoot()
	if _, err := os.Stat(installConfigFile); os.IsNotExist(err) {
		fmt.Printf("%sSing-box is not installed or configuration data is missing.%s\n", ColorYellow, ColorReset)
		return
	}

	// Make sure currentInstallData is loaded before displaying current setting
	loadInstallData()

	fmt.Printf("\n%s--- Manage Certificates ---%s\n", ColorCyan, ColorReset)
	fmt.Printf("Current setting: Use ACME Certificate = %s%v%s", ColorYellow, currentInstallData.UseAcmeCert, ColorReset)
	if currentInstallData.UseAcmeCert {
		fmt.Printf(" (Domain: %s%s%s, Email: %s%s%s)\n", ColorYellow, currentInstallData.Domain, ColorReset, ColorYellow, currentInstallData.AcmeEmail, ColorReset)
	} else {
		fmt.Printf(" %s(Using Self-Signed)%s\n", ColorYellow, ColorReset)
	}

	fmt.Printf("%s1. Switch to/Reconfigure ACME (Domain) Certificate%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s2. Switch to Self-Signed Certificate%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s0. Back to Main Menu%s\n", ColorYellow, ColorReset)

	choice := getUserInput(ColorYellow + "Choice: " + ColorReset)
	switchedConfig := false

	switch choice {
	case "1":
		originalDomain, originalUseAcme, originalEmail := currentInstallData.Domain, currentInstallData.UseAcmeCert, currentInstallData.AcmeEmail
		if currentInstallData.UseAcmeCert {
			fmt.Printf("%sCurrently configured to use ACME for domain: %s%s%s\n", ColorYellow, ColorBlue, currentInstallData.Domain, ColorReset)
			if strings.ToLower(getUserInput(ColorYellow + "Reconfigure for this domain or a new one? (y/N): " + ColorReset)) != "y" {
				fmt.Printf("%sNo changes made to ACME configuration.%s\n", ColorYellow, ColorReset)
				return
			}
		}

		if runAcmeCertbotSetup() { // Call the new automation function
			currentInstallData.UseAcmeCert = true
			switchedConfig = true
			fmt.Printf("%sSing-box is now configured to use ACME for domain: %s%s%s\n", ColorGreen, ColorBlue, currentInstallData.Domain, ColorReset)
		} else {
			fmt.Printf("%sACME setup failed. Reverting to previous certificate settings.%s\n", ColorRed, ColorReset)
			if originalUseAcme {
				currentInstallData.Domain = originalDomain
				currentInstallData.AcmeEmail = originalEmail
				currentInstallData.UseAcmeCert = true
				fmt.Printf("%sReverted to previous ACME settings for domain: %s%s%s\n", ColorYellow, originalDomain, ColorReset)
			} else {
				currentInstallData.UseAcmeCert = false
				currentInstallData.Domain = ""
				currentInstallData.AcmeEmail = ""
				fmt.Printf("%sReverted to Self-Signed settings.%s\n", ColorYellow, ColorReset)
			}
			// No config change if ACME setup failed, so switchedConfig remains false
		}
	case "2":
		if !currentInstallData.UseAcmeCert && currentInstallData.Domain == "" {
			fmt.Printf("%sAlready using self-signed certificate. No change made.%s\n", ColorYellow, ColorReset)
			return
		}
		fmt.Printf("%sSwitching to self-signed certificate...%s\n", ColorYellow, ColorReset)
		generateSelfSignedCert()
		currentInstallData.UseAcmeCert = false
		currentInstallData.Domain = ""
		currentInstallData.AcmeEmail = ""
		switchedConfig = true
		fmt.Printf("%sSuccessfully switched to self-signed certificate.%s\n", ColorGreen, ColorReset)
	case "0":
		return
	default:
		fmt.Printf("%sInvalid choice. Please try again.%s\n", ColorRed, ColorReset)
		return
	}

	if switchedConfig {
		saveInstallData()
		fmt.Printf("%sRebuilding Sing-box server configuration...%s\n", ColorYellow, ColorReset)
		serverConfig := buildSingBoxServerConfig()
		writeSingBoxJSON(serverConfig)
		restartSingBoxService()
		fmt.Printf("%sSing-box configuration has been updated and service restarted.%s\n", ColorGreen, ColorReset)
		manageNodes() // Show updated node info
	}
}

// generateAndShowSubscription generates and displays the Base64 encoded subscription link.
func generateAndShowSubscription() {
	if _, err := os.Stat(installConfigFile); os.IsNotExist(err) {
		fmt.Printf("%sSing-box is not installed or configuration data is missing. Please install first.%s\n", ColorYellow, ColorReset)
		return
	}

	links := generateNodeLinks()
	if len(links) == 0 {
		fmt.Printf("%sNo nodes configured to generate a subscription link.%s\n", ColorYellow, ColorReset)
		return
	}

	var subscriptionBuilder strings.Builder
	for _, link := range links {
		subscriptionBuilder.WriteString(link + "\n")
	}

	base64Subscription := base64.StdEncoding.EncodeToString([]byte(subscriptionBuilder.String()))
	fmt.Printf("\n%s--- Subscription Link (Base64 Encoded) ---%s\n", ColorCyan, ColorReset)
	fmt.Println(ColorYellow + base64Subscription + ColorReset)
	fmt.Printf("\n%sCopy this link and import it into your Sing-box client.%s\n", ColorGreen, ColorReset)
}

// cleanupInstallationFiles removes temporary files created during installation.
func cleanupInstallationFiles() {
	tempDir := os.TempDir()
	patterns := []string{"sing-box-*.tar.gz", "sb-extract*"}
	for _, pattern := range patterns {
		items, err := filepath.Glob(filepath.Join(tempDir, pattern))
		if err != nil {
			fmt.Printf("%sWARN: Error globbing temp files for pattern %s: %v%s\n", ColorYellow, pattern, err, ColorReset)
			continue
		}
		for _, item := range items {
			info, err := os.Stat(item)
			if err != nil {
				fmt.Printf("%sWARN: Error stating temp file %s: %v%s\n", ColorYellow, item, err, ColorReset)
				continue
			}
			if info.IsDir() {
				if err := os.RemoveAll(item); err != nil {
					fmt.Printf("%sWARN: Failed to remove temp directory %s: %v%s\n", ColorYellow, item, err, ColorReset)
				}
			} else {
				if err := os.Remove(item); err != nil {
					fmt.Printf("%sWARN: Failed to remove temp file %s: %v%s\n", ColorYellow, item, err, ColorReset)
				}
			}
		}
	}
	fmt.Printf("%sTemporary installation files cleaned up.%s\n", ColorGreen, ColorReset)
}

// restartSingBoxServiceInteractive restarts the Sing-box service.
func restartSingBoxServiceInteractive() {
	checkRoot()
	restartSingBoxService()
}

// stopSingBoxServiceInteractive stops the Sing-box service.
func stopSingBoxServiceInteractive() {
	checkRoot()
	fmt.Printf("%sStopping Sing-box service...%s\n", ColorYellow, ColorReset)
	if _, err := runCommand("systemctl", "stop", "sing-box"); err != nil {
		fmt.Printf("%sWARN: Sing-box service stop failed: %v%s\n", ColorYellow, err, ColorReset)
	} else {
		fmt.Printf("%sSing-box service stopped successfully.%s\n", ColorGreen, ColorReset)
	}
}

// startSingBoxServiceInteractive starts the Sing-box service.
func startSingBoxServiceInteractive() {
	checkRoot()
	fmt.Printf("%sStarting Sing-box service...%s\n", ColorYellow, ColorReset)
	if _, err := runCommand("systemctl", "enable", "sing-box"); err != nil {
		fmt.Printf("%sWARN: systemctl enable sing-box failed: %v%s\n", ColorYellow, err, ColorReset)
	}
	if _, err := runCommand("systemctl", "start", "sing-box"); err != nil {
		fmt.Printf("%sWARN: Sing-box service start failed: %v%s\n", ColorYellow, err, ColorReset)
	} else {
		fmt.Printf("%sSing-box service started successfully.%s\n", ColorGreen, ColorReset)
	}
}

// viewSingBoxLogs displays real-time Sing-box service logs using journalctl.
func viewSingBoxLogs() {
	fmt.Printf("%sDisplaying Sing-box logs (Ctrl+C to exit):%s\n", ColorYellow, ColorReset)
	cmd := exec.Command("journalctl", "-u", "sing-box", "-f", "-e", "--no-pager")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			fmt.Printf("\n%sLog viewing ended with exit code: %v%s\n", ColorYellow, exitError.ExitCode(), ColorReset)
			return
		}
		fmt.Printf("%sLog viewing error: %v%s\n", ColorRed, err, ColorReset)
	}
}
EOF_GO_CODE
# --- END OF SB.GO CONTENT ---
echo -e "${GREEN}sb.go script content written.${NC}"

# --- 4. Initialize Go Module and Download Dependencies ---
echo -e "${YELLOW}Initializing Go module and downloading dependencies...${NC}"

# Check if go.mod already exists in the project directory
if [ ! -f "$PROJECT_DIR/go.mod" ]; then
    go mod init singbox_manager_go
    echo -e "${GREEN}Go module initialized.${NC}"
else
    echo -e "${YELLOW}Go module already initialized (go.mod exists). Skipping 'go mod init'.${NC}"
fi

go mod tidy
echo -e "${GREEN}Go module dependencies synchronized.${NC}"

# --- 5. Compile Go Script ---
echo -e "${YELLOW}Compiling sb.go into an executable...${NC}"
go build -o sb sb.go
chmod +x sb
echo -e "${GREEN}Compilation complete, executable file is: ${PROJECT_DIR}/sb${NC}"

# --- 6. Create Symlink to /usr/local/bin ---
echo -e "${YELLOW}Creating symlink to /usr/local/bin/sb...${NC}"
ln -sf "$PROJECT_DIR/sb" "/usr/local/bin/sb"
echo -e "${GREEN}You can now run the manager using 'sudo sb' command.${NC}"

# --- 7. Final Instructions ---
echo -e "${CYAN}--- Installation environment prepared ---${NC}"
echo -e "${CYAN}You can now start the Sing-box manager by typing: sudo sb${NC}"
echo -e "${CYAN}Please follow the manager's prompts to install Sing-box itself and configure nodes.${NC}"
echo -e "${YELLOW}If any errors occurred during Go installation or compilation, please review the output above.${NC}"
echo ""

echo -e "${GREEN}Script execution finished.${NC}"
