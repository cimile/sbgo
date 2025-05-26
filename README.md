Sing-box Server Manager (Go)
This is a simple yet powerful Go-based manager script for Sing-box on Debian/Ubuntu servers. It automates the installation of Sing-box binary and simplifies the configuration, node management, and certificate handling (self-signed and ACME with Certbot).

Features
Multi-Protocol Support: Configures VLESS (Reality), VMess (WebSocket + TLS), Hysteria2, TUICv5, Shadowsocks (2022-blake3-aes-128-gcm), and Socks5.

Automated ACME Certificates: Integrates Certbot for streamlined Let's Encrypt certificate acquisition for your domain.

Node Management: Easily view generated node links (including QR codes) and subscription links.

Certificate Management: Switch between self-signed and ACME certificates post-installation.

Service Control: Start, Stop, Restart, and check Sing-box service status, and view logs.

User-Friendly CLI: Interactive menu for easy navigation.

Supported Operating Systems
Debian 10+

Ubuntu 20.04+

Installation
Before You Begin:

DNS Configuration: If you plan to use ACME (Let's Encrypt) certificates, ensure your domain's A (and/or AAAA) record is correctly pointing to your server's public IP address.

Port 80 Open: Certbot requires port 80 to be open for its HTTP-01 challenge. Ensure your server's firewall (e.g., ufw, iptables) and your cloud provider's security groups/firewall rules (e.g., AWS Security Groups, GCP Firewall Rules, Azure Network Security Groups) allow inbound TCP traffic on port 80.

Other Ports Open: Also ensure the ports you intend to use for VLESS, VMess, Hysteria2, TUIC, Shadowsocks, and Socks5 are open in your server's firewalls.

Step 1: Download and Run the Installation Script
This script will set up the Go environment, download sb.go, and prepare it for compilation.

# Create a temporary directory for script download
mkdir -p ~/sb_installer_temp && cd ~/sb_installer_temp

# Download the installation script and Go source code
wget https://raw.githubusercontent.com/cimile/sbgo/main/install.sh
wget https://raw.githubusercontent.com/cimile/sbgo/main/sb.go

# Make the installation script executable
chmod +x install.sh

# Run the installation script (this will set up Go environment and copy sb.go)
# Use 'sudo' as root privileges are required for system-level installations.
sudo ./install.sh
Use code with caution.
Bash
What the install.sh script does:

Updates system packages and installs essential tools (curl, wget, jq, qrencode, openssl, iproute2, iptables, ca-certificates, certbot, dos2unix, vim).

Installs the latest stable Go language environment and configures environment variables (for persistence in future sessions).

Creates a dedicated project directory for the manager (/home/sb_manager_go).

Copies the sb.go file (downloaded alongside install.sh) into this project directory.

Performs automatic cleaning on sb.go (converts line endings with dos2unix and removes non-printable characters with sed) to address potential hidden character/encoding issues from file transfer.

Initializes Go module (go mod init) and downloads all necessary dependencies (go mod tidy).

Compiles sb.go into an executable sb.

Creates a symlink for sb to /usr/local/bin/sb, allowing you to run it globally with sudo sb.

Finally, it automatically starts the Sing-box Manager's interactive menu.

Step 2: Post-Installation & Configuration
Once the Sing-box Manager starts (automatically after sudo ./install.sh completes):

Select 1. Install/Reinstall Sing-box from the main menu.

Follow the interactive prompts:

Set desired ports for VLESS, VMess, Hysteria2, TUIC, Shadowsocks, and Socks5.

Your main UUID, Reality keypair, and protocol-specific passwords will be automatically generated.

You will be asked if you want to use ACME (domain) certificates. If yes, ensure your domain's DNS points to this server and port 80 is open. The manager will guide Certbot to acquire and deploy the certificate.

The manager will generate sb.json configuration, set up the systemd service, and start Sing-box.

Your node links (VLESS, VMess, Hysteria2, TUIC, Shadowsocks, Socks5) and a subscription link will be displayed.

Managing Sing-box
After the initial installation, you can always run the manager from any directory with:

sudo sb
Use code with caution.
Bash
This will bring you back to the main menu where you can:

Show Nodes (Option 3): View all generated node links and QR codes.

Manage Certificates (Option 4): Switch between self-signed and ACME certificates, or re-configure ACME.

Generate & Show Subscription Link (Option 5): Get the base64 encoded subscription URL.

Service Management (Options 6-10): Restart, Stop, Start, View Logs, or Check Status of the Sing-box service.

Uninstall Sing-box (Option 2): Completely remove Sing-box and its manager.

install.sh Script Source Code (for reference)
The install.sh script installs Go environment and downloads sb.go. You do not need to download this file manually unless you wish to inspect or modify the source code.

Click here to view the install.sh source code on GitHub

sb.go Source Code (for reference)
The install.sh script downloads this sb.go file. You do not need to download this file manually unless you wish to inspect or modify the source code.

Click here to view the sb.go source code on GitHub
