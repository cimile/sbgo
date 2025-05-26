Sing-box Server Manager (Go)
This is a simple yet powerful Go-based manager script for Sing-box on Debian/Ubuntu servers. It automates the installation of Go environment, Sing-box binary, and simplifies the configuration, node management, and certificate handling (self-signed and ACME with Certbot).

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
This script will install Go environment, download sb.go, and provide instructions for compilation.

# Create a temporary directory for script download
mkdir -p /tmp/sb_installer && cd /tmp/sb_installer

# Download the installation script and Go source code
wget https://raw.githubusercontent.com/cimile/sbgo/main/install.sh
wget https://raw.githubusercontent.com/cimile/sbgo/main/sb.go

# Make the installation script executable
chmod +x install.sh

# Run the installation script (this will set up Go environment and copy sb.go)
sudo ./install.sh
Use code with caution.
Bash
What sudo ./install.sh does:

Updates system packages and installs essential tools (curl, wget, jq, qrencode, openssl, iproute2, iptables, ca-certificates, certbot, dos2unix, vim).

Installs the latest stable Go language environment and configures environment variables (for persistence in future sessions).

Creates a dedicated project directory for the manager (/home/sb_manager_go).

Copies the sb.go file (downloaded alongside install.sh) into this project directory.

Prints detailed instructions for the next steps (compiling and running).

Step 2: Compile and Run the Sing-box Manager
After Step 1 completes, follow these instructions to compile and start the manager.

# 1. Navigate to the project directory where 'sb.go' was copied by the script:
cd /home/sb_manager_go

# 2. (IMPORTANT) Ensure 'sb.go' is clean for proper compilation.
#    This step addresses potential hidden character/encoding issues from file transfer.
#    Run dos2unix to convert line endings (if necessary)
sudo dos2unix sb.go
#    Use vim to remove any other non-printable or invisible characters.
#    In vim, type: :%s/[^[:print:]\t\n]//g then press ENTER.
#    Then type: :wq then press ENTER to save and exit.
sudo vim sb.go

# 3. Initialize Go module and download dependencies:
go mod init singbox_manager_go
go mod tidy

# 4. Compile your 'sb.go' program:
go build -o sb sb.go

# 5. Run the compiled program (requires root privileges for Sing-box manager operations):
sudo ./sb

# 6. (Optional) Create a symlink for easier global access:
#    This allows you to run 'sudo sb' from any directory.
sudo ln -sf $(pwd)/sb /usr/local/bin/sb
Use code with caution.
Bash
Post-Installation & Configuration (after running sudo ./sb)
Once the Sing-box Manager starts (after sudo ./sb completes):

Select 1. Install/Reinstall Sing-box from the main menu.

Follow the interactive prompts:

Set desired ports for VLESS, VMess, Hysteria2, TUIC, Shadowsocks, and Socks5.

Your main UUID, Reality keypair, and protocol-specific passwords will be automatically generated.

You will be asked if you want to use ACME (domain) certificates. If yes, ensure your domain's DNS points to this server and port 80 is open. The script will guide Certbot to acquire and deploy the certificate.

The manager will generate sb.json configuration, set up the systemd service, and start Sing-box.

Your node links (VLESS, VMess, Hysteria2, TUIC, Shadowsocks, Socks5) and a subscription link will be displayed.

Managing Sing-box
After the initial installation, you can always run the manager with:

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
