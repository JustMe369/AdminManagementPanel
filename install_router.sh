#!/bin/bash
# AdminManagement Router Installation Script
# For TP-Link Archer C7 v5 running OpenWrt
# Version: 1.0
# Author: AdminManagement System

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ADMIN_SYSTEM_DIR="/opt/adminmanagement"
ADMIN_USER="admin"
DB_PATH="/opt/adminmanagement/admin_management.db"
PYTHON_VERSION="python3"

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        error "Please run this script as root or with sudo privileges"
        exit 1
    fi
}

# Check OpenWrt version and compatibility
check_openwrt() {
    log "Checking OpenWrt compatibility..."
    
    if [ ! -f /etc/openwrt_release ]; then
        error "This script is designed for OpenWrt. /etc/openwrt_release not found."
        exit 1
    fi
    
    # Source OpenWrt release info
    source /etc/openwrt_release
    
    info "Detected OpenWrt: $DISTRIB_DESCRIPTION"
    info "Version: $DISTRIB_RELEASE"
    info "Target: $DISTRIB_TARGET"
    
    # Check for TP-Link Archer C7
    if [[ "$DISTRIB_TARGET" != *"ar71xx"* ]] && [[ "$DISTRIB_TARGET" != *"ath79"* ]]; then
        warning "This script is optimized for TP-Link Archer C7. Your device may not be fully compatible."
        echo "Continue anyway? (y/N)"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Update package list
update_packages() {
    log "Updating package lists..."
    opkg update || {
        error "Failed to update package lists"
        exit 1
    }
}

# Install required packages
install_packages() {
    log "Installing required packages..."
    
    # Core packages for Python and web services
    local packages=(
        "python3"
        "python3-pip" 
        "python3-sqlite3"
        "python3-dev"
        "python3-setuptools"
        "sqlite3-cli"
        "curl"
        "wget"
        "ca-certificates"
        "openssl-util"
        "htop"
        "nano"
        "coreutils-nohup"
    )
    
    # Network and firewall packages
    local network_packages=(
        "iptables-mod-extra"
        "kmod-ipt-conntrack-extra"
        "kmod-ipt-nat-extra" 
        "tc"
        "kmod-sched"
        "nodogsplash"
        "hostapd-utils"
        "iw"
        "iwinfo"
    )
    
    # Monitoring packages
    local monitoring_packages=(
        "luci-app-statistics"
        "collectd"
        "collectd-mod-cpu"
        "collectd-mod-memory"
        "collectd-mod-network"
        "collectd-mod-load"
        "vnstat"
        "iftop"
    )
    
    # Install core packages
    for package in "${packages[@]}"; do
        info "Installing $package..."
        opkg install "$package" || warning "Failed to install $package, continuing..."
    done
    
    # Install network packages
    for package in "${network_packages[@]}"; do
        info "Installing $package..."
        opkg install "$package" || warning "Failed to install $package, continuing..."
    done
    
    # Install monitoring packages
    for package in "${monitoring_packages[@]}"; do
        info "Installing $package..."
        opkg install "$package" || warning "Failed to install $package, continuing..."
    done
}

# Install Python packages
install_python_packages() {
    log "Installing Python packages..."
    
    # Check if pip3 is available
    if ! command -v pip3 &> /dev/null; then
        warning "pip3 not available, trying to install manually..."
        wget https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py
        python3 /tmp/get-pip.py
    fi
    
    # Core Python packages for the admin system
    local python_packages=(
        "flask==2.3.3"
        "werkzeug==2.3.7"
        "paramiko==3.3.1"
        "requests==2.31.0"
        "schedule==1.2.0"
        "psutil==5.9.5"
        "cryptography==41.0.4"
        "bcrypt==4.0.1"
    )
    
    for package in "${python_packages[@]}"; do
        info "Installing Python package: $package..."
        pip3 install "$package" --no-cache-dir || warning "Failed to install $package"
    done
}

# Create system directories
create_directories() {
    log "Creating system directories..."
    
    # Main application directory
    mkdir -p "$ADMIN_SYSTEM_DIR"
    mkdir -p "$ADMIN_SYSTEM_DIR/logs"
    mkdir -p "$ADMIN_SYSTEM_DIR/backups"
    mkdir -p "$ADMIN_SYSTEM_DIR/templates"
    mkdir -p "$ADMIN_SYSTEM_DIR/static/css"
    mkdir -p "$ADMIN_SYSTEM_DIR/static/js"
    mkdir -p "$ADMIN_SYSTEM_DIR/config"
    
    # NoDogSplash directories
    mkdir -p /etc/nodogsplash/htdocs
    mkdir -p /tmp/ndslog
    
    # Set permissions
    chmod 755 "$ADMIN_SYSTEM_DIR"
    chmod 755 "$ADMIN_SYSTEM_DIR/logs"
    chmod 755 "$ADMIN_SYSTEM_DIR/backups"
}

# Create admin user
create_admin_user() {
    log "Setting up admin user..."
    
    # Check if user exists
    if ! id "$ADMIN_USER" &>/dev/null; then
        # Create user if it doesn't exist
        useradd -r -s /bin/false -d "$ADMIN_SYSTEM_DIR" "$ADMIN_USER" || {
            warning "Failed to create user $ADMIN_USER, using root instead"
            ADMIN_USER="root"
        }
    fi
    
    # Set ownership
    chown -R "$ADMIN_USER:$ADMIN_USER" "$ADMIN_SYSTEM_DIR" || {
        warning "Failed to set ownership, continuing..."
    }
}

# Download and install AdminManagement system
install_admin_system() {
    log "Installing AdminManagement system files..."
    
    # For this example, we'll assume the files are being copied from the development directory
    # In production, you might download from a repository
    
    local source_dir="./AdminManagementPanel"
    
    if [ -d "$source_dir" ]; then
        info "Copying AdminManagement files from $source_dir..."
        cp -r "$source_dir"/* "$ADMIN_SYSTEM_DIR/"
    else
        warning "Source directory $source_dir not found. Please ensure AdminManagement files are available."
        
        # Create minimal system files
        create_minimal_system
    fi
    
    # Set execute permissions for Python files
    find "$ADMIN_SYSTEM_DIR" -name "*.py" -exec chmod +x {} \;
    
    # Create configuration file
    create_config_file
}

# Create minimal system files if source not available
create_minimal_system() {
    log "Creating minimal system configuration..."
    
    cat > "$ADMIN_SYSTEM_DIR/config.py" << 'EOF'
# Minimal Configuration for AdminManagement
import os
import secrets

DEBUG = False
SECRET_KEY = secrets.token_hex(32)

# Database
DB_PATH = '/opt/adminmanagement/admin_management.db'

# Network settings
ROUTER_IP = '192.168.1.1'
ROUTER_SSH_PORT = 22
ROUTER_USERNAME = 'root'

# NoDogSplash
NODOGSPLASH_ENABLED = True
NODOGSPLASH_PORT = 2050
NODOGSPLASH_INTERFACE = 'br-lan'

# Monitoring
MONITORING_INTERVAL = 300
LOG_LEVEL = 'INFO'
LOG_FILE = '/opt/adminmanagement/logs/admin.log'
EOF

    # Create basic database schema
    create_database_schema
}

# Create database schema
create_database_schema() {
    log "Creating database schema..."
    
    sqlite3 "$DB_PATH" << 'EOF'
-- Basic database schema for AdminManagement
CREATE TABLE IF NOT EXISTS branches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    location TEXT,
    ip_address TEXT NOT NULL,
    router_model TEXT DEFAULT 'TP-Link Archer C7 v5',
    status TEXT DEFAULT 'Active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    branch_id INTEGER NOT NULL,
    user_type TEXT DEFAULT 'User',
    status TEXT DEFAULT 'Active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    session_token TEXT,
    token_expires DATETIME,
    FOREIGN KEY (branch_id) REFERENCES branches (id)
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    device_type TEXT DEFAULT 'unknown',
    branch_id INTEGER NOT NULL,
    status TEXT DEFAULT 'Active',
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (branch_id) REFERENCES branches (id),
    UNIQUE(mac_address, branch_id)
);

CREATE TABLE IF NOT EXISTS guest_passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    password TEXT NOT NULL UNIQUE,
    branch_id INTEGER NOT NULL,
    time_limit INTEGER DEFAULT 60,
    speed_limit_down INTEGER DEFAULT 5120,
    speed_limit_up INTEGER DEFAULT 1024,
    max_usage INTEGER DEFAULT 1,
    current_usage INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    FOREIGN KEY (branch_id) REFERENCES branches (id)
);

-- Insert default data
INSERT OR IGNORE INTO branches (id, name, location, ip_address) 
VALUES (1, 'Main Branch', 'Router Location', '192.168.1.1');

-- Create default admin user (password: admin123)
INSERT OR IGNORE INTO users (username, password_hash, password_salt, branch_id, user_type, status)
VALUES ('admin', 'hashed_password_here', 'salt_here', 1, 'Admin', 'Active');
EOF

    # Set database permissions
    chmod 644 "$DB_PATH"
    chown "$ADMIN_USER:$ADMIN_USER" "$DB_PATH"
}

# Configure NoDogSplash
configure_nodogsplash() {
    log "Configuring NoDogSplash captive portal..."
    
    cat > /etc/nodogsplash/nodogsplash.conf << 'EOF'
# NoDogSplash Configuration - AdminManagement
GatewayInterface br-lan
GatewayName "AdminManagement Guest Portal"
GatewayAddress 192.168.1.1
MaxClients 250
SessionTimeout 0
ClientIdleTimeout 10
ClientForceTimeout 60

# Bandwidth limits (kbps)
DownloadLimit 5120
UploadLimit 1024

# Firewall rules for authenticated clients
FirewallRule allow tcp port 53
FirewallRule allow udp port 53
FirewallRule allow tcp port 80
FirewallRule allow tcp port 443

# Pre-authentication rules
FirewallRule allow tcp port 80 to 192.168.1.1
FirewallRule allow tcp port 443 to 192.168.1.1

# Portal settings
AuthDir /etc/nodogsplash/htdocs/
SplashPage /splash.html
RedirectURL http://192.168.1.1/portal/welcome

# Daemon settings
Daemon 1
DebugLevel 1
LogLevel 2
PidFile /var/run/nodogsplash.pid
EOF

    # Create basic splash page
    create_splash_page
    
    # Enable NoDogSplash service
    /etc/init.d/nodogsplash enable || warning "Failed to enable NoDogSplash service"
}

# Create basic splash page
create_splash_page() {
    log "Creating captive portal splash page..."
    
    cat > /etc/nodogsplash/htdocs/splash.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Guest WiFi Portal</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f0f2f5; }
        .portal { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; margin-bottom: 20px; }
        input[type="text"] { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background: #0056b3; }
        .info { margin-top: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="portal">
        <h1>Welcome to Guest WiFi</h1>
        <p>Enter your access code to connect</p>
        <form method="post" action="$authaction$">
            <input type="hidden" name="tok" value="$tok$">
            <input type="hidden" name="redir" value="$redir$">
            <input type="text" name="username" placeholder="Access Code" maxlength="8" required style="text-transform: uppercase;">
            <button type="submit">Connect</button>
        </form>
        <div class="info">
            <p>Access codes are provided by IT administration</p>
            <p>For support, contact your IT department</p>
        </div>
    </div>
</body>
</html>
EOF
}

# Create systemd service
create_service() {
    log "Creating AdminManagement system service..."
    
    cat > /etc/init.d/adminmanagement << 'EOF'
#!/bin/sh /etc/rc.common
# AdminManagement System Init Script

START=99
STOP=10

USE_PROCD=1
PROG="/usr/bin/python3"
ARGS="/opt/adminmanagement/main_api_backend.py"
ADMIN_USER="admin"

start_service() {
    procd_open_instance
    procd_set_param command $PROG $ARGS
    procd_set_param user $ADMIN_USER
    procd_set_param group $ADMIN_USER
    procd_set_param respawn ${respawn_threshold:-3600} ${respawn_timeout:-5} ${respawn_retry:-5}
    procd_set_param env HOME="/opt/adminmanagement"
    procd_set_param env PATH="/usr/bin:/bin:/usr/sbin:/sbin"
    procd_set_param pidfile /var/run/adminmanagement.pid
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

stop_service() {
    service_stop $PROG
}
EOF

    chmod +x /etc/init.d/adminmanagement
    
    # Enable the service
    /etc/init.d/adminmanagement enable || warning "Failed to enable AdminManagement service"
}

# Configure firewall rules
configure_firewall() {
    log "Configuring firewall rules..."
    
    # Add firewall rules for AdminManagement
    uci add firewall rule
    uci set firewall.@rule[-1].name='Allow-AdminManagement-HTTP'
    uci set firewall.@rule[-1].src='lan'
    uci set firewall.@rule[-1].dest_port='5000'
    uci set firewall.@rule[-1].proto='tcp'
    uci set firewall.@rule[-1].target='ACCEPT'
    
    uci add firewall rule
    uci set firewall.@rule[-1].name='Allow-AdminManagement-HTTPS'
    uci set firewall.@rule[-1].src='lan'
    uci set firewall.@rule[-1].dest_port='5001'
    uci set firewall.@rule[-1].proto='tcp'
    uci set firewall.@rule[-1].target='ACCEPT'
    
    # Commit firewall changes
    uci commit firewall
    /etc/init.d/firewall reload
}

# Configure network settings
configure_network() {
    log "Configuring network settings for AdminManagement..."
    
    # Enable IPv4 forwarding
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    
    # Set up QoS support
    echo 'net.core.default_qdisc=fq_codel' >> /etc/sysctl.conf
    
    # Apply sysctl settings
    sysctl -p
}

# Create configuration file
create_config_file() {
    log "Creating system configuration..."
    
    # Get router IP dynamically
    ROUTER_IP=$(uci get network.lan.ipaddr 2>/dev/null || echo "192.168.1.1")
    
    cat > "$ADMIN_SYSTEM_DIR/local_settings.py" << EOF
# Local settings for AdminManagement on OpenWrt
# Auto-generated on $(date)

import os

# Router specific settings
ROUTER_IP = '$ROUTER_IP'
ROUTER_SSH_PORT = 22
ROUTER_USERNAME = 'root'

# Database path
DB_PATH = '$DB_PATH'

# Logging
LOG_FILE = '$ADMIN_SYSTEM_DIR/logs/admin.log'
LOG_LEVEL = 'INFO'

# NoDogSplash
NODOGSPLASH_ENABLED = True
NODOGSPLASH_PORT = 2050
NODOGSPLASH_INTERFACE = 'br-lan'

# Performance settings for embedded device
MAX_CLIENTS = 50
MONITORING_INTERVAL = 300
CACHE_TYPE = 'simple'

# Security settings
SESSION_COOKIE_SECURE = False  # Set to True if using HTTPS
DEBUG = False
EOF
}

# Setup log rotation
setup_log_rotation() {
    log "Setting up log rotation..."
    
    cat > /etc/logrotate.d/adminmanagement << 'EOF'
/opt/adminmanagement/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 admin admin
    postrotate
        /etc/init.d/adminmanagement restart
    endscript
}
EOF
}

# Optimize system for embedded device
optimize_system() {
    log "Optimizing system for embedded device..."
    
    # Reduce Python cache files
    export PYTHONDONTWRITEBYTECODE=1
    echo 'export PYTHONDONTWRITEBYTECODE=1' >> /etc/profile
    
    # Set memory limits
    echo 'vm.swappiness=10' >> /etc/sysctl.conf
    echo 'vm.vfs_cache_pressure=50' >> /etc/sysctl.conf
    
    # Optimize network buffers
    echo 'net.core.rmem_max=262144' >> /etc/sysctl.conf
    echo 'net.core.wmem_max=262144' >> /etc/sysctl.conf
}

# Create backup script
create_backup_script() {
    log "Creating backup script..."
    
    cat > "$ADMIN_SYSTEM_DIR/backup.sh" << 'EOF'
#!/bin/bash
# AdminManagement Backup Script

BACKUP_DIR="/opt/adminmanagement/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/adminmanagement_backup_$TIMESTAMP.tar.gz"

# Create backup
tar -czf "$BACKUP_FILE" \
    --exclude="$BACKUP_DIR" \
    --exclude="*.pyc" \
    --exclude="__pycache__" \
    /opt/adminmanagement/

# Keep only last 5 backups
cd "$BACKUP_DIR"
ls -t *.tar.gz | tail -n +6 | xargs rm -f

echo "Backup created: $BACKUP_FILE"
EOF

    chmod +x "$ADMIN_SYSTEM_DIR/backup.sh"
    
    # Add to crontab for daily backups
    echo "0 2 * * * $ADMIN_SYSTEM_DIR/backup.sh" >> /etc/crontabs/root
    /etc/init.d/cron restart
}

# Final system checks
final_checks() {
    log "Performing final system checks..."
    
    # Check if Python is working
    if ! python3 --version > /dev/null 2>&1; then
        error "Python3 is not properly installed"
        return 1
    fi
    
    # Check database
    if [ ! -f "$DB_PATH" ]; then
        warning "Database file not found at $DB_PATH"
    fi
    
    # Check services
    if ! /etc/init.d/adminmanagement enabled; then
        warning "AdminManagement service is not enabled"
    fi
    
    # Check available memory
    local available_mem=$(awk '/MemAvailable/{print $2}' /proc/meminfo 2>/dev/null || echo "0")
    if [ "$available_mem" -lt 50000 ]; then  # Less than 50MB
        warning "Low available memory: ${available_mem}KB. System may be unstable."
    fi
    
    # Check storage space
    local available_space=$(df /opt | tail -1 | awk '{print $4}')
    if [ "$available_space" -lt 10000 ]; then  # Less than 10MB
        warning "Low disk space: ${available_space}KB available"
    fi
    
    info "System checks completed"
}

# Start services
start_services() {
    log "Starting AdminManagement services..."
    
    # Start NoDogSplash
    /etc/init.d/nodogsplash start || warning "Failed to start NoDogSplash"
    
    # Start AdminManagement
    /etc/init.d/adminmanagement start || warning "Failed to start AdminManagement"
    
    # Wait a moment for services to initialize
    sleep 5
    
    # Check if services are running
    if pidof python3 > /dev/null; then
        info "AdminManagement service is running"
    else
        warning "AdminManagement service may not be running properly"
    fi
    
    if pidof nodogsplash > /dev/null; then
        info "NoDogSplash service is running"
    else
        warning "NoDogSplash service may not be running properly"
    fi
}

# Display installation summary
show_summary() {
    log "Installation completed successfully!"
    
    echo -e "${GREEN}"
    echo "======================================="
    echo "AdminManagement System Installation Complete"
    echo "======================================="
    echo -e "${NC}"
    
    echo "System Information:"
    echo "  - Installation Directory: $ADMIN_SYSTEM_DIR"
    echo "  - Database: $DB_PATH"
    echo "  - Router IP: $(uci get network.lan.ipaddr 2>/dev/null || echo 'Unknown')"
    echo "  - Admin Interface: http://$(uci get network.lan.ipaddr 2>/dev/null || echo 'router-ip'):5000"
    echo
    echo "Default Credentials:"
    echo "  - Username: admin"
    echo "  - Password: admin123 (please change immediately)"
    echo
    echo "Services Status:"
    echo "  - AdminManagement: $(/etc/init.d/adminmanagement enabled && echo 'Enabled' || echo 'Disabled')"
    echo "  - NoDogSplash: $(/etc/init.d/nodogsplash enabled && echo 'Enabled' || echo 'Disabled')"
    echo
    echo "Next Steps:"
    echo "  1. Access the admin panel at http://$(uci get network.lan.ipaddr 2>/dev/null || echo 'router-ip'):5000"
    echo "  2. Change the default admin password"
    echo "  3. Configure your network settings"
    echo "  4. Set up guest access codes"
    echo
    echo "For support and documentation, visit the AdminManagement repository"
    echo
}

# Main installation function
main() {
    echo -e "${BLUE}"
    echo "======================================="
    echo "AdminManagement System Installer"
    echo "for TP-Link Archer C7 v5 (OpenWrt)"
    echo "======================================="
    echo -e "${NC}"
    
    check_root
    check_openwrt
    
    info "Starting installation process..."
    
    # Installation steps
    update_packages
    install_packages
    install_python_packages
    create_directories
    create_admin_user
    install_admin_system
    configure_nodogsplash
    create_service
    configure_firewall
    configure_network
    setup_log_rotation
    optimize_system
    create_backup_script
    final_checks
    start_services
    show_summary
    
    log "Installation process completed!"
}

# Cleanup function for interrupted installations
cleanup() {
    warning "Installation interrupted. Cleaning up..."
    
    # Stop services if they were started
    /etc/init.d/adminmanagement stop 2>/dev/null
    /etc/init.d/nodogsplash stop 2>/dev/null
    
    # Remove partially installed files if needed
    # (Add cleanup logic here if necessary)
    
    exit 1
}

# Trap cleanup function on script exit
trap cleanup INT TERM

# Run main installation
main "$@"