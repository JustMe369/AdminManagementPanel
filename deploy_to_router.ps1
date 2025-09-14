# deploy_to_router.ps1
# PowerShell script to deploy AdminManagement system to OpenWrt router

param(
    [string]$RouterIP = "192.168.1.1",
    [string]$Username = "root",
    [string]$SourcePath = "D:\Cp\AdminManagementPanel"
)

Write-Host "AdminManagement Router Deployment Script" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host "Router IP: $RouterIP" -ForegroundColor Yellow
Write-Host "Username: $Username" -ForegroundColor Yellow
Write-Host "Source Path: $SourcePath" -ForegroundColor Yellow
Write-Host ""

# Check if SCP is available
$scpAvailable = Get-Command scp -ErrorAction SilentlyContinue
if (-not $scpAvailable) {
Write-Host "ERROR: SCP not found. Please install OpenSSH Client or use WinSCP." -ForegroundColor Red
    Write-Host "You can install OpenSSH Client via Windows Features or:" -ForegroundColor Yellow
    Write-Host "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0" -ForegroundColor Cyan
    exit 1
}

Write-Host "SUCCESS: SCP is available" -ForegroundColor Green

# Function to copy files
function Copy-FilesToRouter {
    param($Files, $Destination)
    
    Write-Host "Copying files to $Destination..." -ForegroundColor Blue
    
    foreach ($file in $Files) {
        $sourcePath = Join-Path $SourcePath $file
        if (Test-Path $sourcePath) {
        Write-Host "  Copying $file..." -ForegroundColor Gray
            scp "$sourcePath" "${Username}@${RouterIP}:${Destination}/${file}"
            if ($LASTEXITCODE -eq 0) {
            Write-Host "    SUCCESS" -ForegroundColor Green
            } else {
            Write-Host "    FAILED" -ForegroundColor Red
            }
        } else {
        Write-Host "  WARNING: File not found: $file" -ForegroundColor Yellow
        }
    }
}

# Essential files to copy
$essentialFiles = @(
    "simple_main_backend.py",
    "email_notifications.py", 
    "admin_dashboard.html",
    "admin_dashboard.css",
    "admin_dashboard.js",
    "requirements.txt",
    "STARTUP_GUIDE.md"
)

$serviceFile = "adminmanagement"

Write-Host "Testing SSH connection..." -ForegroundColor Blue
ssh -o ConnectTimeout=10 ${Username}@${RouterIP} "echo 'SSH connection successful'"

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: SSH connection failed. Please check:" -ForegroundColor Red
    Write-Host "  1. Router IP address is correct" -ForegroundColor Yellow
    Write-Host "  2. SSH is enabled on router" -ForegroundColor Yellow
    Write-Host "  3. Firewall allows SSH connections" -ForegroundColor Yellow
    exit 1
}

Write-Host "SUCCESS: SSH connection successful" -ForegroundColor Green

# Create directories on router
Write-Host "Creating directories on router..." -ForegroundColor Blue
ssh ${Username}@${RouterIP} "mkdir -p /root/AdminManagementPanel"

# Copy essential files
Copy-FilesToRouter $essentialFiles "/root/AdminManagementPanel"

# Copy service script
Write-Host "Copying service script..." -ForegroundColor Blue
scp "$SourcePath\$serviceFile" "${Username}@${RouterIP}:/etc/init.d/adminmanagement"

if ($LASTEXITCODE -eq 0) {
    Write-Host "  SUCCESS: Service script copied successfully" -ForegroundColor Green
} else {
    Write-Host "  ERROR: Failed to copy service script" -ForegroundColor Red
}

Write-Host ""
Write-Host "Files copied successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. SSH into your router: ssh $Username@$RouterIP" -ForegroundColor Cyan
Write-Host "2. Run the router setup commands (see below)" -ForegroundColor Cyan
Write-Host ""

# Generate setup commands
$setupCommands = @"
# SSH into router
ssh $Username@$RouterIP

# Update packages and install dependencies
opkg update
opkg install python3 python3-pip curl wget

# Install Python packages (this may take time)
pip3 install Flask Jinja2

# Set up service script
chmod +x /etc/init.d/adminmanagement
/etc/init.d/adminmanagement enable

# Configure firewall (allow port 5000)
iptables -I INPUT -p tcp --dport 5000 -j ACCEPT
uci add firewall rule
uci set firewall.@rule[-1].name='AdminManagement'
uci set firewall.@rule[-1].src='lan'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].dest_port='5000'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit firewall
/etc/init.d/firewall reload

# Test the system
cd /root/AdminManagementPanel
python3 simple_main_backend.py

# Or start as service
/etc/init.d/adminmanagement start

# Check status
/etc/init.d/adminmanagement status
"@

Write-Host "Router Setup Commands:" -ForegroundColor Yellow
Write-Host $setupCommands -ForegroundColor Cyan

Write-Host ""
Write-Host "Tips:" -ForegroundColor Yellow
Write-Host "- Default login: admin/admin" -ForegroundColor Gray
Write-Host "- Access web interface: http://$RouterIP`:5000" -ForegroundColor Gray
Write-Host "- Check logs: tail -f /var/log/adminmanagement.log" -ForegroundColor Gray
Write-Host "- For email setup, see STARTUP_GUIDE.md" -ForegroundColor Gray
