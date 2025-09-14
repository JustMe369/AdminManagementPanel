# AdminManagement System - Complete Setup & Startup Guide

This guide will help you set up and run the AdminManagement system on both Windows (for development) and OpenWrt router (for production).

## 📋 Table of Contents

1. [Quick Start (Windows Development)](#quick-start-windows-development)
2. [OpenWrt Router Installation](#openwrt-router-installation)
3. [Email Configuration](#email-configuration)
4. [Accessing the Web Interface](#accessing-the-web-interface)
5. [Troubleshooting](#troubleshooting)
6. [API Documentation](#api-documentation)

## 🚀 Quick Start (Windows Development)

### Prerequisites
- Python 3.7 or higher
- Windows PowerShell or Command Prompt

### Step 1: Navigate to Project Directory
```powershell
cd "D:\Cp\AdminManagementPanel"
```

### Step 2: Install Required Dependencies
Create a `requirements.txt` file first:
```powershell
# Create requirements file
echo "Flask==2.3.3
Jinja2==3.1.2" > requirements.txt

# Install dependencies
pip install -r requirements.txt
```

### Step 3: Start the System (Simple Version)
```powershell
python simple_main_backend.py
```

### Step 4: Access the Web Interface
Open your browser and go to:
- **Web Dashboard**: http://localhost:5000
- **API Status**: http://localhost:5000/api/status

### Default Login Credentials
- **Username**: admin
- **Password**: admin

---

## 🏠 OpenWrt Router Installation

### Prerequisites
- OpenWrt router (tested on TP-Link Archer C7 v5)
- SSH access to the router
- Internet connection on the router

### Step 1: Copy Files to Router
Using SCP or your preferred method, copy these files to your router:

```bash
# Copy all files to router
scp -r "D:\Cp\AdminManagementPanel\*" root@192.168.1.1:/root/AdminManagementPanel/

# Or copy individually if needed:
scp simple_main_backend.py root@192.168.1.1:/root/AdminManagementPanel/
scp email_notifications.py root@192.168.1.1:/root/AdminManagementPanel/
scp admin_dashboard.html root@192.168.1.1:/root/AdminManagementPanel/
scp admin_dashboard.css root@192.168.1.1:/root/AdminManagementPanel/
scp admin_dashboard.js root@192.168.1.1:/root/AdminManagementPanel/
scp adminmanagement root@192.168.1.1:/etc/init.d/adminmanagement
```

### Step 2: SSH into Router and Install Dependencies
```bash
# SSH into router
ssh root@192.168.1.1

# Update package list
opkg update

# Install Python and pip
opkg install python3 python3-pip

# Install Flask (may take time on router)
pip3 install Flask Jinja2

# Optional: Install additional packages if needed
opkg install curl wget sqlite3-cli
```

### Step 3: Set Up the Service Script
```bash
# Make init script executable
chmod +x /etc/init.d/adminmanagement

# Enable service to start on boot
/etc/init.d/adminmanagement enable
```

### Step 4: Start the AdminManagement Service

**Option A: Using init script (recommended)**
```bash
/etc/init.d/adminmanagement start
```

**Option B: Manual start (for testing)**
```bash
/etc/init.d/adminmanagement manual_start
```

**Option C: Direct execution (for debugging)**
```bash
cd /root/AdminManagementPanel
python3 simple_main_backend.py
```

### Step 5: Check Service Status
```bash
# Check if service is running
/etc/init.d/adminmanagement status

# Check logs
tail -f /var/log/adminmanagement.log

# Check if port 5000 is listening
netstat -tlnp | grep 5000
```

### Step 6: Configure Firewall
```bash
# Allow access to port 5000
iptables -I INPUT -p tcp --dport 5000 -j ACCEPT

# Make firewall rule persistent (save to UCI)
uci add firewall rule
uci set firewall.@rule[-1].name='AdminManagement'
uci set firewall.@rule[-1].src='lan'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].dest_port='5000'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit firewall
/etc/init.d/firewall reload
```

---

## 📧 Email Configuration

To enable email notifications for tickets and system alerts:

### Environment Variables (Recommended for Production)
```bash
# SSH into router and set environment variables
export SMTP_SERVER="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USERNAME="your-email@gmail.com"
export SMTP_PASSWORD="your-app-password"
export SMTP_USE_TLS="True"
export ADMIN_EMAIL="admin@yourcompany.com"
export IT_SUPPORT_EMAIL="it@yourcompany.com"

# Make permanent by adding to /etc/profile
echo 'export SMTP_SERVER="smtp.gmail.com"' >> /etc/profile
echo 'export SMTP_USERNAME="your-email@gmail.com"' >> /etc/profile
echo 'export SMTP_PASSWORD="your-app-password"' >> /etc/profile
echo 'export ADMIN_EMAIL="admin@yourcompany.com"' >> /etc/profile
echo 'export IT_SUPPORT_EMAIL="it@yourcompany.com"' >> /etc/profile
```

### Gmail Configuration Example
1. Enable 2-factor authentication on your Gmail account
2. Generate an "App Password" for the AdminManagement system
3. Use the app password instead of your regular password

### Test Email Configuration
```bash
# Using curl to test email
curl -X POST http://localhost:5000/api/email/test \
  -H "Content-Type: application/json"
```

---

## 🌐 Accessing the Web Interface

### From Same Network
- **Router IP**: http://192.168.1.1:5000
- **Your Router's IP**: http://[YOUR_ROUTER_IP]:5000

### From Different Network (Port Forwarding Required)
1. Log into router admin panel
2. Set up port forwarding: External Port 5000 → Internal Port 5000
3. Access via your public IP: http://[YOUR_PUBLIC_IP]:5000

### API Endpoints
- `GET /api/status` - System status
- `POST /api/login` - User authentication  
- `GET /api/devices` - List devices
- `POST /api/tickets` - Create support ticket
- `GET /api/branches` - List branches
- `POST /api/email/test` - Test email configuration

---

## 🔧 Troubleshooting

### Service Won't Start
1. **Check if Python3 is installed**:
   ```bash
   python3 --version
   ```

2. **Check if files exist**:
   ```bash
   ls -la /root/AdminManagementPanel/
   ```

3. **Check permissions**:
   ```bash
   chmod +x /etc/init.d/adminmanagement
   ```

4. **Run directly for debugging**:
   ```bash
   cd /root/AdminManagementPanel
   python3 simple_main_backend.py
   ```

### Can't Access Web Interface
1. **Check if service is listening on port 5000**:
   ```bash
   netstat -tlnp | grep 5000
   ```

2. **Check firewall rules**:
   ```bash
   iptables -L | grep 5000
   ```

3. **Test locally first**:
   ```bash
   curl http://127.0.0.1:5000/api/status
   ```

### Database Issues
1. **Check if database exists**:
   ```bash
   ls -la /root/AdminManagementPanel/admin_management.db
   ```

2. **Initialize database manually**:
   ```bash
   cd /root/AdminManagementPanel
   python3 -c "from simple_main_backend import init_db; init_db()"
   ```

### Email Notifications Not Working
1. **Check if email module loads**:
   ```bash
   python3 -c "from email_notifications import EmailNotificationManager; print('Email module OK')"
   ```

2. **Verify SMTP settings**:
   ```bash
   echo $SMTP_USERNAME
   echo $SMTP_SERVER
   ```

3. **Test email configuration**:
   ```bash
   curl -X POST http://localhost:5000/api/email/test
   ```

### Memory Issues (OpenWrt)
If you experience memory issues on the router:

1. **Monitor memory usage**:
   ```bash
   free -m
   top
   ```

2. **Reduce Flask debugging**:
   ```bash
   export FLASK_ENV=production
   ```

3. **Restart service periodically** (add to cron):
   ```bash
   # Add to /etc/crontabs/root
   0 3 * * * /etc/init.d/adminmanagement restart
   ```

---

## 📚 API Documentation

### Authentication
Most endpoints require a Bearer token obtained from `/api/login`.

### Main Endpoints

#### System Status
```bash
GET /api/status
```

#### Login
```bash
POST /api/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin"
}
```

#### Create Ticket
```bash
POST /api/tickets
Content-Type: application/json
Authorization: Bearer [token]

{
  "title": "Network Issue",
  "description": "Internet connection is slow",
  "priority": "High",
  "category": "Network",
  "reporter_name": "John Doe",
  "reporter_email": "john@company.com"
}
```

#### Create Device
```bash
POST /api/devices
Content-Type: application/json

{
  "name": "Office Laptop",
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "ip_address": "192.168.1.100",
  "device_type": "Laptop"
}
```

#### Send System Alert
```bash
POST /api/system/alert
Content-Type: application/json

{
  "title": "High CPU Usage",
  "message": "CPU usage is above 90%",
  "severity": "high",
  "recommended_action": "Check running processes"
}
```

---

## 🎯 Next Steps

Once your system is running:

1. **Change default password** in production
2. **Configure SSL/TLS** for secure access
3. **Set up email notifications** for your organization
4. **Configure automatic backups** of the database
5. **Monitor system performance** and logs
6. **Add more branches and users** as needed

---

## 📞 Support

If you encounter issues:

1. Check the logs: `/var/log/adminmanagement.log`
2. Verify all files are copied correctly
3. Ensure Python3 and Flask are installed
4. Check network connectivity and firewall settings

For development questions, refer to the code comments in the Python files.

---

**Happy Networking! 🚀**