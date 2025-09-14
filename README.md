# AdminManagement System

**Professional IT Support and Network Management Platform for OpenWrt Routers**

## Overview

AdminManagement is a comprehensive network management and IT support system designed specifically for TP-Link Archer C7 v5 routers running OpenWrt. This system provides advanced network monitoring, device management, guest access control, and IT ticketing capabilities in a professional web interface.

## 🚀 Key Features

### Network Management
- **Real-time Device Monitoring** - Automatic detection and tracking of all network devices
- **Bandwidth Control** - Per-device speed limiting and usage monitoring  
- **Firewall Management** - Advanced firewall rule configuration and management
- **Guest Network Control** - NoDogSplash captive portal with time/speed limits
- **Network Analytics** - Comprehensive network usage statistics and reports

### IT Support System
- **Support Ticket Management** - Complete ticketing system with priority levels
- **Device Asset Tracking** - IP addresses, MAC addresses, AnyDesk IDs, serial numbers
- **Branch Management** - Multi-branch network administration
- **User Management** - Role-based access control with multiple user types
- **Automated Incident Response** - AI-powered network anomaly detection

### Advanced Features
- **Cloud Synchronization** - Multi-branch data synchronization
- **Intelligent Guest System** - Dynamic guest portal with usage analytics
- **Predictive Device Management** - Device behavior analysis and predictions
- **Cross-Branch Analytics** - Network performance comparison across locations
- **Professional UI/UX** - Modern, responsive web interface

## 🛠 System Architecture

```
AdminManagement System Architecture
├── Frontend (Web Interface)
│   ├── Modern HTML5/CSS3/JavaScript
│   ├── Responsive Design
│   └── Real-time Dashboard
├── Backend API (Python Flask)
│   ├── RESTful API Endpoints
│   ├── Authentication & Authorization
│   ├── Business Logic Layer
│   └── Database Integration
├── Network Services
│   ├── Device Discovery & Monitoring
│   ├── Bandwidth Monitoring
│   ├── NoDogSplash Integration
│   └── Firewall Control
├── Database (SQLite)
│   ├── Users & Authentication
│   ├── Devices & Tracking
│   ├── Network Logs
│   ├── Support Tickets
│   └── Configuration Data
└── System Services
    ├── Real-time Monitoring
    ├── Scheduled Tasks
    ├── Cloud Synchronization
    └── Backup & Maintenance
```

## 📋 Requirements

### Hardware Requirements
- **Router**: TP-Link Archer C7 v5 (recommended) or compatible OpenWrt device
- **Memory**: Minimum 128MB RAM (256MB recommended)
- **Storage**: Minimum 32MB free space (64MB recommended)
- **Network**: Ethernet and WiFi interfaces

### Software Requirements
- **OpenWrt**: Version 19.07+ (tested on 21.02+)
- **Python**: 3.7+
- **Database**: SQLite 3
- **Web Server**: Built-in Flask development server or nginx/Apache

### OpenWrt Packages
```bash
# Core packages
python3 python3-pip python3-sqlite3 sqlite3-cli
curl wget ca-certificates openssl-util

# Network packages  
iptables-mod-extra kmod-ipt-conntrack-extra tc kmod-sched
nodogsplash hostapd-utils iw iwinfo

# Monitoring packages
collectd vnstat iftop htop
```

## 🚀 Quick Installation

### Automated Installation (Recommended)

1. **Download the installer script:**
   ```bash
   wget https://raw.githubusercontent.com/your-repo/AdminManagement/main/install_router.sh
   chmod +x install_router.sh
   ```

2. **Run the installer as root:**
   ```bash
   ./install_router.sh
   ```

3. **Access the admin panel:**
   ```
   http://[router-ip]:5000
   Default credentials: admin / admin123
   ```

### Manual Installation

1. **Prepare the system:**
   ```bash
   opkg update
   opkg install python3 python3-pip sqlite3-cli nodogsplash
   ```

2. **Create directories:**
   ```bash
   mkdir -p /opt/adminmanagement/{logs,backups,static,templates}
   mkdir -p /etc/nodogsplash/htdocs
   ```

3. **Copy system files:**
   ```bash
   cp -r AdminManagementPanel/* /opt/adminmanagement/
   chmod +x /opt/adminmanagement/*.py
   ```

4. **Install Python dependencies:**
   ```bash
   pip3 install flask werkzeug paramiko requests schedule psutil
   ```

5. **Initialize database:**
   ```bash
   cd /opt/adminmanagement
   python3 -c "from db_config import init_database; init_database()"
   ```

6. **Configure and start services:**
   ```bash
   cp install_router.sh /tmp/
   /tmp/install_router.sh --config-only
   /etc/init.d/adminmanagement start
   /etc/init.d/nodogsplash start
   ```

## 📖 Configuration

### Basic Configuration

The system uses configuration files in `/opt/adminmanagement/`:

- `config.py` - Main configuration file
- `local_settings.py` - Router-specific settings (auto-generated)

### Key Configuration Options

```python
# Network Settings
ROUTER_IP = '192.168.1.1'
ROUTER_SSH_PORT = 22
ROUTER_USERNAME = 'root'

# NoDogSplash Configuration
NODOGSPLASH_ENABLED = True
NODOGSPLASH_PORT = 2050
NODOGSPLASH_INTERFACE = 'br-lan'

# Guest Network Defaults
GUEST_DEFAULT_TIME_LIMIT = '1 hour'
GUEST_DEFAULT_SPEED_LIMIT = '5 Mbps'
GUEST_ISOLATION_ENABLED = True

# Monitoring Settings
MONITORING_INTERVAL = 300  # seconds
DEVICE_SCAN_INTERVAL = 30  # seconds
BANDWIDTH_SCAN_INTERVAL = 10  # seconds
```

### Database Configuration

The system automatically creates and manages an SQLite database with the following main tables:

- **users** - User accounts and authentication
- **devices** - Network device registry
- **branches** - Multi-branch management
- **tickets** - IT support tickets
- **guest_passwords** - Guest access codes
- **device_activity** - Device connection history
- **device_bandwidth** - Bandwidth usage logs
- **network_logs** - System activity logs

## 🌐 Web Interface

### Dashboard Overview
- Real-time network statistics
- Active device count and status
- Network traffic charts
- Recent activity feed
- System health indicators

### Device Management
- Automatic device discovery
- Device information (IP, MAC, type, etc.)
- Bandwidth usage monitoring
- Connection history tracking
- Device blocking/unblocking
- Speed limit configuration

### User Management  
- User account creation and management
- Role-based access control (Admin, Support, User)
- Branch assignment
- Session management
- Password policies

### Guest Network
- Guest access code generation
- Time and speed limit configuration  
- Usage monitoring and analytics
- Captive portal customization
- Session management

### Support Tickets
- Ticket creation and tracking
- Priority levels and categories
- Assignment and status updates
- Branch-specific ticketing
- Email notifications (when configured)

### Firewall Management
- Firewall rule configuration
- Traffic blocking and allowing
- Port management
- Security policies
- Real-time rule application

## 🔧 API Documentation

The system provides a comprehensive RESTful API for automation and integration:

### Authentication
```bash
POST /api/login
{
  "username": "admin",
  "password": "admin123"
}
```

### Device Management
```bash
# Get all devices
GET /api/devices?branch_id=1

# Add new device  
POST /api/devices
{
  "name": "Laptop-001",
  "ip_address": "192.168.1.100", 
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "device_type": "laptop",
  "branch_id": 1
}

# Block device
POST /api/devices/{mac_address}/block
{
  "duration": 3600,
  "reason": "Policy violation"
}

# Apply bandwidth limit
POST /api/devices/{mac_address}/bandwidth  
{
  "download_limit": 1024,
  "upload_limit": 512
}
```

### Guest Network
```bash
# Generate guest password
POST /api/guest-passwords
{
  "time_limit": 60,
  "speed_limit_down": 5120,
  "max_usage": 1,
  "branch_id": 1
}

# Get active sessions
GET /api/guest-sessions?branch_id=1
```

### Support Tickets
```bash
# Create ticket
POST /api/tickets
{
  "title": "Network connectivity issue",
  "description": "Unable to connect to internet",
  "reporter_name": "John Doe",
  "category": "Network", 
  "priority": "High",
  "branch_id": 1
}

# Get tickets
GET /api/tickets?branch_id=1&status=Open
```

## 🔒 Security Features

### Authentication & Authorization
- Secure password hashing (bcrypt)
- Session-based authentication
- Role-based access control
- Account lockout protection
- Password complexity requirements

### Network Security
- Firewall integration
- Traffic monitoring and analysis
- Anomaly detection
- Guest network isolation
- Bandwidth controls

### Data Protection
- Input validation and sanitization
- SQL injection prevention  
- XSS protection
- CSRF protection
- Secure session management

## 📊 Monitoring & Analytics

### Real-time Monitoring
- Device connection/disconnection events
- Bandwidth usage tracking
- Network performance metrics
- System resource monitoring
- Security event logging

### Reporting
- Daily network usage reports
- Device activity summaries
- Bandwidth utilization analytics
- Security incident reports
- Performance trend analysis

### Alerting
- Automated incident detection
- Threshold-based alerts
- Email notifications (when configured)
- System health monitoring
- Performance degradation alerts

## 🚀 Advanced Features

### Multi-Branch Management
- Centralized management of multiple locations
- Branch-specific configurations
- Cross-branch analytics
- Synchronized user management
- Distributed monitoring

### Cloud Integration
- Cloud database synchronization
- Remote branch management
- Centralized reporting
- Backup and disaster recovery
- Cross-site analytics

### AI-Powered Features
- Intelligent device classification
- Predictive analytics
- Anomaly detection
- Automated incident response
- Usage pattern analysis

## 🛠 Maintenance & Operations

### System Monitoring
```bash
# Check service status
/etc/init.d/adminmanagement status
/etc/init.d/nodogsplash status

# View logs
tail -f /opt/adminmanagement/logs/admin.log
logread | grep adminmanagement

# Monitor resources
htop
df -h
free -m
```

### Backup & Recovery
```bash
# Manual backup
/opt/adminmanagement/backup.sh

# Restore from backup
tar -xzf /opt/adminmanagement/backups/backup_file.tar.gz -C /
/etc/init.d/adminmanagement restart
```

### Database Maintenance
```bash
# Database vacuum (monthly)
sqlite3 /opt/adminmanagement/admin_management.db "VACUUM;"

# Check database integrity
sqlite3 /opt/adminmanagement/admin_management.db "PRAGMA integrity_check;"

# View database size
ls -lh /opt/adminmanagement/admin_management.db
```

## 🔧 Troubleshooting

### Common Issues

**Service won't start:**
```bash
# Check Python installation
python3 --version
which python3

# Check dependencies  
pip3 list | grep flask

# Check permissions
ls -la /opt/adminmanagement/
```

**Database errors:**
```bash
# Check database file
ls -la /opt/adminmanagement/admin_management.db

# Test database connection
sqlite3 /opt/adminmanagement/admin_management.db ".tables"

# Reinitialize if needed
mv /opt/adminmanagement/admin_management.db /tmp/
python3 -c "from db_config import init_database; init_database()"
```

**NoDogSplash issues:**
```bash
# Check NoDogSplash status
ndsctl status

# Check configuration
cat /etc/nodogsplash/nodogsplash.conf

# Check firewall rules
iptables -L -n
```

**Network monitoring not working:**
```bash
# Check network interfaces
ip link show
iwconfig

# Check monitoring processes
ps aux | grep python
ps aux | grep nodogsplash

# Check file permissions
ls -la /tmp/dhcp.leases
ls -la /proc/net/arp
```

### Performance Optimization

**Memory optimization:**
```bash
# Check memory usage
free -m
cat /proc/meminfo

# Reduce Python memory usage
export PYTHONDONTWRITEBYTECODE=1
echo 'export PYTHONDONTWRITEBYTECODE=1' >> /etc/profile
```

**Storage optimization:**
```bash
# Clean up logs
logrotate -f /etc/logrotate.d/adminmanagement

# Clean old data
/opt/adminmanagement/cleanup.sh

# Check disk usage
df -h
du -sh /opt/adminmanagement/*
```

## 📚 Development

### Development Environment Setup
```bash
git clone https://github.com/your-repo/AdminManagement.git
cd AdminManagement
pip3 install -r requirements.txt
python3 main_api_backend.py
```

### Testing
```bash
# Run unit tests
python3 -m pytest tests/

# Run integration tests  
python3 tests/integration_tests.py

# Test API endpoints
curl -X GET http://localhost:5000/api/health
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Support

### Community Support
- **Documentation**: [Wiki](https://github.com/your-repo/AdminManagement/wiki)
- **Issues**: [GitHub Issues](https://github.com/your-repo/AdminManagement/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/AdminManagement/discussions)

### Commercial Support
For enterprise deployments and commercial support, please contact [support@adminmanagement.com](mailto:support@adminmanagement.com).

## 🙏 Acknowledgments

- OpenWrt community for the excellent embedded Linux distribution
- NoDogSplash project for the captive portal functionality
- Flask framework for the web application foundation
- All contributors and testers who helped improve this project

## 📈 Roadmap

### Upcoming Features
- [ ] HTTPS/SSL support with Let's Encrypt
- [ ] Advanced reporting dashboard
- [ ] Mobile app for iOS/Android
- [ ] Integration with external monitoring tools
- [ ] Advanced AI/ML analytics
- [ ] Multi-language support
- [ ] Advanced firewall templates
- [ ] VPN integration
- [ ] IoT device management
- [ ] Network topology visualization

### Version History
- **v1.0.0** (Current) - Initial release with core functionality
- **v0.9.0** - Beta release with NoDogSplash integration
- **v0.8.0** - Alpha release with basic monitoring
- **v0.7.0** - Development preview

---

**AdminManagement System** - Professional IT Support and Network Management Platform  
Built with ❤️ for the OpenWrt and IT community