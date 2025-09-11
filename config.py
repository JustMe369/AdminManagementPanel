# config.py
import os
import secrets

# Application settings
DEBUG = False
TESTING = False
SECRET_KEY = secrets.token_hex(32)

# Database settings
DB_PATH = os.path.join(os.path.dirname(__file__), 'admin_management.db')

# Security settings
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
PERMANENT_SESSION_LIFETIME = 86400  # 24 hours in seconds

# OpenWrt settings
ROUTER_IP = '192.168.1.1'  # Default TP-Link Archer C7 IP
ROUTER_SSH_PORT = 22
ROUTER_USERNAME = 'root'  # Default OpenWrt username
# Router password should be stored securely, not in this file
# Use environment variables or a secure vault

# NoDogSplash settings
NODOGSPLASH_ENABLED = True
NODOGSPLASH_PORT = 2050
NODOGSPLASH_INTERFACE = 'br-lan'

# Branch settings
MAIN_BRANCH_ID = 1
CLOUD_SYNC_INTERVAL = 3600  # 1 hour in seconds

# API settings
API_VERSION = 'v1'
API_RATE_LIMIT = 100  # requests per minute
API_TIMEOUT = 30  # seconds

# Logging settings
LOG_LEVEL = 'INFO'
LOG_FILE = '/var/log/adminmanagement.log'

# Cache settings
CACHE_TYPE = 'simple'  # Options: simple, redis, memcached
CACHE_DEFAULT_TIMEOUT = 300  # 5 minutes in seconds

# Email notification settings
SMTP_SERVER = 'smtp.example.com'
SMTP_PORT = 587
SMTP_USE_TLS = True
SMTP_USERNAME = 'notifications@example.com'
# SMTP password should be stored securely, not in this file

# Device monitoring settings
MONITORING_INTERVAL = 300  # 5 minutes in seconds
ALERT_CPU_THRESHOLD = 90  # percentage
ALERT_MEMORY_THRESHOLD = 90  # percentage
ALERT_BANDWIDTH_THRESHOLD = 90  # percentage

# AI settings
AI_ENABLED = True
ANOMALY_DETECTION_SENSITIVITY = 0.1  # Lower values are more sensitive

# Ticket system settings
TICKET_AUTO_CLOSE_DAYS = 7  # Auto-close resolved tickets after 7 days
TICKET_REMINDER_HOURS = 24  # Send reminder for unresolved tickets after 24 hours

# Cloud database settings
CLOUD_DB_ENABLED = True
CLOUD_DB_TYPE = 'mysql'  # Options: mysql, postgresql, mongodb
CLOUD_DB_HOST = 'cloud-db.example.com'
CLOUD_DB_PORT = 3306
CLOUD_DB_NAME = 'admin_management_cloud'
CLOUD_DB_USER = 'admin_cloud'
# Cloud DB password should be stored securely, not in this file

# User settings
PASSWORD_MIN_LENGTH = 8
PASSWORD_REQUIRE_SPECIAL = True
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_NUMBERS = True
PASSWORD_EXPIRY_DAYS = 90  # Force password change after 90 days
FAILED_LOGIN_LIMIT = 5  # Lock account after 5 failed attempts
ACCOUNT_LOCKOUT_MINUTES = 30  # Lock duration after failed attempts

# Guest network settings
GUEST_NETWORK_ENABLED = True
GUEST_NETWORK_SSID = 'Guest-WiFi'
GUEST_DEFAULT_TIME_LIMIT = '1 hour'
GUEST_DEFAULT_SPEED_LIMIT = '5 Mbps'
GUEST_ISOLATION_ENABLED = True

# Firewall settings
FIREWALL_DEFAULT_POLICY = 'DROP'  # Options: ACCEPT, DROP, REJECT
FIREWALL_ALLOW_SSH = True
FIREWALL_ALLOW_HTTP = True
FIREWALL_ALLOW_HTTPS = True
FIREWALL_ALLOW_PING = True

# Load environment-specific settings
try:
    from local_settings import *
except ImportError:
    pass  # No local settings found, use defaults