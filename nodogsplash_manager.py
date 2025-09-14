# nodogsplash_manager.py
import subprocess
import json
import secrets
import string
from datetime import datetime, timedelta
from db_config import get_db_connection
from error_handling import logger

class NoDogSplashManager:
    def __init__(self, config):
        self.config = config
        self.nds_config_path = '/etc/nodogsplash/nodogsplash.conf'
        self.portal_path = '/etc/nodogsplash/htdocs'
        
    def install_nodogsplash(self):
        """Install NoDogSplash package on OpenWrt"""
        try:
            # Update package list and install NoDogSplash
            commands = [
                'opkg update',
                'opkg install nodogsplash',
                'mkdir -p /etc/nodogsplash/htdocs',
                'mkdir -p /tmp/ndslog'
            ]
            
            for cmd in commands:
                result = subprocess.run(cmd.split(), capture_output=True, text=True)
                if result.returncode != 0:
                    logger.error(f"Failed to execute: {cmd} - {result.stderr}")
                    return False
            
            logger.info("NoDogSplash installed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error installing NoDogSplash: {e}")
            return False
    
    def configure_nodogsplash(self, interface='br-lan', portal_url=None):
        """Configure NoDogSplash with custom settings"""
        try:
            config_content = f"""
# NoDogSplash Configuration - AdminManagement
# Generated on {datetime.now().isoformat()}

# Interface to bind to
GatewayInterface {interface}

# Gateway name and address
GatewayName "AdminManagement Guest Portal"
GatewayAddress 192.168.1.1

# Maximum number of clients
MaxClients 250

# Session timeout in minutes (0 = unlimited)
SessionTimeout 0

# Idle timeout in minutes
ClientIdleTimeout 10

# Force DHCP timeout in minutes
ClientForceTimeout 60

# Authentication
AuthDir /etc/nodogsplash/htdocs/

# Redirect URL after authentication
RedirectURL http://192.168.1.1/portal/welcome

# Deny/Allow rules for authenticated clients
FirewallRule allow tcp port 53
FirewallRule allow udp port 53
FirewallRule allow tcp port 80
FirewallRule allow tcp port 443

# Pre-authentication rules (for login portal)
FirewallRule allow tcp port 80 to 192.168.1.1
FirewallRule allow tcp port 443 to 192.168.1.1

# Bandwidth limits (per client)
DownloadLimit 5120  # 5 Mbps in kbps
UploadLimit 1024    # 1 Mbps in kbps

# Enable status page
StatusPage /nodogsplash_status/

# Custom splash page
SplashPage /splash/

# Daemon options
Daemon 1
DebugLevel 1
LogLevel 2

# PID file
PidFile /var/run/nodogsplash.pid

# Lock file
LockFile /tmp/nodogsplash.lock

# Client list
ClientListFile /tmp/ndslog/clients.log

# Enable preauth script
#PreAuthScript /usr/lib/nodogsplash/preauth.sh

# Enable authentication script  
#BinAuthScript /usr/lib/nodogsplash/binauth.sh

# Enable post authentication script
#PostAuthScript /usr/lib/nodogsplash/postauth.sh
"""
            
            # Write configuration file
            with open(self.nds_config_path, 'w') as f:
                f.write(config_content)
            
            logger.info("NoDogSplash configuration written successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error configuring NoDogSplash: {e}")
            return False
    
    def create_portal_pages(self):
        """Create custom splash pages for the captive portal"""
        try:
            # Main splash page
            splash_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Guest WiFi Portal - AdminManagement</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .portal-container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 40px;
            max-width: 400px;
            width: 90%;
            text-align: center;
        }
        .logo {
            color: #667eea;
            font-size: 48px;
            margin-bottom: 20px;
        }
        h1 {
            color: #2d3748;
            margin-bottom: 10px;
            font-size: 28px;
            font-weight: 600;
        }
        .subtitle {
            color: #718096;
            margin-bottom: 30px;
            font-size: 16px;
        }
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #4a5568;
            font-weight: 500;
            font-size: 14px;
        }
        input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e2e8f0;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn-connect {
            width: 100%;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 14px;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .btn-connect:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }
        .info-box {
            background: #f7fafc;
            border-radius: 10px;
            padding: 20px;
            margin-top: 20px;
            border-left: 4px solid #667eea;
        }
        .info-title {
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 8px;
        }
        .info-text {
            color: #718096;
            font-size: 14px;
            line-height: 1.5;
        }
        .loading {
            display: none;
            margin-top: 20px;
        }
        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .error {
            color: #e53e3e;
            font-size: 14px;
            margin-top: 10px;
            display: none;
        }
    </style>
</head>
<body>
    <div class="portal-container">
        <div class="logo">
            <i class="fas fa-wifi"></i>
        </div>
        <h1>Welcome to Guest WiFi</h1>
        <p class="subtitle">Enter your access code to connect to the internet</p>
        
        <form id="authForm" onsubmit="authenticate(event)">
            <div class="form-group">
                <label for="accessCode">Access Code</label>
                <input type="text" id="accessCode" name="access_code" 
                       placeholder="Enter your 8-character code" 
                       maxlength="8" required 
                       style="text-transform: uppercase; letter-spacing: 2px;">
            </div>
            
            <button type="submit" class="btn-connect">
                <i class="fas fa-globe"></i> Connect to Internet
            </button>
        </form>
        
        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p>Connecting...</p>
        </div>
        
        <div class="error" id="errorMsg"></div>
        
        <div class="info-box">
            <div class="info-title">
                <i class="fas fa-info-circle"></i> Information
            </div>
            <div class="info-text">
                • Access codes are provided by the IT administrator<br>
                • Each code has time and speed limitations<br>
                • For technical support, contact your IT department
            </div>
        </div>
    </div>

    <script>
        // Auto-format input to uppercase
        document.getElementById('accessCode').addEventListener('input', function(e) {
            e.target.value = e.target.value.toUpperCase();
        });

        function authenticate(event) {
            event.preventDefault();
            
            const accessCode = document.getElementById('accessCode').value;
            const form = document.getElementById('authForm');
            const loading = document.getElementById('loading');
            const errorMsg = document.getElementById('errorMsg');
            
            // Hide error and show loading
            errorMsg.style.display = 'none';
            form.style.display = 'none';
            loading.style.display = 'block';
            
            // Validate access code with backend
            fetch('/nodogsplash_auth/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `access_code=${accessCode}&mac=${getMacAddress()}&ip=${getClientIP()}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Redirect to NoDogSplash authentication URL
                    window.location.href = data.auth_url;
                } else {
                    showError(data.error || 'Invalid access code');
                }
            })
            .catch(error => {
                showError('Connection failed. Please try again.');
                console.error('Authentication error:', error);
            });
        }
        
        function showError(message) {
            const form = document.getElementById('authForm');
            const loading = document.getElementById('loading');
            const errorMsg = document.getElementById('errorMsg');
            
            loading.style.display = 'none';
            form.style.display = 'block';
            errorMsg.textContent = message;
            errorMsg.style.display = 'block';
        }
        
        function getMacAddress() {
            // This would be populated by NoDogSplash template variables
            return '$clientmac$';
        }
        
        function getClientIP() {
            // This would be populated by NoDogSplash template variables
            return '$clientip$';
        }
    </script>
</body>
</html>"""

            # Welcome page after successful authentication
            welcome_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connected - Guest WiFi Portal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .success-container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 40px;
            max-width: 400px;
            width: 90%;
            text-align: center;
        }
        .success-icon {
            color: #48bb78;
            font-size: 64px;
            margin-bottom: 20px;
        }
        h1 {
            color: #2d3748;
            margin-bottom: 10px;
            font-size: 28px;
            font-weight: 600;
        }
        .subtitle {
            color: #718096;
            margin-bottom: 30px;
            font-size: 16px;
        }
        .session-info {
            background: #f7fafc;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .info-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            font-size: 14px;
        }
        .info-label {
            color: #4a5568;
            font-weight: 500;
        }
        .info-value {
            color: #2d3748;
            font-weight: 600;
        }
        .btn-browse {
            width: 100%;
            background: linear-gradient(135deg, #48bb78, #38a169);
            color: white;
            border: none;
            padding: 14px;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
    </style>
</head>
<body>
    <div class="success-container">
        <div class="success-icon">
            <i class="fas fa-check-circle"></i>
        </div>
        <h1>Successfully Connected!</h1>
        <p class="subtitle">You now have internet access</p>
        
        <div class="session-info">
            <div class="info-row">
                <span class="info-label">Session Time:</span>
                <span class="info-value" id="sessionTime">Loading...</span>
            </div>
            <div class="info-row">
                <span class="info-label">Speed Limit:</span>
                <span class="info-value" id="speedLimit">Loading...</span>
            </div>
            <div class="info-row">
                <span class="info-label">Data Usage:</span>
                <span class="info-value" id="dataUsage">0 MB</span>
            </div>
        </div>
        
        <a href="https://www.google.com" class="btn-browse">
            <i class="fas fa-globe"></i> Start Browsing
        </a>
    </div>
</body>
</html>"""

            # Write splash page
            with open(f"{self.portal_path}/splash.html", 'w') as f:
                f.write(splash_html)
                
            # Write welcome page
            with open(f"{self.portal_path}/welcome.html", 'w') as f:
                f.write(welcome_html)
            
            logger.info("Portal pages created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error creating portal pages: {e}")
            return False
    
    def generate_access_code(self, branch_id, time_limit=60, speed_down=5120, speed_up=1024, max_usage=1, created_by='admin'):
        """Generate a new guest access code"""
        try:
            # Generate random 8-character code
            characters = string.ascii_uppercase + string.digits
            access_code = ''.join(secrets.choice(characters) for _ in range(8))
            
            # Calculate expiration time
            expires_at = datetime.now() + timedelta(minutes=time_limit)
            
            # Store in database
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO guest_passwords 
                    (password, branch_id, time_limit, speed_limit_down, speed_limit_up, max_usage, created_by, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (access_code, branch_id, time_limit, speed_down, speed_up, max_usage, created_by, expires_at.isoformat()))
                
                password_id = cursor.lastrowid
                
            logger.info(f"Generated access code: {access_code} for branch {branch_id}")
            
            return {
                'id': password_id,
                'password': access_code,
                'time_limit': time_limit,
                'speed_limit_down': speed_down,
                'speed_limit_up': speed_up,
                'expires_at': expires_at.isoformat(),
                'max_usage': max_usage
            }
            
        except Exception as e:
            logger.error(f"Error generating access code: {e}")
            return None
    
    def validate_access_code(self, access_code, client_mac, client_ip):
        """Validate access code and return authentication details"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Check if code exists and is valid
                cursor.execute("""
                    SELECT * FROM guest_passwords 
                    WHERE password = ? AND is_active = 1 
                    AND (expires_at IS NULL OR expires_at > ?) 
                    AND current_usage < max_usage
                """, (access_code, datetime.now().isoformat()))
                
                password_record = cursor.fetchone()
                
                if not password_record:
                    return {'success': False, 'error': 'Invalid or expired access code'}
                
                # Check if client is already authenticated
                cursor.execute("""
                    SELECT * FROM guest_sessions 
                    WHERE mac_address = ? AND is_active = 1 
                    AND expires_at > ?
                """, (client_mac, datetime.now().isoformat()))
                
                existing_session = cursor.fetchone()
                
                if existing_session:
                    return {'success': False, 'error': 'Device already authenticated'}
                
                # Create new session
                session_expires = datetime.now() + timedelta(minutes=password_record['time_limit'])
                
                cursor.execute("""
                    INSERT INTO guest_sessions 
                    (password_id, mac_address, ip_address, expires_at, speed_limit_down, speed_limit_up)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (password_record['id'], client_mac, client_ip, session_expires.isoformat(),
                      password_record['speed_limit_down'], password_record['speed_limit_up']))
                
                # Update usage count
                cursor.execute("""
                    UPDATE guest_passwords 
                    SET current_usage = current_usage + 1 
                    WHERE id = ?
                """, (password_record['id'],))
                
                # Generate NoDogSplash auth token
                auth_token = self.generate_nds_token(client_mac, client_ip)
                
                return {
                    'success': True,
                    'auth_url': f"http://192.168.1.1:2050/nodogsplash_auth/?token={auth_token}",
                    'session_time': password_record['time_limit'],
                    'speed_down': password_record['speed_limit_down'],
                    'speed_up': password_record['speed_limit_up']
                }
                
        except Exception as e:
            logger.error(f"Error validating access code: {e}")
            return {'success': False, 'error': 'Authentication failed'}
    
    def generate_nds_token(self, client_mac, client_ip):
        """Generate NoDogSplash authentication token"""
        # This would integrate with NoDogSplash's token system
        # For now, we'll use a simple approach
        token_data = f"{client_mac}:{client_ip}:{datetime.now().timestamp()}"
        return secrets.token_urlsafe(32)
    
    def get_active_sessions(self, branch_id=None):
        """Get list of active guest sessions"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                query = """
                    SELECT gs.*, gp.password, gp.branch_id 
                    FROM guest_sessions gs
                    JOIN guest_passwords gp ON gs.password_id = gp.id
                    WHERE gs.is_active = 1 AND gs.expires_at > ?
                """
                params = [datetime.now().isoformat()]
                
                if branch_id:
                    query += " AND gp.branch_id = ?"
                    params.append(branch_id)
                
                query += " ORDER BY gs.created_at DESC"
                
                cursor.execute(query, params)
                sessions = cursor.fetchall()
                
                return [dict(session) for session in sessions]
                
        except Exception as e:
            logger.error(f"Error getting active sessions: {e}")
            return []
    
    def terminate_session(self, session_id):
        """Terminate a guest session"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Get session details
                cursor.execute("""
                    SELECT mac_address FROM guest_sessions WHERE id = ?
                """, (session_id,))
                
                session = cursor.fetchone()
                
                if not session:
                    return False
                
                # Deactivate session
                cursor.execute("""
                    UPDATE guest_sessions 
                    SET is_active = 0, terminated_at = ? 
                    WHERE id = ?
                """, (datetime.now().isoformat(), session_id))
                
                # Remove from NoDogSplash (if possible)
                self.deauth_client(session['mac_address'])
                
                return True
                
        except Exception as e:
            logger.error(f"Error terminating session: {e}")
            return False
    
    def deauth_client(self, mac_address):
        """Deauthenticate client from NoDogSplash"""
        try:
            # Use NoDogSplash control interface to deauth client
            cmd = f"ndsctl deauth {mac_address}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Successfully deauthenticated client: {mac_address}")
                return True
            else:
                logger.error(f"Failed to deauth client {mac_address}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error deauthenticating client: {e}")
            return False
    
    def start_service(self):
        """Start NoDogSplash service"""
        try:
            # Start the service
            result = subprocess.run(['service', 'nodogsplash', 'start'], capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("NoDogSplash service started successfully")
                return True
            else:
                logger.error(f"Failed to start NoDogSplash: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error starting NoDogSplash service: {e}")
            return False
    
    def stop_service(self):
        """Stop NoDogSplash service"""
        try:
            result = subprocess.run(['service', 'nodogsplash', 'stop'], capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("NoDogSplash service stopped successfully")
                return True
            else:
                logger.error(f"Failed to stop NoDogSplash: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error stopping NoDogSplash service: {e}")
            return False
    
    def get_status(self):
        """Get NoDogSplash service status"""
        try:
            # Check if service is running
            result = subprocess.run(['pidof', 'nodogsplash'], capture_output=True, text=True)
            is_running = result.returncode == 0
            
            # Get client statistics if running
            clients_info = {}
            if is_running:
                try:
                    status_result = subprocess.run(['ndsctl', 'status'], capture_output=True, text=True)
                    if status_result.returncode == 0:
                        # Parse status output
                        for line in status_result.stdout.split('\n'):
                            if 'clients' in line.lower():
                                clients_info = {'status_output': line}
                except:
                    pass
            
            return {
                'running': is_running,
                'clients': clients_info,
                'config_path': self.nds_config_path,
                'portal_path': self.portal_path
            }
            
        except Exception as e:
            logger.error(f"Error getting NoDogSplash status: {e}")
            return {'running': False, 'error': str(e)}

# Add guest sessions table to database schema
def create_guest_sessions_table():
    """Create guest sessions table if not exists"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS guest_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    password_id INTEGER NOT NULL,
                    mac_address TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME NOT NULL,
                    terminated_at DATETIME,
                    speed_limit_down INTEGER,
                    speed_limit_up INTEGER,
                    bytes_downloaded BIGINT DEFAULT 0,
                    bytes_uploaded BIGINT DEFAULT 0,
                    FOREIGN KEY (password_id) REFERENCES guest_passwords (id)
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_guest_sessions_mac ON guest_sessions(mac_address)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_guest_sessions_active ON guest_sessions(is_active)
            """)
            
    except Exception as e:
        logger.error(f"Error creating guest sessions table: {e}")