# simple_main_backend.py
# Simplified AdminManagement Backend with Email Notifications
import os
import json
import sqlite3
import subprocess
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g

# Import custom modules with fallback handling
try:
    from db_config import get_db_connection
except ImportError:
    # Fallback database connection
    def get_db_connection():
        import sqlite3
        conn = sqlite3.connect('admin_management.db')
        conn.row_factory = sqlite3.Row
        return conn

try:
    from error_handling import logger
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

try:
    from email_notifications import init_email_notifications
    EMAIL_AVAILABLE = True
except ImportError:
    logger.warning("Email notifications not available")
    EMAIL_AVAILABLE = False
    def init_email_notifications(app):
        return None

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['DATABASE_PATH'] = 'admin_management.db'
app.config['ROUTER_IP'] = '192.168.1.1'  # Change to your router IP

# Email Configuration (Set these via environment variables in production)
app.config['SMTP_SERVER'] = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
app.config['SMTP_PORT'] = int(os.getenv('SMTP_PORT', '587'))
app.config['SMTP_USERNAME'] = os.getenv('SMTP_USERNAME', '')
app.config['SMTP_PASSWORD'] = os.getenv('SMTP_PASSWORD', '')
app.config['SMTP_USE_TLS'] = os.getenv('SMTP_USE_TLS', 'True').lower() == 'true'
app.config['FROM_EMAIL'] = os.getenv('FROM_EMAIL', app.config['SMTP_USERNAME'])
app.config['FROM_NAME'] = os.getenv('FROM_NAME', 'AdminManagement System')
app.config['ADMIN_EMAIL'] = os.getenv('ADMIN_EMAIL', 'admin@company.com')
app.config['IT_SUPPORT_EMAIL'] = os.getenv('IT_SUPPORT_EMAIL', 'it@company.com')

# Initialize email manager if available
email_manager = None
if EMAIL_AVAILABLE:
    try:
        email_manager = init_email_notifications(app)
        logger.info("Email notifications initialized")
    except Exception as e:
        logger.error(f"Failed to initialize email notifications: {e}")

# Database path
DB_PATH = os.path.join(os.path.dirname(__file__), 'admin_management.db')

# Simple auth decorator
def require_auth():
    def decorator(f):
        def wrapper(*args, **kwargs):
            # In a production environment, implement proper JWT or session validation
            # For now, we'll just check for a basic Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Authentication required'}), 401
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

# Initialize database if not exists
def init_db():
    """Initialize database with basic schema"""
    try:
        with get_db_connection() as conn:
            # Create basic tables if they don't exist
            conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                user_type TEXT DEFAULT 'User',
                branch_id INTEGER DEFAULT 1,
                status TEXT DEFAULT 'Active',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_login TEXT,
                session_token TEXT,
                token_expires TEXT,
                login_attempts INTEGER DEFAULT 0,
                lockout_until TEXT
            );
            
            CREATE TABLE IF NOT EXISTS branches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                location TEXT,
                manager_name TEXT,
                contact_email TEXT,
                contact_phone TEXT,
                network_config TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'Active'
            );
            
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                mac_address TEXT UNIQUE NOT NULL,
                ip_address TEXT,
                device_type TEXT DEFAULT 'Unknown',
                manufacturer TEXT,
                branch_id INTEGER,
                user_id INTEGER,
                status TEXT DEFAULT 'Active',
                first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (branch_id) REFERENCES branches (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
            
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_number TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                category TEXT DEFAULT 'General',
                priority TEXT DEFAULT 'Medium',
                status TEXT DEFAULT 'Open',
                reporter_name TEXT,
                reporter_email TEXT,
                assigned_to TEXT,
                branch_id INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT,
                resolved_at TEXT,
                notes TEXT,
                FOREIGN KEY (branch_id) REFERENCES branches (id)
            );
            
            CREATE TABLE IF NOT EXISTS network_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                branch_id INTEGER,
                log_type TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT,
                severity TEXT DEFAULT 'info',
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (branch_id) REFERENCES branches (id)
            );
            
            -- Insert default data if not exists
            INSERT OR IGNORE INTO branches (id, name, location) VALUES (1, 'Main Branch', 'Headquarters');
            INSERT OR IGNORE INTO users (id, username, password_hash, user_type) VALUES (1, 'admin', 'pbkdf2:sha256:600000$default$hashedpassword', 'Admin');
            ''')
            logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")

# Middleware to check if database exists
@app.before_request
def before_request():
    if not os.path.exists(DB_PATH):
        init_db()

# API Routes

@app.route('/api/status', methods=['GET'])
def api_status():
    """API status endpoint for health checks"""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'services': {
            'database': os.path.exists(DB_PATH),
            'email': EMAIL_AVAILABLE and email_manager is not None
        }
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok', 'timestamp': datetime.now().isoformat()})

# User Management
@app.route('/api/login', methods=['POST'])
def login():
    """Simple login endpoint"""
    try:
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ? AND status = 'Active'", (username,))
            user = cursor.fetchone()
            
            if user and password == 'admin':  # Simple password check for testing
                # Generate a simple token (in production, use proper JWT)
                token = f"token_{user['id']}_{int(datetime.now().timestamp())}"
                expires = datetime.now() + timedelta(hours=24)
                
                # Update user session
                cursor.execute("""
                UPDATE users 
                SET session_token = ?, token_expires = ?, last_login = ? 
                WHERE id = ?
                """, (token, expires.isoformat(), datetime.now().isoformat(), user['id']))
                
                return jsonify({
                    'success': True,
                    'token': token,
                    'expires': expires.isoformat(),
                    'user_id': user['id'],
                    'username': user['username'],
                    'user_type': user['user_type']
                })
            else:
                return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
                
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'message': 'Login failed'}), 500

# Device Management
@app.route('/api/devices', methods=['GET'])
def get_devices():
    """Get all devices"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT d.*, b.name as branch_name 
                FROM devices d 
                LEFT JOIN branches b ON d.branch_id = b.id 
                ORDER BY d.last_seen DESC
            """)
            devices = [dict(row) for row in cursor.fetchall()]
            
        return jsonify({'success': True, 'devices': devices})
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/devices', methods=['POST'])
def create_device():
    """Create a new device"""
    try:
        data = request.get_json()
        name = data.get('name', '')
        mac_address = data.get('mac_address', '')
        ip_address = data.get('ip_address', '')
        device_type = data.get('device_type', 'Unknown')
        branch_id = data.get('branch_id', 1)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO devices (name, mac_address, ip_address, device_type, branch_id) 
                VALUES (?, ?, ?, ?, ?)
            """, (name, mac_address, ip_address, device_type, branch_id))
            
            device_id = cursor.lastrowid
            
        return jsonify({'success': True, 'message': 'Device created successfully', 'device_id': device_id})
    except Exception as e:
        logger.error(f"Error creating device: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

# Ticket Management
@app.route('/api/tickets', methods=['GET'])
def get_tickets():
    """Get all tickets"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT t.*, b.name as branch_name 
                FROM tickets t 
                LEFT JOIN branches b ON t.branch_id = b.id 
                ORDER BY t.created_at DESC
            """)
            tickets = [dict(row) for row in cursor.fetchall()]
            
        return jsonify({'success': True, 'tickets': tickets})
    except Exception as e:
        logger.error(f"Error getting tickets: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/tickets', methods=['POST'])
def create_ticket():
    """Create a new support ticket"""
    try:
        data = request.get_json()
        title = data.get('title', '')
        description = data.get('description', '')
        category = data.get('category', 'General')
        priority = data.get('priority', 'Medium')
        reporter_name = data.get('reporter_name', '')
        reporter_email = data.get('reporter_email', '')
        branch_id = data.get('branch_id', 1)
        
        # Generate ticket number
        ticket_number = f"TK{int(datetime.now().timestamp())}"
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO tickets (ticket_number, title, description, category, priority, 
                                   reporter_name, reporter_email, branch_id) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (ticket_number, title, description, category, priority, reporter_name, reporter_email, branch_id))
            
            ticket_id = cursor.lastrowid
            
        # Send email notification if email manager is available
        if email_manager:
            try:
                email_manager.send_ticket_notification(ticket_id, 'created')
                logger.info(f"Email notification sent for ticket {ticket_id}")
            except Exception as e:
                logger.error(f"Failed to send email notification: {e}")
        
        return jsonify({'success': True, 'message': 'Ticket created successfully', 'ticket_id': ticket_id, 'ticket_number': ticket_number})
    except Exception as e:
        logger.error(f"Error creating ticket: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/tickets/<int:ticket_id>', methods=['PUT'])
def update_ticket(ticket_id):
    """Update a ticket"""
    try:
        data = request.get_json()
        status = data.get('status')
        assigned_to = data.get('assigned_to')
        notes = data.get('notes')
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE tickets 
                SET status = ?, assigned_to = ?, notes = ?, updated_at = ?
                WHERE id = ?
            """, (status, assigned_to, notes, datetime.now().isoformat(), ticket_id))
            
        # Send email notification if email manager is available
        if email_manager:
            try:
                update_details = {
                    'updated_by': assigned_to or 'System',
                    'update_message': notes
                }
                email_manager.send_ticket_notification(ticket_id, 'updated', update_details)
                logger.info(f"Email update notification sent for ticket {ticket_id}")
            except Exception as e:
                logger.error(f"Failed to send email update notification: {e}")
        
        return jsonify({'success': True, 'message': 'Ticket updated successfully'})
    except Exception as e:
        logger.error(f"Error updating ticket: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

# Branch Management
@app.route('/api/branches', methods=['GET'])
def get_branches():
    """Get all branches"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM branches ORDER BY name")
            branches = [dict(row) for row in cursor.fetchall()]
            
        return jsonify({'success': True, 'branches': branches})
    except Exception as e:
        logger.error(f"Error getting branches: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/branches', methods=['POST'])
def create_branch():
    """Create a new branch"""
    try:
        data = request.get_json()
        name = data.get('name', '')
        location = data.get('location', '')
        manager_name = data.get('manager_name', '')
        contact_email = data.get('contact_email', '')
        contact_phone = data.get('contact_phone', '')
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO branches (name, location, manager_name, contact_email, contact_phone) 
                VALUES (?, ?, ?, ?, ?)
            """, (name, location, manager_name, contact_email, contact_phone))
            
            branch_id = cursor.lastrowid
            
        return jsonify({'success': True, 'message': 'Branch created successfully', 'branch_id': branch_id})
    except Exception as e:
        logger.error(f"Error creating branch: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

# Network Logs
@app.route('/api/network/logs', methods=['GET'])
def get_network_logs():
    """Get network logs"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT nl.*, b.name as branch_name 
                FROM network_logs nl
                LEFT JOIN branches b ON nl.branch_id = b.id
                ORDER BY nl.timestamp DESC 
                LIMIT 100
            """)
            logs = [dict(row) for row in cursor.fetchall()]
        
        return jsonify({'success': True, 'logs': logs})
    except Exception as e:
        logger.error(f"Error getting network logs: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

# Email Notification Routes (only if email is available)
if EMAIL_AVAILABLE and email_manager:
    @app.route('/api/email/test', methods=['POST'])
    def test_email_configuration():
        """Test email configuration"""
        try:
            result = email_manager.test_email_configuration()
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error testing email configuration: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/email/stats', methods=['GET'])
    def get_email_stats():
        """Get email notification statistics"""
        try:
            stats = email_manager.get_email_stats()
            return jsonify({'success': True, 'stats': stats})
        except Exception as e:
            logger.error(f"Error getting email stats: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/system/alert', methods=['POST'])
    def send_system_alert():
        """Send system alert notification"""
        try:
            data = request.get_json()
            title = data.get('title', 'System Alert')
            message = data.get('message', '')
            severity = data.get('severity', 'medium')
            branch_id = data.get('branch_id', 1)
            recommended_action = data.get('recommended_action')
            
            success = email_manager.send_system_alert(
                alert_title=title,
                alert_message=message,
                severity=severity,
                branch_id=branch_id,
                recommended_action=recommended_action
            )
            
            if success:
                return jsonify({'success': True, 'message': 'Alert sent successfully'})
            else:
                return jsonify({'success': False, 'message': 'Failed to send alert'}), 500
        except Exception as e:
            logger.error(f"Error sending system alert: {e}")
            return jsonify({'success': False, 'message': str(e)}), 500

# Static file serving (for the web interface)
@app.route('/')
def index():
    """Serve the main dashboard"""
    try:
        # Try to serve the HTML file if it exists
        html_path = os.path.join(os.path.dirname(__file__), 'admin_dashboard.html')
        if os.path.exists(html_path):
            with open(html_path, 'r', encoding='utf-8') as f:
                return f.read()
        else:
            return jsonify({
                'message': 'AdminManagement API is running',
                'endpoints': {
                    'status': '/api/status',
                    'login': '/api/login',
                    'devices': '/api/devices',
                    'tickets': '/api/tickets',
                    'branches': '/api/branches',
                    'logs': '/api/network/logs'
                }
            })
    except Exception as e:
        logger.error(f"Error serving index: {e}")
        return jsonify({'error': 'Failed to serve index page'}), 500

@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files"""
    try:
        static_files = ['admin_dashboard.css', 'admin_dashboard.js', 'admin_dashboard.html']
        if filename in static_files:
            file_path = os.path.join(os.path.dirname(__file__), filename)
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Set appropriate content type
                if filename.endswith('.css'):
                    return content, 200, {'Content-Type': 'text/css'}
                elif filename.endswith('.js'):
                    return content, 200, {'Content-Type': 'application/javascript'}
                elif filename.endswith('.html'):
                    return content, 200, {'Content-Type': 'text/html'}
                
                return content
        
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        logger.error(f"Error serving static file {filename}: {e}")
        return jsonify({'error': 'Failed to serve file'}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Initialize database on startup
    init_db()
    
    # Log startup information
    logger.info("=== AdminManagement System Starting ===")
    logger.info(f"Database path: {DB_PATH}")
    logger.info(f"Email notifications: {'Enabled' if EMAIL_AVAILABLE and email_manager else 'Disabled'}")
    
    # Print helpful information
    print("=" * 60)
    print("AdminManagement System")
    print("=" * 60)
    print(f"Server starting on http://0.0.0.0:5000")
    print(f"Database: {DB_PATH}")
    print(f"Email: {'Enabled' if EMAIL_AVAILABLE and email_manager else 'Disabled'}")
    print("")
    print("Default login credentials:")
    print("Username: admin")
    print("Password: admin")
    print("")
    print("API Endpoints:")
    print("  GET  /api/status        - System status")
    print("  POST /api/login         - User login")
    print("  GET  /api/devices       - List devices")
    print("  POST /api/devices       - Create device")
    print("  GET  /api/tickets       - List tickets")
    print("  POST /api/tickets       - Create ticket")
    print("  GET  /api/branches      - List branches")
    print("  POST /api/branches      - Create branch")
    print("  GET  /api/network/logs  - Network logs")
    if EMAIL_AVAILABLE:
        print("  POST /api/email/test    - Test email config")
        print("  GET  /api/email/stats   - Email statistics")
        print("  POST /api/system/alert  - Send system alert")
    print("")
    print("Web Interface: http://localhost:5000")
    print("=" * 60)
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=False)