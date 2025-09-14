# main_api_backend.py
import os
import json
import sqlite3
import subprocess
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g
from functools import wraps

# Import custom modules
from auth import hash_password, check_password, generate_session_token, require_auth, UserManager
from security import sanitize_input, validate_mac_address, validate_ip_address, require_secure_headers
from db_config import get_db_connection
from error_handling import register_error_handlers, logger
from validation import validate_json, USER_SCHEMA
from caching import cached_response
from firewall_controller import FirewallController
from branch_manager import BranchManager
from ai_network_optimizer import AINetworkOptimizer
from automated_incident_response import AutomatedIncidentResponse
from cross_branch_analytics import CrossBranchAnalytics
from intelligent_guest_system import IntelligentGuestSystem
from predictive_registration import PredictiveDeviceManager

# Initialize Flask app
app = Flask(__name__)
app.config.from_object('config')

# Register error handlers
register_error_handlers(app)

# Initialize components
firewall_controller = FirewallController(app.config)
branch_manager = BranchManager(app.config)
network_optimizer = AINetworkOptimizer()
incident_response = AutomatedIncidentResponse()
branch_analytics = CrossBranchAnalytics()
guest_system = IntelligentGuestSystem()
device_manager = PredictiveDeviceManager()
user_manager = UserManager(app.config)

# Import and initialize device tracker
from device_tracker import DeviceTracker
device_tracker = DeviceTracker(app.config)

# Import and initialize cloud sync manager
from cloud_sync import CloudSyncManager
cloud_sync_manager = CloudSyncManager(app.config)

# Import and initialize cloud sync scheduler
from cloud_sync_scheduler import CloudSyncScheduler
cloud_sync_scheduler = CloudSyncScheduler(app.config)

# Database path
DB_PATH = os.path.join(os.path.dirname(__file__), 'admin_management.db')

# Initialize database if not exists
def init_db():
    with get_db_connection() as conn:
        with open('db.sql') as f:
            conn.executescript(f.read())
        logger.info("Database initialized successfully")

# Middleware to check if database exists
@app.before_request
def before_request():
    if not os.path.exists(DB_PATH):
        init_db()

# API Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok', 'timestamp': datetime.now().isoformat()})

# User Management
@app.route('/api/users', methods=['POST'])
@validate_json(USER_SCHEMA)
@require_auth(roles=['Admin'])
def create_user():
    data = request.get_json()
    username = sanitize_input(data['username'])
    password = data['password']
    user_type = data.get('user_type', 'User')
    branch_id = data.get('branch_id', 1)
    
    result, status_code = user_manager.create_user(username, password, user_type, branch_id)
    return jsonify(result), status_code

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = sanitize_input(data.get('username', ''))
    password = data.get('password', '')
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT id, username, password_hash, branch_id, user_type, status, lockout_until 
        FROM users 
        WHERE username = ?
        """, (username,))
        
        user = cursor.fetchone()
        
        # Check if user exists
        if not user:
            return user_manager.handle_failed_login(username)
        
        # Check if account is locked
        if user['status'] == 'Locked':
            # Check if lockout period has expired
            if user['lockout_until']:
                lockout_until = datetime.fromisoformat(user['lockout_until'])
                if lockout_until > datetime.now():
                    remaining_minutes = int((lockout_until - datetime.now()).total_seconds() / 60)
                    return jsonify({'error': f'Account is locked. Try again in {remaining_minutes} minutes'}), 403
                else:
                    # Unlock account if lockout period has expired
                    cursor.execute("""
                    UPDATE users 
                    SET status = 'Active', login_attempts = 0, lockout_until = NULL 
                    WHERE id = ?
                    """, (user['id'],))
        
        # Check if account is blocked
        if user['status'] == 'Blocked':
            return jsonify({'error': 'Account is blocked. Contact administrator'}), 403
        
        # Verify password
        if not check_password(password, user['password_hash']):
            return user_manager.handle_failed_login(username)
        
        # Generate session token
        token = generate_session_token()
        expires = datetime.now() + timedelta(hours=24)
        
        # Update user session
        cursor.execute("""
        UPDATE users 
        SET session_token = ?, token_expires = ?, last_login = ?, login_attempts = 0 
        WHERE id = ?
        """, (token, expires.isoformat(), datetime.now().isoformat(), user['id']))
        
        return jsonify({
            'token': token,
            'expires': expires.isoformat(),
            'user_id': user['id'],
            'username': user['username'],
            'branch_id': user['branch_id'],
            'user_type': user['user_type']
        })

@app.route('/api/users', methods=['GET'])
@require_auth(roles=['Admin'])
def get_users():
    branch_id = request.args.get('branch_id', type=int)
    
    query = "SELECT id, username, user_type, branch_id, status, created_at, last_login FROM users"
    params = []
    
    if branch_id:
        query += " WHERE branch_id = ?"
        params.append(branch_id)
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        users = cursor.fetchall()
        
        return jsonify({
            'users': [dict(user) for user in users],
            'count': len(users)
        })

@app.route('/api/users/<int:user_id>', methods=['GET'])
@require_auth(roles=['Admin'])
def get_user(user_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT id, username, user_type, branch_id, status, created_at, last_login 
        FROM users WHERE id = ?
        """, (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify(dict(user))

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@require_auth(roles=['Admin'])
def update_user_route(user_id):
    data = request.get_json()
    result, status_code = user_manager.update_user(user_id, data)
    return jsonify(result), status_code

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@require_auth(roles=['Admin'])
def delete_user_route(user_id):
    result, status_code = user_manager.delete_user(user_id)
    return jsonify(result), status_code

@app.route('/api/users/change-password', methods=['POST'])
@require_auth()
def change_password():
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({'error': 'Current password and new password are required'}), 400
    
    user_id = request.current_user['id']
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        if not user or not check_password(current_password, user['password_hash']):
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Validate new password
        password_validation = user_manager._validate_password(new_password)
        if 'error' in password_validation:
            return jsonify(password_validation), 400
        
        # Update password
        hashed_password = hash_password(new_password)
        cursor.execute("""
        UPDATE users 
        SET password_hash = ?, updated_at = ? 
        WHERE id = ?
        """, (hashed_password, datetime.now().isoformat(), user_id))
        
        return jsonify({'message': 'Password changed successfully'}), 200

# Branch Management
@app.route('/api/branches', methods=['GET'])
@require_auth(roles=['Admin'])
def get_branches():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM branches ORDER BY name")
        branches = cursor.fetchall()
        
        return jsonify({
            'branches': [dict(branch) for branch in branches],
            'count': len(branches)
        })

@app.route('/api/branches/<int:branch_id>', methods=['GET'])
@require_auth()
def get_branch(branch_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM branches WHERE id = ?", (branch_id,))
        branch = cursor.fetchone()
        
        if not branch:
            return jsonify({'error': 'Branch not found'}), 404
        
        return jsonify(dict(branch))

# Device Management
@app.route('/api/devices', methods=['GET'])
@require_auth(roles=['Admin', 'NetworkManager', 'Support', 'User'])
def get_devices():
    branch_id = request.args.get('branch_id', type=int)
    
    query = "SELECT * FROM devices"
    params = []
    
    if branch_id:
        query += " WHERE branch_id = ?"
        params.append(branch_id)
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        devices = cursor.fetchall()
        
        return jsonify({
            'devices': [dict(device) for device in devices],
            'count': len(devices)
        })

@app.route('/api/devices', methods=['POST'])
@require_auth()
def add_device():
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['name', 'ip_address', 'mac_address', 'branch_id']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    # Validate IP and MAC
    if not validate_ip_address(data['ip_address']):
        return jsonify({'error': 'Invalid IP address format'}), 400
    
    if not validate_mac_address(data['mac_address']):
        return jsonify({'error': 'Invalid MAC address format'}), 400
    
    current_time = datetime.now().isoformat()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO devices (name, ip_address, mac_address, device_type, anydesk_id, serial_number, branch_id, status, first_seen, last_seen, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            sanitize_input(data['name']),
            sanitize_input(data['ip_address']),
            sanitize_input(data['mac_address']),
            sanitize_input(data.get('device_type', 'unknown')),
            sanitize_input(data.get('anydesk_id', '')),
            sanitize_input(data.get('serial_number', '')),
            data['branch_id'],
            'Active',
            current_time,
            current_time,
            current_time,
            current_time
        ))
        
        device_id = cursor.lastrowid
        
        # Record initial device activity
        device_tracker.record_device_activity(
            device_id,
            'connect',
            {'initial_registration': True, 'registered_by': request.current_user['username']}
        )
        
        return jsonify({
            'id': device_id,
            'message': 'Device added successfully'
        }), 201

# Firewall Control
@app.route('/api/firewall/rules', methods=['GET'])
@require_auth(roles=['Admin'])
def get_firewall_rules():
    branch_id = request.args.get('branch_id', None)
    if branch_id:
        branch_id = int(branch_id)
        result = firewall_controller.get_firewall_rules(request.current_user, branch_id)
    else:
        result = firewall_controller.get_firewall_rules(request.current_user)
    
    return jsonify(result)

@app.route('/api/firewall/rules/<int:rule_id>', methods=['DELETE'])
@require_auth(roles=['Admin', 'NetworkManager'])
def delete_firewall_rule(rule_id):
    branch_id = request.args.get('branch_id', None)
    
    if branch_id:
        branch_id = int(branch_id)
        result = firewall_controller.delete_firewall_rule(rule_id, request.current_user, branch_id)
    else:
        result = firewall_controller.delete_firewall_rule(rule_id, request.current_user)
    
    return jsonify(result)

@app.route('/api/firewall/rules', methods=['POST'])
@require_auth(roles=['Admin', 'NetworkManager'])
def add_firewall_rule():
    data = request.get_json()
    branch_id = data.pop('branch_id', None)
    
    # Validate required fields
    required_fields = ['name', 'src', 'dest', 'proto', 'target']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    try:
        if branch_id:
            branch_id = int(branch_id)
            result = firewall_controller.add_firewall_rule(data, request.current_user, branch_id)
        else:
            result = firewall_controller.add_firewall_rule(data, request.current_user)
        
        return jsonify(result), 201
    except Exception as e:
        logger.error(f"Firewall rule error: {e}")
        return jsonify({'error': 'Failed to add firewall rule'}), 500

@app.route('/api/firewall/rules/<int:rule_id>', methods=['PUT'])
@require_auth(roles=['Admin', 'NetworkManager'])
def update_firewall_rule(rule_id):
    data = request.get_json()
    branch_id = data.pop('branch_id', None)
    
    try:
        if branch_id:
            branch_id = int(branch_id)
            result = firewall_controller.update_firewall_rule(rule_id, data, request.current_user, branch_manager, branch_id)
        else:
            result = firewall_controller.update_firewall_rule(rule_id, data, request.current_user)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Update firewall rule error: {e}")
        return jsonify({'error': 'Failed to update firewall rule'}), 500

# Ticket Management
@app.route('/api/tickets', methods=['POST'])
@require_auth()
def create_ticket():
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['title', 'description', 'branch_id', 'reporter_name', 'category']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO tickets (title, description, branch_id, reporter_name, category, priority, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            sanitize_input(data['title']),
            sanitize_input(data['description']),
            data['branch_id'],
            sanitize_input(data['reporter_name']),
            sanitize_input(data['category']),
            sanitize_input(data.get('priority', 'Medium')),
            'Open',
            datetime.now().isoformat()
        ))
        
        ticket_id = cursor.lastrowid
        ticket_number = f"TKT-{ticket_id:04d}"
        
        # Update ticket number
        cursor.execute("UPDATE tickets SET ticket_number = ? WHERE id = ?", 
                      (ticket_number, ticket_id))
        
        return jsonify({
            'id': ticket_id,
            'ticket_number': ticket_number,
            'message': 'Ticket created successfully'
        }), 201

@app.route('/api/tickets', methods=['GET'])
@require_auth()
def get_tickets():
    branch_id = request.args.get('branch_id', type=int)
    status = request.args.get('status')
    
    query = "SELECT * FROM tickets"
    params = []
    conditions = []
    
    if branch_id:
        conditions.append("branch_id = ?")
        params.append(branch_id)
    
    if status:
        conditions.append("status = ?")
        params.append(status)
    
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    
    query += " ORDER BY created_at DESC"
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        tickets = cursor.fetchall()
        
        return jsonify({
            'tickets': [dict(ticket) for ticket in tickets],
            'count': len(tickets)
        })

# Analytics
@app.route('/api/analytics/branch-performance', methods=['GET'])
@require_auth(roles=['Admin'])
@cached_response(ttl=3600)  # Cache for 1 hour
def branch_performance():
    return jsonify(branch_analytics.compare_branch_performance())

@app.route('/api/analytics/network-optimization/<int:branch_id>', methods=['GET'])
@require_auth()
def optimize_network(branch_id):
    return jsonify(network_optimizer.analyze_network_patterns(branch_id))

@app.route('/api/devices/<string:mac_address>/block', methods=['POST'])
@require_auth(roles=['Admin', 'NetworkManager', 'Support'])
def block_device(mac_address):
    data = request.get_json() or {}
    duration = data.get('duration', 0)
    branch_id = data.get('branch_id', None)
    
    if branch_id:
        branch_id = int(branch_id)
        result = firewall_controller.block_device(mac_address, duration, request.current_user, branch_manager, branch_id)
    else:
        result = firewall_controller.block_device(mac_address, duration, request.current_user)
    
    # Record device activity if successful
    if 'success' in result and result['success'] and 'device_id' in result:
        device_tracker.record_device_activity(
            result['device_id'], 
            'block', 
            {'duration': duration, 'reason': data.get('reason', 'Manual block')}
        )
    
    return jsonify(result)

@app.route('/api/devices/<string:mac_address>/unblock', methods=['POST'])
@require_auth(roles=['Admin', 'NetworkManager', 'Support'])
def unblock_device(mac_address):
    data = request.get_json() or {}
    branch_id = data.get('branch_id', None)
    
    if branch_id:
        branch_id = int(branch_id)
        result = firewall_controller.unblock_device(mac_address, request.current_user, branch_manager, branch_id)
    else:
        result = firewall_controller.unblock_device(mac_address, request.current_user)
    
    # Record device activity if successful
    if 'success' in result and result['success'] and 'device_id' in result:
        device_tracker.record_device_activity(
            result['device_id'], 
            'unblock', 
            {'reason': data.get('reason', 'Manual unblock')}
        )
    
    return jsonify(result)

@app.route('/api/devices/<string:mac_address>/bandwidth', methods=['POST'])
@require_auth(roles=['Admin', 'NetworkManager'])
@validate_json(['download_limit', 'upload_limit'])
def limit_bandwidth(mac_address):
    data = request.get_json()
    download_limit = data['download_limit']
    upload_limit = data['upload_limit']
    branch_id = data.get('branch_id', None)
    
    if branch_id:
        branch_id = int(branch_id)
        result = firewall_controller.apply_bandwidth_limit(mac_address, download_limit, upload_limit, request.current_user, branch_manager, branch_id)
    else:
        result = firewall_controller.apply_bandwidth_limit(mac_address, download_limit, upload_limit, request.current_user)
    
    # Record device activity if successful
    if 'success' in result and result['success'] and 'device_id' in result:
        device_tracker.record_device_activity(
            result['device_id'], 
            'bandwidth_change', 
            {'download_limit': download_limit, 'upload_limit': upload_limit}
        )
    
    return jsonify(result)

# Guest System
@app.route('/api/guest/portal', methods=['GET'])
@cached_response(ttl=300)  # Cache for 5 minutes
@require_auth(roles=['Admin', 'NetworkManager'])
def guest_portal():
    mac_address = request.args.get('mac')
    if not mac_address or not validate_mac_address(mac_address):
        return jsonify({'error': 'Valid MAC address required'}), 400
    
    return jsonify(guest_system.personalize_guest_portal(mac_address, g.user))

@app.route('/api/guest-network', methods=['POST'])
@require_auth(roles=['Admin', 'NetworkManager'])
def setup_guest_network():
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['name', 'password']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    branch_id = data.pop('branch_id', None)
    
    if branch_id:
        branch_id = int(branch_id)
        result = firewall_controller.setup_guest_network(data['name'], data['password'], request.current_user, branch_id)
    else:
        result = firewall_controller.setup_guest_network(data['name'], data['password'], request.current_user)
    
    return jsonify(result)

# Device Tracking Endpoints
@app.route('/api/devices/<string:mac_address>/info', methods=['GET'])
@require_auth()
def get_device_info(mac_address):
    branch_id = request.args.get('branch_id', type=int)
    result = device_tracker.get_device_by_mac(mac_address, request.current_user, branch_id)
    
    if 'error' in result:
        return jsonify({'error': result['error']}), 404 if result['error'] == 'Device not found' else 400
    
    return jsonify(result)

@app.route('/api/devices/<int:device_id>/activity', methods=['GET'])
@require_auth(roles=['Admin', 'NetworkManager', 'Support'])
def get_device_activity(device_id):
    days = request.args.get('days', default=7, type=int)
    result = device_tracker.get_device_activity(device_id, request.current_user, days)
    
    if 'error' in result:
        return jsonify({'error': result['error']}), 404 if result['error'] == 'Device not found' else 400
    
    return jsonify(result)

@app.route('/api/devices/<int:device_id>/bandwidth', methods=['GET'])
@require_auth(roles=['Admin', 'NetworkManager', 'Support'])
def get_device_bandwidth(device_id):
    days = request.args.get('days', default=1, type=int)
    interval = request.args.get('interval', default='hourly')
    
    if interval not in ['hourly', 'daily', 'raw']:
        return jsonify({'error': 'Invalid interval. Must be one of: hourly, daily, raw'}), 400
    
    result = device_tracker.get_device_bandwidth(device_id, request.current_user, days, interval)
    
    if 'error' in result:
        return jsonify({'error': result['error']}), 404 if result['error'] == 'Device not found' else 400
    
    return jsonify(result)

@app.route('/api/devices/<int:device_id>/activity', methods=['POST'])
@require_auth(roles=['Admin', 'NetworkManager', 'Support'])
def record_device_activity(device_id):
    data = request.get_json()
    
    if not data or 'activity_type' not in data:
        return jsonify({'error': 'Missing required field: activity_type'}), 400
    
    activity_type = data['activity_type']
    details = data.get('details')
    
    result = device_tracker.record_device_activity(device_id, activity_type, details)
    
    if 'error' in result:
        return jsonify({'error': result['error']}), 404 if result['error'] == 'Device not found' else 400
    
    return jsonify(result), 201

@app.route('/api/devices/<int:device_id>/bandwidth', methods=['POST'])
@require_auth(roles=['Admin', 'NetworkManager'])
def update_device_bandwidth(device_id):
    data = request.get_json()
    
    if not data or 'download_bytes' not in data or 'upload_bytes' not in data:
        return jsonify({'error': 'Missing required fields: download_bytes and upload_bytes'}), 400
    
    download_bytes = data['download_bytes']
    upload_bytes = data['upload_bytes']
    
    result = device_tracker.update_device_bandwidth(device_id, download_bytes, upload_bytes)
    
    if 'error' in result:
        return jsonify({'error': result['error']}), 404 if result['error'] == 'Device not found' else 400
    
    return jsonify(result), 201

@app.route('/api/devices/summary', methods=['GET'])
@require_auth()
def get_device_summary():
    branch_id = request.args.get('branch_id', type=int)
    result = device_tracker.get_device_status_summary(branch_id, request.current_user)
    
    if 'error' in result:
        return jsonify({'error': result['error']}), 400
    
    return jsonify(result)

# Cloud Sync
@app.route('/api/sync/push', methods=['POST'])
@require_auth(roles=['Admin'])
def push_to_cloud():
    """Push local data to cloud"""
    try:
        current_user = request.current_user
        result = cloud_sync_manager.push_to_cloud(current_user)
        
        if 'error' in result:
            return jsonify({'error': result['error']}), 400
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in push_to_cloud endpoint: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/sync/pull', methods=['POST'])
@require_auth(roles=['Admin'])
def pull_from_cloud():
    """Pull data from cloud to local database"""
    try:
        current_user = request.current_user
        result = cloud_sync_manager.pull_from_cloud(current_user)
        
        if 'error' in result:
            return jsonify({'error': result['error']}), 400
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in pull_from_cloud endpoint: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/sync/status', methods=['GET'])
@require_auth(roles=['Admin', 'NetworkManager'])
def get_sync_status():
    """Get synchronization status"""
    try:
        current_user = request.current_user
        result = cloud_sync_manager.get_sync_status(current_user)
        
        if 'error' in result:
            return jsonify({'error': result['error']}), 400
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in get_sync_status endpoint: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Cloud Sync Scheduler Management
@app.route('/api/sync/scheduler/start', methods=['POST'])
@require_auth(roles=['Admin'])
def start_sync_scheduler():
    """Start the cloud sync scheduler"""
    try:
        result = cloud_sync_scheduler.start()
        if result:
            return jsonify({
                'status': 'success',
                'message': 'Cloud sync scheduler started successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to start cloud sync scheduler'
            }), 500
    except Exception as e:
        logger.error(f"Error starting sync scheduler: {e}")
        return jsonify({'error': 'Failed to start sync scheduler'}), 500

@app.route('/api/sync/scheduler/stop', methods=['POST'])
@require_auth(roles=['Admin'])
def stop_sync_scheduler():
    """Stop the cloud sync scheduler"""
    try:
        result = cloud_sync_scheduler.stop()
        if result:
            return jsonify({
                'status': 'success',
                'message': 'Cloud sync scheduler stopped successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to stop cloud sync scheduler'
            }), 500
    except Exception as e:
        logger.error(f"Error stopping sync scheduler: {e}")
        return jsonify({'error': 'Failed to stop sync scheduler'}), 500

@app.route('/api/sync/scheduler/status', methods=['GET'])
@require_auth(roles=['Admin', 'NetworkManager'])
def get_scheduler_status():
    """Get the status of the cloud sync scheduler"""
    try:
        status = cloud_sync_scheduler.get_status()
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting scheduler status: {e}")
        return jsonify({'error': 'Failed to get scheduler status'}), 500

@app.route('/api/sync/scheduler/force-sync', methods=['POST'])
@require_auth(roles=['Admin'])
def force_sync():
    """Force an immediate synchronization"""
    try:
        data = request.get_json() or {}
        sync_type = data.get('type', 'both')  # 'push', 'pull', or 'both'
        
        if sync_type not in ['push', 'pull', 'both']:
            return jsonify({
                'error': 'Invalid sync type. Must be push, pull, or both'
            }), 400
        
        result = cloud_sync_scheduler.force_sync(sync_type)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in force sync: {e}")
        return jsonify({'error': 'Failed to force sync'}), 500

# Device monitoring service endpoints
@app.route('/api/device-monitoring/start', methods=['POST'])
@require_auth(roles=['Admin', 'NetworkManager'])
def start_device_monitoring():
    """Start the device monitoring services"""
    try:
        # Get the current user for logging
        current_user = request.current_user
        
        # Start the monitoring services in the background
        import subprocess
        import sys
        import os
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        monitor_script = os.path.join(script_dir, 'run_device_monitors.py')
        
        # Start the process detached from this process
        if os.name == 'nt':  # Windows
            subprocess.Popen([sys.executable, monitor_script], 
                            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        else:  # Unix/Linux
            subprocess.Popen([sys.executable, monitor_script], 
                            start_new_session=True)
        
        return jsonify({
            'status': 'success',
            'message': 'Device monitoring services started',
            'started_by': current_user['username']
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to start device monitoring: {str(e)}'
        }), 500

@app.route('/api/device-monitoring/stop', methods=['POST'])
@require_auth(roles=['Admin', 'NetworkManager'])
def stop_device_monitoring():
    """Stop the device monitoring services"""
    try:
        # Get the current user for logging
        current_user = request.current_user
        
        # Find and stop the monitoring processes
        import subprocess
        import os
        
        # This is a simplified approach - in production you would want to use a more robust
        # process management system or store the PIDs in a file
        if os.name == 'nt':  # Windows
            # Find Python processes running the monitor scripts
            subprocess.run(['taskkill', '/F', '/FI', 'IMAGENAME eq python.exe', '/FI', 
                          'WINDOWTITLE eq *device_*monitor*'])
        else:  # Unix/Linux
            # Find and kill the monitor processes
            subprocess.run(['pkill', '-f', 'device_.*_monitor\.py'])
            subprocess.run(['pkill', '-f', 'run_device_monitors\.py'])
        
        return jsonify({
            'status': 'success',
            'message': 'Device monitoring services stopped',
            'stopped_by': current_user['username']
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to stop device monitoring: {str(e)}'
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)