# device_tracker.py
import sqlite3
import json
from datetime import datetime, timedelta
from error_handling import logger
from db_config import get_db_connection
from security import sanitize_input, validate_mac_address, validate_ip_address

class DeviceTracker:
    def __init__(self, config):
        self.config = config
        self.required_roles = {
            'view_devices': ['Admin', 'NetworkManager', 'Support', 'User'],
            'track_devices': ['Admin', 'NetworkManager', 'Support'],
            'manage_devices': ['Admin', 'NetworkManager']
        }
    
    def check_permission(self, user, action):
        """Check if user has permission to perform an action"""
        if not user or 'role' not in user:
            return False
            
        # Admin can do everything
        if user['role'] == 'Admin':
            return True
            
        # Check if user's role is in the required roles for this action
        if action in self.required_roles and user['role'] in self.required_roles[action]:
            return True
            
        return False
    
    def get_device_by_mac(self, mac_address, user=None, branch_id=None):
        """Get device details by MAC address"""
        if user and not self.check_permission(user, 'view_devices'):
            return {'error': 'Permission denied: Insufficient privileges to view device information'}
        
        if not validate_mac_address(mac_address):
            return {'error': 'Invalid MAC address format'}
        
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                query = "SELECT * FROM devices WHERE mac_address = ?"
                params = [mac_address]
                
                if branch_id:
                    query += " AND branch_id = ?"
                    params.append(branch_id)
                
                cursor.execute(query, params)
                device = cursor.fetchone()
                
                if not device:
                    return {'error': 'Device not found'}
                
                return dict(device)
        except Exception as e:
            logger.error(f"Error getting device: {e}")
            return {'error': 'Failed to retrieve device information'}
    
    def get_device_activity(self, device_id, user=None, days=7):
        """Get device activity history"""
        if user and not self.check_permission(user, 'track_devices'):
            return {'error': 'Permission denied: Insufficient privileges to view device activity'}
        
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # First check if device exists
                cursor.execute("SELECT id FROM devices WHERE id = ?", (device_id,))
                if not cursor.fetchone():
                    return {'error': 'Device not found'}
                
                # Get activity from the last X days
                from_date = (datetime.now() - timedelta(days=days)).isoformat()
                
                cursor.execute("""
                SELECT * FROM device_activity 
                WHERE device_id = ? AND timestamp >= ? 
                ORDER BY timestamp DESC
                """, (device_id, from_date))
                
                activities = cursor.fetchall()
                
                return {
                    'device_id': device_id,
                    'activities': [dict(activity) for activity in activities],
                    'count': len(activities)
                }
        except Exception as e:
            logger.error(f"Error getting device activity: {e}")
            return {'error': 'Failed to retrieve device activity'}
    
    def get_device_bandwidth(self, device_id, user=None, days=1, interval='hourly'):
        """Get device bandwidth usage"""
        if user and not self.check_permission(user, 'track_devices'):
            return {'error': 'Permission denied: Insufficient privileges to view bandwidth usage'}
        
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # First check if device exists
                cursor.execute("SELECT id FROM devices WHERE id = ?", (device_id,))
                if not cursor.fetchone():
                    return {'error': 'Device not found'}
                
                # Get bandwidth data from the last X days
                from_date = (datetime.now() - timedelta(days=days)).isoformat()
                
                # Different grouping based on interval
                if interval == 'hourly':
                    group_by = "strftime('%Y-%m-%d %H:00:00', timestamp)"
                elif interval == 'daily':
                    group_by = "strftime('%Y-%m-%d', timestamp)"
                else:  # Default to no grouping
                    group_by = "timestamp"
                
                cursor.execute(f"""
                SELECT {group_by} as period, 
                       SUM(download_bytes) as total_download, 
                       SUM(upload_bytes) as total_upload 
                FROM device_bandwidth 
                WHERE device_id = ? AND timestamp >= ? 
                GROUP BY period 
                ORDER BY period ASC
                """, (device_id, from_date))
                
                usage = cursor.fetchall()
                
                return {
                    'device_id': device_id,
                    'interval': interval,
                    'usage': [dict(item) for item in usage],
                    'count': len(usage)
                }
        except Exception as e:
            logger.error(f"Error getting bandwidth usage: {e}")
            return {'error': 'Failed to retrieve bandwidth usage'}
    
    def record_device_activity(self, device_id, activity_type, details=None):
        """Record device activity"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # First check if device exists
                cursor.execute("SELECT id FROM devices WHERE id = ?", (device_id,))
                if not cursor.fetchone():
                    return {'error': 'Device not found'}
                
                # Validate activity type
                valid_types = ['connect', 'disconnect', 'block', 'unblock', 'bandwidth_change']
                if activity_type not in valid_types:
                    return {'error': f'Invalid activity type. Must be one of: {", ".join(valid_types)}'}
                
                # Insert activity record
                cursor.execute("""
                INSERT INTO device_activity (device_id, activity_type, details, timestamp)
                VALUES (?, ?, ?, ?)
                """, (device_id, activity_type, json.dumps(details) if details else None, datetime.now().isoformat()))
                
                # Update device last_seen timestamp
                cursor.execute("""
                UPDATE devices SET last_seen = ?, updated_at = ? WHERE id = ?
                """, (datetime.now().isoformat(), datetime.now().isoformat(), device_id))
                
                return {
                    'success': True,
                    'message': 'Activity recorded successfully',
                    'activity_id': cursor.lastrowid
                }
        except Exception as e:
            logger.error(f"Error recording device activity: {e}")
            return {'error': 'Failed to record device activity'}
    
    def update_device_bandwidth(self, device_id, download_bytes, upload_bytes):
        """Update device bandwidth usage"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # First check if device exists
                cursor.execute("SELECT id FROM devices WHERE id = ?", (device_id,))
                if not cursor.fetchone():
                    return {'error': 'Device not found'}
                
                # Insert bandwidth record
                cursor.execute("""
                INSERT INTO device_bandwidth (device_id, download_bytes, upload_bytes, timestamp)
                VALUES (?, ?, ?, ?)
                """, (device_id, download_bytes, upload_bytes, datetime.now().isoformat()))
                
                # Update device last_seen timestamp
                cursor.execute("""
                UPDATE devices SET last_seen = ?, updated_at = ? WHERE id = ?
                """, (datetime.now().isoformat(), datetime.now().isoformat(), device_id))
                
                return {
                    'success': True,
                    'message': 'Bandwidth usage updated successfully',
                    'record_id': cursor.lastrowid
                }
        except Exception as e:
            logger.error(f"Error updating bandwidth usage: {e}")
            return {'error': 'Failed to update bandwidth usage'}
    
    def get_device_status_summary(self, branch_id=None, user=None):
        """Get summary of device statuses"""
        if user and not self.check_permission(user, 'view_devices'):
            return {'error': 'Permission denied: Insufficient privileges to view device summary'}
        
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                query = """
                SELECT status, COUNT(*) as count 
                FROM devices
                """
                params = []
                
                if branch_id:
                    query += " WHERE branch_id = ?"
                    params.append(branch_id)
                
                query += " GROUP BY status"
                
                cursor.execute(query, params)
                status_counts = cursor.fetchall()
                
                # Get recently active devices (last 24 hours)
                recent_time = (datetime.now() - timedelta(hours=24)).isoformat()
                
                query = """
                SELECT COUNT(*) as count 
                FROM devices 
                WHERE last_seen >= ?
                """
                params = [recent_time]
                
                if branch_id:
                    query += " AND branch_id = ?"
                    params.append(branch_id)
                
                cursor.execute(query, params)
                recent_active = cursor.fetchone()['count']
                
                # Format the response
                status_summary = {}
                for item in status_counts:
                    status_summary[item['status']] = item['count']
                
                return {
                    'status_summary': status_summary,
                    'recently_active': recent_active,
                    'branch_id': branch_id
                }
        except Exception as e:
            logger.error(f"Error getting device status summary: {e}")
            return {'error': 'Failed to retrieve device status summary'}