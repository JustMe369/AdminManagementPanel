# intelligent_guest_system.py
import random
import sqlite3
import subprocess
import os
import json
from datetime import datetime, timedelta
from db_config import get_db_connection
from error_handling import logger
import config

class IntelligentGuestSystem:
    def __init__(self):
        self.nodogsplash_enabled = getattr(config, 'NODOGSPLASH_ENABLED', True)
        self.nodogsplash_port = getattr(config, 'NODOGSPLASH_PORT', 2050)
        self.nodogsplash_interface = getattr(config, 'NODOGSPLASH_INTERFACE', 'br-lan')
        self.init_guest_tables()
    
    def init_guest_tables(self):
        """Initialize guest system database tables"""
        try:
            with get_db_connection() as conn:
                # Guest sessions table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS guest_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mac_address TEXT NOT NULL,
                        ip_address TEXT,
                        device_type TEXT,
                        session_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        session_end TIMESTAMP,
                        duration_minutes INTEGER,
                        data_used_mb REAL DEFAULT 0,
                        portal_theme TEXT,
                        branch_id INTEGER DEFAULT 1,
                        status TEXT DEFAULT 'active',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Guest preferences table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS guest_preferences (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mac_address TEXT UNIQUE NOT NULL,
                        device_name TEXT,
                        preferred_theme TEXT DEFAULT 'default',
                        visit_count INTEGER DEFAULT 0,
                        total_time_minutes INTEGER DEFAULT 0,
                        last_visit TIMESTAMP,
                        language_preference TEXT DEFAULT 'en',
                        marketing_consent BOOLEAN DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indexes
                conn.execute('CREATE INDEX IF NOT EXISTS idx_guest_sessions_mac ON guest_sessions(mac_address)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_guest_sessions_branch ON guest_sessions(branch_id)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_guest_preferences_mac ON guest_preferences(mac_address)')
                
                conn.commit()
                logger.info("Guest system database tables initialized")
        except Exception as e:
            logger.error(f"Error initializing guest tables: {e}")
    
    def personalize_guest_portal(self, mac_address, current_user=None):
        """Personalize the guest portal based on device type and previous visits"""
        try:
            device_type = self.detect_device_type(mac_address)
            guest_info = self.get_guest_info(mac_address)
            visit_count = guest_info.get('visit_count', 0)
            
            # Update visit count
            self.update_guest_preferences(mac_address, visit_count + 1)
            
            # Custom welcome messages and time limits based on visit count
            if visit_count == 0:
                welcome_message = "Welcome to our WiFi! Enjoy your first visit."
                time_limit_minutes = 60  # 1 hour
                access_level = "basic"
            elif visit_count < 5:
                welcome_message = "Welcome back! We've extended your access time."
                time_limit_minutes = 120  # 2 hours
                access_level = "extended"
            else:
                welcome_message = "Welcome back, valued guest! Enjoy premium access."
                time_limit_minutes = 240  # 4 hours
                access_level = "premium"
            
            # Special offers based on time of day
            current_hour = datetime.now().hour
            promotion = self.get_time_based_promotion(current_hour)
            
            # Generate portal configuration
            portal_config = {
                'welcome_message': welcome_message,
                'time_limit_minutes': time_limit_minutes,
                'access_level': access_level,
                'promotion': promotion,
                'device_type': device_type,
                'visit_count': visit_count + 1,
                'personalized_background': self.select_background(device_type),
                'portal_url': self.generate_portal_url(mac_address),
                'terms_url': '/guest/terms',
                'support_contact': 'support@network.local'
         }
    
    def authorize_guest(self, mac_address, duration_minutes=None):
        """Authorize guest access through NoDogSplash"""
        try:
            if not self.nodogsplash_enabled:
                return {'status': 'error', 'message': 'NoDogSplash not enabled'}
            
            # Get guest info to determine duration
            guest_info = self.get_guest_info(mac_address)
            if duration_minutes is None:
                visit_count = guest_info.get('visit_count', 0)
                if visit_count == 0:
                    duration_minutes = 60
                elif visit_count < 5:
                    duration_minutes = 120
                else:
                    duration_minutes = 240
            
            # Authorize through NoDogSplash
            cmd = f"ndsctl auth {mac_address} {duration_minutes}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Update session in database
                self.start_guest_session(mac_address, duration_minutes)
                return {
                    'status': 'success',
                    'message': f'Guest authorized for {duration_minutes} minutes',
                    'duration_minutes': duration_minutes
                }
            else:
                logger.error(f"NoDogSplash authorization failed: {result.stderr}")
                return {'status': 'error', 'message': 'Authorization failed'}
                
        except Exception as e:
            logger.error(f"Error authorizing guest: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def deauthorize_guest(self, mac_address):
        """Deauthorize guest access through NoDogSplash"""
        try:
            if not self.nodogsplash_enabled:
                return {'status': 'error', 'message': 'NoDogSplash not enabled'}
            
            cmd = f"ndsctl deauth {mac_address}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                # End session in database
                self.end_guest_session(mac_address)
                return {'status': 'success', 'message': 'Guest deauthorized'}
            else:
                logger.error(f"NoDogSplash deauthorization failed: {result.stderr}")
                return {'status': 'error', 'message': 'Deauthorization failed'}
                
        except Exception as e:
            logger.error(f"Error deauthorizing guest: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def start_guest_session(self, mac_address, duration_minutes):
        """Start a new guest session"""
        try:
            device_type = self.detect_device_type(mac_address)
            with get_db_connection() as conn:
                conn.execute('''
                    INSERT INTO guest_sessions 
                    (mac_address, device_type, duration_minutes, status, branch_id)
                    VALUES (?, ?, ?, 'active', ?)
                ''', (mac_address, device_type, duration_minutes, 1))
                conn.commit()
        except Exception as e:
            logger.error(f"Error starting guest session: {e}")
    
    def end_guest_session(self, mac_address):
        """End the current guest session"""
        try:
            with get_db_connection() as conn:
                # Update the most recent active session
                conn.execute('''
                    UPDATE guest_sessions 
                    SET session_end = ?, status = 'ended'
                    WHERE mac_address = ? AND status = 'active'
                    ORDER BY session_start DESC
                    LIMIT 1
                ''', (datetime.now().isoformat(), mac_address))
                conn.commit()
        except Exception as e:
            logger.error(f"Error ending guest session: {e}")
    
    def get_active_sessions(self, branch_id=None):
        """Get all active guest sessions"""
        try:
            with get_db_connection() as conn:
                if branch_id:
                    cursor = conn.execute(
                        'SELECT * FROM guest_sessions WHERE status = "active" AND branch_id = ? ORDER BY session_start DESC',
                        (branch_id,)
                    )
                else:
                    cursor = conn.execute(
                        'SELECT * FROM guest_sessions WHERE status = "active" ORDER BY session_start DESC'
                    )
                
                sessions = []
                for row in cursor.fetchall():
                    sessions.append({
                        'id': row[0],
                        'mac_address': row[1],
                        'ip_address': row[2],
                        'device_type': row[3],
                        'session_start': row[4],
                        'duration_minutes': row[6],
                        'data_used_mb': row[7],
                        'branch_id': row[9],
                        'status': row[10]
                    })
                
                return sessions
        except Exception as e:
            logger.error(f"Error getting active sessions: {e}")
            return []
    
    def get_guest_statistics(self, branch_id=None, days=30):
        """Get guest usage statistics"""
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            with get_db_connection() as conn:
                if branch_id:
                    # Total sessions
                    cursor = conn.execute(
                        'SELECT COUNT(*) FROM guest_sessions WHERE branch_id = ? AND session_start >= ?',
                        (branch_id, cutoff_date)
                    )
                    total_sessions = cursor.fetchone()[0]
                    
                    # Unique guests
                    cursor = conn.execute(
                        'SELECT COUNT(DISTINCT mac_address) FROM guest_sessions WHERE branch_id = ? AND session_start >= ?',
                        (branch_id, cutoff_date)
                    )
                    unique_guests = cursor.fetchone()[0]
                    
                    # Average session duration
                    cursor = conn.execute(
                        'SELECT AVG(duration_minutes) FROM guest_sessions WHERE branch_id = ? AND session_start >= ? AND duration_minutes IS NOT NULL',
                        (branch_id, cutoff_date)
                    )
                    avg_duration = cursor.fetchone()[0] or 0
                    
                    # Device type breakdown
                    cursor = conn.execute(
                        'SELECT device_type, COUNT(*) FROM guest_sessions WHERE branch_id = ? AND session_start >= ? GROUP BY device_type',
                        (branch_id, cutoff_date)
                    )
                    device_breakdown = dict(cursor.fetchall())
                else:
                    # Global statistics (all branches)
                    cursor = conn.execute(
                        'SELECT COUNT(*) FROM guest_sessions WHERE session_start >= ?',
                        (cutoff_date,)
                    )
                    total_sessions = cursor.fetchone()[0]
                    
                    cursor = conn.execute(
                        'SELECT COUNT(DISTINCT mac_address) FROM guest_sessions WHERE session_start >= ?',
                        (cutoff_date,)
                    )
                    unique_guests = cursor.fetchone()[0]
                    
                    cursor = conn.execute(
                        'SELECT AVG(duration_minutes) FROM guest_sessions WHERE session_start >= ? AND duration_minutes IS NOT NULL',
                        (cutoff_date,)
                    )
                    avg_duration = cursor.fetchone()[0] or 0
                    
                    cursor = conn.execute(
                        'SELECT device_type, COUNT(*) FROM guest_sessions WHERE session_start >= ? GROUP BY device_type',
                        (cutoff_date,)
                    )
                    device_breakdown = dict(cursor.fetchall())
                
                return {
                    'period_days': days,
                    'total_sessions': total_sessions,
                    'unique_guests': unique_guests,
                    'average_duration_minutes': round(avg_duration, 2),
                    'device_breakdown': device_breakdown,
                    'branch_id': branch_id
                }
                
        except Exception as e:
            logger.error(f"Error getting guest statistics: {e}")
            return {
                'period_days': days,
                'total_sessions': 0,
                'unique_guests': 0,
                'average_duration_minutes': 0,
                'device_breakdown': {},
                'branch_id': branch_id,
                'error': str(e)
            }
    
    def cleanup_expired_sessions(self):
        """Clean up expired guest sessions"""
        try:
            with get_db_connection() as conn:
                # Mark sessions as expired if they've exceeded their duration
                conn.execute('''
                    UPDATE guest_sessions 
                    SET status = 'expired'
                    WHERE status = 'active' 
                    AND datetime(session_start, '+' || duration_minutes || ' minutes') < datetime('now')
                ''')
                
                # Clean up old session records (older than 90 days)
                cutoff_date = (datetime.now() - timedelta(days=90)).isoformat()
                conn.execute(
                    'DELETE FROM guest_sessions WHERE session_start < ?',
                    (cutoff_date,)
                )
                
                conn.commit()
                logger.info("Guest session cleanup completed")
                
        except Exception as e:
            logger.error(f"Error cleaning up guest sessions: {e}")
    
    def get_nodogsplash_status(self):
        """Get NoDogSplash service status"""
        try:
            if not self.nodogsplash_enabled:
                return {'status': 'disabled', 'message': 'NoDogSplash is disabled in configuration'}
            
            # Check if NoDogSplash is running
            result = subprocess.run('ndsctl status', shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                return {
                    'status': 'running',
                    'message': 'NoDogSplash is active',
                    'details': result.stdout.strip()
                }
            else:
                return {
                    'status': 'stopped',
                    'message': 'NoDogSplash is not running',
                    'error': result.stderr.strip()
                }
                
        except Exception as e:
            logger.error(f"Error checking NoDogSplash status: {e}")
            return {
                'status': 'error',
                'message': f'Error checking status: {str(e)}'
            }
            
            # Log the portal access
            self.log_portal_access(mac_address, device_type, portal_config)
            
            return portal_config
            
        except Exception as e:
            logger.error(f"Error personalizing guest portal: {e}")
            return self.get_default_portal_config()
    
    def detect_device_type(self, mac_address):
        """Determine device type from MAC address prefix"""
        try:
            mac_upper = mac_address.upper().replace(':', '').replace('-', '')
            
            # Extended device detection based on OUI (Organizationally Unique Identifier)
            device_prefixes = {
                'apple': ['001CB3', '0023DF', '003EE1', '0050E4', '001451', '0017F2', '001EC2', '001F5B'],
                'samsung': ['001E7D', '001FFA', '002339', '0024E9', '002566', '0026CC', '002713', '0027F8'],
                'google': ['001A11', '00259C', '002586', '0025BC', '002722', '0027E3', '002826', '0028F8'],
                'microsoft': ['000D3A', '001DD8', '002155', '002248', '0023AE', '002454', '0025AE', '002608'],
                'huawei': ['001E10', '001F64', '002016', '0020ED', '002125', '0021D1', '002252', '0022A1'],
                'xiaomi': ['001A11', '002586', '0025BC', '002722', '0027E3', '002826', '0028F8', '002967']
            }
            
            for device_type, prefixes in device_prefixes.items():
                if any(mac_upper.startswith(prefix) for prefix in prefixes):
                    return device_type
            
            return 'generic'
        except Exception as e:
            logger.error(f"Error detecting device type: {e}")
            return 'generic'
    
    def get_guest_info(self, mac_address):
        """Get guest information from database"""
        try:
            with get_db_connection() as conn:
                cursor = conn.execute(
                    'SELECT * FROM guest_preferences WHERE mac_address = ?',
                    (mac_address,)
                )
                row = cursor.fetchone()
                
                if row:
                    return {
                        'visit_count': row[4],  # visit_count column
                        'total_time_minutes': row[5],
                        'last_visit': row[6],
                        'preferred_theme': row[3],
                        'language_preference': row[7],
                        'marketing_consent': row[8]
                    }
                else:
                    return {'visit_count': 0, 'total_time_minutes': 0}
        except Exception as e:
            logger.error(f"Error getting guest info: {e}")
            return {'visit_count': 0, 'total_time_minutes': 0}
    
    def update_guest_preferences(self, mac_address, visit_count):
        """Update guest preferences in database"""
        try:
            with get_db_connection() as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO guest_preferences 
                    (mac_address, visit_count, last_visit, updated_at)
                    VALUES (?, ?, ?, ?)
                ''', (mac_address, visit_count, datetime.now().isoformat(), datetime.now().isoformat()))
                conn.commit()
        except Exception as e:
            logger.error(f"Error updating guest preferences: {e}")
    
    def get_time_based_promotion(self, current_hour):
        """Get promotional message based on time of day"""
        if 6 <= current_hour < 10:
            return "Morning Special: Start your day with free WiFi!"
        elif 10 <= current_hour < 14:
            return "Midday Boost: Enjoy high-speed internet for work!"
        elif 14 <= current_hour < 18:
            return "Afternoon Delight: Perfect time for social media!"
        elif 18 <= current_hour < 22:
            return "Evening Entertainment: Stream your favorite content!"
        else:
            return "Night Owl Special: Quiet browsing hours!"
    
    def select_background(self, device_type):
        """Select appropriate background based on device type"""
        backgrounds = {
            'apple': 'ios_optimized_portal.html',
            'samsung': 'android_samsung_portal.html',
            'google': 'android_google_portal.html',
            'microsoft': 'windows_portal.html',
            'huawei': 'android_huawei_portal.html',
            'xiaomi': 'android_xiaomi_portal.html',
            'generic': 'universal_portal.html'
        }
        return backgrounds.get(device_type, 'universal_portal.html')
    
    def generate_portal_url(self, mac_address):
        """Generate personalized portal URL"""
        if self.nodogsplash_enabled:
            return f"http://192.168.1.1:{self.nodogsplash_port}/splash?mac={mac_address}"
        else:
            return f"/guest/portal?mac={mac_address}"
    
    def log_portal_access(self, mac_address, device_type, portal_config):
        """Log portal access to database"""
        try:
            with get_db_connection() as conn:
                conn.execute('''
                    INSERT INTO guest_sessions 
                    (mac_address, device_type, portal_theme, duration_minutes, branch_id)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    mac_address,
                    device_type,
                    portal_config.get('personalized_background'),
                    portal_config.get('time_limit_minutes'),
                    1  # Default branch_id
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Error logging portal access: {e}")
    
    def get_default_portal_config(self):
        """Get default portal configuration for error cases"""
        return {
            'welcome_message': 'Welcome to our WiFi network!',
            'time_limit_minutes': 60,
            'access_level': 'basic',
            'promotion': 'Enjoy your internet access!',
            'device_type': 'generic',
            'visit_count': 1,
            'personalized_background': 'universal_portal.html',
            'portal_url': '/guest/portal',
            'terms_url': '/guest/terms',
            'support_contact': 'support@network.local'
        }