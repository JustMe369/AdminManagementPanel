# cloud_sync.py
import json
import requests
import sqlite3
from datetime import datetime, timedelta
import hashlib
import os
import sys

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from db_config import get_db_connection
from error_handling import logger
from security import encrypt_data, decrypt_data

class CloudSyncManager:
    def __init__(self, config):
        self.config = config
        self.cloud_api_url = config.get('CLOUD_API_URL', 'https://api.example.com')
        self.api_key = config.get('CLOUD_API_KEY', '')
        self.branch_id = config.get('BRANCH_ID', 1)
        self.encryption_key = config.get('ENCRYPTION_KEY', 'default_key')
        self.sync_interval = config.get('SYNC_INTERVAL', 3600)  # Default 1 hour
        
    def check_permission(self, user, required_roles):
        """Check if user has required permissions"""
        if not user:
            return False
        return user.get('user_type') in required_roles
    
    def get_last_sync_timestamp(self, sync_type):
        """Get the timestamp of the last successful sync"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT last_sync FROM sync_status 
                WHERE sync_type = ? AND branch_id = ?
                """, (sync_type, self.branch_id))
                
                result = cursor.fetchone()
                if result:
                    return result['last_sync']
                return None
        except Exception as e:
            logger.error(f"Error getting last sync timestamp: {e}")
            return None
    
    def update_sync_timestamp(self, sync_type, timestamp=None):
        """Update the last sync timestamp"""
        if timestamp is None:
            timestamp = datetime.now().isoformat()
        
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                INSERT OR REPLACE INTO sync_status 
                (sync_type, branch_id, last_sync, updated_at)
                VALUES (?, ?, ?, ?)
                """, (sync_type, self.branch_id, timestamp, timestamp))
                
                return True
        except Exception as e:
            logger.error(f"Error updating sync timestamp: {e}")
            return False
    
    def get_data_to_sync(self, table_name, last_sync=None):
        """Get data that needs to be synchronized"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                if last_sync:
                    # Get only data modified since last sync
                    cursor.execute(f"""
                    SELECT * FROM {table_name} 
                    WHERE updated_at > ? AND branch_id = ?
                    """, (last_sync, self.branch_id))
                else:
                    # Get all data for initial sync
                    cursor.execute(f"""
                    SELECT * FROM {table_name} 
                    WHERE branch_id = ?
                    """, (self.branch_id,))
                
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Error getting data to sync from {table_name}: {e}")
            return []
    
    def prepare_sync_data(self, data, table_name):
        """Prepare data for cloud synchronization"""
        try:
            sync_data = {
                'branch_id': self.branch_id,
                'table_name': table_name,
                'timestamp': datetime.now().isoformat(),
                'data': []
            }
            
            for row in data:
                # Convert row to dictionary if it's not already
                if hasattr(row, 'keys'):
                    row_dict = dict(row)
                else:
                    row_dict = row
                
                # Encrypt sensitive data
                if table_name == 'users':
                    if 'password_hash' in row_dict:
                        row_dict['password_hash'] = encrypt_data(row_dict['password_hash'], self.encryption_key)
                
                sync_data['data'].append(row_dict)
            
            # Create data hash for integrity verification
            data_string = json.dumps(sync_data['data'], sort_keys=True)
            sync_data['data_hash'] = hashlib.sha256(data_string.encode()).hexdigest()
            
            return sync_data
        except Exception as e:
            logger.error(f"Error preparing sync data: {e}")
            return None
    
    def push_to_cloud(self, user):
        """Push local data to cloud"""
        if not self.check_permission(user, ['Admin']):
            return {'error': 'Insufficient permissions'}
        
        try:
            # Tables to synchronize
            tables_to_sync = ['users', 'devices', 'device_activity', 'device_bandwidth_usage', 'tickets']
            sync_results = []
            
            for table in tables_to_sync:
                try:
                    # Get last sync timestamp for this table
                    last_sync = self.get_last_sync_timestamp(f'push_{table}')
                    
                    # Get data to sync
                    data = self.get_data_to_sync(table, last_sync)
                    
                    if not data:
                        sync_results.append({
                            'table': table,
                            'status': 'no_changes',
                            'records': 0
                        })
                        continue
                    
                    # Prepare data for cloud
                    sync_data = self.prepare_sync_data(data, table)
                    
                    if not sync_data:
                        sync_results.append({
                            'table': table,
                            'status': 'error',
                            'message': 'Failed to prepare data'
                        })
                        continue
                    
                    # Send to cloud (mock implementation)
                    # In a real implementation, you would make an HTTP request to your cloud API
                    cloud_response = self.send_to_cloud_api(sync_data)
                    
                    if cloud_response.get('success'):
                        # Update sync timestamp
                        self.update_sync_timestamp(f'push_{table}')
                        
                        sync_results.append({
                            'table': table,
                            'status': 'success',
                            'records': len(data),
                            'cloud_id': cloud_response.get('sync_id')
                        })
                    else:
                        sync_results.append({
                            'table': table,
                            'status': 'error',
                            'message': cloud_response.get('error', 'Unknown error')
                        })
                
                except Exception as e:
                    logger.error(f"Error syncing table {table}: {e}")
                    sync_results.append({
                        'table': table,
                        'status': 'error',
                        'message': str(e)
                    })
            
            return {
                'status': 'completed',
                'branch_id': self.branch_id,
                'timestamp': datetime.now().isoformat(),
                'results': sync_results,
                'pushed_by': user['username']
            }
        
        except Exception as e:
            logger.error(f"Error in push_to_cloud: {e}")
            return {'error': f'Push failed: {str(e)}'}
    
    def send_to_cloud_api(self, sync_data):
        """Send data to cloud API (mock implementation)"""
        try:
            # This is a mock implementation
            # In a real scenario, you would make an HTTP request to your cloud service
            
            # Simulate API call
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            # Mock successful response
            return {
                'success': True,
                'sync_id': f'sync_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
                'message': 'Data synchronized successfully'
            }
            
            # Uncomment below for real API call
            # response = requests.post(
            #     f'{self.cloud_api_url}/sync/receive',
            #     json=sync_data,
            #     headers=headers,
            #     timeout=30
            # )
            # 
            # if response.status_code == 200:
            #     return response.json()
            # else:
            #     return {
            #         'success': False,
            #         'error': f'HTTP {response.status_code}: {response.text}'
            #     }
        
        except Exception as e:
            logger.error(f"Error sending to cloud API: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def pull_from_cloud(self, user):
        """Pull data from cloud to local database"""
        if not self.check_permission(user, ['Admin']):
            return {'error': 'Insufficient permissions'}
        
        try:
            # Get data from cloud (mock implementation)
            cloud_data = self.fetch_from_cloud_api()
            
            if not cloud_data.get('success'):
                return {'error': cloud_data.get('error', 'Failed to fetch from cloud')}
            
            sync_results = []
            
            for table_data in cloud_data.get('data', []):
                try:
                    table_name = table_data['table_name']
                    records = table_data['data']
                    
                    # Verify data integrity
                    if not self.verify_data_integrity(table_data):
                        sync_results.append({
                            'table': table_name,
                            'status': 'error',
                            'message': 'Data integrity check failed'
                        })
                        continue
                    
                    # Apply data to local database
                    applied_count = self.apply_cloud_data(table_name, records)
                    
                    # Update sync timestamp
                    self.update_sync_timestamp(f'pull_{table_name}')
                    
                    sync_results.append({
                        'table': table_name,
                        'status': 'success',
                        'records': applied_count
                    })
                
                except Exception as e:
                    logger.error(f"Error processing cloud data for table {table_data.get('table_name', 'unknown')}: {e}")
                    sync_results.append({
                        'table': table_data.get('table_name', 'unknown'),
                        'status': 'error',
                        'message': str(e)
                    })
            
            return {
                'status': 'completed',
                'branch_id': self.branch_id,
                'timestamp': datetime.now().isoformat(),
                'results': sync_results,
                'pulled_by': user['username']
            }
        
        except Exception as e:
            logger.error(f"Error in pull_from_cloud: {e}")
            return {'error': f'Pull failed: {str(e)}'}
    
    def fetch_from_cloud_api(self):
        """Fetch data from cloud API (mock implementation)"""
        try:
            # This is a mock implementation
            # In a real scenario, you would make an HTTP request to your cloud service
            
            # Mock successful response with sample data
            return {
                'success': True,
                'data': [
                    {
                        'table_name': 'devices',
                        'data': [],  # Would contain actual device data from cloud
                        'data_hash': 'mock_hash',
                        'timestamp': datetime.now().isoformat()
                    }
                ],
                'message': 'Data fetched successfully'
            }
            
            # Uncomment below for real API call
            # headers = {
            #     'Authorization': f'Bearer {self.api_key}',
            #     'Content-Type': 'application/json'
            # }
            # 
            # response = requests.get(
            #     f'{self.cloud_api_url}/sync/data/{self.branch_id}',
            #     headers=headers,
            #     timeout=30
            # )
            # 
            # if response.status_code == 200:
            #     return response.json()
            # else:
            #     return {
            #         'success': False,
            #         'error': f'HTTP {response.status_code}: {response.text}'
            #     }
        
        except Exception as e:
            logger.error(f"Error fetching from cloud API: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def verify_data_integrity(self, table_data):
        """Verify the integrity of data received from cloud"""
        try:
            data = table_data.get('data', [])
            received_hash = table_data.get('data_hash', '')
            
            # Calculate hash of received data
            data_string = json.dumps(data, sort_keys=True)
            calculated_hash = hashlib.sha256(data_string.encode()).hexdigest()
            
            return calculated_hash == received_hash
        except Exception as e:
            logger.error(f"Error verifying data integrity: {e}")
            return False
    
    def apply_cloud_data(self, table_name, records):
        """Apply cloud data to local database"""
        try:
            applied_count = 0
            
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                for record in records:
                    try:
                        # Decrypt sensitive data if needed
                        if table_name == 'users' and 'password_hash' in record:
                            record['password_hash'] = decrypt_data(record['password_hash'], self.encryption_key)
                        
                        # Check if record already exists
                        if table_name == 'users':
                            cursor.execute("SELECT id FROM users WHERE username = ?", (record['username'],))
                        elif table_name == 'devices':
                            cursor.execute("SELECT id FROM devices WHERE mac_address = ? AND branch_id = ?", 
                                         (record['mac_address'], record['branch_id']))
                        else:
                            # For other tables, check by ID if it exists
                            if 'id' in record:
                                cursor.execute(f"SELECT id FROM {table_name} WHERE id = ?", (record['id'],))
                            else:
                                continue
                        
                        existing = cursor.fetchone()
                        
                        if existing:
                            # Update existing record
                            # This is a simplified update - in production you'd want more sophisticated conflict resolution
                            continue
                        else:
                            # Insert new record
                            # This is a simplified insert - you'd need proper column mapping
                            applied_count += 1
                    
                    except Exception as e:
                        logger.error(f"Error applying record to {table_name}: {e}")
                        continue
            
            return applied_count
        
        except Exception as e:
            logger.error(f"Error applying cloud data to {table_name}: {e}")
            return 0
    
    def get_sync_status(self, user):
        """Get synchronization status"""
        if not self.check_permission(user, ['Admin', 'NetworkManager']):
            return {'error': 'Insufficient permissions'}
        
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT sync_type, last_sync, updated_at 
                FROM sync_status 
                WHERE branch_id = ?
                ORDER BY updated_at DESC
                """, (self.branch_id,))
                
                sync_statuses = cursor.fetchall()
                
                return {
                    'branch_id': self.branch_id,
                    'sync_statuses': [dict(status) for status in sync_statuses],
                    'last_check': datetime.now().isoformat()
                }
        
        except Exception as e:
            logger.error(f"Error getting sync status: {e}")
            return {'error': f'Failed to get sync status: {str(e)}'}