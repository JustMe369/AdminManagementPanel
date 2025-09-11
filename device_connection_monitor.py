# device_connection_monitor.py
import time
import subprocess
import re
import json
import sqlite3
from datetime import datetime, timedelta
import os
import sys

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from device_tracker import DeviceTracker
from db_config import get_db_connection
from error_handling import logger

class DeviceConnectionMonitor:
    def __init__(self, config):
        self.config = config
        self.device_tracker = DeviceTracker(config)
        self.interval = config.get('CONNECTION_MONITOR_INTERVAL', 60)  # Default 1 minute
        self.disconnect_threshold = config.get('DISCONNECT_THRESHOLD', 300)  # Default 5 minutes
        self.last_seen = {}  # Track when devices were last seen
    
    def get_connected_devices(self):
        """Get list of currently connected devices using OpenWrt tools"""
        try:
            # This is a simplified example - in a real implementation, you would use
            # OpenWrt's tools or other network monitoring tools to get actual connected devices
            
            # Example command for OpenWrt (would need to be adjusted for actual environment)
            # command = "iw dev wlan0 station dump | grep Station"
            # result = subprocess.run(command, shell=True, capture_output=True, text=True)
            
            # For demonstration purposes, we'll get all active devices from the database
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT id, mac_address, last_seen FROM devices 
                WHERE status = 'Active'
                """)
                
                devices = cursor.fetchall()
                
                # In a real implementation, you would compare this list with actual connected devices
                # For now, we'll simulate by randomly marking some as connected
                import random
                connected_macs = []
                
                for device in devices:
                    # 80% chance a device is still connected (for simulation)
                    if random.random() < 0.8:
                        connected_macs.append(device['mac_address'])
                
                return connected_macs
        except Exception as e:
            logger.error(f"Error getting connected devices: {e}")
            return []
    
    def check_connections(self):
        """Check for new connections and disconnections"""
        try:
            # Get currently connected devices
            connected_macs = self.get_connected_devices()
            current_time = datetime.now()
            
            # Get all devices from database
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT id, mac_address, last_seen, status FROM devices
                """)
                
                all_devices = {device['mac_address']: device for device in cursor.fetchall()}
                
                # Check for new connections and update last seen
                for mac in connected_macs:
                    if mac in all_devices:
                        device = all_devices[mac]
                        device_id = device['id']
                        
                        # Update last_seen timestamp
                        cursor.execute("""
                        UPDATE devices 
                        SET last_seen = ?, updated_at = ? 
                        WHERE id = ?
                        """, (current_time.isoformat(), current_time.isoformat(), device_id))
                        
                        # If device was previously disconnected, record a connect event
                        if mac not in self.last_seen:
                            self.device_tracker.record_device_activity(
                                device_id,
                                'connect',
                                {'auto_detected': True}
                            )
                            logger.info(f"Device connected: {mac} (ID: {device_id})")
                        
                        # Update our last seen tracking
                        self.last_seen[mac] = current_time
                
                # Check for disconnections
                disconnect_time = current_time - timedelta(seconds=self.disconnect_threshold)
                
                for mac, last_time in list(self.last_seen.items()):
                    if mac not in connected_macs and last_time < disconnect_time:
                        # Device has been disconnected for longer than the threshold
                        if mac in all_devices:
                            device = all_devices[mac]
                            device_id = device['id']
                            
                            # Record disconnect event
                            self.device_tracker.record_device_activity(
                                device_id,
                                'disconnect',
                                {'auto_detected': True, 'last_seen': last_time.isoformat()}
                            )
                            logger.info(f"Device disconnected: {mac} (ID: {device_id})")
                        
                        # Remove from our tracking
                        del self.last_seen[mac]
                
                return len(connected_macs)
        except Exception as e:
            logger.error(f"Error checking connections: {e}")
            return 0
    
    def run(self):
        """Run the connection monitor continuously"""
        logger.info(f"Starting device connection monitor with interval {self.interval} seconds")
        
        try:
            while True:
                start_time = time.time()
                
                # Check connections
                devices_checked = self.check_connections()
                logger.info(f"Checked {devices_checked} connected devices")
                
                # Calculate sleep time to maintain consistent interval
                elapsed = time.time() - start_time
                sleep_time = max(1, self.interval - elapsed)
                
                logger.debug(f"Sleeping for {sleep_time} seconds")
                time.sleep(sleep_time)
        except KeyboardInterrupt:
            logger.info("Connection monitor stopped by user")
        except Exception as e:
            logger.error(f"Connection monitor error: {e}")

if __name__ == '__main__':
    # Load configuration
    import config
    
    # Initialize and run the connection monitor
    monitor = DeviceConnectionMonitor(config)
    monitor.run()