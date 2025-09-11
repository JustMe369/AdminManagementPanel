# device_bandwidth_monitor.py
import time
import subprocess
import re
import json
import sqlite3
from datetime import datetime
import os
import sys

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from device_tracker import DeviceTracker
from db_config import get_db_connection
from error_handling import logger

class DeviceBandwidthMonitor:
    def __init__(self, config):
        self.config = config
        self.device_tracker = DeviceTracker(config)
        self.interval = config.get('BANDWIDTH_MONITOR_INTERVAL', 300)  # Default 5 minutes
    
    def get_device_bandwidth_usage(self, mac_address):
        """Get current bandwidth usage for a device using OpenWrt tools"""
        try:
            # This is a simplified example - in a real implementation, you would use
            # OpenWrt's traffic monitoring tools or other network monitoring tools
            # to get actual bandwidth usage
            
            # Example command for OpenWrt (would need to be adjusted for actual environment)
            command = f"luci-bwc -i br-lan | grep {mac_address}"
            
            # For demonstration purposes, we'll generate random values
            # In a real implementation, parse the output of the command
            import random
            download_bytes = random.randint(1000, 10000000)  # Random value between 1KB and 10MB
            upload_bytes = random.randint(1000, 5000000)    # Random value between 1KB and 5MB
            
            return {
                'mac_address': mac_address,
                'download_bytes': download_bytes,
                'upload_bytes': upload_bytes,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting bandwidth usage for {mac_address}: {e}")
            return None
    
    def update_all_devices(self):
        """Update bandwidth usage for all active devices"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT id, mac_address FROM devices 
                WHERE status = 'Active'
                """)
                
                devices = cursor.fetchall()
                
                for device in devices:
                    device_id = device['id']
                    mac_address = device['mac_address']
                    
                    # Get current bandwidth usage
                    usage = self.get_device_bandwidth_usage(mac_address)
                    
                    if usage:
                        # Update device bandwidth in database
                        self.device_tracker.update_device_bandwidth(
                            device_id,
                            usage['download_bytes'],
                            usage['upload_bytes']
                        )
                        
                        # Update last_seen timestamp
                        cursor.execute("""
                        UPDATE devices 
                        SET last_seen = ?, updated_at = ? 
                        WHERE id = ?
                        """, (datetime.now().isoformat(), datetime.now().isoformat(), device_id))
                
                logger.info(f"Updated bandwidth usage for {len(devices)} devices")
                return len(devices)
        except Exception as e:
            logger.error(f"Error updating device bandwidth: {e}")
            return 0
    
    def run(self):
        """Run the bandwidth monitor continuously"""
        logger.info(f"Starting device bandwidth monitor with interval {self.interval} seconds")
        
        try:
            while True:
                start_time = time.time()
                
                # Update all devices
                devices_updated = self.update_all_devices()
                logger.info(f"Updated {devices_updated} devices")
                
                # Calculate sleep time to maintain consistent interval
                elapsed = time.time() - start_time
                sleep_time = max(1, self.interval - elapsed)
                
                logger.debug(f"Sleeping for {sleep_time} seconds")
                time.sleep(sleep_time)
        except KeyboardInterrupt:
            logger.info("Bandwidth monitor stopped by user")
        except Exception as e:
            logger.error(f"Bandwidth monitor error: {e}")

if __name__ == '__main__':
    # Load configuration
    import config
    
    # Initialize and run the bandwidth monitor
    monitor = DeviceBandwidthMonitor(config)
    monitor.run()