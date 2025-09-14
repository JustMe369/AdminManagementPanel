# network_monitor.py
import subprocess
import time
import json
import threading
import schedule
from datetime import datetime, timedelta
from collections import defaultdict, deque
import psutil
import re

from db_config import get_db_connection
from error_handling import logger
from device_tracker import DeviceTracker

class NetworkMonitor:
    def __init__(self, config):
        self.config = config
        self.monitoring = False
        self.monitor_threads = []
        self.device_tracker = DeviceTracker(config)
        
        # Data storage for real-time monitoring
        self.bandwidth_data = defaultdict(lambda: deque(maxlen=100))  # Store last 100 samples per device
        self.connection_history = defaultdict(list)
        self.network_stats = {'total_devices': 0, 'active_devices': 0, 'total_bandwidth': {'down': 0, 'up': 0}}
        
        # Monitoring intervals (seconds)
        self.device_scan_interval = 30
        self.bandwidth_scan_interval = 10
        self.stats_update_interval = 60
        
        # Device detection patterns
        self.device_patterns = {
            'dhcp_leases': '/tmp/dhcp.leases',
            'arp_table': '/proc/net/arp',
            'wireless_clients': '/proc/net/wireless'
        }
        
    def start_monitoring(self):
        """Start all monitoring services"""
        if self.monitoring:
            logger.warning("Network monitoring is already running")
            return False
            
        logger.info("Starting network monitoring services...")
        self.monitoring = True
        
        try:
            # Start device discovery monitoring
            device_thread = threading.Thread(target=self._device_monitor_loop, daemon=True)
            device_thread.start()
            self.monitor_threads.append(device_thread)
            
            # Start bandwidth monitoring
            bandwidth_thread = threading.Thread(target=self._bandwidth_monitor_loop, daemon=True)
            bandwidth_thread.start()
            self.monitor_threads.append(bandwidth_thread)
            
            # Start network statistics monitoring
            stats_thread = threading.Thread(target=self._stats_monitor_loop, daemon=True)
            stats_thread.start()
            self.monitor_threads.append(stats_thread)
            
            # Start scheduled tasks
            self._setup_scheduled_tasks()
            schedule_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
            schedule_thread.start()
            self.monitor_threads.append(schedule_thread)
            
            logger.info("Network monitoring services started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start network monitoring: {e}")
            self.stop_monitoring()
            return False
    
    def stop_monitoring(self):
        """Stop all monitoring services"""
        logger.info("Stopping network monitoring services...")
        self.monitoring = False
        
        # Wait for threads to finish (with timeout)
        for thread in self.monitor_threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        self.monitor_threads.clear()
        schedule.clear()
        logger.info("Network monitoring services stopped")
    
    def _device_monitor_loop(self):
        """Main loop for device monitoring"""
        logger.info("Device monitoring loop started")
        
        while self.monitoring:
            try:
                self._scan_for_devices()
                time.sleep(self.device_scan_interval)
            except Exception as e:
                logger.error(f"Error in device monitoring: {e}")
                time.sleep(5)  # Short delay before retry
    
    def _bandwidth_monitor_loop(self):
        """Main loop for bandwidth monitoring"""
        logger.info("Bandwidth monitoring loop started")
        
        while self.monitoring:
            try:
                self._monitor_bandwidth()
                time.sleep(self.bandwidth_scan_interval)
            except Exception as e:
                logger.error(f"Error in bandwidth monitoring: {e}")
                time.sleep(5)
    
    def _stats_monitor_loop(self):
        """Main loop for network statistics monitoring"""
        logger.info("Network statistics monitoring loop started")
        
        while self.monitoring:
            try:
                self._update_network_stats()
                time.sleep(self.stats_update_interval)
            except Exception as e:
                logger.error(f"Error in statistics monitoring: {e}")
                time.sleep(5)
    
    def _scheduler_loop(self):
        """Main loop for scheduled tasks"""
        logger.info("Scheduler loop started")
        
        while self.monitoring:
            try:
                schedule.run_pending()
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error in scheduler: {e}")
                time.sleep(5)
    
    def _scan_for_devices(self):
        """Scan for connected devices using multiple methods"""
        discovered_devices = {}
        
        # Method 1: DHCP leases
        dhcp_devices = self._scan_dhcp_leases()
        discovered_devices.update(dhcp_devices)
        
        # Method 2: ARP table
        arp_devices = self._scan_arp_table()
        for mac, device_info in arp_devices.items():
            if mac in discovered_devices:
                discovered_devices[mac].update(device_info)
            else:
                discovered_devices[mac] = device_info
        
        # Method 3: Wireless clients
        wireless_devices = self._scan_wireless_clients()
        for mac, device_info in wireless_devices.items():
            if mac in discovered_devices:
                discovered_devices[mac].update(device_info)
                discovered_devices[mac]['connection_type'] = 'wireless'
            else:
                device_info['connection_type'] = 'wireless'
                discovered_devices[mac] = device_info
        
        # Method 4: Active network connections
        active_devices = self._scan_active_connections()
        for mac, device_info in active_devices.items():
            if mac in discovered_devices:
                discovered_devices[mac].update(device_info)
            else:
                discovered_devices[mac] = device_info
        
        # Process discovered devices
        self._process_discovered_devices(discovered_devices)
    
    def _scan_dhcp_leases(self):
        """Scan DHCP leases file for connected devices"""
        devices = {}
        
        try:
            with open(self.device_patterns['dhcp_leases'], 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        lease_time, mac, ip, hostname = parts[0], parts[1], parts[2], parts[3]
                        if mac != "00:00:00:00:00:00":  # Filter invalid MACs
                            devices[mac.lower()] = {
                                'ip_address': ip,
                                'hostname': hostname if hostname != '*' else 'Unknown',
                                'lease_expires': datetime.fromtimestamp(int(lease_time)).isoformat(),
                                'connection_type': 'wired',
                                'source': 'dhcp'
                            }
        except FileNotFoundError:
            logger.debug("DHCP leases file not found")
        except Exception as e:
            logger.error(f"Error reading DHCP leases: {e}")
        
        return devices
    
    def _scan_arp_table(self):
        """Scan ARP table for device information"""
        devices = {}
        
        try:
            with open(self.device_patterns['arp_table'], 'r') as f:
                next(f)  # Skip header
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 6:
                        ip, hw_type, flags, mac, mask, device = parts
                        if mac != "00:00:00:00:00:00" and flags != "0x0":
                            devices[mac.lower()] = {
                                'ip_address': ip,
                                'interface': device,
                                'source': 'arp'
                            }
        except FileNotFoundError:
            logger.debug("ARP table file not found")
        except Exception as e:
            logger.error(f"Error reading ARP table: {e}")
        
        return devices
    
    def _scan_wireless_clients(self):
        """Scan for wireless clients using iwinfo"""
        devices = {}
        
        try:
            # Get wireless interfaces
            result = subprocess.run(['iwinfo'], capture_output=True, text=True)
            if result.returncode != 0:
                return devices
            
            interfaces = []
            for line in result.stdout.split('\n'):
                if line and not line.startswith(' '):
                    interface = line.split()[0]
                    interfaces.append(interface)
            
            # Get clients for each interface
            for interface in interfaces:
                try:
                    result = subprocess.run(['iwinfo', interface, 'assoclist'], capture_output=True, text=True)
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if 'dBm' in line and ':' in line:
                                # Parse line like: "AA:BB:CC:DD:EE:FF  -42 dBm / -95 dBm (SNR 53)"
                                mac = line.split()[0].lower()
                                signal_info = line.split()[1:3]
                                devices[mac] = {
                                    'interface': interface,
                                    'signal_strength': signal_info[0] if signal_info else 'Unknown',
                                    'connection_type': 'wireless',
                                    'source': 'wireless'
                                }
                except Exception as e:
                    logger.debug(f"Error scanning wireless interface {interface}: {e}")
        
        except Exception as e:
            logger.error(f"Error scanning wireless clients: {e}")
        
        return devices
    
    def _scan_active_connections(self):
        """Scan for active network connections using netstat"""
        devices = {}
        
        try:
            result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True)
            if result.returncode == 0:
                # Parse routing table to identify active connections
                for line in result.stdout.split('\n'):
                    if '192.168.' in line and 'UH' in line:  # Host routes
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[0]
                            # Try to get MAC from ARP
                            arp_result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
                            if arp_result.returncode == 0 and ':' in arp_result.stdout:
                                mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', arp_result.stdout)
                                if mac_match:
                                    mac = mac_match.group().lower().replace('-', ':')
                                    devices[mac] = {
                                        'ip_address': ip,
                                        'source': 'netstat'
                                    }
        except Exception as e:
            logger.debug(f"Error scanning active connections: {e}")
        
        return devices
    
    def _process_discovered_devices(self, discovered_devices):
        """Process discovered devices and update database"""
        current_time = datetime.now().isoformat()
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            for mac, device_info in discovered_devices.items():
                try:
                    # Check if device exists in database
                    cursor.execute("SELECT id, name, ip_address, last_seen FROM devices WHERE mac_address = ?", (mac,))
                    existing_device = cursor.fetchone()
                    
                    if existing_device:
                        # Update existing device
                        device_id = existing_device['id']
                        
                        # Check if IP changed
                        if 'ip_address' in device_info and device_info['ip_address'] != existing_device['ip_address']:
                            cursor.execute("""
                                UPDATE devices 
                                SET ip_address = ?, last_seen = ?, updated_at = ? 
                                WHERE id = ?
                            """, (device_info['ip_address'], current_time, current_time, device_id))
                            
                            # Record IP change activity
                            self.device_tracker.record_device_activity(
                                device_id, 'ip_change',
                                {'old_ip': existing_device['ip_address'], 'new_ip': device_info['ip_address']}
                            )
                        else:
                            # Just update last seen
                            cursor.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (current_time, device_id))
                        
                        # Record connection activity if device was inactive
                        last_seen = datetime.fromisoformat(existing_device['last_seen'])
                        if (datetime.now() - last_seen).total_seconds() > 300:  # 5 minutes threshold
                            self.device_tracker.record_device_activity(
                                device_id, 'connect',
                                {'connection_type': device_info.get('connection_type', 'unknown'),
                                 'interface': device_info.get('interface', 'unknown')}
                            )
                    
                    else:
                        # New device discovered
                        device_name = device_info.get('hostname', f"Device-{mac.replace(':', '')[-6:]}")
                        device_type = self._identify_device_type(device_info)
                        
                        cursor.execute("""
                            INSERT INTO devices 
                            (name, ip_address, mac_address, device_type, branch_id, status, first_seen, last_seen, created_at, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            device_name,
                            device_info.get('ip_address', 'Unknown'),
                            mac,
                            device_type,
                            1,  # Default branch
                            'Active',
                            current_time,
                            current_time,
                            current_time,
                            current_time
                        ))
                        
                        device_id = cursor.lastrowid
                        
                        # Record discovery activity
                        self.device_tracker.record_device_activity(
                            device_id, 'connect',
                            {'initial_discovery': True, **device_info}
                        )
                        
                        logger.info(f"New device discovered: {device_name} ({mac})")
                
                except Exception as e:
                    logger.error(f"Error processing device {mac}: {e}")
    
    def _identify_device_type(self, device_info):
        """Identify device type based on available information"""
        hostname = device_info.get('hostname', '').lower()
        mac = device_info.get('mac_address', '').upper()
        
        # Check hostname patterns
        if any(keyword in hostname for keyword in ['iphone', 'ipad', 'ios']):
            return 'smartphone'
        elif any(keyword in hostname for keyword in ['android', 'samsung', 'pixel']):
            return 'smartphone'
        elif any(keyword in hostname for keyword in ['laptop', 'notebook']):
            return 'laptop'
        elif any(keyword in hostname for keyword in ['desktop', 'pc']):
            return 'desktop'
        elif any(keyword in hostname for keyword in ['tablet', 'ipad']):
            return 'tablet'
        elif any(keyword in hostname for keyword in ['tv', 'roku', 'chromecast']):
            return 'media_device'
        
        # Check MAC address OUI (first 3 octets) for manufacturer
        if mac:
            oui = mac[:8]
            # Common OUIs (simplified list)
            oui_patterns = {
                'smartphone': ['28:CD:C4', '44:00:10', '88:53:2E'],  # Some Apple/Samsung OUIs
                'laptop': ['00:1B:77', '00:21:CC', '00:26:82'],      # Some laptop manufacturer OUIs
            }
            
            for device_type, patterns in oui_patterns.items():
                if any(oui.startswith(pattern) for pattern in patterns):
                    return device_type
        
        # Default based on connection type
        if device_info.get('connection_type') == 'wireless':
            return 'mobile_device'
        else:
            return 'unknown'
    
    def _monitor_bandwidth(self):
        """Monitor bandwidth usage for all devices"""
        try:
            # Get network interface statistics
            interface_stats = self._get_interface_stats()
            
            # Get per-device bandwidth (simplified approach)
            device_bandwidth = self._get_device_bandwidth()
            
            current_time = datetime.now()
            
            # Update bandwidth data in memory
            for device_mac, bandwidth in device_bandwidth.items():
                self.bandwidth_data[device_mac].append({
                    'timestamp': current_time,
                    'download_bytes': bandwidth.get('rx_bytes', 0),
                    'upload_bytes': bandwidth.get('tx_bytes', 0),
                    'download_rate': bandwidth.get('rx_rate', 0),
                    'upload_rate': bandwidth.get('tx_rate', 0)
                })
            
            # Update database periodically (every 5 samples)
            if len(next(iter(self.bandwidth_data.values()), [])) % 5 == 0:
                self._update_bandwidth_database()
        
        except Exception as e:
            logger.error(f"Error monitoring bandwidth: {e}")
    
    def _get_interface_stats(self):
        """Get network interface statistics"""
        stats = {}
        
        try:
            # Use psutil to get network interface stats
            net_io = psutil.net_io_counters(pernic=True)
            
            for interface, counters in net_io.items():
                stats[interface] = {
                    'rx_bytes': counters.bytes_recv,
                    'tx_bytes': counters.bytes_sent,
                    'rx_packets': counters.packets_recv,
                    'tx_packets': counters.packets_sent
                }
        except Exception as e:
            logger.error(f"Error getting interface stats: {e}")
        
        return stats
    
    def _get_device_bandwidth(self):
        """Get bandwidth usage per device (simplified approach)"""
        device_bandwidth = {}
        
        try:
            # This is a simplified approach - in production, you'd use more sophisticated
            # traffic analysis tools like ntopng or custom iptables logging
            
            # For now, we'll estimate based on connection monitoring
            result = subprocess.run(['cat', '/proc/net/dev'], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')[2:]  # Skip headers
                
                for line in lines:
                    if ':' in line:
                        parts = line.split(':')
                        interface = parts[0].strip()
                        
                        if interface.startswith(('wlan', 'eth', 'br-')):
                            values = parts[1].split()
                            if len(values) >= 16:
                                rx_bytes = int(values[0])
                                tx_bytes = int(values[8])
                                
                                # This is a placeholder - actual per-device tracking
                                # would require more sophisticated monitoring
                                device_bandwidth[f"{interface}_total"] = {
                                    'rx_bytes': rx_bytes,
                                    'tx_bytes': tx_bytes,
                                    'rx_rate': 0,  # Would calculate from previous samples
                                    'tx_rate': 0
                                }
        
        except Exception as e:
            logger.error(f"Error getting device bandwidth: {e}")
        
        return device_bandwidth
    
    def _update_bandwidth_database(self):
        """Update bandwidth usage in database"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                for device_mac, samples in self.bandwidth_data.items():
                    if samples:
                        latest = samples[-1]
                        
                        # Get device ID from MAC
                        cursor.execute("SELECT id FROM devices WHERE mac_address = ?", (device_mac,))
                        device = cursor.fetchone()
                        
                        if device:
                            # Update device bandwidth
                            self.device_tracker.update_device_bandwidth(
                                device['id'],
                                latest['download_bytes'],
                                latest['upload_bytes']
                            )
        
        except Exception as e:
            logger.error(f"Error updating bandwidth database: {e}")
    
    def _update_network_stats(self):
        """Update overall network statistics"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Count devices by status
                cursor.execute("SELECT status, COUNT(*) as count FROM devices GROUP BY status")
                device_counts = {row['status']: row['count'] for row in cursor.fetchall()}
                
                # Get recently active devices (last 5 minutes)
                recent_time = (datetime.now() - timedelta(minutes=5)).isoformat()
                cursor.execute("SELECT COUNT(*) as count FROM devices WHERE last_seen >= ?", (recent_time,))
                active_count = cursor.fetchone()['count']
                
                # Update network stats
                self.network_stats.update({
                    'total_devices': sum(device_counts.values()),
                    'active_devices': active_count,
                    'device_status': device_counts,
                    'last_updated': datetime.now().isoformat()
                })
                
                # Log network activity to database
                cursor.execute("""
                    INSERT INTO network_logs (branch_id, log_type, message, details, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    1,  # Default branch
                    'statistics',
                    f"Network stats updated: {active_count} active devices",
                    json.dumps(self.network_stats),
                    datetime.now().isoformat()
                ))
        
        except Exception as e:
            logger.error(f"Error updating network stats: {e}")
    
    def _setup_scheduled_tasks(self):
        """Setup scheduled maintenance tasks"""
        # Clean up old bandwidth data (daily)
        schedule.every().day.at("02:00").do(self._cleanup_old_data)
        
        # Generate daily network reports
        schedule.every().day.at("23:00").do(self._generate_daily_report)
        
        # Check for inactive devices (hourly)
        schedule.every().hour.do(self._check_inactive_devices)
    
    def _cleanup_old_data(self):
        """Clean up old monitoring data"""
        try:
            # Clean up in-memory data
            cutoff_time = datetime.now() - timedelta(hours=24)
            
            for device_mac in list(self.bandwidth_data.keys()):
                # Remove old samples
                samples = self.bandwidth_data[device_mac]
                while samples and samples[0]['timestamp'] < cutoff_time:
                    samples.popleft()
                
                # Remove empty entries
                if not samples:
                    del self.bandwidth_data[device_mac]
            
            # Clean up database (keep 30 days of detailed logs)
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                old_time = (datetime.now() - timedelta(days=30)).isoformat()
                
                cursor.execute("DELETE FROM network_logs WHERE timestamp < ?", (old_time,))
                cursor.execute("DELETE FROM device_bandwidth WHERE timestamp < ?", (old_time,))
                
                logger.info("Cleaned up old monitoring data")
        
        except Exception as e:
            logger.error(f"Error cleaning up old data: {e}")
    
    def _generate_daily_report(self):
        """Generate daily network usage report"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Get today's statistics
                today = datetime.now().date().isoformat()
                
                cursor.execute("""
                    SELECT COUNT(*) as new_devices 
                    FROM devices 
                    WHERE DATE(created_at) = ?
                """, (today,))
                
                new_devices = cursor.fetchone()['new_devices']
                
                # Generate report
                report = {
                    'date': today,
                    'new_devices': new_devices,
                    'total_devices': self.network_stats['total_devices'],
                    'active_devices': self.network_stats['active_devices'],
                    'peak_usage_time': None,  # Would be calculated from bandwidth data
                    'total_bandwidth': self.network_stats['total_bandwidth']
                }
                
                # Log report
                cursor.execute("""
                    INSERT INTO network_logs (branch_id, log_type, message, details, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    1,
                    'report',
                    f"Daily network report generated",
                    json.dumps(report),
                    datetime.now().isoformat()
                ))
                
                logger.info(f"Generated daily report: {new_devices} new devices, {self.network_stats['active_devices']} active")
        
        except Exception as e:
            logger.error(f"Error generating daily report: {e}")
    
    def _check_inactive_devices(self):
        """Check for devices that have become inactive"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Find devices that haven't been seen in the last 10 minutes
                inactive_time = (datetime.now() - timedelta(minutes=10)).isoformat()
                
                cursor.execute("""
                    SELECT id, name, mac_address, last_seen 
                    FROM devices 
                    WHERE status = 'Active' AND last_seen < ?
                """, (inactive_time,))
                
                inactive_devices = cursor.fetchall()
                
                for device in inactive_devices:
                    # Record disconnect activity
                    self.device_tracker.record_device_activity(
                        device['id'], 'disconnect',
                        {'last_seen': device['last_seen'], 'detected_at': datetime.now().isoformat()}
                    )
                    
                    logger.debug(f"Device went inactive: {device['name']} ({device['mac_address']})")
        
        except Exception as e:
            logger.error(f"Error checking inactive devices: {e}")
    
    def get_real_time_stats(self):
        """Get current real-time network statistics"""
        return {
            'network_stats': self.network_stats,
            'active_devices': len([d for d in self.bandwidth_data.keys() if self.bandwidth_data[d]]),
            'monitoring_status': self.monitoring,
            'last_scan': datetime.now().isoformat()
        }
    
    def get_device_bandwidth_history(self, device_mac, hours=1):
        """Get bandwidth history for a specific device"""
        if device_mac in self.bandwidth_data:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            return [
                sample for sample in self.bandwidth_data[device_mac]
                if sample['timestamp'] > cutoff_time
            ]
        return []
    
    def get_network_topology(self):
        """Get current network topology information"""
        topology = {
            'interfaces': {},
            'devices': {},
            'connections': []
        }
        
        try:
            # Get interface information
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()
            
            for interface, addresses in net_if_addrs.items():
                if interface in net_if_stats:
                    stats = net_if_stats[interface]
                    topology['interfaces'][interface] = {
                        'addresses': [{'address': addr.address, 'family': addr.family.name} for addr in addresses],
                        'is_up': stats.isup,
                        'speed': stats.speed,
                        'mtu': stats.mtu
                    }
            
            # Get device connections from database
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT name, ip_address, mac_address, device_type, status, last_seen 
                    FROM devices 
                    WHERE status = 'Active'
                """)
                
                devices = cursor.fetchall()
                
                for device in devices:
                    topology['devices'][device['mac_address']] = {
                        'name': device['name'],
                        'ip': device['ip_address'],
                        'type': device['device_type'],
                        'last_seen': device['last_seen']
                    }
        
        except Exception as e:
            logger.error(f"Error getting network topology: {e}")
        
        return topology

def main():
    """Main function for running network monitor as standalone service"""
    import config
    
    logger.info("Starting NetworkMonitor service...")
    
    monitor = NetworkMonitor(config)
    
    try:
        monitor.start_monitoring()
        
        # Keep the service running
        while True:
            time.sleep(60)
            stats = monitor.get_real_time_stats()
            logger.info(f"Monitor status: {stats['active_devices']} devices, monitoring: {stats['monitoring_status']}")
    
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, stopping...")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        monitor.stop_monitoring()
        logger.info("NetworkMonitor service stopped")

if __name__ == "__main__":
    main()