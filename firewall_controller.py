# firewall_controller.py
import subprocess
import re
import json
import time
from datetime import datetime, timedelta
from error_handling import logger

class FirewallController:
    def __init__(self, config):
        self.config = config
        self.router_ip = config.ROUTER_IP
        self.ssh_port = config.ROUTER_SSH_PORT
        self.username = config.ROUTER_USERNAME
        # Password should be retrieved securely, not stored in code
        self.required_roles = {
            'view_rules': ['Admin', 'NetworkManager', 'Support'],
            'modify_rules': ['Admin', 'NetworkManager'],
            'guest_network': ['Admin', 'NetworkManager'],
            'bandwidth_control': ['Admin', 'NetworkManager'],
            'device_control': ['Admin', 'NetworkManager', 'Support'],
            'view_devices': ['Admin', 'NetworkManager', 'Support', 'User']
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
    
    def execute_command(self, command, branch_manager=None, branch_id=None):
        """Execute a command on the router"""
        try:
            if branch_manager and branch_id:
                # Execute on a remote branch router
                return branch_manager.execute_command(branch_id, command)
            else:
                # Execute on the local router
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                return {
                    'success': result.returncode == 0,
                    'output': result.stdout,
                    'error': result.stderr
                }
        except Exception as e:
            logger.error(f"Firewall command error: {e}")
            return {'error': str(e)}
    
    def get_firewall_rules(self, user=None, branch_manager=None, branch_id=None):
        """Get all firewall rules"""
        # Check if user has permission to view rules
        if user and not self.check_permission(user, 'view_rules'):
            return {'error': 'Permission denied: Insufficient privileges to view firewall rules'}
            
        command = "uci show firewall | grep firewall.@rule"
        result = self.execute_command(command, branch_manager, branch_id)
        
        if 'error' in result:
            return {'error': result['error']}
        
        rules = []
        rule_pattern = re.compile(r'firewall\.@rule\[(\d+)\]\.(\w+)=(.*)')
        
        current_rule = {}
        current_index = None
        
        for line in result['output'].splitlines():
            match = rule_pattern.match(line)
            if match:
                index, key, value = match.groups()
                
                if current_index != index:
                    if current_rule:
                        rules.append(current_rule)
                    current_rule = {'index': index}
                    current_index = index
                
                current_rule[key] = value.strip("'")
        
        if current_rule:
            rules.append(current_rule)
        
        return rules
    
    def add_firewall_rule(self, rule_data, user=None, branch_manager=None, branch_id=None):
        """Add a new firewall rule"""
        # Check if user has permission to modify rules
        if user and not self.check_permission(user, 'modify_rules'):
            return {'error': 'Permission denied: Insufficient privileges to add firewall rules'}
            
        # Validate required fields
        required_fields = ['name', 'src', 'dest', 'proto', 'target']
        for field in required_fields:
            if field not in rule_data:
                return {'error': f'Missing required field: {field}'}
        
        commands = [
            "uci add firewall rule",
            f"uci set firewall.@rule[-1].name='{rule_data['name']}'",
            f"uci set firewall.@rule[-1].src='{rule_data['src']}'",
            f"uci set firewall.@rule[-1].dest='{rule_data['dest']}'",
            f"uci set firewall.@rule[-1].proto='{rule_data['proto']}'",
            f"uci set firewall.@rule[-1].target='{rule_data['target']}'"
        ]
        
        # Add optional fields if provided
        optional_fields = ['src_ip', 'dest_ip', 'src_port', 'dest_port', 'family', 'icmp_type']
        for field in optional_fields:
            if field in rule_data:
                commands.append(f"uci set firewall.@rule[-1].{field}='{rule_data[field]}'")
        
        # Commit changes and restart firewall
        commands.append("uci commit firewall")
        commands.append("/etc/init.d/firewall restart")
        
        # Execute commands
        results = []
        for command in commands:
            result = self.execute_command(command, branch_manager, branch_id)
            results.append(result)
            
            if 'error' in result:
                # If any command fails, return the error
                return {'error': result['error'], 'command': command}
        
        return {
            'success': True,
            'rule': rule_data,
            'message': 'Firewall rule added successfully'
        }
    
    def delete_firewall_rule(self, rule_index, user=None, branch_manager=None, branch_id=None):
        """Delete a firewall rule by index"""
        # Check if user has permission to modify rules
        if user and not self.check_permission(user, 'modify_rules'):
            return {'error': 'Permission denied: Insufficient privileges to delete firewall rules'}
            
        commands = [
            f"uci delete firewall.@rule[{rule_index}]",
            "uci commit firewall",
            "/etc/init.d/firewall restart"
        ]
        
        # Execute commands
        results = []
        for command in commands:
            result = self.execute_command(command, branch_manager, branch_id)
            results.append(result)
            
            if 'error' in result:
                return {'error': result['error'], 'command': command}
        
        return {
            'success': True,
            'message': f'Firewall rule at index {rule_index} deleted successfully'
        }
    
    def update_firewall_rule(self, rule_index, rule_data, user=None, branch_manager=None, branch_id=None):
        """Update an existing firewall rule"""
        # Check if user has permission to modify rules
        if user and not self.check_permission(user, 'modify_rules'):
            return {'error': 'Permission denied: Insufficient privileges to update firewall rules'}
            
        # Get all valid fields that can be updated
        valid_fields = [
            'name', 'src', 'dest', 'proto', 'target', 'src_ip', 'dest_ip', 
            'src_port', 'dest_port', 'family', 'icmp_type', 'enabled'
        ]
        
        commands = []
        for field in valid_fields:
            if field in rule_data:
                commands.append(f"uci set firewall.@rule[{rule_index}].{field}='{rule_data[field]}'")
        
        if not commands:
            return {'error': 'No valid fields to update'}
        
        # Commit changes and restart firewall
        commands.append("uci commit firewall")
        commands.append("/etc/init.d/firewall restart")
        
        # Execute commands
        results = []
        for command in commands:
            result = self.execute_command(command, branch_manager, branch_id)
            results.append(result)
            
            if 'error' in result:
                return {'error': result['error'], 'command': command}
        
        return {
            'success': True,
            'rule': rule_data,
            'message': f'Firewall rule at index {rule_index} updated successfully'
        }
    
    def get_firewall_zones(self, branch_manager=None, branch_id=None):
        """Get all firewall zones"""
        command = "uci show firewall | grep firewall.@zone"
        result = self.execute_command(command, branch_manager, branch_id)
        
        if 'error' in result:
            return {'error': result['error']}
        
        zones = []
        zone_pattern = re.compile(r'firewall\.@zone\[(\d+)\]\.(\w+)=(.*)')
        
        current_zone = {}
        current_index = None
        
        for line in result['output'].splitlines():
            match = zone_pattern.match(line)
            if match:
                index, key, value = match.groups()
                
                if current_index != index:
                    if current_zone:
                        zones.append(current_zone)
                    current_zone = {'index': index}
                    current_index = index
                
                current_zone[key] = value.strip("'")
        
        if current_zone:
            zones.append(current_zone)
        
        return zones
    
    def setup_guest_network(self, ssid, password, isolation=True, user=None, branch_manager=None, branch_id=None):
        """Set up a guest WiFi network"""
        # Check if user has permission to manage guest network
        if user and not self.check_permission(user, 'guest_network'):
            return {'error': 'Permission denied: Insufficient privileges to set up guest network'}
            
        # Create a new wireless network
        commands = [
            "uci set wireless.guest=wifi-iface",
            "uci set wireless.guest.device='radio0'",
            f"uci set wireless.guest.ssid='{ssid}'",
            "uci set wireless.guest.mode='ap'",
            "uci set wireless.guest.network='guest'",
            f"uci set wireless.guest.encryption='psk2'",
            f"uci set wireless.guest.key='{password}'",
            "uci set wireless.guest.disabled='0'"
        ]
        
        # Create a guest network
        commands.extend([
            "uci set network.guest=interface",
            "uci set network.guest.proto='static'",
            "uci set network.guest.ipaddr='192.168.2.1'",
            "uci set network.guest.netmask='255.255.255.0'"
        ])
        
        # Create a guest firewall zone with isolation
        commands.extend([
            "uci add firewall zone",
            "uci set firewall.@zone[-1].name='guest'",
            "uci set firewall.@zone[-1].network='guest'",
            "uci set firewall.@zone[-1].input='REJECT'",
            "uci set firewall.@zone[-1].output='ACCEPT'",
            "uci set firewall.@zone[-1].forward='REJECT'"
        ])
        
        # Allow guest to access internet (WAN)
        commands.extend([
            "uci add firewall forwarding",
            "uci set firewall.@forwarding[-1].src='guest'",
            "uci set firewall.@forwarding[-1].dest='wan'"
        ])
        
        # If isolation is not enabled, allow guest to access LAN
        if not isolation:
            commands.extend([
                "uci add firewall forwarding",
                "uci set firewall.@forwarding[-1].src='guest'",
                "uci set firewall.@forwarding[-1].dest='lan'"
            ])
        
        # Set up DHCP for guest network
        commands.extend([
            "uci set dhcp.guest=dhcp",
            "uci set dhcp.guest.interface='guest'",
            "uci set dhcp.guest.start='100'",
            "uci set dhcp.guest.limit='150'",
            "uci set dhcp.guest.leasetime='1h'"
        ])
        
        # Commit changes and restart services
        commands.extend([
            "uci commit wireless",
            "uci commit network",
            "uci commit firewall",
            "uci commit dhcp",
            "/etc/init.d/network restart",
            "/etc/init.d/firewall restart",
            "/etc/init.d/dnsmasq restart"
        ])
        
        # Execute commands
        results = []
        for command in commands:
            result = self.execute_command(command, branch_manager, branch_id)
            results.append(result)
            
            if 'error' in result:
                return {'error': result['error'], 'command': command}
        
        return {
            'success': True,
            'message': f'Guest network "{ssid}" set up successfully',
            'isolation_enabled': isolation
        }
    
    def setup_nodogsplash(self, interface='br-lan', branch_manager=None, branch_id=None):
        """Set up NoDogSplash captive portal"""
        # Check if NoDogSplash is installed
        check_cmd = "opkg list-installed | grep nodogsplash"
        result = self.execute_command(check_cmd, branch_manager, branch_id)
        
        if 'error' in result or not result['output']:
            # Install NoDogSplash if not already installed
            install_cmd = "opkg update && opkg install nodogsplash"
            install_result = self.execute_command(install_cmd, branch_manager, branch_id)
            
            if 'error' in install_result:
                return {'error': install_result['error'], 'command': install_cmd}
        
        # Configure NoDogSplash
        config_commands = [
            f"uci set nodogsplash.@nodogsplash[0].enabled='1'",
            f"uci set nodogsplash.@nodogsplash[0].gatewayinterface='{interface}'",
            f"uci set nodogsplash.@nodogsplash[0].maxclients='250'",
            f"uci set nodogsplash.@nodogsplash[0].authidletimeout='1200'",  # 20 minutes
            f"uci set nodogsplash.@nodogsplash[0].sessiontimeout='1200'",  # 20 minutes
            f"uci commit nodogsplash",
            f"/etc/init.d/nodogsplash restart"
        ]
        
        # Execute configuration commands
        results = []
        for command in config_commands:
            result = self.execute_command(command, branch_manager, branch_id)
            results.append(result)
            
            if 'error' in result:
                return {'error': result['error'], 'command': command}
        
        return {
            'success': True,
            'message': 'NoDogSplash captive portal set up successfully',
            'interface': interface
        }
    
    def apply_bandwidth_limit(self, mac_address, download_limit, upload_limit, user=None, branch_manager=None, branch_id=None):
        """Apply bandwidth limits to a specific device by MAC address"""
        # Check if user has permission to control bandwidth
        if user and not self.check_permission(user, 'bandwidth_control'):
            return {'error': 'Permission denied: Insufficient privileges to apply bandwidth limits'}
            
        # Check if tc (traffic control) is installed
        check_cmd = "which tc"
        result = self.execute_command(check_cmd, branch_manager, branch_id)
        
        if 'error' in result or not result['output']:
            # Install tc if not already installed
            install_cmd = "opkg update && opkg install tc"
            install_result = self.execute_command(install_cmd, branch_manager, branch_id)
            
            if 'error' in install_result:
                return {'error': install_result['error'], 'command': install_cmd}
        
        # Set up traffic control for the device
        commands = [
            # Clear existing rules for this MAC
            f"tc qdisc del dev br-lan root",
            
            # Set up HTB qdisc
            f"tc qdisc add dev br-lan root handle 1: htb default 30",
            
            # Create parent class
            f"tc class add dev br-lan parent 1: classid 1:1 htb rate 1000mbit",
            
            # Create class for this device
            f"tc class add dev br-lan parent 1:1 classid 1:10 htb rate {download_limit}kbit ceil {download_limit}kbit burst 15k",
            
            # Filter traffic for this MAC address
            f"tc filter add dev br-lan protocol ip parent 1:0 prio 1 u32 match ether dst {mac_address} flowid 1:10"
        ]
        
        # If upload limit is specified, add upload limiting rules
        if upload_limit:
            commands.extend([
                f"tc qdisc add dev br-lan parent 1:10 handle 10: sfq perturb 10",
                f"tc filter add dev br-lan protocol ip parent 1:0 prio 2 u32 match ether src {mac_address} flowid 1:10"
            ])
        
        # Execute commands
        results = []
        for command in commands:
            result = self.execute_command(command, branch_manager, branch_id)
            results.append(result)
            
            # Don't fail on the first command (del) as it might not exist yet
            if 'error' in result and commands.index(command) > 0:
                return {'error': result['error'], 'command': command}
        
        return {
            'success': True,
            'message': f'Bandwidth limits applied to {mac_address}',
            'download_limit': f'{download_limit} kbit',
            'upload_limit': f'{upload_limit} kbit' if upload_limit else 'No limit'
        }
    
    def block_device(self, mac_address, duration=None, user=None, branch_manager=None, branch_id=None):
        """Block a device from accessing the network"""
        # Check if user has permission to control devices
        if user and not self.check_permission(user, 'device_control'):
            return {'error': 'Permission denied: Insufficient privileges to block devices'}
            
        # Add iptables rule to block the device
        block_cmd = f"iptables -I FORWARD -m mac --mac-source {mac_address} -j DROP"
        result = self.execute_command(block_cmd, branch_manager, branch_id)
        
        if 'error' in result:
            return {'error': result['error'], 'command': block_cmd}
        
        # If duration is specified, set up automatic unblock after the duration
        if duration:
            # Calculate unblock time
            unblock_time = datetime.now() + timedelta(minutes=duration)
            
            # Create a temporary script to unblock the device
            script_content = f"""
            #!/bin/sh
            # Unblock {mac_address} after {duration} minutes
            iptables -D FORWARD -m mac --mac-source {mac_address} -j DROP
            """
            
            # Write script to temporary file
            temp_script = f"/tmp/unblock_{mac_address.replace(':', '')}.sh"
            echo_cmd = f"echo '{script_content}' > {temp_script}"
            chmod_cmd = f"chmod +x {temp_script}"
            at_cmd = f"at -f {temp_script} {unblock_time.strftime('%H:%M')}"
            
            # Execute commands to set up automatic unblock
            commands = [echo_cmd, chmod_cmd, at_cmd]
            for command in commands:
                cmd_result = self.execute_command(command, branch_manager, branch_id)
                if 'error' in cmd_result:
                    # If setting up automatic unblock fails, still return success for the block
                    return {
                        'success': True,
                        'message': f'Device {mac_address} blocked, but automatic unblock could not be set up',
                        'error': cmd_result['error'],
                        'command': command
                    }
            
            return {
                'success': True,
                'message': f'Device {mac_address} blocked for {duration} minutes',
                'unblock_time': unblock_time.isoformat()
            }
        
        return {
            'success': True,
            'message': f'Device {mac_address} blocked indefinitely'
        }
    
    def unblock_device(self, mac_address, user=None, branch_manager=None, branch_id=None):
        """Unblock a previously blocked device"""
        # Check if user has permission to control devices
        if user and not self.check_permission(user, 'device_control'):
            return {'error': 'Permission denied: Insufficient privileges to unblock devices'}
            
        unblock_cmd = f"iptables -D FORWARD -m mac --mac-source {mac_address} -j DROP"
        result = self.execute_command(unblock_cmd, branch_manager, branch_id)
        
        if 'error' in result:
            return {'error': result['error'], 'command': unblock_cmd}
        
        return {
            'success': True,
            'message': f'Device {mac_address} unblocked successfully'
        }
    
    def get_connected_devices(self, user=None, branch_manager=None, branch_id=None):
        """Get a list of all connected devices"""
        # Check if user has permission to view devices
        if user and not self.check_permission(user, 'view_devices'):
            return {'error': 'Permission denied: Insufficient privileges to view connected devices'}
            
        commands = [
            # Get wireless clients
            "iw dev wlan0 station dump",
            # Get DHCP leases
            "cat /tmp/dhcp.leases",
            # Get ARP table
            "cat /proc/net/arp"
        ]
        
        results = {}
        for command in commands:
            result = self.execute_command(command, branch_manager, branch_id)
            if 'error' not in result:
                results[command] = result['output']
        
        # Parse the results to extract device information
        devices = []
        
        # Parse wireless clients
        if "iw dev wlan0 station dump" in results:
            current_mac = None
            current_device = {}
            
            for line in results["iw dev wlan0 station dump"].splitlines():
                if "Station" in line and "on wlan0" in line:
                    # New station entry
                    if current_mac and current_device:
                        devices.append(current_device)
                    
                    mac = line.split()[1]
                    current_mac = mac
                    current_device = {
                        'mac_address': mac,
                        'connection_type': 'wireless',
                        'interface': 'wlan0'
                    }
                elif current_mac and ':' in line:
                    # Station property
                    parts = line.strip().split(':', 1)
                    if len(parts) == 2:
                        key = parts[0].strip().lower().replace(' ', '_')
                        value = parts[1].strip()
                        current_device[key] = value
            
            # Add the last device
            if current_mac and current_device:
                devices.append(current_device)
        
        # Parse DHCP leases to get IP addresses and hostnames
        if "cat /tmp/dhcp.leases" in results:
            for line in results["cat /tmp/dhcp.leases"].splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    lease_mac = parts[1]
                    lease_ip = parts[2]
                    lease_hostname = parts[3]
                    
                    # Find the device in our list
                    for device in devices:
                        if device['mac_address'].lower() == lease_mac.lower():
                            device['ip_address'] = lease_ip
                            device['hostname'] = lease_hostname
                            break
                    else:
                        # Device not found in wireless clients, add it
                        devices.append({
                            'mac_address': lease_mac,
                            'ip_address': lease_ip,
                            'hostname': lease_hostname,
                            'connection_type': 'wired',
                            'interface': 'br-lan'
                        })
        
        # Parse ARP table to get additional devices
        if "cat /proc/net/arp" in results:
            for line in results["cat /proc/net/arp"].splitlines():
                if "IP address" in line:  # Skip header
                    continue
                
                parts = line.split()
                if len(parts) >= 6:
                    arp_ip = parts[0]
                    arp_mac = parts[3]
                    
                    # Skip invalid MACs
                    if arp_mac == '00:00:00:00:00:00':
                        continue
                    
                    # Find the device in our list
                    for device in devices:
                        if device['mac_address'].lower() == arp_mac.lower():
                            device['ip_address'] = arp_ip
                            break
                    else:
                        # Device not found, add it
                        devices.append({
                            'mac_address': arp_mac,
                            'ip_address': arp_ip,
                            'connection_type': 'unknown',
                            'interface': 'br-lan'
                        })
        
        return {
            'devices': devices,
            'count': len(devices),
            'timestamp': datetime.now().isoformat()
        }