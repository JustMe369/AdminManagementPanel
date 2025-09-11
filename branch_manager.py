# branch_manager.py
import os
import json
import sqlite3
import requests
import paramiko
import subprocess
from datetime import datetime
from functools import wraps
from db_config import get_db_connection
from error_handling import logger

class BranchManager:
    def __init__(self, config):
        self.config = config
        self.main_branch_id = config.MAIN_BRANCH_ID
    
    def get_all_branches(self):
        """Get all branches from the database"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT * FROM branches 
            ORDER BY name
            """)
            return [dict(branch) for branch in cursor.fetchall()]
    
    def get_branch(self, branch_id):
        """Get a specific branch by ID"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT * FROM branches 
            WHERE id = ?
            """, (branch_id,))
            branch = cursor.fetchone()
            return dict(branch) if branch else None
    
    def add_branch(self, name, location, ip_address, router_model='TP-Link Archer C7', status='Active'):
        """Add a new branch to the system"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO branches (name, location, ip_address, router_model, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (name, location, ip_address, router_model, status, datetime.now().isoformat()))
            
            branch_id = cursor.lastrowid
            return {
                'id': branch_id,
                'name': name,
                'location': location,
                'ip_address': ip_address,
                'router_model': router_model,
                'status': status
            }
    
    def update_branch(self, branch_id, data):
        """Update branch information"""
        allowed_fields = ['name', 'location', 'ip_address', 'router_model', 'status']
        update_fields = []
        params = []
        
        for field in allowed_fields:
            if field in data:
                update_fields.append(f"{field} = ?")
                params.append(data[field])
        
        if not update_fields:
            return None
        
        params.append(branch_id)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
            UPDATE branches 
            SET {', '.join(update_fields)}
            WHERE id = ?
            """, params)
            
            if cursor.rowcount > 0:
                cursor.execute("SELECT * FROM branches WHERE id = ?", (branch_id,))
                return dict(cursor.fetchone())
            
            return None
    
    def delete_branch(self, branch_id):
        """Delete a branch (soft delete by setting status to 'Inactive')"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE branches 
            SET status = 'Inactive'
            WHERE id = ?
            """, (branch_id,))
            
            return cursor.rowcount > 0
    
    def connect_to_branch(self, branch_id):
        """Establish SSH connection to branch router"""
        branch = self.get_branch(branch_id)
        if not branch or branch['status'] != 'Active':
            return None
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # In production, use a secure method to retrieve passwords
            # For example, from environment variables or a secure vault
            router_password = os.environ.get('ROUTER_PASSWORD', 'default_password')
            
            client.connect(
                hostname=branch['ip_address'],
                port=self.config.ROUTER_SSH_PORT,
                username=self.config.ROUTER_USERNAME,
                password=router_password,
                timeout=10
            )
            
            return client
        except Exception as e:
            logger.error(f"Failed to connect to branch {branch_id}: {e}")
            return None
    
    def execute_command(self, branch_id, command):
        """Execute a command on the branch router"""
        client = self.connect_to_branch(branch_id)
        if not client:
            return {'error': 'Failed to connect to branch router'}
        
        try:
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            return {
                'success': not error,
                'output': output,
                'error': error
            }
        except Exception as e:
            logger.error(f"Command execution error on branch {branch_id}: {e}")
            return {'error': str(e)}
        finally:
            client.close()
    
    def get_branch_status(self, branch_id):
        """Get the current status of a branch router"""
        result = self.execute_command(branch_id, 'uptime && free -m && df -h')
        if 'error' in result:
            return {'status': 'Offline', 'error': result['error']}
        
        # Parse the output to extract uptime, memory, and disk usage
        lines = result['output'].splitlines()
        uptime = lines[0] if lines else 'Unknown'
        
        memory_info = {}
        disk_info = {}
        
        for line in lines:
            if 'Mem:' in line:
                parts = line.split()
                if len(parts) >= 3:
                    memory_info = {
                        'total': parts[1],
                        'used': parts[2],
                        'free': parts[3] if len(parts) > 3 else 'Unknown'
                    }
            
            if '/overlay' in line:
                parts = line.split()
                if len(parts) >= 5:
                    disk_info = {
                        'total': parts[1],
                        'used': parts[2],
                        'available': parts[3],
                        'use_percent': parts[4]
                    }
        
        return {
            'status': 'Online',
            'uptime': uptime,
            'memory': memory_info,
            'disk': disk_info,
            'timestamp': datetime.now().isoformat()
        }
    
    def restart_branch_service(self, branch_id, service_name):
        """Restart a service on the branch router"""
        command = f"/etc/init.d/{service_name} restart"
        return self.execute_command(branch_id, command)
    
    def update_branch_config(self, branch_id, config_file, settings):
        """Update configuration on the branch router"""
        # Create a temporary file with the new settings
        temp_file = f"/tmp/config_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        commands = []
        
        for key, value in settings.items():
            commands.append(f"uci set {config_file}.{key}='{value}'")
        
        commands.append("uci commit")
        
        # Join commands with semicolons
        command_str = '; '.join(commands)
        
        return self.execute_command(branch_id, command_str)
    
    def get_branch_users(self, branch_id):
        """Get all users from a specific branch"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id, username, branch_id, user_type, status, created_at, last_login
            FROM users
            WHERE branch_id = ?
            ORDER BY username
            """, (branch_id,))
            
            return [dict(user) for user in cursor.fetchall()]
    
    def get_branch_devices(self, branch_id):
        """Get all devices from a specific branch"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT *
            FROM devices
            WHERE branch_id = ?
            ORDER BY name
            """, (branch_id,))
            
            return [dict(device) for device in cursor.fetchall()]
    
    def get_connected_clients(self, branch_id):
        """Get currently connected clients on the branch router"""
        # For TP-Link Archer with OpenWrt, we can get connected clients from various sources
        commands = [
            # Get wireless clients
            "iw dev wlan0 station dump | grep Station",
            # Get DHCP leases
            "cat /tmp/dhcp.leases",
            # Get ARP table
            "cat /proc/net/arp"
        ]
        
        results = {}
        for command in commands:
            result = self.execute_command(branch_id, command)
            if 'error' not in result:
                results[command] = result['output']
        
        # Parse the results to extract client information
        clients = []
        
        # Parse wireless clients
        if "iw dev wlan0 station dump | grep Station" in results:
            for line in results["iw dev wlan0 station dump | grep Station"].splitlines():
                if "Station" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        mac = parts[1]
                        clients.append({
                            'mac_address': mac,
                            'connection_type': 'wireless',
                            'ip_address': self._find_ip_for_mac(mac, results)
                        })
        
        return clients
    
    def _find_ip_for_mac(self, mac, results):
        """Helper method to find IP address for a given MAC from DHCP leases or ARP table"""
        # Check DHCP leases
        if "cat /tmp/dhcp.leases" in results:
            for line in results["cat /tmp/dhcp.leases"].splitlines():
                if mac.lower() in line.lower():
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]  # IP address is typically the 3rd field
        
        # Check ARP table
        if "cat /proc/net/arp" in results:
            for line in results["cat /proc/net/arp"].splitlines():
                if mac.lower() in line.lower():
                    parts = line.split()
                    if len(parts) >= 1:
                        return parts[0]  # IP address is the first field
        
        return 'Unknown'
    
    def apply_internet_policy(self, branch_id, mac_address, policy):
        """Apply internet access policy for a specific device"""
        # Policy can include time_limit, speed_limit, blocked_sites, etc.
        commands = []
        
        # Set up QoS for speed limiting if specified
        if 'speed_limit' in policy:
            commands.append(f"tc class add dev br-lan parent 1:0 classid 1:1 htb rate {policy['speed_limit']}")
            commands.append(f"tc filter add dev br-lan protocol ip parent 1:0 prio 1 u32 match ether src {mac_address} flowid 1:1")
        
        # Set up time-based access if specified
        if 'time_limit' in policy:
            # This is a simplified example - in production, you'd use more sophisticated scheduling
            # For example, using cron jobs or firewall time-based rules
            current_time = datetime.now()
            end_time = current_time + policy['time_limit']
            
            # Create a temporary script to disable access after time limit
            script_content = f"""
            #!/bin/sh
            # Disable internet access for {mac_address} after time limit
            iptables -I FORWARD -m mac --mac-source {mac_address} -j DROP
            """
            
            # Write script to temporary file
            temp_script = f"/tmp/limit_{mac_address.replace(':', '')}.sh"
            echo_cmd = f"echo '{script_content}' > {temp_script}"
            chmod_cmd = f"chmod +x {temp_script}"
            at_cmd = f"at -f {temp_script} {end_time.strftime('%H:%M')}"
            
            commands.extend([echo_cmd, chmod_cmd, at_cmd])
        
        # Block specific sites if specified
        if 'blocked_sites' in policy and policy['blocked_sites']:
            for site in policy['blocked_sites']:
                commands.append(f"iptables -I FORWARD -m mac --mac-source {mac_address} -m string --string '{site}' --algo bm -j DROP")
        
        # Execute all commands
        results = []
        for command in commands:
            result = self.execute_command(branch_id, command)
            results.append(result)
        
        return {
            'success': all('error' not in r for r in results),
            'policy_applied': policy,
            'mac_address': mac_address,
            'results': results
        }
    
    def reset_branch_router(self, branch_id):
        """Reset the branch router to default settings (use with caution)"""
        # This is a potentially dangerous operation and should require confirmation
        command = "firstboot -y && reboot"  # OpenWrt command to reset to factory defaults
        
        # In a real implementation, you'd want additional safeguards here
        return self.execute_command(branch_id, command)
    
    def backup_branch_config(self, branch_id):
        """Backup the configuration of a branch router"""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        backup_file = f"/tmp/backup_{branch_id}_{timestamp}.tar.gz"
        
        # OpenWrt backup command
        command = f"sysupgrade -b {backup_file}"
        result = self.execute_command(branch_id, command)
        
        if 'error' in result:
            return {'error': result['error']}
        
        # Download the backup file (in a real implementation)
        # This would involve SCP or another file transfer method
        
        return {
            'success': True,
            'backup_file': backup_file,
            'timestamp': timestamp
        }
    
    def restore_branch_config(self, branch_id, backup_file):
        """Restore a branch router from a backup"""
        # Upload the backup file (in a real implementation)
        # This would involve SCP or another file transfer method
        
        # Restore command
        command = f"sysupgrade -r {backup_file}"
        return self.execute_command(branch_id, command)