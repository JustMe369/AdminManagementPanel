# automated_incident_response.py
import re
from datetime import datetime

class AutomatedIncidentResponse:
    def __init__(self):
        self.rules = self.load_response_rules()
    
    def load_response_rules(self):
        """Load automated response rules from database"""
        return {
            'high_cpu': {
                'condition': lambda data: data['cpu_usage'] > 90,
                'action': self.handle_high_cpu,
                'priority': 'high'
            },
            'bandwidth_saturation': {
                'condition': lambda data: data['bandwidth_usage'] > data['bandwidth_capacity'] * 0.85,
                'action': self.handle_bandwidth_saturation,
                'priority': 'medium'
            },
            'multiple_connection_failures': {
                'condition': lambda data: data['auth_failures'] > 10,
                'action': self.handle_auth_attacks,
                'priority': 'high'
            }
        }
    
    def monitor_and_respond(self, branch_id):
        """Monitor network conditions and trigger automated responses"""
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        # Get current network status
        cursor.execute("""
        SELECT * FROM network_stats 
        WHERE branch_id = ? 
        ORDER BY timestamp DESC LIMIT 1
        """, (branch_id,))
        
        current_status = cursor.fetchone()
        
        if current_status:
            status_dict = dict(current_status)
            
            # Check each rule
            for rule_name, rule in self.rules.items():
                if rule['condition'](status_dict):
                    rule['action'](branch_id, status_dict)
        
        conn.close()
    
    def handle_high_cpu(self, branch_id, data):
        """Automated response to high CPU usage"""
        # Implement QoS to reduce load
        qos_controller = QoSController()
        qos_controller.setup_qos('br-lan', '80%')
        
        # Log the incident and response
        SystemLogger.log('WARNING', 'auto_response', 
                        f"High CPU detected ({data['cpu_usage']}%), implemented QoS throttling",
                        branch_id=branch_id)
        
        # Create a ticket for follow-up
        TicketManager.create_ticket(
            title="Automatic: High CPU Usage Detected",
            description=f"CPU usage reached {data['cpu_usage']}%. QoS rules have been automatically applied.",
            branch_id=branch_id,
            reporter_name="System Auto-Response",
            category="Performance",
            priority="High"
        )