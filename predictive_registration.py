# predictive_registration.py
from datetime import datetime, time
import sqlite3

class PredictiveDeviceManager:
    def predict_device_arrival(self, mac_prefix, branch_id):
        """Predict when a device is likely to connect based on historical patterns"""
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        query = """
        SELECT strftime('%H', session_start) as hour, COUNT(*) as count
        FROM sessions 
        WHERE mac_address LIKE ? AND branch_id = ?
        GROUP BY hour
        ORDER BY count DESC
        """
        
        cursor.execute(query, (mac_prefix + '%', branch_id))
        results = cursor.fetchall()
        
        if results:
            peak_hour = int(results[0]['hour'])
            confidence = results[0]['count'] / sum(r['count'] for r in results)
            
            return {
                'likely_arrival': f"{peak_hour:02d}:00",
                'confidence': round(confidence, 2),
                'historical_connections': sum(r['count'] for r in results)
            }
        
        return None
    
    def auto_allocate_bandwidth(self, device_type, history):
        """Automatically allocate bandwidth based on device type and usage history"""
        base_allocations = {
            'mobile': '5 Mbps',
            'laptop': '10 Mbps',
            'tablet': '5 Mbps',
            'iot': '2 Mbps',
            'streaming': '15 Mbps'
        }
        
        # Adjust based on historical usage patterns
        allocation = base_allocations.get(device_type.lower(), '5 Mbps')
        
        if history and history.get('avg_usage', 0) > 0.8 * self.parse_bandwidth(allocation):
            # Increase allocation for heavy users
            return self.increase_bandwidth(allocation, 1.5)
        
        return allocation