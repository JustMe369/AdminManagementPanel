# ai_network_optimizer.py
import pandas as pd
from sklearn.ensemble import IsolationForest
import numpy as np
from db_config import db_manager

class AINetworkOptimizer:
    def __init__(self):
        self.anomaly_detector = IsolationForest(contamination=0.1)
        
    def analyze_network_patterns(self, branch_id):
        """Use ML to detect unusual network patterns and optimize performance"""
        conn = db_manager.get_connection()
        
        # Get historical network data
        query = """
        SELECT timestamp, active_users, bandwidth_usage, cpu_usage, memory_usage 
        FROM network_stats 
        WHERE branch_id = ? AND timestamp > datetime('now', '-7 days')
        ORDER BY timestamp
        """
        
        df = pd.read_sql_query(query, conn, params=[branch_id])
        conn.close()
        
        if len(df) > 10:  # Enough data for analysis
            # Prepare features for anomaly detection
            features = df[['active_users', 'bandwidth_usage', 'cpu_usage', 'memory_usage']]
            anomalies = self.anomaly_detector.fit_predict(features)
            
            # Identify peak usage times
            df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
            peak_hours = df.groupby('hour')['bandwidth_usage'].mean().sort_values(ascending=False)
            
            return {
                'anomalies': int(sum(anomalies == -1)),
                'peak_hours': peak_hours.head(3).index.tolist(),
                'recommendations': self.generate_recommendations(df, peak_hours)
            }
        
        return None
    
    def generate_recommendations(self, data, peak_hours):
        """Generate AI-driven optimization recommendations"""
        recs = []
        
        # Bandwidth allocation recommendations
        if len(peak_hours) > 0:
            recs.append(f"Implement QoS rules during peak hours ({', '.join(map(str, peak_hours))}:00)")
        
        # Resource allocation suggestions
        max_usage = data['cpu_usage'].max()
        if max_usage > 85:
            recs.append("Consider load balancing or hardware upgrade - CPU frequently at {}%".format(int(max_usage)))
        
        return recs