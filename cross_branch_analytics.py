# cross_branch_analytics.py
from collections import defaultdict

class CrossBranchAnalytics:
    def compare_branch_performance(self):
        """Compare performance across all branches to identify best practices"""
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
        SELECT b.name, b.location, 
               AVG(ns.bandwidth_usage) as avg_bandwidth,
               AVG(ns.cpu_usage) as avg_cpu,
               COUNT(DISTINCT u.id) as total_users,
               COUNT(DISTINCT d.id) as total_devices
        FROM branches b
        LEFT JOIN network_stats ns ON b.id = ns.branch_id
        LEFT JOIN users u ON b.id = u.branch_id
        LEFT JOIN devices d ON b.id = d.branch_id
        WHERE ns.timestamp > datetime('now', '-7 days')
        GROUP BY b.id
        ORDER BY avg_bandwidth DESC
        """)
        
        results = cursor.fetchall()
        conn.close()
        
        # Analyze for correlations and insights
        insights = []
        for i, branch in enumerate(results):
            if i == 0:
                insights.append({
                    'type': 'performance_leader',
                    'branch': branch['name'],
                    'metric': 'bandwidth efficiency',
                    'suggestion': f"Other branches should study {branch['name']}'s configuration"
                })
        
        return {
            'rankings': [dict(r) for r in results],
            'insights': insights
        }
    
    def detect_cross_branch_issues(self):
        """Identify issues affecting multiple branches simultaneously"""
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        # Check for correlated downtime or performance issues
        cursor.execute("""
        SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour, 
               COUNT(DISTINCT branch_id) as affected_branches,
               AVG(cpu_usage) as avg_cpu
        FROM network_stats 
        WHERE cpu_usage > 80
        GROUP BY hour
        HAVING affected_branches > 1
        ORDER BY hour DESC
        LIMIT 10
        """)
        
        correlated_issues = cursor.fetchall()
        conn.close()
        
        issues = []
        for issue in correlated_issues:
            if issue['affected_branches'] > 3:
                issues.append({
                    'time': issue['hour'],
                    'affected_branches': issue['affected_branches'],
                    'severity': 'high',
                    'likely_cause': 'Possible external network issue or coordinated attack'
                })
        
        return issues