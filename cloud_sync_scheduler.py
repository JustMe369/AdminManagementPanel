# cloud_sync_scheduler.py
import time
import schedule
import threading
from datetime import datetime
import os
import sys

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from cloud_sync import CloudSyncManager
from error_handling import logger
import config

class CloudSyncScheduler:
    def __init__(self, config_obj):
        self.config = config_obj
        self.cloud_sync_manager = CloudSyncManager(config_obj)
        self.is_running = False
        self.scheduler_thread = None
        
        # Configuration
        self.auto_push_enabled = config_obj.get('AUTO_PUSH_ENABLED', True)
        self.auto_pull_enabled = config_obj.get('AUTO_PULL_ENABLED', True)
        self.push_interval_hours = config_obj.get('PUSH_INTERVAL_HOURS', 6)  # Default every 6 hours
        self.pull_interval_hours = config_obj.get('PULL_INTERVAL_HOURS', 12)  # Default every 12 hours
        
        # Mock admin user for automated operations
        self.system_user = {
            'id': 0,
            'username': 'system',
            'user_type': 'Admin',
            'branch_id': config_obj.get('BRANCH_ID', 1)
        }
    
    def setup_schedule(self):
        """Setup the synchronization schedule"""
        try:
            # Clear any existing schedules
            schedule.clear()
            
            if self.auto_push_enabled:
                # Schedule automatic push
                schedule.every(self.push_interval_hours).hours.do(self.scheduled_push)
                logger.info(f"Scheduled automatic push every {self.push_interval_hours} hours")
            
            if self.auto_pull_enabled:
                # Schedule automatic pull
                schedule.every(self.pull_interval_hours).hours.do(self.scheduled_pull)
                logger.info(f"Scheduled automatic pull every {self.pull_interval_hours} hours")
            
            # Schedule daily cleanup (remove old sync logs, etc.)
            schedule.every().day.at("02:00").do(self.daily_cleanup)
            logger.info("Scheduled daily cleanup at 02:00")
            
        except Exception as e:
            logger.error(f"Error setting up sync schedule: {e}")
    
    def scheduled_push(self):
        """Perform scheduled push to cloud"""
        try:
            logger.info("Starting scheduled push to cloud")
            result = self.cloud_sync_manager.push_to_cloud(self.system_user)
            
            if 'error' in result:
                logger.error(f"Scheduled push failed: {result['error']}")
            else:
                logger.info(f"Scheduled push completed successfully: {result.get('status')}")
                
                # Log summary of what was synced
                for table_result in result.get('results', []):
                    if table_result['status'] == 'success':
                        logger.info(f"Pushed {table_result['records']} records from {table_result['table']}")
                    elif table_result['status'] == 'error':
                        logger.warning(f"Failed to push {table_result['table']}: {table_result.get('message')}")
        
        except Exception as e:
            logger.error(f"Error in scheduled push: {e}")
    
    def scheduled_pull(self):
        """Perform scheduled pull from cloud"""
        try:
            logger.info("Starting scheduled pull from cloud")
            result = self.cloud_sync_manager.pull_from_cloud(self.system_user)
            
            if 'error' in result:
                logger.error(f"Scheduled pull failed: {result['error']}")
            else:
                logger.info(f"Scheduled pull completed successfully: {result.get('status')}")
                
                # Log summary of what was synced
                for table_result in result.get('results', []):
                    if table_result['status'] == 'success':
                        logger.info(f"Pulled {table_result['records']} records to {table_result['table']}")
                    elif table_result['status'] == 'error':
                        logger.warning(f"Failed to pull {table_result['table']}: {table_result.get('message')}")
        
        except Exception as e:
            logger.error(f"Error in scheduled pull: {e}")
    
    def daily_cleanup(self):
        """Perform daily cleanup tasks"""
        try:
            logger.info("Starting daily cleanup")
            
            # Clean up old sync logs (keep last 30 days)
            from datetime import timedelta
            cutoff_date = (datetime.now() - timedelta(days=30)).isoformat()
            
            # This would clean up old sync status records if needed
            # For now, we'll just log that cleanup ran
            logger.info("Daily cleanup completed")
        
        except Exception as e:
            logger.error(f"Error in daily cleanup: {e}")
    
    def run_scheduler(self):
        """Run the scheduler in a loop"""
        logger.info("Cloud sync scheduler started")
        
        while self.is_running:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}")
                time.sleep(60)  # Continue running even if there's an error
        
        logger.info("Cloud sync scheduler stopped")
    
    def start(self):
        """Start the sync scheduler"""
        if self.is_running:
            logger.warning("Sync scheduler is already running")
            return False
        
        try:
            self.setup_schedule()
            self.is_running = True
            
            # Start the scheduler in a separate thread
            self.scheduler_thread = threading.Thread(target=self.run_scheduler, daemon=True)
            self.scheduler_thread.start()
            
            logger.info("Cloud sync scheduler started successfully")
            return True
        
        except Exception as e:
            logger.error(f"Error starting sync scheduler: {e}")
            self.is_running = False
            return False
    
    def stop(self):
        """Stop the sync scheduler"""
        if not self.is_running:
            logger.warning("Sync scheduler is not running")
            return False
        
        try:
            self.is_running = False
            
            # Wait for the scheduler thread to finish
            if self.scheduler_thread and self.scheduler_thread.is_alive():
                self.scheduler_thread.join(timeout=5)
            
            # Clear the schedule
            schedule.clear()
            
            logger.info("Cloud sync scheduler stopped successfully")
            return True
        
        except Exception as e:
            logger.error(f"Error stopping sync scheduler: {e}")
            return False
    
    def get_status(self):
        """Get the current status of the scheduler"""
        try:
            next_jobs = []
            
            for job in schedule.jobs:
                next_jobs.append({
                    'job': str(job.job_func.__name__),
                    'next_run': job.next_run.isoformat() if job.next_run else None,
                    'interval': str(job.interval),
                    'unit': job.unit
                })
            
            return {
                'is_running': self.is_running,
                'auto_push_enabled': self.auto_push_enabled,
                'auto_pull_enabled': self.auto_pull_enabled,
                'push_interval_hours': self.push_interval_hours,
                'pull_interval_hours': self.pull_interval_hours,
                'scheduled_jobs': next_jobs,
                'last_check': datetime.now().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Error getting scheduler status: {e}")
            return {
                'is_running': self.is_running,
                'error': str(e)
            }
    
    def force_sync(self, sync_type='both'):
        """Force an immediate synchronization"""
        try:
            results = {}
            
            if sync_type in ['push', 'both']:
                logger.info("Forcing immediate push to cloud")
                push_result = self.cloud_sync_manager.push_to_cloud(self.system_user)
                results['push'] = push_result
            
            if sync_type in ['pull', 'both']:
                logger.info("Forcing immediate pull from cloud")
                pull_result = self.cloud_sync_manager.pull_from_cloud(self.system_user)
                results['pull'] = pull_result
            
            return {
                'status': 'completed',
                'sync_type': sync_type,
                'timestamp': datetime.now().isoformat(),
                'results': results
            }
        
        except Exception as e:
            logger.error(f"Error in force sync: {e}")
            return {
                'status': 'error',
                'message': str(e)
            }

if __name__ == '__main__':
    # Initialize and start the scheduler
    scheduler = CloudSyncScheduler(config)
    
    try:
        scheduler.start()
        
        # Keep the script running
        while True:
            time.sleep(60)
    
    except KeyboardInterrupt:
        logger.info("Stopping cloud sync scheduler...")
        scheduler.stop()
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        scheduler.stop()