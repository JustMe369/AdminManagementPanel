# run_device_monitors.py
import subprocess
import time
import os
import sys
import signal
from error_handling import logger

def run_monitors():
    """Start both device monitoring services"""
    try:
        # Get the directory of this script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Start the bandwidth monitor
        bandwidth_monitor_path = os.path.join(script_dir, 'device_bandwidth_monitor.py')
        bandwidth_process = subprocess.Popen([sys.executable, bandwidth_monitor_path])
        logger.info(f"Started bandwidth monitor with PID {bandwidth_process.pid}")
        
        # Start the connection monitor
        connection_monitor_path = os.path.join(script_dir, 'device_connection_monitor.py')
        connection_process = subprocess.Popen([sys.executable, connection_monitor_path])
        logger.info(f"Started connection monitor with PID {connection_process.pid}")
        
        # Setup signal handlers for graceful shutdown
        def signal_handler(sig, frame):
            logger.info("Shutting down monitors...")
            bandwidth_process.terminate()
            connection_process.terminate()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Keep the script running
        while True:
            # Check if processes are still running
            if bandwidth_process.poll() is not None:
                logger.error(f"Bandwidth monitor exited with code {bandwidth_process.returncode}")
                bandwidth_process = subprocess.Popen([sys.executable, bandwidth_monitor_path])
                logger.info(f"Restarted bandwidth monitor with PID {bandwidth_process.pid}")
            
            if connection_process.poll() is not None:
                logger.error(f"Connection monitor exited with code {connection_process.returncode}")
                connection_process = subprocess.Popen([sys.executable, connection_monitor_path])
                logger.info(f"Restarted connection monitor with PID {connection_process.pid}")
            
            time.sleep(10)  # Check every 10 seconds
    
    except KeyboardInterrupt:
        logger.info("Monitors stopped by user")
    except Exception as e:
        logger.error(f"Error running monitors: {e}")
    finally:
        # Ensure processes are terminated
        try:
            bandwidth_process.terminate()
            connection_process.terminate()
        except:
            pass

if __name__ == '__main__':
    run_monitors()