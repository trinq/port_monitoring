#!/usr/bin/env python3
"""
Entry point for the Port Monitor application.
"""

import os
import sys
import signal
import argparse
import time
import logging
from datetime import datetime

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from port_monitor.config.configuration import ConfigManager
from port_monitor.core.monitor import PortMonitor
from port_monitor.utils.logger import setup_logging

# Global flag for graceful shutdown
SHUTDOWN_REQUESTED = False

def signal_handler(sig, frame):
    """Handle signal for graceful shutdown"""
    global SHUTDOWN_REQUESTED
    logging.info(f"Received signal {sig}, initiating graceful shutdown...")
    SHUTDOWN_REQUESTED = True

def main():
    """Main function to run the port monitor"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Port Monitoring System - Continuous monitoring with alerting")
    parser.add_argument("-c", "--config", default="port_monitor.conf", help="Path to configuration file")
    parser.add_argument("--run-once", action="store_true", help="Run once and exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--version", action="store_true", help="Show version information")
    args = parser.parse_args()

    if args.version:
        from port_monitor import __version__
        print(f"Port Monitoring System version {__version__}")
        return 0

    # Set up logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Load configuration
        config_manager = ConfigManager(args.config)
        
        # Create and run the monitor
        monitor = PortMonitor(config_manager)
        
        if args.run_once:
            logging.info("Running a single monitoring cycle")
            monitor.run_cycle()
        else:
            scan_interval = config_manager.get_scan_interval()
            logging.info(f"Starting continuous monitoring with interval of {scan_interval} seconds")
            
            while not SHUTDOWN_REQUESTED:
                cycle_start = time.time()
                
                try:
                    monitor.run_cycle()
                except Exception as e:
                    logging.error(f"Error in monitoring cycle: {e}")
                
                # Sleep until next cycle, accounting for how long the current cycle took
                elapsed = time.time() - cycle_start
                sleep_time = max(0, scan_interval - elapsed)
                
                if SHUTDOWN_REQUESTED:
                    break
                
                if sleep_time > 0:
                    logging.info(f"Waiting {sleep_time:.1f} seconds until next scan cycle")
                    # Sleep in smaller increments to check for shutdown flag
                    for _ in range(int(sleep_time / 5) + 1):
                        if SHUTDOWN_REQUESTED:
                            break
                        time.sleep(min(5, sleep_time))
                else:
                    logging.warning("Scan cycle took longer than the configured interval")
        
        return 0
        
    except KeyboardInterrupt:
        logging.info("Monitoring stopped by user")
    except Exception as e:
        logging.exception(f"Unhandled error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())