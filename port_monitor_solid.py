#!/usr/bin/env python3
"""
Port Monitor SOLID - Continuously monitor open ports on specified IP addresses and alert on changes
Refactored to follow SOLID principles with clear separation of concerns
"""

import argparse
import logging
import os
import signal
import sys
import time
from datetime import datetime

# Add the proper path to import our modules
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from port_monitor.config.configuration import ConfigManager
from port_monitor.core.port_monitor import PortMonitor
from port_monitor.scanning.nmap_scanner import NmapScanner
from port_monitor.analysis.result_parser import ResultParser
from port_monitor.analysis.analyzer import ResultAnalyzer
from port_monitor.notification.notification_manager import NotificationManager

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("port_monitor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("port_monitor")

def main():
    """Main function to run the port monitor service"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Port Monitoring System - SOLID version")
    parser.add_argument("-c", "--config", default="port_monitor.conf", help="Path to configuration file")
    parser.add_argument("--run-once", action="store_true", help="Run once and exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Debug logging enabled")

    try:
        # Initialize the port monitor with configuration
        monitor = PortMonitor(args.config)
        
        # Print banner
        logger.info("=" * 80)
        logger.info("Port Monitor Service (SOLID Edition) - Starting")
        logger.info("=" * 80)
        
        # Choose run mode
        if args.run_once:
            logger.info("Running in single scan mode")
            monitor.run_cycle()
        else:
            logger.info("Running in continuous monitoring mode")
            monitor.run_continuous()
            
    except KeyboardInterrupt:
        logger.info("Port monitor stopped by user")
    except Exception as e:
        logger.exception(f"Unhandled error: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
"""
