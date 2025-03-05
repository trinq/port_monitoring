"""
Core Port Monitor implementation.
Orchestrates the scanning, analysis, and notification components.
"""

import os
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

from port_monitor.config.configuration import ConfigManager
from port_monitor.core.state_manager import StateManager
from port_monitor.scanning.nmap_scanner import NmapScanner
from port_monitor.analysis.analyzer import ResultAnalyzer
from port_monitor.analysis.result_parser import ResultParser
from port_monitor.plugins.plugin_manager import NotificationPluginManager

class PortMonitor:
    """Main port monitor implementation that orchestrates the monitoring process"""
    
    def __init__(self, config: ConfigManager):
        """Initialize the port monitor with configuration"""
        self.config = config
        self.state_manager = StateManager(config.get_state_file())
        self.scanner = NmapScanner(config)
        self.result_parser = ResultParser()
        self.analyzer = ResultAnalyzer()
        self.notification_manager = NotificationPluginManager(config)
        
        # Register built-in notification plugins
        self.notification_manager.discover_plugins()
        
        # Load state from previous runs
        self._check_interrupted_scan()
        
    def _check_interrupted_scan(self) -> None:
        """Check for and recover from interrupted scans"""
        if self.state_manager.is_scan_in_progress():
            scan_id = self.state_manager.get_current_scan_id()
            logging.warning(f"Previous scan {scan_id} was interrupted. Will attempt to recover.")
            self._recover_interrupted_scan(scan_id)
            
    def _recover_interrupted_scan(self, scan_id: str) -> None:
        """Attempt to recover from an interrupted scan"""
        logging.info(f"Attempting to recover from interrupted scan: {scan_id}")
        
        # Look for partial results
        xml_file = os.path.join(self.config.get_output_dir(), f"scan_{scan_id}.xml")
        
        if os.path.exists(xml_file):
            logging.info(f"Found partial scan results: {xml_file}")
            
            try:
                # Try to process the partial results
                scan_results = self.result_parser.parse_xml(xml_file)
                
                if scan_results:
                    logging.info("Successfully recovered partial scan results")
                    self._process_scan_results(xml_file)
                    return
            except Exception as e:
                logging.error(f"Error recovering partial results: {e}")
        
        logging.info("Could not recover partial scan results, will start a new scan")
        self.state_manager.set_scan_completed(success=False)
    
    def run_cycle(self) -> None:
        """Run a single monitoring cycle"""
        logging.info("Starting port monitoring cycle")
        
        current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Run the scan
        scan_result_file = self.scanner.run_scan(current_time)
        
        if scan_result_file:
            self._process_scan_results(scan_result_file)
        else:
            logging.error("Scan failed, skipping analysis and notification")
            self.state_manager.set_scan_completed(success=False)
            
        logging.info("Port monitoring cycle completed")
    
    def _process_scan_results(self, scan_file: str) -> None:
        """Process scan results, analyze changes, and send notifications"""
        # Parse the current scan results
        current_results = self.result_parser.parse_xml(scan_file)
        
        if not current_results:
            logging.error("Failed to parse scan results")
            self.state_manager.set_scan_completed(success=False)
            return
        
        # Get previous scan results for comparison
        previous_scan_file = self._get_latest_history_file()
        previous_results = None
        
        if previous_scan_file:
            previous_results = self.result_parser.parse_xml(previous_scan_file)
            if not previous_results:
                logging.warning("Failed to parse previous scan results, treating all ports as new")
        
        # Compare results to find changes
        changes = self.analyzer.compare_results(current_results, previous_results)
        
        # Log changes
        self._log_changes(changes)
        
        # Send notifications if there are changes
        self._send_notifications(changes)
        
        # Mark scan as completed successfully
        self.state_manager.set_scan_completed(success=True)
    
    def _get_latest_history_file(self) -> Optional[str]:
        """Get the latest history file"""
        history_dir = self.config.get_history_dir()
        
        try:
            history_files = sorted([
                f for f in os.listdir(history_dir) 
                if f.startswith("scan_") and f.endswith(".xml")
            ])
            
            if history_files:
                return os.path.join(history_dir, history_files[-1])
            return None
        except Exception as e:
            logging.error(f"Error getting latest history file: {e}")
            return None
    
    def _log_changes(self, changes: Dict[str, Any]) -> None:
        """Log detected changes"""
        if changes["new_hosts"]:
            logging.warning(f"New hosts detected: {', '.join(changes['new_hosts'].keys())}")
        
        if changes["new_ports"]:
            logging.warning(f"New open ports detected on {len(changes['new_ports'])} hosts")
            for host, ports in changes["new_ports"].items():
                logging.info(f"Host {host} has new open ports: {', '.join(ports.keys())}")
        
        if changes["closed_ports"]:
            logging.info(f"Ports closed on {len(changes['closed_ports'])} hosts")
    
    def _send_notifications(self, changes: Dict[str, Any]) -> None:
        """Send notifications for detected changes"""
        # Only send notifications if notifications are enabled and there are changes
        if not self.config.getboolean('Notification', 'enabled', fallback=True):
            logging.info("Notifications disabled in config")
            return
        
        if not (changes["new_hosts"] or changes["new_ports"] or changes["closed_ports"]):
            logging.info("No changes detected, no notifications sent")
            return
        
        # Send notifications through all registered plugins
        self.notification_manager.send_notifications(changes)