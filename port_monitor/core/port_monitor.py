"""
Core Port Monitor implementation following SOLID principles.
Orchestrates the scanning, analysis, and notification components.
"""

import os
import time
import logging
import signal
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any

from port_monitor.config.configuration import ConfigManager
from port_monitor.core.state_manager import StateManager
from port_monitor.scanning.base_scanner import BaseScanner
from port_monitor.scanning.nmap_scanner import NmapScanner
from port_monitor.analysis.analyzer import ResultAnalyzer
from port_monitor.analysis.result_parser import ResultParser
from port_monitor.notification.notification_manager import NotificationManager

class PortMonitor:
    """
    Main port monitor implementation that orchestrates the monitoring process
    following the Single Responsibility and Dependency Inversion principles
    """
    
    def __init__(self, config_file: str):
        """Initialize the port monitor with configuration"""
        # Initialize shutdown flag
        self.shutdown_requested = False
        
        # Initialize configuration
        self.config = ConfigManager(config_file)
        
        # Initialize components
        self.state_manager = StateManager(self.config.get_state_file())
        self.scanner = self._create_scanner()
        self.result_parser = ResultParser()
        self.analyzer = ResultAnalyzer()
        self.notification_manager = NotificationManager(self.config)
        
        # Set up signal handling
        self._setup_signal_handlers()
        
        # Check for interrupted scans
        self._check_interrupted_scan()
        
    def _create_scanner(self) -> BaseScanner:
        """Create the appropriate scanner based on configuration"""
        # For future extensibility, could select different scanner implementations
        scanner = NmapScanner(self.config)
        # Set the parent reference so the scanner can access the notification manager
        scanner._parent = self
        return scanner
    
    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown"""
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _signal_handler(self, sig: int, frame) -> None:
        """Handle shutdown signals"""
        logging.info(f"Received signal {sig}, initiating graceful shutdown...")
        self.shutdown_requested = True
    
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
                    self._process_scan_results(xml_file, scan_id)
                    return
            except Exception as e:
                logging.error(f"Error recovering partial results: {e}")
        
        logging.info("Could not recover partial scan results, will start a new scan")
        self.state_manager.set_scan_completed(success=False)
    
    def run_cycle(self) -> bool:
        """
        Run a single monitoring cycle
        
        Returns:
            True if the cycle completed successfully, False otherwise
        """
        logging.info("Starting port monitoring cycle")
        
        current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_id = current_time
        
        # Update state
        self.state_manager.set_scan_started(scan_id)
        
        # Send scan started notification
        try:
            target_ips = self._get_target_count()
            self.notification_manager.notify_scan_started(scan_id, target_ips)
        except Exception as e:
            logging.error(f"Error sending scan start notification: {e}")
        
        # Run the scan sequentially (one IP at a time)
        scan_result_file = self.scanner.run_scan_sequential(scan_id)
        
        if scan_result_file:
            success = self._process_scan_results(scan_result_file, scan_id)
            self.state_manager.set_scan_completed(success=success)
            
            # Send scan completed notification with detailed results
            try:
                # Get current scan results for detailed notification
                xml_file_path = scan_result_file  # This is the path to the combined XML file
                
                # Try to use the structured data stored in the scanner first
                structured_data_attr = f"_structured_data_{scan_id}"
                current_results = None
                
                # Check if the scanner has the structured data attribute
                if hasattr(self.scanner, structured_data_attr):
                    current_results = getattr(self.scanner, structured_data_attr)
                    logging.info(f"Using structured data from scanner attribute: {structured_data_attr}")
                    
                    # Add detailed debug logging for the structured data
                    if current_results and 'hosts' in current_results:
                        host_count = len(current_results['hosts'])
                        logging.info(f"Found {host_count} hosts in structured data")
                        
                        for ip, host_data in current_results.get('hosts', {}).items():
                            port_count = len(host_data.get('ports', {}))
                            logging.info(f"Structured data for {ip}: {port_count} open ports")
                    else:
                        logging.warning("No hosts found in structured data, or structured data is invalid")
                
                # Fallback to parsing the XML file if structured data is not available
                if not current_results or 'hosts' not in current_results or not current_results['hosts']:
                    logging.info("Falling back to XML parsing")
                    current_results = self.result_parser.parse_xml(xml_file_path)
                    
                    # Add detailed debug logging for the parsed results
                    if current_results:
                        logging.info(f"Parsed scan results successfully from XML: {xml_file_path}")
                        if 'hosts' in current_results:
                            logging.info(f"Number of hosts in XML results: {len(current_results['hosts'])}")
                            for ip, host_data in current_results.get('hosts', {}).items():
                                logging.info(f"Host details for {ip}: {len(host_data.get('ports', {}))} open ports")
                        else:
                            logging.warning("No 'hosts' key found in parsed XML results")
                    else:
                        logging.error("Failed to parse scan results from XML")
                
                # Get changes (if any)
                previous_scan_file = self._get_latest_history_file()
                previous_results = None
                changes = None
                
                if previous_scan_file:
                    previous_results = self.result_parser.parse_xml(previous_scan_file)
                    if previous_results:
                        changes = self.analyzer.compare_scans(current_results, previous_results)
                
                # Send detailed completion notification
                self.notification_manager.notify_scan_completed(
                    scan_id, success, target_ips, target_ips, 
                    scan_results=current_results, changes=changes)
                    
                # Log the key information for debugging
                logging.info(f"Sending completion notification with data: scan_id={scan_id}, success={success}, "
                             f"targets={target_ips}, scan_results keys={current_results.keys() if current_results else 'None'}")
                    
            except Exception as e:
                logging.error(f"Error sending scan completion notification: {e}", exc_info=True)
                
            logging.info(f"Port monitoring cycle completed (success={success})")
            return success
        else:
            logging.error("Scan failed, skipping analysis and notification")
            self.state_manager.set_scan_completed(success=False)
            
            # Send scan completed notification for failure case
            try:
                self.notification_manager.notify_scan_completed(
                    scan_id, False, 0, target_ips,
                    scan_results=None, changes=None)
            except Exception as e:
                logging.error(f"Error sending scan completion notification: {e}", exc_info=True)
                
            logging.info("Port monitoring cycle completed (success=False)")
            return False
    
    def run_continuous(self) -> None:
        """Run the port monitor continuously"""
        cycle_count = 0
        
        while not self.shutdown_requested:
            cycle_count += 1
            logging.info(f"Starting scan cycle #{cycle_count}")
            
            try:
                self.run_cycle()
            except Exception as e:
                logging.error(f"Error during scan cycle: {e}")
            
            # Check if shutdown was requested during the scan
            if self.shutdown_requested:
                logging.info("Shutdown requested, terminating continuous monitoring")
                break
            
            # Wait for the next scan interval with periodic checks for shutdown
            scan_interval = self.config.getint('Scan', 'scan_interval_minutes', fallback=240) * 60
            
            next_scan_time = datetime.now().timestamp() + scan_interval
            next_scan_str = datetime.fromtimestamp(next_scan_time).strftime('%Y-%m-%d %H:%M:%S')
            
            logging.info(f"Scan cycle #{cycle_count} completed. Waiting {scan_interval} seconds for next scan at {next_scan_str}")
            
            # Wait with periodic checks for shutdown
            self._wait_with_shutdown_check(scan_interval)
        
        logging.info("Port monitor has been shut down")
    
    def _wait_with_shutdown_check(self, wait_seconds: int) -> None:
        """
        Wait for specified seconds while periodically checking for shutdown requests
        
        Args:
            wait_seconds: Total time to wait in seconds
        """
        check_interval = 10  # Check for shutdown every 10 seconds
        waited = 0
        
        while waited < wait_seconds and not self.shutdown_requested:
            time.sleep(min(check_interval, wait_seconds - waited))
            waited += check_interval
            
            if waited % 300 == 0:  # Log every 5 minutes
                remaining = wait_seconds - waited
                if remaining > 0:
                    next_scan = datetime.now().timestamp() + remaining
                    next_scan_str = datetime.fromtimestamp(next_scan).strftime('%Y-%m-%d %H:%M:%S')
                    logging.info(f"Waiting for next scan cycle. Next scan at {next_scan_str} (in {remaining//60} minutes)")
    
    def _get_target_count(self) -> int:
        """Get the number of target IPs for scanning"""
        ip_list_file = self.config.get_ip_list_file()
        
        try:
            with open(ip_list_file, 'r') as f:
                return sum(1 for line in f if line.strip() and not line.strip().startswith('#'))
        except Exception as e:
            logging.error(f"Error reading IP list file: {e}")
            return 0
    
    def _process_scan_results(self, scan_file: str, scan_id: str) -> bool:
        """
        Process scan results, analyze changes, and send notifications
        
        Args:
            scan_file: Path to the scan results file
            scan_id: Unique identifier for this scan
            
        Returns:
            True if processing was successful, False otherwise
        """
        # Parse the current scan results
        current_results = self.result_parser.parse_xml(scan_file)
        
        if not current_results:
            logging.error("Failed to parse scan results")
            return False
            
        # Send notification for each individual IP in the scan results
        if current_results.get('hosts'):
            total_hosts = len(current_results['hosts'])
            logging.info(f"Processing scan results for {total_hosts} hosts")
            
            # Process individual host scan results
            for idx, (ip, host_data) in enumerate(current_results['hosts'].items(), 1):
                # Prepare scan data for this IP
                timestamp = current_results.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                scan_data = {
                    'timestamp': timestamp,
                    'ports': host_data.get('ports', {}),
                    'port_count': len(host_data.get('ports', {})),
                    'os': host_data.get('os', ''),
                    'status': host_data.get('status', 'unknown')
                }
                
                try:
                    # Send notification for this IP with position information
                    logging.info(f"Sending notification for IP {ip} ({idx}/{total_hosts})")
                    self.notification_manager.notify_ip_scanned(ip, scan_data, position=idx, total=total_hosts)
                except Exception as e:
                    logging.error(f"Error sending individual IP scan notification for {ip}: {e}")
        
        # Get previous scan results for comparison
        previous_scan_file = self._get_latest_history_file()
        previous_results = None
        
        if previous_scan_file:
            previous_results = self.result_parser.parse_xml(previous_scan_file)
            if not previous_results:
                logging.warning("Failed to parse previous scan results, treating as first scan")
        
        # Compare current and previous results to find changes
        changes = self.analyzer.compare_scans(current_results, previous_results)
        
        # Archive current scan results to history
        self._archive_scan_results(scan_file, scan_id)
        
        # Send notifications if there are changes
        if self.analyzer.has_changes(changes):
            logging.info("Changes detected, sending notifications")
            try:
                self.notification_manager.notify_changes(changes)
            except Exception as e:
                logging.error(f"Error sending change notifications: {e}")
                return False
        else:
            logging.info("No changes detected, skipping notifications")
        
        return True
    
    def _get_latest_history_file(self) -> Optional[str]:
        """Get the path to the latest history file"""
        history_dir = os.path.join(self.config.get_output_dir(), 'history')
        
        if not os.path.exists(history_dir):
            return None
            
        history_files = [os.path.join(history_dir, f) for f in os.listdir(history_dir) 
                         if f.startswith('scan_') and f.endswith('.xml')]
        
        if not history_files:
            return None
            
        # Sort files by modification time (newest first)
        history_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        
        return history_files[0]
    
    def _archive_scan_results(self, scan_file: str, scan_id: str) -> None:
        """
        Archive scan results to history directory
        
        Args:
            scan_file: Path to the scan results file
            scan_id: Unique identifier for this scan
        """
        if not os.path.exists(scan_file):
            logging.error(f"Cannot archive scan file {scan_file} - file not found")
            return
            
        history_dir = os.path.join(self.config.get_output_dir(), 'history')
        os.makedirs(history_dir, exist_ok=True)
        
        try:
            import shutil
            archive_file = os.path.join(history_dir, f"scan_{scan_id}.xml")
            shutil.copy2(scan_file, archive_file)
            logging.debug(f"Archived scan results to {archive_file}")
        except Exception as e:
            logging.error(f"Error archiving scan results: {e}")
