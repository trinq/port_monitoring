"""
Nmap scanner implementation for the Port Monitor system.
"""

import os
import subprocess
import shutil
import random
import time
import logging
import socket
from datetime import datetime
from typing import List, Dict, Optional, Any

from port_monitor.config.configuration import ConfigManager
from port_monitor.scanning.base_scanner import BaseScanner

class NmapScanner(BaseScanner):
    """Implementation of a port scanner using nmap"""
    
    def __init__(self, config: ConfigManager):
        """Initialize the nmap scanner with configuration"""
        self.config = config
        self.output_dir = config.get_output_dir()
        self.history_dir = config.get_history_dir()
        self.max_retries = config.getint('Reliability', 'max_retries', fallback=3)
        self.retry_delay_base = config.getint('Reliability', 'retry_delay_base_seconds', fallback=60)
        self.verification_enabled = config.getboolean('Reliability', 'verify_scan_results', fallback=True)
        self.verification_timeout = config.getint('Reliability', 'verification_timeout_seconds', fallback=5)
        self.verification_ports = config.get('Reliability', 'verification_ports', fallback='22,80,443').split(',')
    
    def run_scan(self, scan_id: str) -> Optional[str]:
        """Run nmap scan with retry mechanism and return the output file path"""
        xml_output = os.path.join(self.output_dir, f"scan_{scan_id}.xml")
        normal_output = os.path.join(self.output_dir, f"scan_{scan_id}.txt")
        
        # Send notifications for each IP being scanned
        self._notify_ip_scan_started(scan_id)
        
        # Create nmap command
        cmd = self._create_nmap_command(xml_output, normal_output)
        
        # Run scan with retry logic
        success = False
        attempt = 0
        
        while not success and attempt < self.max_retries:
            attempt += 1
            logging.info(f"Starting nmap scan (attempt {attempt}/{self.max_retries})")
            logging.debug(f"Command: {' '.join(cmd)}")
            
            try:
                # Start the scan process
                process = subprocess.Popen(
                    cmd, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                
                # Monitor the scan process
                try:
                    stdout, stderr = process.communicate()
                    
                    # Check scan result
                    if process.returncode == 0:
                        logging.info(f"Scan completed successfully. Output saved to {xml_output}")
                        success = True
                    else:
                        logging.error(f"Scan failed with return code {process.returncode}")
                        logging.error(f"STDOUT: {stdout}")
                        logging.error(f"STDERR: {stderr}")
                        
                        # Exponential backoff with jitter for retry
                        if attempt < self.max_retries:
                            delay = self.retry_delay_base * (2 ** (attempt - 1)) + random.uniform(0, self.retry_delay_base)
                            logging.info(f"Retrying in {delay:.1f} seconds...")
                            time.sleep(delay)
                except KeyboardInterrupt:
                    logging.warning("Scan interrupted, terminating nmap process")
                    process.terminate()
                    try:
                        process.wait(timeout=30)  # Give it 30 seconds to terminate gracefully
                    except subprocess.TimeoutExpired:
                        process.kill()  # Force kill if it doesn't terminate
                    return None
                    
            except Exception as e:
                logging.error(f"Exception during scan: {e}")
                # Exponential backoff with jitter for retry
                if attempt < self.max_retries:
                    delay = self.retry_delay_base * (2 ** (attempt - 1)) + random.uniform(0, self.retry_delay_base)
                    logging.info(f"Retrying in {delay:.1f} seconds...")
                    time.sleep(delay)
        
        if success:
            try:
                # Save to history with timestamp
                history_file = os.path.join(self.history_dir, f"scan_{scan_id}.xml")
                shutil.copy2(xml_output, history_file)
                
                # Verify scan results if enabled
                if self.verification_enabled:
                    if not self.verify_scan_results(xml_output):
                        logging.warning("Scan verification failed, results may be incomplete")
                        failed_dir = os.path.join(self.output_dir, 'failed')
                        os.makedirs(failed_dir, exist_ok=True)
                        shutil.copy2(xml_output, os.path.join(failed_dir, f"scan_{scan_id}.xml"))
                    else:
                        # Copy to verified directory if verification passes
                        verified_dir = os.path.join(self.output_dir, 'verified')
                        os.makedirs(verified_dir, exist_ok=True)
                        shutil.copy2(xml_output, os.path.join(verified_dir, f"scan_{scan_id}.xml"))
                
                return xml_output
            except Exception as e:
                logging.error(f"Error saving scan history: {e}")
        else:
            logging.error("Scan failed after all retry attempts")
        
        return None
    
    def verify_scan_results(self, output_file: str) -> bool:
        """Verify scan results for consistency and accuracy"""
        import xml.etree.ElementTree as ET
        logging.info(f"Verifying scan results: {output_file}")
        
        try:
            # First check if the XML file is valid
            try:
                tree = ET.parse(output_file)
                root = tree.getroot()
            except Exception as e:
                logging.error(f"XML parsing failed during verification: {e}")
                return False
            
            # Check if the scan has completed successfully
            if root.get('scanner') != 'nmap':
                logging.error("Not a valid nmap XML file")
                return False
                
            # Check if we have at least one host
            hosts = root.findall('./host')
            if not hosts:
                logging.warning("No hosts found in scan results")
                # This might be ok if there are truly no hosts
                return True
                
            # Verify a sample of ports on some hosts if deep verification is enabled
            if self.config.getboolean('Reliability', 'deep_verification', fallback=False):
                return self._perform_deep_verification(output_file)
            
            logging.info("Basic scan verification passed")
            return True
        
        except Exception as e:
            logging.error(f"Error during scan verification: {e}")
            return False
    
    def _perform_deep_verification(self, xml_file: str) -> bool:
        """Perform a deeper verification by directly checking a sample of ports"""
        import xml.etree.ElementTree as ET
        logging.info("Performing deep verification by checking sample ports")
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            hosts = root.findall('./host')
            
            # Get a sample of hosts to verify (max 3)
            sample_size = min(3, len(hosts))
            sample_hosts = random.sample(hosts, sample_size)
            
            if not self.verification_ports:
                logging.warning("No verification ports specified")
                return True  # Skip deep verification
            
            success_count = 0
            
            for host_elem in sample_hosts:
                addr_elem = host_elem.find('./address')
                if addr_elem is None or addr_elem.get('addrtype') != 'ipv4':
                    continue
                    
                ip = addr_elem.get('addr')
                logging.debug(f"Verifying host: {ip}")
                
                # Check a sample of ports
                for port in self.verification_ports:
                    try:
                        port = int(port.strip())
                        # Check if this port is reported as open in the scan
                        port_open_in_scan = False
                        
                        # Find all ports for this host
                        ports_elem = host_elem.findall('./ports/port')
                        for port_elem in ports_elem:
                            if port_elem.get('portid') == str(port):
                                state_elem = port_elem.find('./state')
                                if state_elem is not None and state_elem.get('state') == 'open':
                                    port_open_in_scan = True
                                    break
                        
                        # Verify the port directly
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(self.verification_timeout)
                        result = sock.connect_ex((ip, port))
                        sock.close()
                        
                        port_open_direct = (result == 0)
                        
                        # Compare results
                        if port_open_in_scan == port_open_direct:
                            logging.debug(f"Port {port} verification successful for {ip}")
                        else:
                            logging.warning(f"Port {port} verification failed for {ip}: scan={port_open_in_scan}, direct={port_open_direct}")
                            
                    except Exception as e:
                        logging.error(f"Error verifying port {port} on {ip}: {e}")
                
                success_count += 1
            
            # If we successfully verified at least one host, consider it a success
            verification_success = success_count > 0
            logging.info(f"Deep verification {'passed' if verification_success else 'failed'}: {success_count}/{sample_size} hosts verified")
            return verification_success
            
        except Exception as e:
            logging.error(f"Error during deep verification: {e}")
            return False
    
    def _notify_ip_scan_started(self, scan_id: str) -> None:
        """Send notifications for each IP being scanned"""
        ip_list_file = self.config.get_ip_list_file()
        logging.info(f"Starting to process IP scan notifications from file: {ip_list_file}")
        
        # Check if notification manager is available
        notification_manager = getattr(self, 'notification_manager', None)
        if not notification_manager:
            # Try to get it from the parent PortMonitor if available
            from port_monitor.core.port_monitor import PortMonitor
            parent = getattr(self, '_parent', None)
            if isinstance(parent, PortMonitor):
                notification_manager = getattr(parent, 'notification_manager', None)
                logging.info(f"Found notification manager from parent PortMonitor: {notification_manager is not None}")
            else:
                logging.warning(f"Parent is not PortMonitor or not available: {parent}")
        
        # If we can't find a notification manager, we can't send notifications
        if not notification_manager:
            logging.warning("Cannot send IP scan start notifications: notification manager not available")
            return
        
        # List enabled notifiers
        enabled_notifiers = [n.get_name() for n in notification_manager.notifiers if n.is_enabled()]
        logging.info(f"Enabled notification services: {', '.join(enabled_notifiers) if enabled_notifiers else 'None'}")
        
        try:
            # Read the IP list file
            if os.path.exists(ip_list_file):
                logging.info(f"Reading IP list from {ip_list_file}")
                with open(ip_list_file, 'r') as f:
                    ips = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                    total_ips = len(ips)
                    logging.info(f"Found {total_ips} IPs to process")
                    
                    for idx, ip in enumerate(ips, 1):  # Start from 1 for user-friendly position
                        try:
                            # Send notification for this IP with position information
                            result = notification_manager.notify_ip_scan_started(ip, scan_id, position=idx, total=total_ips)
                            logging.info(f"Sent scan start notification for IP: {ip} ({idx}/{total_ips}), result: {result}")
                        except Exception as e:
                            logging.error(f"Error sending scan start notification for IP {ip}: {e}", exc_info=True)
            else:
                logging.warning(f"IP list file not found: {ip_list_file}")
        except Exception as e:
            logging.error(f"Error reading IP list file: {e}", exc_info=True)
    
    def _create_nmap_command(self, xml_output: str, normal_output: str) -> List[str]:
        """Create the nmap command with appropriate arguments"""
        ip_list_file = self.config.get_ip_list_file()
        
        cmd = [
            "nmap", "-sS", "-sV", "-T4", "-Pn", "-n",
            "--scan-delay", self.config.get('Scan', 'scan_delay', fallback='0.5s'),
            "--max-rate", self.config.get('Scan', 'max_rate', fallback='100'),
            "--randomize-hosts",
        ]
        
        # Add custom ports if specified
        ports = self.config.get('Scan', 'ports', fallback='')
        if ports:
            cmd.extend(["-p", ports])
        
        # Add output options
        cmd.extend(["-oX", xml_output, "-oN", normal_output])
        
        # Add target IPs from file
        cmd.extend(["-iL", ip_list_file])
        
        return cmd