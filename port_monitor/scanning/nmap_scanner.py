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
                if addr_elem is None or addr_elem.get('