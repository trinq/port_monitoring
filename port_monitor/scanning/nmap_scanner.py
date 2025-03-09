"""
Nmap scanner implementation for the Port Monitor system.
"""

import os
import subprocess
import shutil
import random
import time
import json
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
    
    def run_scan_sequential(self, scan_id: str) -> Optional[str]:
        """Run nmap scan for each IP one at a time in sequence"""
        # Create output directories
        os.makedirs(self.output_dir, exist_ok=True)
        temp_dir = os.path.join(self.output_dir, f"scan_{scan_id}_temp")
        os.makedirs(temp_dir, exist_ok=True)
        
        # Final output files
        final_xml_output = os.path.join(self.output_dir, f"scan_{scan_id}.xml")
        final_txt_output = os.path.join(self.output_dir, f"scan_{scan_id}.txt")
        
        # Read the IP list file
        ip_list_file = self.config.get_ip_list_file()
        if not os.path.exists(ip_list_file):
            logging.error(f"IP list file not found: {ip_list_file}")
            return None
            
        logging.info(f"Reading IP list from {ip_list_file}")
        with open(ip_list_file, 'r') as f:
            ips = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        
        total_ips = len(ips)
        logging.info(f"Found {total_ips} IPs to scan sequentially")
        
        # Get notification manager
        notification_manager = None
        if getattr(self, '_parent', None):
            notification_manager = getattr(self._parent, 'notification_manager', None)
        
        successful_scans = 0
        individual_results = []
        
        # Process each IP individually
        for idx, ip in enumerate(ips, 1):
            try:
                # Send notification for this IP with position information
                if notification_manager:
                    result = notification_manager.notify_ip_scan_started(ip, scan_id, position=idx, total=total_ips)
                    logging.info(f"Sent scan start notification for IP: {ip} ({idx}/{total_ips}), result: {result}")
                
                # Create temp files for this IP scan
                ip_xml_output = os.path.join(temp_dir, f"{ip}.xml")
                ip_txt_output = os.path.join(temp_dir, f"{ip}.txt")
                
                # Create a temporary file with just this IP
                ip_list_temp = os.path.join(temp_dir, f"{ip}.list")
                with open(ip_list_temp, 'w') as f:
                    f.write(f"{ip}\n")
                
                # Run nmap for this single IP
                logging.info(f"Scanning IP {idx}/{total_ips}: {ip}")
                
                # Create nmap command for this IP
                ports = self.config.get('Scan', 'ports', fallback='22,80,443,3389,8080')
                cmd = [
                    'nmap',
                    '-sS',                 # SYN scan
                    '-sV',                 # Version detection
                    '-T4',                 # Timing template (higher is faster)
                    '-Pn',                 # Skip host discovery
                    '-n',                  # No DNS resolution
                    '--scan-delay', '0.5s',  # Add delay between probes
                    '--max-rate', '100',   # Maximum number of packets sent per second
                    '--randomize-hosts',   # Randomize target host order
                    '-p', ports,           # Port specification
                    '-oX', ip_xml_output,  # XML output
                    '-oN', ip_txt_output,  # Normal output
                    '-iL', ip_list_temp    # Input from list
                ]
                
                # Run scan with retry logic for this IP
                success = False
                attempt = 0
                
                while not success and attempt < self.max_retries:
                    attempt += 1
                    logging.info(f"Starting nmap scan for {ip} (attempt {attempt}/{self.max_retries})")
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
                            if process.returncode == 0 and os.path.exists(ip_xml_output):
                                logging.info(f"Scan completed successfully for {ip}. Output saved to {ip_xml_output}")
                                success = True
                                successful_scans += 1
                                individual_results.append((ip, ip_xml_output, ip_txt_output))
                            else:
                                logging.error(f"Scan failed for {ip} with return code {process.returncode}")
                                if stdout: logging.error(f"STDOUT: {stdout}")
                                if stderr: logging.error(f"STDERR: {stderr}")
                                
                                # Exponential backoff with jitter for retry
                                if attempt < self.max_retries:
                                    delay = self.retry_delay_base * (2 ** (attempt - 1)) + random.uniform(0, self.retry_delay_base)
                                    logging.info(f"Retrying in {delay:.1f} seconds...")
                                    time.sleep(delay)
                        except KeyboardInterrupt:
                            logging.warning("Scan interrupted, terminating nmap process")
                            process.terminate()
                            raise
                    except Exception as e:
                        logging.error(f"Error during scan execution for {ip}: {e}")
                        if attempt < self.max_retries:
                            delay = self.retry_delay_base * (2 ** (attempt - 1)) + random.uniform(0, self.retry_delay_base)
                            logging.info(f"Retrying in {delay:.1f} seconds...")
                            time.sleep(delay)
                
                # If scan was successful, send the individual IP scan result notification
                if success and notification_manager and getattr(self._parent, 'result_parser', None):
                    try:
                        # Create a more direct way to get host results
                        logging.info(f"Reading scan results from {ip_xml_output}")
                        
                        # Direct XML parsing approach for this specific IP
                        try:
                            import xml.etree.ElementTree as ET
                            tree = ET.parse(ip_xml_output)
                            root = tree.getroot()
                            
                            # Check directly for host elements
                            hosts_found = root.findall('./host')
                            logging.info(f"Direct XML parsing found {len(hosts_found)} hosts")
                            
                            if hosts_found:
                                # Get IP address from the first host
                                addr_elem = hosts_found[0].find('./address')
                                actual_ip = addr_elem.get('addr') if addr_elem is not None else ip
                                logging.info(f"Found actual IP in scan: {actual_ip}")
                                
                                # Get status
                                status_elem = hosts_found[0].find('./status')
                                status = status_elem.get('state', 'unknown') if status_elem is not None else 'unknown'
                                
                                # Get ports
                                ports_dict = {}
                                for port_elem in hosts_found[0].findall('./ports/port'):
                                    port_id = port_elem.get('portid')
                                    protocol = port_elem.get('protocol')
                                    port_key = f"{port_id}/{protocol}"
                                    
                                    # Check if port is open
                                    state_elem = port_elem.find('./state')
                                    if state_elem is not None and state_elem.get('state') == 'open':
                                        # Get service info
                                        service_info = {
                                            'state': 'open',
                                            'reason': state_elem.get('reason', ''),
                                        }
                                        
                                        service_elem = port_elem.find('./service')
                                        if service_elem is not None:
                                            service_info.update({
                                                'name': service_elem.get('name', ''),
                                                'product': service_elem.get('product', ''),
                                                'version': service_elem.get('version', ''),
                                                'extrainfo': service_elem.get('extrainfo', '')
                                            })
                                        
                                        ports_dict[port_key] = service_info
                                        logging.debug(f"Found open port {port_key}: {service_info}")
                                
                                # Prepare scan data manually
                                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                scan_data = {
                                    'timestamp': timestamp,
                                    'ports': ports_dict,
                                    'port_count': len(ports_dict),
                                    'status': status
                                }
                                
                                # Send notification with the manually parsed data
                                logging.info(f"Sending scan result notification for {ip} with {len(ports_dict)} ports")
                                notification_manager.notify_ip_scanned(ip, scan_data, position=idx, total=total_ips)
                                logging.info(f"Sent scan result notification for IP: {ip} ({idx}/{total_ips})")
                            else:
                                logging.warning(f"No host elements found in XML for IP {ip}")
                                
                        except Exception as xml_parse_err:
                            logging.error(f"Direct XML parsing failed: {xml_parse_err}")
                            
                            # Fallback to the original parser as a backup
                            parser = getattr(self._parent, 'result_parser')
                            ip_scan_result = parser.parse_xml(ip_xml_output)
                            
                            if ip_scan_result and ip_scan_result.get('hosts', {}):
                                hosts = ip_scan_result.get('hosts', {})
                                if len(hosts) > 0:
                                    # Use the first host found
                                    actual_ip = list(hosts.keys())[0]
                                    host_data = hosts[actual_ip]
                                    
                                    # Prepare scan data
                                    scan_data = {
                                        'timestamp': host_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                                        'ports': host_data.get('ports', {}),
                                        'port_count': len(host_data.get('ports', {})),
                                        'status': host_data.get('status', 'unknown')
                                    }
                                    
                                    # Send notification
                                    notification_manager.notify_ip_scanned(ip, scan_data, position=idx, total=total_ips)
                                    logging.info(f"Sent scan result notification using fallback parser for IP: {ip} ({idx}/{total_ips})")
                    except Exception as e:
                        logging.error(f"Error sending scan result notification for {ip}: {e}")
            except Exception as e:
                logging.error(f"Error processing IP {ip}: {e}", exc_info=True)
        
        # All individual scans completed, now merge the results
        if not individual_results:
            logging.error("No individual IP scans were successful")
            return None
        
        # Store both XML host elements and structured data for each IP to use in notifications
        all_hosts_data = []
        combined_hosts_dict = {}
        
        for ip, xml_file, _ in individual_results:
            try:
                logging.info(f"Processing XML file {xml_file} for IP {ip}")
                # Parse the individual XML file to extract all information for XML combination
                try:
                    tree = ET.parse(xml_file)
                    root = tree.getroot()
                    # Extract host elements
                    host_elements = root.findall('./host')
                    if host_elements:
                        logging.info(f"Found {len(host_elements)} host elements in {xml_file}")
                        all_hosts_data.append((ip, host_elements[0]))
                        
                        # Also extract structured data for this host for notifications
                        host_element = host_elements[0]
                        status = 'unknown'
                        status_elem = host_element.find('./status')
                        if status_elem is not None:
                            status = status_elem.get('state', 'unknown')
                            
                        # Extract port information
                        ports_dict = {}
                        ports_elem = host_element.findall('./ports/port')
                        for port_elem in ports_elem:
                            port_id = port_elem.get('portid')
                            protocol = port_elem.get('protocol')
                            port_key = f"{port_id}/{protocol}"
                            
                            # Check if port is open
                            state_elem = port_elem.find('./state')
                            if state_elem is not None and state_elem.get('state') == 'open':
                                # Get service info
                                service_info = {
                                    'state': 'open',
                                    'reason': state_elem.get('reason', ''),
                                }
                                
                                service_elem = port_elem.find('./service')
                                if service_elem is not None:
                                    service_info.update({
                                        'name': service_elem.get('name', ''),
                                        'product': service_elem.get('product', ''),
                                        'version': service_elem.get('version', ''),
                                        'extrainfo': service_elem.get('extrainfo', '')
                                    })
                                
                                ports_dict[port_key] = service_info
                        
                        # Save structured data for this host
                        combined_hosts_dict[ip] = {
                            'status': status,
                            'ports': ports_dict,
                            'port_count': len(ports_dict)
                        }
                        logging.info(f"Saved structured data for {ip} with {len(ports_dict)} ports")
                        
                    else:
                        logging.warning(f"No host elements found in {xml_file}")
                except Exception as e:
                    logging.error(f"Error parsing XML file {xml_file}: {e}")
            except Exception as e:
                logging.error(f"Error processing file {xml_file} for IP {ip}: {e}")
                
        # Save the combined structured data as a JSON file for notification purposes
        combined_structured_data = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'hosts': combined_hosts_dict
        }
        
        # Write the structured data to a JSON file for debugging
        json_output = os.path.join(self.output_dir, f"scan_{scan_id}_structured.json")
        try:
            with open(json_output, 'w') as f:
                json.dump(combined_structured_data, f, indent=2)
            logging.info(f"Saved structured data to {json_output}")
        except Exception as e:
            logging.error(f"Error saving structured data to JSON: {e}")
            
        # Store the structured data as an attribute for use in notifications
        setattr(self, f"_structured_data_{scan_id}", combined_structured_data)
            
        # Create combined XML output with all parsed data
        with open(final_xml_output, 'w') as f:
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
            f.write('<!DOCTYPE nmaprun>\n')
            f.write(f'<nmaprun scanner="nmap" args="combined scan {scan_id}" start="{int(time.time())}" startstr="{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}" version="7.80">\n')
            
            f.write('  <scaninfo type="syn" protocol="tcp" services=""/>\n')
            f.write('  <verbose level="0"/>\n')
            f.write('  <debugging level="0"/>\n')
            
            # Include all host elements that we've extracted and parsed
            for ip, host_element in all_hosts_data:
                try:
                    # Convert the host element to string
                    host_xml = ET.tostring(host_element, encoding='unicode')
                    f.write(f'  {host_xml}\n')
                    logging.info(f"Added host data for IP {ip} to combined XML")
                except Exception as e:
                    logging.error(f"Error adding host data for IP {ip} to combined XML: {e}")
            
            # Close the root element
            f.write('  <runstats>\n')
            f.write(f'    <finished time="{int(time.time())}" timestr="{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}" summary="Combined scan complete"/>\n')
            f.write(f'    <hosts up="{successful_scans}" down="{total_ips - successful_scans}" total="{total_ips}"/>\n')
            f.write('  </runstats>\n')
            f.write('</nmaprun>\n')
        
        # Combine all text outputs
        with open(final_txt_output, 'w') as outfile:
            outfile.write(f"# Combined scan results for scan_id: {scan_id}\n")
            outfile.write(f"# Total IPs: {total_ips}, Successfully scanned: {successful_scans}\n\n")
            
            for ip, _, txt_file in individual_results:
                if os.path.exists(txt_file):
                    outfile.write(f"\n# --- Results for {ip} ---\n\n")
                    with open(txt_file, 'r') as infile:
                        outfile.write(infile.read())
                    outfile.write("\n")
        
        # Save to history
        if os.path.exists(final_xml_output):
            history_file = os.path.join(self.history_dir, f"scan_{scan_id}.xml")
            shutil.copy2(final_xml_output, history_file)
            logging.info(f"Saved combined scan results to history: {history_file}")
        
        return final_xml_output
    
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