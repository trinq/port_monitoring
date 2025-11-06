"""
XML result parser for nmap scan results.
Extracts structured data from nmap XML output format.
"""

import os
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional
from datetime import datetime

class ResultParser:
    """Parses nmap XML scan results into structured data"""
    
    def parse_xml(self, xml_file: str) -> Optional[Dict[str, Any]]:
        """
        Parse nmap XML results into a structured dictionary
        
        Args:
            xml_file: Path to the XML result file
            
        Returns:
            Dictionary with structured scan results or None if parsing failed
        """
        if not os.path.exists(xml_file):
            logging.error(f"Scan file does not exist: {xml_file}")
            return None
            
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            hosts_total = len(root.findall('./host'))
            logging.info(f"Found {hosts_total} hosts in scan file")
            
            results = {}
            for host in root.findall('./host'):
                addr_elem = host.find('./address')
                if addr_elem is None:
                    logging.debug("Found host without address element, skipping")
                    continue
                    
                if addr_elem.get('addrtype') != 'ipv4':
                    logging.debug(f"Skipping non-IPv4 address of type {addr_elem.get('addrtype')}")
                    continue
                    
                ip = addr_elem.get('addr')
                logging.debug(f"Processing IP: {ip}")
                results[ip] = {'ports': {}}
                
                # Get host status
                status_elem = host.find('./status')
                if status_elem is not None:
                    results[ip]['status'] = status_elem.get('state')
                else:
                    results[ip]['status'] = 'unknown'
                
                # Process ports
                for port in host.findall('./ports/port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    port_key = f"{port_id}/{protocol}"

                    # Get state
                    state_elem = port.find('./state')
                    if state_elem is None:
                        continue

                    state = state_elem.get('state')
                    if state != 'open':
                        continue

                    # Get service info with comprehensive details
                    service_info = {
                        'state': state,
                        'reason': state_elem.get('reason', ''),
                    }

                    service_elem = port.find('./service')
                    if service_elem is not None:
                        service_info.update({
                            'name': service_elem.get('name', ''),
                            'product': service_elem.get('product', ''),
                            'version': service_elem.get('version', ''),
                            'extrainfo': service_elem.get('extrainfo', ''),
                            'ostype': service_elem.get('ostype', ''),
                            'method': service_elem.get('method', ''),
                            'conf': service_elem.get('conf', ''),  # Confidence level
                            'devicetype': service_elem.get('devicetype', ''),
                            'hostname': service_elem.get('hostname', ''),
                        })

                        # Extract CPE (Common Platform Enumeration) for vulnerability matching
                        cpe_list = []
                        for cpe_elem in service_elem.findall('./cpe'):
                            if cpe_elem.text:
                                cpe_list.append(cpe_elem.text)
                        if cpe_list:
                            service_info['cpe'] = cpe_list

                    # Extract script outputs (banner, http-title, ssl-cert, etc.)
                    scripts = {}
                    for script_elem in port.findall('./script'):
                        script_id = script_elem.get('id', '')
                        script_output = script_elem.get('output', '')

                        if script_id and script_output:
                            scripts[script_id] = script_output

                            # Parse specific useful scripts
                            if script_id == 'banner':
                                service_info['banner'] = script_output.strip()
                            elif script_id == 'http-title':
                                service_info['http_title'] = script_output.strip()
                            elif script_id == 'http-server-header':
                                service_info['http_server'] = script_output.strip()
                            elif script_id == 'ssl-cert':
                                # Extract basic SSL cert info from output
                                service_info['ssl_cert_info'] = script_output.strip()[:200]  # First 200 chars

                    if scripts:
                        service_info['scripts'] = scripts

                    results[ip]['ports'][port_key] = service_info
                
                # Count open ports
                results[ip]['port_count'] = len(results[ip]['ports'])
                results[ip]['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            return results
                
        except Exception as e:
            logging.error(f"Error parsing XML scan file: {e}")
            return None
