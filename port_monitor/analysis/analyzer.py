"""
Port scan result analyzer.
Compares scan results to identify changes in hosts and ports.
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional, List

class ResultAnalyzer:
    """Analyzes scan results to detect changes"""
    
    def compare_scans(self, current_scan: Dict[str, Any], previous_scan: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Compare current scan with previous scan to identify changes
        
        Args:
            current_scan: Results from the current scan
            previous_scan: Results from the previous scan or None
            
        Returns:
            Dictionary containing detected changes
        """
        changes = {
            "new_hosts": {},
            "new_ports": {},
            "closed_ports": {},
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        if not previous_scan:
            # First scan, all hosts are new
            changes["new_hosts"] = current_scan
            return changes
        
        # Find new hosts
        for host, data in current_scan.items():
            if host not in previous_scan:
                changes["new_hosts"][host] = data
        
        # Find new and closed ports
        for host, data in current_scan.items():
            if host in previous_scan:
                # Check for new ports
                for port, service in data["ports"].items():
                    if port not in previous_scan[host]["ports"]:
                        if host not in changes["new_ports"]:
                            changes["new_ports"][host] = {}
                        changes["new_ports"][host][port] = service
        
        # Check for closed ports
        for host, data in previous_scan.items():
            if host not in current_scan:
                # Host is down in current scan
                changes["closed_ports"][host] = {"all": "host down"}
            else:
                # Check for closed ports
                for port in data["ports"]:
                    if port not in current_scan[host]["ports"]:
                        if host not in changes["closed_ports"]:
                            changes["closed_ports"][host] = {}
                        changes["closed_ports"][host][port] = data["ports"][port]
        
        return changes
    
    def has_changes(self, changes: Dict[str, Any]) -> bool:
        """
        Check if any changes were detected
        
        Args:
            changes: The result of compare_scans()
            
        Returns:
            True if any changes were detected, False otherwise
        """
        return bool(changes["new_hosts"] or changes["new_ports"] or changes["closed_ports"])
