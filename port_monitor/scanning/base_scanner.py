"""
Base scanner interface for the Port Monitor system.
Defines the contract for scanner implementations.
"""

from abc import ABC, abstractmethod
from typing import Optional

class BaseScanner(ABC):
    """Abstract base class for port scanner implementations"""
    
    @abstractmethod
    def run_scan(self, scan_id: str) -> Optional[str]:
        """
        Run a port scan and return the path to the scan output file
        
        Args:
            scan_id: Unique identifier for this scan
            
        Returns:
            Path to the scan output file or None if the scan failed
        """
        pass
    
    @abstractmethod
    def verify_scan_results(self, output_file: str) -> bool:
        """
        Verify that scan results are valid
        
        Args:
            output_file: Path to the scan output file
            
        Returns:
            True if the results are valid, False otherwise
        """
        pass