"""
Notification interfaces for the Port Monitor system.
Defines contracts for notification implementations following Interface Segregation Principle.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseNotifier(ABC):
    """Base interface for all notification services"""
    
    @abstractmethod
    def is_enabled(self) -> bool:
        """Check if this notification service is enabled in config"""
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Get the name of this notification service"""
        pass


class ChangeNotifier(BaseNotifier):
    """Interface for services that notify about host/port changes"""
    
    @abstractmethod
    def notify_changes(self, changes: Dict[str, Any]) -> bool:
        """
        Send notification about detected changes
        
        Args:
            changes: Dictionary with detected changes
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        pass


class ScanNotifier(BaseNotifier):
    """Interface for services that notify about scan events"""
    
    @abstractmethod
    def notify_scan_started(self, scan_id: str, targets: int) -> bool:
        """
        Send notification that a scan has started
        
        Args:
            scan_id: Unique ID of the current scan
            targets: Number of targets being scanned
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        pass
    
    @abstractmethod
    def notify_scan_completed(self, scan_id: str, success: bool, scanned: int, total: int) -> bool:
        """
        Send notification that a scan has completed
        
        Args:
            scan_id: Unique ID of the scan
            success: Whether the scan completed successfully
            scanned: Number of targets successfully scanned
            total: Total number of targets
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        pass


class IPScanNotifier(BaseNotifier):
    """Interface for services that notify about individual IP scan events"""
    
    @abstractmethod
    def notify_ip_scanned(self, ip: str, scan_data: Dict[str, Any]) -> bool:
        """
        Send notification with details about a scanned IP
        
        Args:
            ip: The IP address that was scanned
            scan_data: Dictionary with scan results for this IP
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        pass
