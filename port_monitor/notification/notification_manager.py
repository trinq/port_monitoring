"""
Notification Manager for the Port Monitor system.
Implements the Dependency Inversion Principle by organizing all notification types
through common interfaces.
"""

import logging
import importlib
import inspect
import os
from typing import Dict, Any, List, Type

from port_monitor.config.configuration import ConfigManager
from port_monitor.notification.notification_interface import BaseNotifier, ChangeNotifier, ScanNotifier, IPScanNotifier

class NotificationManager:
    """
    Manages all notification services, following Dependency Inversion Principle
    by depending on abstractions (interfaces) rather than concrete implementations
    """
    
    def __init__(self, config: ConfigManager):
        """Initialize the notification manager with configuration"""
        self.config = config
        self.notifiers: List[BaseNotifier] = []
        self.load_notifiers()
        
    def load_notifiers(self) -> None:
        """Load and initialize all notification services"""
        # Import all built-in notifiers
        from port_monitor.notification.email_notifier import EmailNotifier
        from port_monitor.notification.slack_notifier import SlackNotifier
        from port_monitor.notification.teams_notifier import TeamsNotifier
        from port_monitor.notification.telegram_notifier import TelegramNotifier
        
        # Initialize built-in notifiers
        self.notifiers.append(EmailNotifier(self.config))
        self.notifiers.append(SlackNotifier(self.config))
        self.notifiers.append(TeamsNotifier(self.config))
        self.notifiers.append(TelegramNotifier(self.config))
        
        # Load custom notifiers from plugin directory if specified
        plugin_dir = self.config.get('Notification', 'plugin_dir', fallback='')
        if plugin_dir and os.path.exists(plugin_dir):
            self._load_notifier_plugins(plugin_dir)
        
        # Log enabled notifiers
        enabled_notifiers = [n.get_name() for n in self.notifiers if n.is_enabled()]
        if enabled_notifiers:
            logging.info(f"Enabled notification services: {', '.join(enabled_notifiers)}")
        else:
            logging.warning("No notification services are enabled")
    
    def _load_notifier_plugins(self, plugin_dir: str) -> None:
        """Load custom notifier plugins from directory"""
        try:
            for filename in os.listdir(plugin_dir):
                if filename.endswith('.py') and not filename.startswith('__'):
                    module_name = filename[:-3]  # Remove .py extension
                    
                    try:
                        # Import the module
                        spec = importlib.util.spec_from_file_location(
                            module_name, 
                            os.path.join(plugin_dir, filename)
                        )
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        
                        # Find all classes in the module that are notifier implementations
                        for name, obj in inspect.getmembers(module, inspect.isclass):
                            if (issubclass(obj, BaseNotifier) and 
                                obj is not BaseNotifier and 
                                obj is not ChangeNotifier and 
                                obj is not ScanNotifier and 
                                obj is not IPScanNotifier):
                                
                                # Initialize and add the notifier
                                notifier = obj(self.config)
                                self.notifiers.append(notifier)
                                logging.info(f"Loaded notifier plugin: {notifier.get_name()}")
                                
                    except Exception as e:
                        logging.error(f"Error loading notifier plugin {module_name}: {e}")
                        
        except Exception as e:
            logging.error(f"Error scanning plugin directory {plugin_dir}: {e}")
    
    def notify_changes(self, changes: Dict[str, Any]) -> None:
        """Send notifications about detected changes to all enabled change notifiers"""
        # Skip if no actual changes
        if not (changes.get("new_hosts") or changes.get("new_ports") or changes.get("closed_ports")):
            logging.info("No changes detected, skipping change notifications")
            return
            
        # Find all enabled change notifiers
        change_notifiers = [n for n in self.notifiers 
                            if isinstance(n, ChangeNotifier) and n.is_enabled()]
        
        if not change_notifiers:
            logging.warning("No enabled change notifiers found")
            return
            
        # Send notifications
        for notifier in change_notifiers:
            try:
                success = notifier.notify_changes(changes)
                if success:
                    logging.info(f"Successfully sent change notification via {notifier.get_name()}")
                else:
                    logging.warning(f"Failed to send change notification via {notifier.get_name()}")
            except Exception as e:
                logging.error(f"Error sending change notification via {notifier.get_name()}: {e}")
    
    def notify_scan_started(self, scan_id: str, targets: int) -> None:
        """Send notifications about scan start to all enabled scan notifiers"""
        # Find all enabled scan notifiers
        scan_notifiers = [n for n in self.notifiers 
                         if isinstance(n, ScanNotifier) and n.is_enabled()]
        
        if not scan_notifiers:
            return
            
        # Send notifications
        for notifier in scan_notifiers:
            try:
                success = notifier.notify_scan_started(scan_id, targets)
                if success:
                    logging.info(f"Successfully sent scan start notification via {notifier.get_name()}")
                else:
                    logging.warning(f"Failed to send scan start notification via {notifier.get_name()}")
            except Exception as e:
                logging.error(f"Error sending scan start notification via {notifier.get_name()}: {e}")
    
    def notify_scan_completed(self, scan_id: str, success: bool, scanned: int, total: int) -> None:
        """Send notifications about scan completion to all enabled scan notifiers"""
        # Find all enabled scan notifiers
        scan_notifiers = [n for n in self.notifiers 
                         if isinstance(n, ScanNotifier) and n.is_enabled()]
        
        if not scan_notifiers:
            return
            
        # Send notifications
        for notifier in scan_notifiers:
            try:
                notif_success = notifier.notify_scan_completed(scan_id, success, scanned, total)
                if notif_success:
                    logging.info(f"Successfully sent scan completion notification via {notifier.get_name()}")
                else:
                    logging.warning(f"Failed to send scan completion notification via {notifier.get_name()}")
            except Exception as e:
                logging.error(f"Error sending scan completion notification via {notifier.get_name()}: {e}")
    
    def notify_ip_scan_started(self, ip: str, scan_id: str, position: int = 0, total: int = 0) -> bool:
        """Send notifications about IP scan start to all enabled IP scan notifiers
        
        Args:
            ip: The IP address being scanned
            scan_id: The scan identifier
            position: The position of this IP in the scan sequence (1-based)
            total: The total number of IPs to be scanned
            
        Returns:
            bool: True if any notification was sent successfully
        """
        # Find all enabled IP scan notifiers
        ip_notifiers = [n for n in self.notifiers 
                       if isinstance(n, IPScanNotifier) and n.is_enabled()]
        
        if not ip_notifiers:
            logging.warning(f"No enabled IP scan notifiers found for {ip}")
            return False
            
        # Send notifications
        success_count = 0
        for notifier in ip_notifiers:
            try:
                success = notifier.notify_ip_scan_started(ip, scan_id, position, total)
                if success:
                    success_count += 1
                    logging.info(f"Successfully sent IP scan start notification for {ip} via {notifier.get_name()}")
                else:
                    logging.warning(f"Failed to send IP scan start notification for {ip} via {notifier.get_name()}")
            except Exception as e:
                logging.error(f"Error sending IP scan start notification for {ip} via {notifier.get_name()}: {e}")
        
        return success_count > 0
    
    def notify_ip_scanned(self, ip: str, scan_data: Dict[str, Any], position: int = 0, total: int = 0) -> bool:
        """Send notifications about individual IP scan to all enabled IP scan notifiers
        
        Args:
            ip: The IP address that was scanned
            scan_data: Data from the scan result
            position: The position of this IP in the scan sequence (1-based)
            total: The total number of IPs being scanned
            
        Returns:
            bool: True if any notification was sent successfully
        """
        # Find all enabled IP scan notifiers
        ip_notifiers = [n for n in self.notifiers 
                       if isinstance(n, IPScanNotifier) and n.is_enabled()]
        
        if not ip_notifiers:
            return False
            
        # Send notifications
        success_count = 0
        for notifier in ip_notifiers:
            try:
                success = notifier.notify_ip_scanned(ip, scan_data, position, total)
                if success:
                    success_count += 1
                    logging.info(f"Successfully sent IP scan notification for {ip} via {notifier.get_name()}")
                else:
                    logging.warning(f"Failed to send IP scan notification for {ip} via {notifier.get_name()}")
            except Exception as e:
                logging.error(f"Error sending IP scan notification for {ip} via {notifier.get_name()}: {e}")

