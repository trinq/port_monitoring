"""
Telegram notification implementation for Port Monitor system.
"""

import logging
import json
import time
import requests
from datetime import datetime
from typing import Dict, Any, List

from port_monitor.config.configuration import ConfigManager
from port_monitor.notification.notification_interface import ChangeNotifier, ScanNotifier, IPScanNotifier

class TelegramNotifier(ChangeNotifier, ScanNotifier, IPScanNotifier):
    """Telegram notification implementation that can handle all notification types"""
    
    def __init__(self, config: ConfigManager):
        """Initialize Telegram notifier with configuration"""
        self.config = config
        self.max_retries = 3
        
    def is_enabled(self) -> bool:
        """Check if Telegram notifications are enabled"""
        return self.config.getboolean('Telegram', 'enabled', fallback=False)
    
    def get_name(self) -> str:
        """Get the name of this notification service"""
        return "Telegram"
    
    def _get_bot_token(self) -> str:
        """Get Telegram bot token from configuration"""
        token = self.config.get('Telegram', 'bot_token', fallback='')
        if not token:
            logging.error("Telegram bot token not configured")
        return token
    
    def _get_chat_id(self) -> str:
        """Get Telegram chat ID from configuration"""
        chat_id = self.config.get('Telegram', 'chat_id', fallback='')
        if not chat_id:
            logging.error("Telegram chat ID not configured")
        return chat_id
    
    def _send_telegram_message(self, message: str) -> bool:
        """Send a message to Telegram chat"""
        token = self._get_bot_token()
        chat_id = self._get_chat_id()
        
        if not token or not chat_id:
            return False
        
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        
        # Prepare the payload
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "Markdown"
        }
        
        # Send the request with retry logic
        for attempt in range(self.max_retries):
            try:
                response = requests.post(url, json=payload, timeout=10)
                if response.status_code == 200:
                    return True
                else:
                    logging.error(f"Failed to send Telegram message. Status code: {response.status_code}, Response: {response.text}")
                    
                    if attempt < self.max_retries - 1:
                        time.sleep(2 ** attempt)  # Exponential backoff
                        
            except Exception as e:
                logging.error(f"Error sending Telegram message: {e}")
                
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
        
        return False
    
    def notify_changes(self, changes: Dict[str, Any]) -> bool:
        """Send Telegram notification about detected changes"""
        if not self.is_enabled():
            return False
            
        logging.debug("Sending changes Telegram notification")
        
        # Create message
        message = "*⚠️ Port Changes Detected*\n\n"
        message += "The following changes were detected in the latest port scan:\n\n"
        
        # New hosts
        message += "*New Hosts Detected:*\n"
        if changes["new_hosts"]:
            for host, data in changes["new_hosts"].items():
                ports_str = ", ".join(data["ports"].keys())
                message += f"• {host} - Ports: {ports_str}\n"
        else:
            message += "_No new hosts detected_\n"
        
        message += "\n"
        
        # New ports
        message += "*New Open Ports:*\n"
        if changes["new_ports"]:
            for host, ports in changes["new_ports"].items():
                for port, service in ports.items():
                    service_str = f"{service.get('name', 'unknown')} {service.get('product', '')} {service.get('version', '')}"
                    message += f"• {host}:{port} - {service_str}\n"
        else:
            message += "_No new open ports detected_\n"
        
        message += "\n"
        
        # Closed ports
        message += "*Closed Ports:*\n"
        if changes["closed_ports"]:
            for host, ports in changes["closed_ports"].items():
                if "all" in ports:
                    message += f"• {host} - All ports (host down)\n"
                else:
                    for port in ports:
                        message += f"• {host}:{port}\n"
        else:
            message += "_No ports closed since last scan_\n"
        
        # Footer
        message += f"\n_Port Monitor | {changes.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}_"
        
        return self._send_telegram_message(message)
    
    def notify_scan_started(self, scan_id: str, targets: int) -> bool:
        """Send Telegram notification about scan start"""
        if not self.is_enabled():
            return False
            
        logging.debug("Sending scan start Telegram notification")
        
        message = "*🔄 Port Scan Started*\n\n"
        message += f"A new port scan has been initiated.\n"
        message += f"*Scan ID:* {scan_id}\n"
        message += f"*Targets:* {targets} IP addresses\n"
        message += f"*Start Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        message += f"\n_Port Monitor | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_"
        
        return self._send_telegram_message(message)
    
    def notify_scan_completed(self, scan_id: str, success: bool, scanned: int, total: int) -> bool:
        """Send Telegram notification about scan completion"""
        if not self.is_enabled():
            return False
            
        logging.debug("Sending scan completion Telegram notification")
        
        status = "✅ Successfully" if success else "❌ With Errors"
        percentage = (scanned / total) * 100 if total > 0 else 0
        
        message = f"*🏁 Port Scan Completed {status}*\n\n"
        message += f"The port scan has completed.\n"
        message += f"*Scan ID:* {scan_id}\n"
        message += f"*Completion Status:* {'Success' if success else 'Failed'}\n"
        message += f"*Scanned:* {scanned}/{total} IP addresses ({percentage:.1f}%)\n"
        message += f"*Completion Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        message += f"\n_Port Monitor | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_"
        
        return self._send_telegram_message(message)
    
    def notify_ip_scan_started(self, ip: str, scan_id: str) -> bool:
        """Send Telegram notification that a scan has started for a specific IP address"""
        if not self.is_enabled():
            return False
            
        logging.debug(f"Sending IP scan start Telegram notification for {ip}")
        
        message = f"*🔍 IP Scan Started: {ip}*\n\n"
        message += f"A port scan has been initiated for this IP address.\n"
        message += f"*IP Address:* {ip}\n"
        message += f"*Scan ID:* {scan_id}\n"
        message += f"*Start Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        message += f"\n_Port Monitor | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_"
        
        return self._send_telegram_message(message)
    
    def notify_ip_scanned(self, ip: str, scan_data: Dict[str, Any]) -> bool:
        """Send Telegram notification with details about a scanned IP"""
        if not self.is_enabled() or not scan_data.get('ports'):
            return False
            
        logging.debug(f"Sending IP scan Telegram notification for {ip}")
        
        message = f"*📊 IP Scan Results: {ip}*\n\n"
        message += f"Scan completed for IP address {ip}\n"
        message += f"*Scan Time:* {scan_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}\n\n"
        
        # Open ports
        message += "*Open Ports:*\n"
        if scan_data.get('port_count', 0) > 0:
            for port, service in scan_data.get('ports', {}).items():
                service_str = f"{service.get('name', 'unknown')} {service.get('product', '')} {service.get('version', '')}".strip()
                message += f"• {port} - {service_str}\n"
        else:
            message += "_No open ports detected_\n"
        
        message += f"\n_Port Monitor | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_"
        
        return self._send_telegram_message(message)
