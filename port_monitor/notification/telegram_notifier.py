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
    
    def _escape_markdown(self, text: str) -> str:
        """Escape special characters for Telegram MarkdownV2 format"""
        # Characters that need to be escaped: _ * [ ] ( ) ~ ` > # + - = | { } . !
        special_chars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
        for char in special_chars:
            text = text.replace(char, f'\\{char}')
        return text
    
    def _send_telegram_message(self, message: str) -> bool:
        """Send a message to Telegram chat"""
        token = self._get_bot_token()
        chat_id = self._get_chat_id()
        
        if not token or not chat_id:
            return False
        
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        
        # Use HTML instead of Markdown to avoid escaping issues
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML"
        }
        
        # For debugging
        logging.debug(f"Sending Telegram message: {message}")
        
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
        
        # Create message with HTML formatting
        message = "<b>⚠️ Port Changes Detected</b>\n\n"
        message += "The following changes were detected in the latest port scan:\n\n"
        
        # New hosts
        message += "<b>New Hosts Detected:</b>\n"
        if changes["new_hosts"]:
            for host, data in changes["new_hosts"].items():
                ports_str = ", ".join(data["ports"].keys())
                message += f"• {host} - Ports: {ports_str}\n"
        else:
            message += "<i>No new hosts detected</i>\n"
        
        message += "\n"
        
        # New ports
        message += "<b>New Open Ports:</b>\n"
        if changes["new_ports"]:
            for host, ports in changes["new_ports"].items():
                for port, service in ports.items():
                    service_str = f"{service.get('name', 'unknown')} {service.get('product', '')} {service.get('version', '')}"
                    message += f"• {host}:{port} - {service_str}\n"
        else:
            message += "<i>No new open ports detected</i>\n"
        
        message += "\n"
        
        # Closed ports
        message += "<b>Closed Ports:</b>\n"
        if changes["closed_ports"]:
            for host, ports in changes["closed_ports"].items():
                if "all" in ports:
                    message += f"• {host} - All ports (host down)\n"
                else:
                    for port in ports:
                        message += f"• {host}:{port}\n"
        else:
            message += "<i>No ports closed since last scan</i>\n"
        
        # Footer
        message += f"\n<i>Port Monitor | {changes.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</i>"
        
        return self._send_telegram_message(message)
    
    def notify_scan_started(self, scan_id: str, targets: int) -> bool:
        """Send Telegram notification about scan start"""
        if not self.is_enabled():
            return False
            
        logging.debug("Sending scan start Telegram notification")
        
        message = "<b>🔄 Port Scan Started</b>\n\n"
        message += f"A new port scan has been initiated.\n"
        message += f"<b>Scan ID:</b> {scan_id}\n"
        message += f"<b>Targets:</b> {targets} IP addresses\n"
        message += f"<b>Start Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        message += f"\n<i>Port Monitor | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
        
        return self._send_telegram_message(message)
    
    def notify_scan_completed(self, scan_id: str, success: bool, scanned: int, total: int, 
                              scan_results=None, changes=None) -> bool:
        """Send Telegram notification about scan completion with detailed port information"""
        if not self.is_enabled():
            return False
            
        # Enhanced debugging
        logging.debug("Sending scan completion Telegram notification with details")
        
        # Log scan_results details if available
        if scan_results:
            if isinstance(scan_results, dict):
                logging.info(f"TelegramNotifier received scan_results with keys: {', '.join(scan_results.keys())}")
                if 'hosts' in scan_results:
                    host_count = len(scan_results.get('hosts', {}))
                    logging.info(f"TelegramNotifier received information for {host_count} hosts")
                    
                    # Log details of each host
                    for ip, host_data in scan_results.get('hosts', {}).items():
                        port_count = len(host_data.get('ports', {}))
                        logging.info(f"TelegramNotifier host {ip} has {port_count} open ports")
                else:
                    logging.warning("TelegramNotifier: No 'hosts' key in scan_results")
            else:
                logging.warning(f"TelegramNotifier: scan_results is not a dictionary, it's a {type(scan_results)}.")
        else:
            logging.warning("TelegramNotifier: No scan_results provided")
        
        status = "✅ Successfully" if success else "❌ With Errors"
        percentage = (scanned / total) * 100 if total > 0 else 0
        
        message = f"<b>🏁 Port Scan Completed {status}</b>\n\n"
        message += f"The port scan has completed.\n"
        message += f"<b>Scan ID:</b> {scan_id}\n"
        message += f"<b>Completion Status:</b> {'Success' if success else 'Failed'}\n"
        message += f"<b>Scanned:</b> {scanned}/{total} IP addresses ({percentage:.1f}%)\n"
        message += f"<b>Completion Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        # Add summary port information for all hosts in a compact format
        if scan_results and isinstance(scan_results, dict) and scan_results.get('hosts'):
            message += "\n<b>📊 Port Monitoring Summary</b>\n"
            message += "\n<b>All Scanned Hosts:</b>\n"
            
            # Sort IPs numerically for better readability
            try:
                sorted_ips = sorted(scan_results.get('hosts', {}).keys(), 
                                  key=lambda ip: [int(octet) for octet in ip.split('.')])
                
                for ip in sorted_ips:
                    host_data = scan_results.get('hosts', {}).get(ip, {})
                    ports = host_data.get('ports', {})
                    
                    # Format the ports list in a compact format
                    port_list = []
                    if ports:
                        # Add safer port sorting that can handle non-numeric port values
                        def safe_port_sort(port_str):
                            try:
                                # Extract port number from string like "80/tcp"
                                port_num = port_str.split('/')[0]
                                if port_num.isdigit():
                                    return int(port_num)
                                # Handle special case 'all'
                                return 999999
                            except (ValueError, IndexError):
                                # Return a high number for non-standard formats to put them at the end
                                return 999999
                        
                        sorted_ports = sorted(ports.keys(), key=safe_port_sort)
                        port_list = sorted_ports
                    
                    # Create a compact representation of the ports
                    ports_str = ", ".join(port_list) if port_list else ""
                    
                    # Add this host to the message
                    message += f"• <b>{ip}</b> - Ports: {ports_str}\n"
            except Exception as e:
                logging.error(f"Error formatting IP summary: {e}")
                message += "• Error formatting host summary\n"
        
        # Add changes information if available
        # First, ensure changes is a dictionary before trying to access it
        if changes and isinstance(changes, dict):
            message += "\n<b>Port Monitoring Alert</b>\n"
            message += "The following changes were detected in the latest scan:\n"
            
            # New Hosts Detected section
            if changes.get('new_hosts') and isinstance(changes.get('new_hosts'), dict):
                message += "\n<b>New Hosts Detected:</b>\n"
                try:
                    sorted_ips = sorted(changes.get('new_hosts', {}).keys(), 
                                       key=lambda ip: [int(octet) for octet in ip.split('.')])
                    
                    if sorted_ips:
                        for ip in sorted_ips:
                            host_data = changes.get('new_hosts', {}).get(ip, {})
                            ports = host_data.get('ports', {})
                            
                            # Format the ports list in a compact format
                            port_list = []
                            if ports:
                                # Add safer port sorting that can handle non-numeric port values
                                def safe_port_sort(port_str):
                                    try:
                                        # Extract port number from string like "80/tcp"
                                        port_num = port_str.split('/')[0]
                                        if port_num.isdigit():
                                            return int(port_num)
                                        # Handle special case 'all'
                                        return 999999
                                    except (ValueError, IndexError):
                                        # Return a high number for non-standard formats to put them at the end
                                        return 999999
                                
                                sorted_ports = sorted(ports.keys(), key=safe_port_sort)
                                port_list = sorted_ports
                            
                            # Create a compact representation of the ports
                            ports_str = ", ".join(port_list) if port_list else ""
                            
                            # Add this host to the message
                            message += f"• <b>{ip}</b> - Ports: {ports_str}\n"
                    else:
                        message += "• None\n"
                except Exception as e:
                    logging.error(f"Error formatting new hosts section: {e}")
                    message += "• Error formatting new hosts section\n"
            else:
                message += "\n<b>New Hosts Detected:</b>\n• None\n"
            
            # New Open Ports
            if changes.get('new_ports') and isinstance(changes.get('new_ports'), dict) and any(changes.get('new_ports', {}).values()):
                message += "\n<b>New Open Ports:</b>\n"
                try:
                    sorted_ips = sorted(changes.get('new_ports', {}).keys(), 
                                       key=lambda ip: [int(octet) for octet in ip.split('.')])
                    
                    for ip in sorted_ips:
                        ports = changes.get('new_ports', {}).get(ip, {})
                        if ports:
                            # Add safer port sorting that can handle non-numeric port values
                            def safe_port_sort(port_str):
                                try:
                                    # Extract port number from string like "80/tcp"
                                    port_num = port_str.split('/')[0]
                                    if port_num.isdigit():
                                        return int(port_num)
                                    # Handle special case 'all'
                                    return 999999
                                except (ValueError, IndexError):
                                    # Return a high number for non-standard formats to put them at the end
                                    return 999999
                            
                            port_list = sorted(ports.keys(), key=safe_port_sort)
                            ports_str = ", ".join(port_list)
                            message += f"• <b>{ip}</b> - Ports: {ports_str}\n"
                except Exception as e:
                    logging.error(f"Error formatting new ports section: {e}")
                    message += "• Error formatting new ports section\n"
            else:
                message += "\n<b>New Open Ports:</b>\n• None\n"
            
            # Closed Ports
            if changes.get('closed_ports') and isinstance(changes.get('closed_ports'), dict) and any(changes.get('closed_ports', {}).values()):
                message += "\n<b>Closed Ports:</b>\n"
                try:
                    sorted_ips = sorted(changes.get('closed_ports', {}).keys(), 
                                       key=lambda ip: [int(octet) for octet in ip.split('.')])
                    
                    for ip in sorted_ips:
                        ports = changes.get('closed_ports', {}).get(ip, {})
                        if ports:
                            # Add safer port sorting that can handle non-numeric port values
                            def safe_port_sort(port_str):
                                try:
                                    # Extract port number from string like "80/tcp"
                                    port_num = port_str.split('/')[0]
                                    if port_num.isdigit():
                                        return int(port_num)
                                    # Handle special case 'all'
                                    return 999999
                                except (ValueError, IndexError):
                                    # Return a high number for non-standard formats to put them at the end
                                    return 999999
                            
                            port_list = sorted(ports.keys(), key=safe_port_sort)
                            ports_str = ", ".join(port_list)
                            message += f"• <b>{ip}</b> - Ports: {ports_str}\n"
                except Exception as e:
                    logging.error(f"Error formatting closed ports section: {e}")
                    message += "• Error formatting closed ports section\n"
            else:
                message += "\n<b>Closed Ports:</b>\n• None\n"
        
        message += f"\n<i>Port Monitor | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
        
        return self._send_telegram_message(message)
    
    def notify_ip_scan_started(self, ip: str, scan_id: str, position: int = 0, total: int = 0) -> bool:
        """Send Telegram notification that a scan has started for a specific IP address"""
        if not self.is_enabled():
            return False
            
        logging.debug(f"Sending IP scan start Telegram notification for {ip}")
        
        # Create ordinal string (1st, 2nd, 3rd, etc.)
        ordinal = ""  
        if position > 0 and total > 0:
            if position % 10 == 1 and position != 11:
                ordinal = f"{position}st"
            elif position % 10 == 2 and position != 12:
                ordinal = f"{position}nd"
            elif position % 10 == 3 and position != 13:
                ordinal = f"{position}rd"
            else:
                ordinal = f"{position}th"
        
        message = f"<b>🔍 IP Scan Started: {ip}</b>\n\n"
        
        if position > 0 and total > 0:
            message += f"Starting scan of the <b>{ordinal}</b> IP address out of <b>{total}</b> total.\n\n"
        
        message += f"<b>IP Address:</b> {ip}\n"
        message += f"<b>Scan ID:</b> {scan_id}\n"
        message += f"<b>Start Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        message += f"\n<i>Port Monitor | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
        
        return self._send_telegram_message(message)
    
    def notify_ip_scanned(self, ip: str, scan_data: Dict[str, Any], position: int = 0, total: int = 0) -> bool:
        """Send Telegram notification with details about a scanned IP
        
        Args:
            ip: The IP address that was scanned
            scan_data: Data from the scan result
            position: The position of this IP in the scan sequence (1-based)
            total: The total number of IPs being scanned
        """
        if not self.is_enabled():
            return False
            
        logging.debug(f"Sending IP scan Telegram notification for {ip}")
        
        message = f"<b>📊 IP Scan Results: {ip}</b>\n\n"
        
        # Add progress information if provided
        if position > 0 and total > 0:
            # Create ordinal string (1st, 2nd, 3rd, etc.)
            ordinal = ""
            if position % 10 == 1 and position != 11:
                ordinal = f"{position}st"
            elif position % 10 == 2 and position != 12:
                ordinal = f"{position}nd"
            elif position % 10 == 3 and position != 13:
                ordinal = f"{position}rd"
            else:
                ordinal = f"{position}th"
                
            message += f"Completed scan of the <b>{ordinal}</b> IP address out of <b>{total}</b> total.\n\n"
        
        message += f"<b>IP Address:</b> {ip}\n"
        message += f"<b>Scan Time:</b> {scan_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}\n\n"
        
        # Open ports
        message += "<b>Open Ports:</b>\n"
        if scan_data.get('ports', {}) and scan_data.get('port_count', 0) > 0:
            for port, service in scan_data.get('ports', {}).items():
                service_str = f"{service.get('name', 'unknown')} {service.get('product', '')} {service.get('version', '')}".strip()
                message += f"• {port} - {service_str}\n"
        else:
            message += "<i>No open ports detected</i>\n"
        
        message += f"\n<i>Port Monitor | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
        
        return self._send_telegram_message(message)
