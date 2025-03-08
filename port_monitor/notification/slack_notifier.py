"""
Slack notification implementation for Port Monitor system.
"""

import logging
import json
import time
import requests
from datetime import datetime
from typing import Dict, Any, List

from port_monitor.config.configuration import ConfigManager
from port_monitor.notification.notification_interface import ChangeNotifier, ScanNotifier, IPScanNotifier

class SlackNotifier(ChangeNotifier, ScanNotifier, IPScanNotifier):
    """Slack notification implementation that can handle change and scan notifications"""
    
    def __init__(self, config: ConfigManager):
        """Initialize Slack notifier with configuration"""
        self.config = config
        self.max_retries = 3
        
    def is_enabled(self) -> bool:
        """Check if Slack notifications are enabled"""
        return self.config.getboolean('Slack', 'enabled', fallback=False)
    
    def get_name(self) -> str:
        """Get the name of this notification service"""
        return "Slack"
    
    def _get_webhook_url(self) -> str:
        """Get Slack webhook URL from config"""
        return self.config.get('Slack', 'webhook_url', fallback='')
    
    def _send_slack_message(self, blocks: List[Dict[str, Any]]) -> bool:
        """
        Send message to Slack webhook with retry logic
        
        Args:
            blocks: Slack message blocks
            
        Returns:
            True if message was sent successfully, False otherwise
        """
        if not self.is_enabled():
            return False
            
        webhook_url = self._get_webhook_url()
        if not webhook_url:
            logging.error("Slack webhook URL not configured")
            return False
            
        payload = {
            "blocks": blocks
        }
        
        headers = {
            "Content-Type": "application/json"
        }
        
        # Implement retry logic
        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    webhook_url,
                    data=json.dumps(payload),
                    headers=headers
                )
                
                if response.status_code == 200:
                    logging.info("Slack notification sent successfully")
                    return True
                else:
                    logging.warning(f"Failed to send Slack notification (attempt {attempt+1}/{self.max_retries}): HTTP {response.status_code}")
                    
            except Exception as e:
                logging.error(f"Error sending Slack notification (attempt {attempt+1}/{self.max_retries}): {e}")
                
            if attempt < self.max_retries - 1:
                time.sleep(5)  # Wait before retrying
                
        logging.error("Maximum Slack notification retry attempts reached")
        return False
    
    def notify_changes(self, changes: Dict[str, Any]) -> bool:
        """Send Slack notification about detected changes"""
        blocks = self._format_changes_for_slack(changes)
        return self._send_slack_message(blocks)
    
    def notify_scan_started(self, scan_id: str, targets: int) -> bool:
        """Send Slack notification about scan start"""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔍 Port Scan Started"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"A new port scan has been initiated.\n*Scan ID:* {scan_id}\n*Targets:* {targets} IP addresses\n*Start Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Port Monitor | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    }
                ]
            }
        ]
        return self._send_slack_message(blocks)
    
    def notify_scan_completed(self, scan_id: str, success: bool, scanned: int, total: int) -> bool:
        """Send Slack notification about scan completion"""
        status = ":white_check_mark: Successfully" if success else ":x: With Errors"
        percentage = (scanned / total) * 100 if total > 0 else 0
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🏁 Port Scan Completed {status}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"The port scan has completed.\n*Scan ID:* {scan_id}\n*Completion Status:* {'Success' if success else 'Failed'}\n*Scanned:* {scanned}/{total} IP addresses ({percentage:.1f}%)\n*Completion Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Port Monitor | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    }
                ]
            }
        ]
        return self._send_slack_message(blocks)
    
    def notify_ip_scan_started(self, ip: str, scan_id: str) -> bool:
        """Send Slack notification that a scan has started for a specific IP address"""
        if not self.is_enabled():
            return False
            
        logging.debug(f"Sending IP scan start Slack notification for {ip}")
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔍 IP Scan Started: {ip}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"A port scan has been initiated for this IP address.\n*IP Address:* {ip}\n*Scan ID:* {scan_id}\n*Start Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Port Monitor | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    }
                ]
            }
        ]
        return self._send_slack_message(blocks)
    
    def notify_ip_scanned(self, ip: str, scan_data: Dict[str, Any]) -> bool:
        """Send Slack notification with details about a scanned IP"""
        if not self.is_enabled() or not scan_data.get('ports'):
            return False
            
        logging.debug(f"Sending IP scan Slack notification for {ip}")
        
        # Create port list text
        port_text = ""
        for port, service in scan_data.get('ports', {}).items():
            service_str = f"{service.get('name', 'unknown')} {service.get('product', '')} {service.get('version', '')}".strip()
            port_text += f"\n• {port} - {service_str}"
        
        if not port_text:
            port_text = "\n_No open ports detected_"
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"📊 IP Scan Results: {ip}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Scan completed for IP address {ip}\n*Scan Time:* {scan_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Open Ports:*{port_text}"
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Port Monitor | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    }
                ]
            }
        ]
        return self._send_slack_message(blocks)
    
    def _format_changes_for_slack(self, changes: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format detected changes for Slack notification"""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "⚠️ Port Changes Detected"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "The following changes were detected in the latest port scan:"
                }
            }
        ]
        
        # New hosts
        new_hosts_text = "*New Hosts Detected:*"
        if changes["new_hosts"]:
            for host, data in changes["new_hosts"].items():
                ports_str = ", ".join(data["ports"].keys())
                new_hosts_text += f"\n• {host} - Ports: {ports_str}"
        else:
            new_hosts_text += "\n_No new hosts detected_"
            
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": new_hosts_text
            }
        })
        
        # New ports
        new_ports_text = "*New Open Ports:*"
        if changes["new_ports"]:
            for host, ports in changes["new_ports"].items():
                for port, service in ports.items():
                    service_str = f"{service.get('name', 'unknown')} {service.get('product', '')} {service.get('version', '')}"
                    new_ports_text += f"\n• {host}:{port} - {service_str}"
        else:
            new_ports_text += "\n_No new open ports detected_"
            
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": new_ports_text
            }
        })
        
        # Closed ports
        closed_ports_text = "*Closed Ports:*"
        if changes["closed_ports"]:
            for host, ports in changes["closed_ports"].items():
                if "all" in ports:
                    closed_ports_text += f"\n• {host} - All ports (host down)"
                else:
                    for port in ports:
                        closed_ports_text += f"\n• {host}:{port}"
        else:
            closed_ports_text += "\n_No ports closed since last scan_"
            
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": closed_ports_text
            }
        })
        
        # Add footer
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Port Monitor | {changes.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}"
                }
            ]
        })
        
        return blocks
