"""
Microsoft Teams notification implementation for Port Monitor system.
"""

import logging
import json
import time
import requests
from datetime import datetime
from typing import Dict, Any, List

from port_monitor.config.configuration import ConfigManager
from port_monitor.notification.notification_interface import ChangeNotifier, ScanNotifier

class TeamsNotifier(ChangeNotifier, ScanNotifier):
    """Microsoft Teams notification implementation"""
    
    def __init__(self, config: ConfigManager):
        """Initialize Teams notifier with configuration"""
        self.config = config
        self.max_retries = 3
        
    def is_enabled(self) -> bool:
        """Check if Teams notifications are enabled"""
        return self.config.getboolean('Teams', 'enabled', fallback=False)
    
    def get_name(self) -> str:
        """Get the name of this notification service"""
        return "Microsoft Teams"
    
    def _get_webhook_url(self) -> str:
        """Get Teams webhook URL from config"""
        return self.config.get('Teams', 'webhook_url', fallback='')
    
    def _send_teams_message(self, card: Dict[str, Any]) -> bool:
        """
        Send message to Microsoft Teams webhook with retry logic
        
        Args:
            card: Teams adaptive card payload
            
        Returns:
            True if message was sent successfully, False otherwise
        """
        if not self.is_enabled():
            return False
            
        webhook_url = self._get_webhook_url()
        if not webhook_url:
            logging.error("Teams webhook URL not configured")
            return False
            
        headers = {
            "Content-Type": "application/json"
        }
        
        # Implement retry logic
        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    webhook_url,
                    data=json.dumps(card),
                    headers=headers
                )
                
                if response.status_code == 200:
                    logging.info("Teams notification sent successfully")
                    return True
                else:
                    logging.warning(f"Failed to send Teams notification (attempt {attempt+1}/{self.max_retries}): HTTP {response.status_code}")
                    
            except Exception as e:
                logging.error(f"Error sending Teams notification (attempt {attempt+1}/{self.max_retries}): {e}")
                
            if attempt < self.max_retries - 1:
                time.sleep(5)  # Wait before retrying
                
        logging.error("Maximum Teams notification retry attempts reached")
        return False
    
    def notify_changes(self, changes: Dict[str, Any]) -> bool:
        """Send Teams notification about detected changes"""
        card = self._format_changes_for_teams(changes)
        return self._send_teams_message(card)
    
    def notify_scan_started(self, scan_id: str, targets: int) -> bool:
        """Send Teams notification about scan start"""
        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "body": [
                            {
                                "type": "TextBlock",
                                "size": "medium",
                                "weight": "bolder",
                                "text": "🔍 Port Scan Started"
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    {
                                        "title": "Scan ID",
                                        "value": scan_id
                                    },
                                    {
                                        "title": "Targets",
                                        "value": f"{targets} IP addresses"
                                    },
                                    {
                                        "title": "Start Time",
                                        "value": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                    }
                                ]
                            }
                        ],
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "version": "1.2"
                    }
                }
            ]
        }
        return self._send_teams_message(card)
    
    def notify_scan_completed(self, scan_id: str, success: bool, scanned: int, total: int) -> bool:
        """Send Teams notification about scan completion"""
        status = "Successfully" if success else "With Errors"
        percentage = (scanned / total) * 100 if total > 0 else 0
        
        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "body": [
                            {
                                "type": "TextBlock",
                                "size": "medium",
                                "weight": "bolder",
                                "text": f"🏁 Port Scan Completed {status}"
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    {
                                        "title": "Scan ID",
                                        "value": scan_id
                                    },
                                    {
                                        "title": "Status",
                                        "value": "Success" if success else "Failed"
                                    },
                                    {
                                        "title": "Scanned",
                                        "value": f"{scanned}/{total} IP addresses ({percentage:.1f}%)"
                                    },
                                    {
                                        "title": "Completion Time",
                                        "value": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                    }
                                ]
                            }
                        ],
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "version": "1.2"
                    }
                }
            ]
        }
        return self._send_teams_message(card)
    
    def _format_changes_for_teams(self, changes: Dict[str, Any]) -> Dict[str, Any]:
        """Format detected changes for Microsoft Teams notification"""
        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "body": [
                            {
                                "type": "TextBlock",
                                "size": "medium",
                                "weight": "bolder",
                                "text": "⚠️ Port Changes Detected"
                            },
                            {
                                "type": "TextBlock",
                                "text": "The following changes were detected in the latest port scan:",
                                "wrap": True
                            }
                        ],
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "version": "1.2"
                    }
                }
            ]
        }
        
        card_content = card["attachments"][0]["content"]["body"]
        
        # New hosts
        new_hosts_text = "**New Hosts Detected:**"
        if changes["new_hosts"]:
            for host, data in changes["new_hosts"].items():
                ports_str = ", ".join(data["ports"].keys())
                new_hosts_text += f"\n- {host} - Ports: {ports_str}"
        else:
            new_hosts_text += "\n*No new hosts detected*"
            
        card_content.append({
            "type": "TextBlock",
            "text": new_hosts_text,
            "wrap": True
        })
        
        # New ports
        new_ports_text = "**New Open Ports:**"
        if changes["new_ports"]:
            for host, ports in changes["new_ports"].items():
                for port, service in ports.items():
                    service_str = f"{service.get('name', 'unknown')} {service.get('product', '')} {service.get('version', '')}"
                    new_ports_text += f"\n- {host}:{port} - {service_str}"
        else:
            new_ports_text += "\n*No new open ports detected*"
            
        card_content.append({
            "type": "TextBlock",
            "text": new_ports_text,
            "wrap": True
        })
        
        # Closed ports
        closed_ports_text = "**Closed Ports:**"
        if changes["closed_ports"]:
            for host, ports in changes["closed_ports"].items():
                if "all" in ports:
                    closed_ports_text += f"\n- {host} - All ports (host down)"
                else:
                    for port in ports:
                        closed_ports_text += f"\n- {host}:{port}"
        else:
            closed_ports_text += "\n*No ports closed since last scan*"
            
        card_content.append({
            "type": "TextBlock",
            "text": closed_ports_text,
            "wrap": True
        })
        
        # Add footer
        card_content.append({
            "type": "TextBlock",
            "text": f"Port Monitor | {changes.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}",
            "isSubtle": True,
            "size": "small"
        })
        
        return card
"""
