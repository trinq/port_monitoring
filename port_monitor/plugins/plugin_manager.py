"""
Plugin manager for notification plugins.
Manages loading, registering, and calling notification plugins.
"""

import os
import logging
import importlib
from typing import Dict, List, Any, Optional

class NotificationPlugin:
    """Base class for notification plugins"""
    
    def __init__(self, config):
        """Initialize the notification plugin with configuration"""
        self.config = config
        self.enabled = False
    
    def is_enabled(self) -> bool:
        """Check if this plugin is enabled in configuration"""
        return self.enabled
    
    def send_notification(self, changes: Dict[str, Any]) -> bool:
        """Send notification with changes. To be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement send_notification")
    
    def format_message(self, changes: Dict[str, Any]) -> str:
        """Format changes for notification. May be overridden by subclasses."""
        message = "Port Monitoring Alert\n\n"
        
        # New hosts
        message += "New Hosts Detected:\n"
        if changes.get("new_hosts"):
            for host, data in changes["new_hosts"].items():
                ports_str = ", ".join(data["ports"].keys()) if "ports" in data else "No open ports"
                message += f"• {host} - Ports: {ports_str}\n"
        else:
            message += "• None\n"
        
        # New ports
        message += "\nNew Open Ports:\n"
        if changes.get("new_ports"):
            for host, ports in changes["new_ports"].items():
                for port, service in ports.items():
                    service_str = f"{service.get('name', 'unknown')} {service.get('product', '')} {service.get('version', '')}"
                    message += f"• {host} - {port} ({service_str.strip()})\n"
        else:
            message += "• None\n"
        
        # Closed ports
        message += "\nClosed Ports:\n"
        if changes.get("closed_ports"):
            for host, ports in changes["closed_ports"].items():
                if ports.get("all"):
                    message += f"• {host} - All ports (host down)\n"
                else:
                    for port in ports:
                        if port != "all":
                            message += f"• {host} - {port}\n"
        else:
            message += "• None\n"
        
        # Scan information
        message += f"\nScan Time: {os.environ.get('SCAN_TIME', 'Unknown')}"
        
        return message

class EmailNotificationPlugin(NotificationPlugin):
    """Email notification plugin"""
    
    def __init__(self, config):
        super().__init__(config)
        self.enabled = config.getboolean('Email', 'enabled', fallback=False)
    
    def send_notification(self, changes: Dict[str, Any]) -> bool:
        # Email notification logic from port_monitor.py
        logging.info("Sending email notification")
        
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText
            
            smtp_server = self.config.get('Email', 'smtp_server')
            smtp_port = self.config.getint('Email', 'smtp_port')
            smtp_user = self.config.get('Email', 'smtp_user')
            smtp_password = self.config.get('Email', 'smtp_password')
            sender_email = self.config.get('Email', 'sender_email')
            recipient_emails = self.config.get('Email', 'recipient_emails').split(',')
            
            if not (smtp_server and smtp_port and sender_email and recipient_emails):
                logging.error("Email configuration incomplete, cannot send notification")
                return False
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = ", ".join(recipient_emails)
            msg['Subject'] = f"[PORT MONITOR] Port Changes Detected"
            
            # Format email message as HTML
            body = self._format_html_message(changes)
            msg.attach(MIMEText(body, 'html'))
            
            # Implement retry logic for email sending
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    server = smtplib.SMTP(smtp_server, smtp_port)
                    server.ehlo()
                    server.starttls()
                    if smtp_user and smtp_password:
                        server.login(smtp_user, smtp_password)
                    server.send_message(msg)
                    server.close()
                    logging.info("Email notification sent successfully")
                    return True
                except Exception as e:
                    logging.error(f"Failed to send email notification (attempt {attempt+1}/{max_retries}): {e}")
                    if attempt < max_retries - 1:
                        import time
                        time.sleep(5)  # Wait before retrying
            
            logging.error("Maximum email retry attempts reached")
            return False
            
        except Exception as e:
            logging.error(f"Error sending email notification: {e}")
            return False
    
    def _format_html_message(self, changes: Dict[str, Any]) -> str:
        """Format changes for email notification in HTML"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; }
                table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .section { margin-top: 20px; margin-bottom: 10px; font-weight: bold; }
                .no-changes { color: #888; font-style: italic; }
            </style>
        </head>
        <body>
            <h2>Port Monitoring Alert</h2>
            <p>The following changes were detected in the latest scan:</p>
        """
        
        # New hosts
        html += "<div class='section'>New Hosts Detected:</div>"
        if changes.get("new_hosts"):
            html += "<table><tr><th>Host IP</th><th>Open Ports</th></tr>"
            for host, data in changes["new_hosts"].items():
                ports_str = ", ".join(data["ports"].keys()) if "ports" in data else "No open ports"
                html += f"<tr><td>{host}</td><td>{ports_str}</td></tr>"
            html += "</table>"
        else:
            html += "<div class='no-changes'>No new hosts detected</div>"
        
        # New ports
        html += "<div class='section'>New Open Ports:</div>"
        if changes.get("new_ports"):
            html += "<table><tr><th>Host IP</th><th>Port</th><th>Service</th></tr>"
            for host, ports in changes["new_ports"].items():
                for port, service in ports.items():
                    service_str = f"{service.get('name', 'unknown')} {service.get('product', '')} {service.get('version', '')}"
                    html += f"<tr><td>{host}</td><td>{port}</td><td>{service_str.strip()}</td></tr>"
            html += "</table>"
        else:
            html += "<div class='no-changes'>No new open ports detected</div>"
        
        # Closed ports
        html += "<div class='section'>Closed Ports:</div>"
        if changes.get("closed_ports"):
            html += "<table><tr><th>Host IP</th><th>Port</th></tr>"
            for host, ports in changes["closed_ports"].items():
                if ports.get("all"):
                    html += f"<tr><td>{host}</td><td>All ports (host down)</td></tr>"
                else:
                    for port in ports:
                        if port != "all":
                            html += f"<tr><td>{host}</td><td>{port}</td></tr>"
            html += "</table>"
        else:
            html += "<div class='no-changes'>No ports closed since last scan</div>"
        
        # Add scan metadata
        import datetime
        html += f"""
        <div class='section'>Scan Information:</div>
        <p>Scan Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>System: {os.uname().nodename}</p>
        <p>User: {os.environ.get('USER', 'unknown')}</p>
        """
        
        html += "</body></html>"
        return html

class SlackNotificationPlugin(NotificationPlugin):
    """Slack notification plugin"""
    
    def __init__(self, config):
        super().__init__(config)
        self.enabled = config.getboolean('Slack', 'enabled', fallback=False)
    
    def send_notification(self, changes: Dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        
        webhook_url = self.config.get('Slack', 'webhook_url')
        if not webhook_url:
            logging.error("Slack webhook URL not configured, cannot send notification")
            return False
        
        message = self.format_message(changes)
        
        # Implement retry logic for Slack notification
        try:
            import requests
            import time
            
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    response = requests.post(
                        webhook_url,
                        json={"text": message},
                        headers={"Content-Type": "application/json"},
                        timeout=10
                    )
                    if response.status_code == 200:
                        logging.info("Slack notification sent successfully")
                        return True
                    else:
                        logging.error(f"Failed to send Slack notification (attempt {attempt+1}/{max_retries}): {response.status_code}, {response.text}")
                        if attempt < max_retries - 1:
                            time.sleep(5)  # Wait before retrying
                except Exception as e:
                    logging.error(f"Error sending Slack notification (attempt {attempt+1}/{max_retries}): {e}")
                    if attempt < max_retries - 1:
                        time.sleep(5)  # Wait before retrying
            
            logging.error("Maximum Slack retry attempts reached")
            return False
            
        except Exception as e:
            logging.error(f"Error sending Slack notification: {e}")
            return False
    
    def format_message(self, changes: Dict[str, Any]) -> str:
        """Format changes for Slack notification"""
        text = "*Port Monitoring Alert*\n"
        text += "The following changes were detected in the latest scan:\n\n"
        
        # New hosts
        text += "*New Hosts Detected:*\n"
        if changes.get("new_hosts"):
            for host, data in changes["new_hosts"].items():
                ports_str = ", ".join(data["ports"].keys()) if "ports" in data else "No open ports"
                text += f"• {host} - Ports: {ports_str}\n"
        else:
            text += "• None\n"
        
        # New ports
        text += "\n*New Open Ports:*\n"
        if changes.get("new_ports"):
            for host, ports in changes["new_ports"].items():
                for port, service in ports.items():
                    service_str = f"{service.get('name', 'unknown')} {service.get('product', '')} {service.get('version', '')}"
                    text += f"• {host} - {port} ({service_str.strip()})\n"
        else:
            text += "• None\n"
        
        # Closed ports
        text += "\n*Closed Ports:*\n"
        if changes.get("closed_ports"):
            for host, ports in changes["closed_ports"].items():
                if ports.get("all"):
                    text += f"• {host} - All ports (host down)\n"
                else:
                    for port in ports:
                        if port != "all":
                            text += f"• {host} - {port}\n"
        else:
            text += "• None\n"
        
        import datetime
        text += f"\nScan Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        return text

class TelegramNotificationPlugin(NotificationPlugin):
    """Telegram notification plugin"""
    
    def __init__(self, config):
        super().__init__(config)
        self.enabled = config.getboolean('Telegram', 'enabled', fallback=False)
        self.bot_token = config.get('Telegram', 'bot_token', fallback='')
        self.chat_id = config.get('Telegram', 'chat_id', fallback='')
    
    def send_notification(self, changes: Dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        
        if not self.bot_token or not self.chat_id:
            logging.error("Telegram bot token or chat ID not configured, cannot send notification")
            return False
        
        message = self.format_message(changes)
        
        # Implement retry logic for Telegram notification
        try:
            import requests
            import time
            
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    response = requests.post(
                        url,
                        json={
                            "chat_id": self.chat_id,
                            "text": message,
                            "parse_mode": "Markdown"
                        },
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        logging.info("Telegram notification sent successfully")
                        return True
                    else:
                        logging.error(f"Failed to send Telegram notification (attempt {attempt+1}/{max_retries}): {response.status_code}, {response.text}")
                        if attempt < max_retries - 1:
                            time.sleep(5)  # Wait before retrying
                except Exception as e:
                    logging.error(f"Error sending Telegram notification (attempt {attempt+1}/{max_retries}): {e}")
                    if attempt < max_retries - 1:
                        time.sleep(5)  # Wait before retrying
            
            logging.error("Maximum Telegram retry attempts reached")
            return False
            
        except Exception as e:
            logging.error(f"Error sending Telegram notification: {e}")
            return False

class NotificationPluginManager:
    """Manager for notification plugins"""
    
    def __init__(self, config):
        self.config = config
        self.plugins = []
    
    def discover_plugins(self):
        """Discover and register all available notification plugins"""
        # Register built-in plugins
        self.plugins.append(EmailNotificationPlugin(self.config))
        self.plugins.append(SlackNotificationPlugin(self.config))
        self.plugins.append(TelegramNotificationPlugin(self.config))
        
        # Log registered plugins
        enabled_plugins = [type(p).__name__ for p in self.plugins if p.is_enabled()]
        if enabled_plugins:
            logging.info(f"Enabled notification plugins: {', '.join(enabled_plugins)}")
        else:
            logging.warning("No notification plugins are enabled")
    
    def send_notifications(self, changes: Dict[str, Any]) -> None:
        """Send notifications through all enabled plugins"""
        if not (changes.get("new_hosts") or changes.get("new_ports") or changes.get("closed_ports")):
            logging.info("No changes detected, not sending notifications")
            return
        
        success = False
        for plugin in self.plugins:
            if plugin.is_enabled():
                plugin_name = type(plugin).__name__
                logging.info(f"Sending notification via {plugin_name}")
                
                try:
                    if plugin.send_notification(changes):
                        success = True
                        logging.info(f"Successfully sent notification via {plugin_name}")
                    else:
                        logging.warning(f"Failed to send notification via {plugin_name}")
                except Exception as e:
                    logging.error(f"Error sending notification via {plugin_name}: {e}")
        
        if not success:
            logging.warning("Failed to send notifications through any enabled plugin")
