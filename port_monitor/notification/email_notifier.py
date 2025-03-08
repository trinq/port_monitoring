"""
Email notification implementation for Port Monitor system.
"""

import logging
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from typing import Dict, Any, List, Optional
import os

from port_monitor.config.configuration import ConfigManager
from port_monitor.notification.notification_interface import ChangeNotifier, ScanNotifier, IPScanNotifier

class EmailNotifier(ChangeNotifier, ScanNotifier, IPScanNotifier):
    """Email notification implementation that can handle all notification types"""
    
    def __init__(self, config: ConfigManager):
        """Initialize email notifier with configuration"""
        self.config = config
        self.max_retries = 3
        
    def is_enabled(self) -> bool:
        """Check if email notifications are enabled"""
        return self.config.getboolean('Email', 'enabled', fallback=False)
    
    def get_name(self) -> str:
        """Get the name of this notification service"""
        return "Email"
    
    def _get_email_config(self) -> Dict[str, Any]:
        """Get email configuration from config file"""
        return {
            'smtp_server': self.config.get('Email', 'smtp_server'),
            'smtp_port': self.config.getint('Email', 'smtp_port'),
            'smtp_user': self.config.get('Email', 'smtp_user', fallback=''),
            'smtp_password': self.config.get('Email', 'smtp_password', fallback=''),
            'sender_email': self.config.get('Email', 'sender_email'),
            'recipient_emails': self.config.get('Email', 'recipient_emails').split(',')
        }
    
    def _send_email(self, subject: str, body: str, html: bool = True) -> bool:
        """
        Send email with retry logic
        
        Args:
            subject: Email subject
            body: Email body content
            html: Whether the body is HTML (True) or plain text (False)
            
        Returns:
            True if email was sent successfully, False otherwise
        """
        if not self.is_enabled():
            return False
            
        email_config = self._get_email_config()
        
        if not (email_config['smtp_server'] and email_config['sender_email'] and email_config['recipient_emails']):
            logging.error("Email configuration incomplete, cannot send notification")
            return False
            
        # Create message
        msg = MIMEMultipart()
        msg['From'] = email_config['sender_email']
        msg['To'] = ", ".join(email_config['recipient_emails'])
        msg['Subject'] = subject
        
        if html:
            msg.attach(MIMEText(body, 'html'))
        else:
            msg.attach(MIMEText(body, 'plain'))
            
        # Implement retry logic for email sending
        for attempt in range(self.max_retries):
            try:
                server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
                server.ehlo()
                server.starttls()
                
                if email_config['smtp_user'] and email_config['smtp_password']:
                    server.login(email_config['smtp_user'], email_config['smtp_password'])
                    
                server.send_message(msg)
                server.close()
                logging.info("Email notification sent successfully")
                return True
                
            except Exception as e:
                logging.error(f"Failed to send email notification (attempt {attempt+1}/{self.max_retries}): {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(5)  # Wait before retrying
                    
        logging.error("Maximum email retry attempts reached")
        return False
    
    def notify_changes(self, changes: Dict[str, Any]) -> bool:
        """Send email notification about detected changes"""
        subject = f"[PORT MONITOR] Port Changes Detected - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        body = self._format_changes_for_email(changes)
        return self._send_email(subject, body, html=True)
    
    def notify_scan_started(self, scan_id: str, targets: int) -> bool:
        """Send email notification about scan start"""
        subject = f"[PORT MONITOR] Scan Started - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        body = f"""
        <html><body>
        <h2>Port Scan Started</h2>
        <p>A new port scan has been initiated.</p>
        <ul>
            <li><b>Scan ID:</b> {scan_id}</li>
            <li><b>Targets:</b> {targets} IP addresses</li>
            <li><b>Start Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</li>
            <li><b>System:</b> {os.uname().nodename}</li>
        </ul>
        </body></html>
        """
        return self._send_email(subject, body, html=True)
    
    def notify_scan_completed(self, scan_id: str, success: bool, scanned: int, total: int) -> bool:
        """Send email notification about scan completion"""
        subject = f"[PORT MONITOR] Scan Completed - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        
        status = "successfully" if success else "with errors"
        percentage = (scanned / total) * 100 if total > 0 else 0
        
        body = f"""
        <html><body>
        <h2>Port Scan Completed {status}</h2>
        <p>The port scan has completed.</p>
        <ul>
            <li><b>Scan ID:</b> {scan_id}</li>
            <li><b>Completion Status:</b> {'Success' if success else 'Failed'}</li>
            <li><b>Scanned:</b> {scanned}/{total} IP addresses ({percentage:.1f}%)</li>
            <li><b>Completion Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</li>
            <li><b>System:</b> {os.uname().nodename}</li>
        </ul>
        </body></html>
        """
        return self._send_email(subject, body, html=True)
    
    def notify_ip_scanned(self, ip: str, scan_data: Dict[str, Any]) -> bool:
        """Send email notification about an individual IP scan"""
        if not scan_data.get('ports'):
            return False
            
        subject = f"[PORT MONITOR] IP Scan Results: {ip} - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        
        # Build HTML body
        body = f"""
        <html><body>
        <h2>IP Scan Completed: {ip}</h2>
        <p>Scan Time: {scan_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>
        
        <h3>Open Ports:</h3>
        """
        
        if scan_data.get('port_count', 0) > 0:
            body += "<table border='1' cellpadding='5' cellspacing='0'>"
            body += "<tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>"
            
            for port, service in scan_data.get('ports', {}).items():
                body += f"<tr><td>{port}</td><td>{service.get('name', 'unknown')}</td>"
                body += f"<td>{service.get('product', '')}</td><td>{service.get('version', '')}</td></tr>"
                
            body += "</table>"
        else:
            body += "<p>No open ports detected</p>"
            
        body += "</body></html>"
        
        return self._send_email(subject, body, html=True)
    
    def _format_changes_for_email(self, changes: Dict[str, Any]) -> str:
        """Format detected changes for email notification"""
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
        if changes["new_hosts"]:
            html += "<table><tr><th>Host IP</th><th>Open Ports</th></tr>"
            for host, data in changes["new_hosts"].items():
                ports_str = ", ".join(data["ports"].keys())
                html += f"<tr><td>{host}</td><td>{ports_str}</td></tr>"
            html += "</table>"
        else:
            html += "<div class='no-changes'>No new hosts detected</div>"
        
        # New ports
        html += "<div class='section'>New Open Ports:</div>"
        if changes["new_ports"]:
            html += "<table><tr><th>Host IP</th><th>Port</th><th>Service</th></tr>"
            for host, ports in changes["new_ports"].items():
                for port, service in ports.items():
                    service_str = f"{service.get('name', 'unknown')} {service.get('product', '')} {service.get('version', '')}"
                    html += f"<tr><td>{host}</td><td>{port}</td><td>{service_str}</td></tr>"
            html += "</table>"
        else:
            html += "<div class='no-changes'>No new open ports detected</div>"
        
        # Closed ports
        html += "<div class='section'>Closed Ports:</div>"
        if changes["closed_ports"]:
            html += "<table><tr><th>Host IP</th><th>Port</th></tr>"
            for host, ports in changes["closed_ports"].items():
                if "all" in ports:
                    html += f"<tr><td>{host}</td><td>All ports (host down)</td></tr>"
                else:
                    for port in ports:
                        html += f"<tr><td>{host}</td><td>{port}</td></tr>"
            html += "</table>"
        else:
            html += "<div class='no-changes'>No ports closed since last scan</div>"
        
        # Add scan metadata
        html += f"""
        <div class='section'>Scan Information:</div>
        <p>Scan Time: {changes.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>
        <p>System: {os.uname().nodename}</p>
        <p>User: {os.environ.get('USER', 'unknown')}</p>
        """
        
        html += "</body></html>"
        return html
"""
