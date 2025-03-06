#!/usr/bin/env python3
"""
Port Monitor - Continuously monitor open ports on specified IP addresses and alert on changes
Enhanced with retry mechanisms, error recovery, and scan verification
"""

import argparse
import configparser
import json
import logging
import os
import subprocess
import smtplib
import sys
import time
import random
import shutil
import tempfile
import threading
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
import xml.etree.ElementTree as ET
import requests
import socket
import signal
import ipaddress

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("port_monitor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("port_monitor")

# Global flag for graceful shutdown
SHUTDOWN_REQUESTED = False

def signal_handler(sig, frame):
    """Handle signal for graceful shutdown"""
    global SHUTDOWN_REQUESTED
    logger.info(f"Received signal {sig}, initiating graceful shutdown...")
    SHUTDOWN_REQUESTED = True

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

class PortMonitor:
    def __init__(self, config_file):
        """Initialize the port monitor with configuration"""
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load_config()
        
        # Set up directories
        self.setup_directories()
        
        # Initialize state tracking
        self.current_scan_id = None
        self.scan_in_progress = False
        self.individual_ip_alerts = self.config.getboolean('Notification', 'individual_ip_alerts', fallback=True)
        self.load_state()
        
    def load_config(self):
        """Load configuration from file with fallback values"""
        try:
            self.config.read(self.config_file)
            
            # Basic configuration
            self.ip_list_file = self.config.get('Scan', 'ip_list_file')
            self.output_dir = self.config.get('General', 'output_dir')
            self.history_dir = os.path.join(self.output_dir, 'history')
            self.scan_interval = self.config.getint('Scan', 'scan_interval_minutes', fallback=240) * 60
            self.notification_enabled = self.config.getboolean('Notification', 'enabled', fallback=True)
            self.individual_ip_alerts = self.config.getboolean('Notification', 'individual_ip_alerts', fallback=True)
            
            # Reliability configuration
            self.max_retries = self.config.getint('Reliability', 'max_retries', fallback=3)
            self.retry_delay_base = self.config.getint('Reliability', 'retry_delay_base_seconds', fallback=60)
            self.verification_enabled = self.config.getboolean('Reliability', 'verify_scan_results', fallback=True)
            self.verification_ports = self.config.get('Reliability', 'verification_ports', fallback='22,80,443')
            self.verification_timeout = self.config.getint('Reliability', 'verification_timeout_seconds', fallback=5)
            self.state_file = self.config.get('Reliability', 'state_file', fallback='port_monitor_state.json')
            
            logger.info(f"Configuration loaded from {self.config_file}")
        except Exception as e:
            logger.error(f"Error loading configuration: {e}. Using default values.")
            # Set default values if config read fails
            self.ip_list_file = "unique_ips.txt"
            self.output_dir = "./port_monitor_output"
            self.history_dir = os.path.join(self.output_dir, 'history')
            self.scan_interval = 240 * 60
            self.notification_enabled = True
            self.individual_ip_alerts = True
            self.max_retries = 3
            self.retry_delay_base = 60
            self.verification_enabled = True
            self.verification_ports = '22,80,443'
            self.verification_timeout = 5
            self.state_file = 'port_monitor_state.json'
        
    def setup_directories(self):
        """Create necessary directories"""
        try:
            Path(self.output_dir).mkdir(parents=True, exist_ok=True)
            Path(self.history_dir).mkdir(parents=True, exist_ok=True)
            Path(os.path.join(self.output_dir, 'tmp')).mkdir(parents=True, exist_ok=True)
            Path(os.path.join(self.output_dir, 'verified')).mkdir(parents=True, exist_ok=True)
            Path(os.path.join(self.output_dir, 'failed')).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Error creating directories: {e}")
            raise
        
    def save_state(self):
        """Save current state to file for recovery"""
        state = {
            'last_scan_time': datetime.now().isoformat(),
            'current_scan_id': self.current_scan_id,
            'scan_in_progress': self.scan_in_progress
        }
        
        try:
            # Create a temporary file first to avoid corruption on system crash
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                json.dump(state, temp_file)
            
            # Replace the original file atomically
            shutil.move(temp_file.name, self.state_file)
        except Exception as e:
            logger.error(f"Error saving state: {e}")
            # Try to remove temp file if it exists
            try:
                if os.path.exists(temp_file.name):
                    os.remove(temp_file.name)
            except:
                pass
    
    def load_state(self):
        """Load state from file for recovery"""
        if not os.path.exists(self.state_file):
            logger.info("No state file found, starting fresh")
            return
        
        try:
            with open(self.state_file, 'r') as f:
                state = json.load(f)
                
            self.current_scan_id = state.get('current_scan_id')
            self.scan_in_progress = state.get('scan_in_progress', False)
            
            # Check if we have a scan in progress that needs recovery
            if self.scan_in_progress and self.current_scan_id:
                logger.warning(f"Previous scan {self.current_scan_id} was interrupted. Will attempt to recover.")
                self.recover_interrupted_scan()
            
        except Exception as e:
            logger.error(f"Error loading state: {e}")
    
    def recover_interrupted_scan(self):
        """Attempt to recover from an interrupted scan"""
        logger.info(f"Attempting to recover from interrupted scan: {self.current_scan_id}")
        
        # Look for partial results
        xml_file = os.path.join(self.output_dir, f"scan_{self.current_scan_id}.xml")
        if os.path.exists(xml_file):
            logger.info(f"Found partial scan results, will continue processing: {xml_file}")
            try:
                # Try to process the partial results
                results = self.parse_scan_results(xml_file)
                if results:
                    logger.info("Successfully recovered partial scan results")
                    self.process_scan_results(xml_file)
                    return
            except Exception as e:
                logger.error(f"Error recovering partial results: {e}")
        
        logger.info("Could not recover partial scan results, will start a new scan")
        self.scan_in_progress = False
        self.current_scan_id = None
        self.save_state()
        
    def send_ip_scan_started_notification(self, ip, attempt, max_retries):
        """Send notification that scanning an IP has started"""
        logger.info(f"Attempting to send scan start notification for IP {ip} (attempt {attempt}/{max_retries})")
        
        if not self.notification_enabled:
            logger.info(f"Notifications are disabled, skipping scan start alert for IP {ip}")
            return
            
        if not self.individual_ip_alerts:
            logger.info(f"Individual IP alerts are disabled, skipping scan start alert for IP {ip}")
            return
        
        # Only send start notifications if debug is enabled in config
        if not self.config.getboolean('Notification', 'send_scan_start_alerts', fallback=False):
            logger.debug(f"Scan start alerts are disabled in config, skipping for IP {ip}")
            return
            
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Create a notification message
        message = {
            "scan_started": {
                "timestamp": timestamp,
                "ip": ip,
                "attempt": attempt,
                "max_retries": max_retries
            }
        }
        
        try:
            notification_sent = False
            
            # Email notification
            if self.config.getboolean('Email', 'enabled', fallback=False):
                logger.info(f"Sending scan start email notification for IP {ip}")
                subject = f"[PORT MONITOR] Scan Started for {ip} - {timestamp}"
                body = f"Scan started for IP: {ip} (Attempt {attempt}/{max_retries})\n\nTimestamp: {timestamp}"
                self._send_simple_email(subject, body)
                notification_sent = True
            
            # Slack notification
            if self.config.getboolean('Slack', 'enabled', fallback=False):
                logger.info(f"Sending scan start Slack notification for IP {ip}")
                slack_text = f":satellite_antenna: *Scan started for IP: {ip}*\n>Attempt {attempt}/{max_retries}\n>Timestamp: {timestamp}"
                self._send_simple_slack(slack_text)
                notification_sent = True
            
            # Telegram notification
            if self.config.getboolean('Telegram', 'enabled', fallback=False):
                logger.info(f"Sending scan start Telegram notification for IP {ip}")
                telegram_text = f"🛰 *Scan started for IP: {ip}*\n\nAttempt {attempt}/{max_retries}\nTimestamp: {timestamp}"
                self._send_simple_telegram(telegram_text)
                notification_sent = True
                
            # Microsoft Teams notification
            if self.config.getboolean('Teams', 'enabled', fallback=False):
                logger.info(f"Sending scan start Teams notification for IP {ip}")
                teams_text = f"🛰 **Scan started for IP: {ip}**\n\nAttempt {attempt}/{max_retries}\nTimestamp: {timestamp}"
                self._send_simple_teams(teams_text)
                notification_sent = True
                
            if notification_sent:
                logger.info(f"Successfully sent scan start notification for IP {ip}")
            else:
                logger.debug(f"No scan start notifications were sent for IP {ip} - all notification channels are disabled")
        except Exception as e:
            logger.error(f"Error sending scan start notification for {ip}: {e}")
    
    def send_ip_scanned_notification(self, ip, scan_data):
        """Send notification that an IP has been scanned"""
        logger.info(f"Attempting to send notification for IP {ip}")
        
        if not self.notification_enabled:
            logger.info(f"Notifications are disabled, skipping alert for IP {ip}")
            return
            
        if not self.individual_ip_alerts:
            logger.info(f"Individual IP alerts are disabled, skipping alert for IP {ip}")
            return
            
        logger.info(f"Processing notification for IP {ip} with {len(scan_data.get('ports', {}))} open ports")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ports_info = {}
        
        # Format the port information
        if scan_data and 'ports' in scan_data:
            ports_info = scan_data['ports']
            port_list = list(ports_info.keys())
            logger.info(f"Found open ports for {ip}: {port_list[:5]}{'...' if len(port_list) > 5 else ''}")
        else:
            logger.info(f"No open ports found for {ip}")
        
        # Create a notification message
        message = {
            "ip_scan": {
                "ip": ip,
                "timestamp": timestamp,
                "port_count": len(ports_info),
                "ports": ports_info
            }
        }
        
        try:
            notification_sent = False
            
            # Email notification
            if self.config.getboolean('Email', 'enabled', fallback=False):
                logger.info(f"Sending email notification for IP {ip}")
                self._send_ip_scan_email(ip, message["ip_scan"])
                notification_sent = True
            else:
                logger.info("Email notifications disabled in config")
            
            # Slack notification
            if self.config.getboolean('Slack', 'enabled', fallback=False):
                logger.info(f"Sending Slack notification for IP {ip}")
                self._send_ip_scan_slack(ip, message["ip_scan"])
                notification_sent = True
            else:
                logger.info("Slack notifications disabled in config")
            
            # Telegram notification
            if self.config.getboolean('Telegram', 'enabled', fallback=False):
                logger.info(f"Sending Telegram notification for IP {ip}")
                self._send_ip_scan_telegram(ip, message["ip_scan"])
                notification_sent = True
            else:
                logger.info("Telegram notifications disabled in config")
                
            # Microsoft Teams notification
            if self.config.getboolean('Teams', 'enabled', fallback=False):
                logger.info(f"Sending Teams notification for IP {ip}")
                self._send_ip_scan_teams(ip, message["ip_scan"])
                notification_sent = True
            else:
                logger.info("Teams notifications disabled in config")
                
            if notification_sent:
                logger.info(f"Successfully sent scan notification for IP {ip}")
            else:
                logger.warning(f"No notifications were sent for IP {ip} - all notification channels are disabled")
        except Exception as e:
            logger.error(f"Error sending IP scan notification for {ip}: {e}")
    
    def _send_ip_scan_email(self, ip, scan_data):
        """Send email notification for a scanned IP"""
        smtp_server = self.config.get('Email', 'smtp_server')
        smtp_port = self.config.getint('Email', 'smtp_port')
        smtp_user = self.config.get('Email', 'smtp_user')
        smtp_password = self.config.get('Email', 'smtp_password')
        sender_email = self.config.get('Email', 'sender_email')
        recipient_emails = self.config.get('Email', 'recipient_emails').split(',')
        
        if not (smtp_server and smtp_port and sender_email and recipient_emails):
            return
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = ", ".join(recipient_emails)
        msg['Subject'] = f"[PORT MONITOR] IP Scan Completed - {ip} - {scan_data['timestamp']}"
        
        # Create HTML body
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .section {{ margin-top: 20px; margin-bottom: 10px; font-weight: bold; }}
                .no-ports {{ color: #888; font-style: italic; }}
            </style>
        </head>
        <body>
            <h2>IP Scan Completed: {ip}</h2>
            <p>Scan Time: {scan_data['timestamp']}</p>
            
            <div class='section'>Open Ports:</div>
        """
        
        if scan_data['port_count'] > 0:
            html += "<table><tr><th>Port</th><th>Service</th></tr>"
            for port, service in scan_data['ports'].items():
                service_str = f"{service.get('name', 'unknown')} {service.get('product', '')} {service.get('version', '')}"
                html += f"<tr><td>{port}</td><td>{service_str.strip()}</td></tr>"
            html += "</table>"
        else:
            html += "<div class='no-ports'>No open ports detected</div>"
        
        html += f"""
            <p>System: {os.uname().nodename}</p>
            <p>User: {os.environ.get('USER', 'unknown')}</p>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(html, 'html'))
        
        # Send email
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
                break
            except Exception as e:
                logger.error(f"Failed to send IP scan email notification for {ip} (attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(5)  # Wait before retrying
    
    def _send_ip_scan_slack(self, ip, scan_data):
        """Send Slack notification for a scanned IP"""
        webhook_url = self.config.get('Slack', 'webhook_url')
        if not webhook_url:
            return
        
        # Create message
        text = f"*IP Scan Completed: {ip}*\n"
        text += f"Scan Time: {scan_data['timestamp']}\n\n"
        
        text += "*Open Ports:*\n"
        if scan_data['port_count'] > 0:
            for port, service in scan_data['ports'].items():
                service_str = f"{service.get('name', 'unknown')} {service.get('product', '')} {service.get('version', '')}"
                text += f"• {port} - {service_str.strip()}\n"
        else:
            text += "• No open ports detected\n"
        
        # Send message
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    webhook_url,
                    json={"text": text},
                    headers={"Content-Type": "application/json"},
                    timeout=10
                )
                if response.status_code == 200:
                    break
                else:
                    logger.error(f"Failed to send IP scan Slack notification for {ip} (attempt {attempt+1}/{max_retries}): {response.status_code}, {response.text}")
                    if attempt < max_retries - 1:
                        time.sleep(5)  # Wait before retrying
            except Exception as e:
                logger.error(f"Error sending IP scan Slack notification for {ip} (attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(5)  # Wait before retrying
    
    def _send_ip_scan_telegram(self, ip, scan_data):
        """Send Telegram notification for a scanned IP"""
        bot_token = self.config.get('Telegram', 'bot_token')
        chat_id = self.config.get('Telegram', 'chat_id')
        
        if not bot_token or not chat_id:
            return
        
        # Create message
        text = f"*IP Scan Completed: {ip}*\n"
        text += f"Scan Time: {scan_data['timestamp']}\n\n"
        
        text += "*Open Ports:*\n"
        if scan_data['port_count'] > 0:
            for port, service in scan_data['ports'].items():
                service_str = f"{service.get('name', 'unknown')} {service.get('product', '')} {service.get('version', '')}"
                text += f"• {port} - {service_str.strip()}\n"
        else:
            text += "• No open ports detected\n"
        
        # Send message
        max_retries = 3
        for attempt in range(max_retries):
            try:
                url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                response = requests.post(
                    url,
                    json={
                        "chat_id": chat_id,
                        "text": text,
                        "parse_mode": "Markdown"
                    },
                    timeout=10
                )
                
                if response.status_code == 200:
                    break
                else:
                    logger.error(f"Failed to send IP scan Telegram notification for {ip} (attempt {attempt+1}/{max_retries}): {response.status_code}, {response.text}")
                    if attempt < max_retries - 1:
                        time.sleep(5)  # Wait before retrying
            except Exception as e:
                logger.error(f"Error sending IP scan Telegram notification for {ip} (attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(5)  # Wait before retrying
    
    def _send_simple_email(self, subject, body):
        """Send a simple email notification with custom subject and body"""
        try:
            if not self.config.getboolean('Email', 'enabled', fallback=False):
                return
                
            # Get email configuration
            smtp_server = self.config.get('Email', 'smtp_server')
            smtp_port = self.config.getint('Email', 'smtp_port')
            sender_email = self.config.get('Email', 'sender_email')
            recipient_emails = [email.strip() for email in self.config.get('Email', 'recipient_emails').split(',')]
            use_tls = self.config.getboolean('Email', 'use_tls', fallback=True)
            smtp_username = self.config.get('Email', 'smtp_username', fallback=None)
            smtp_password = self.config.get('Email', 'smtp_password', fallback=None)
            
            # Create a simple email message
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = ", ".join(recipient_emails)
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            # Send the email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if use_tls:
                    server.starttls()
                if smtp_username and smtp_password:
                    server.login(smtp_username, smtp_password)
                server.send_message(msg)
                
        except Exception as e:
            logger.error(f"Error sending simple email: {e}")
    
    def _send_simple_slack(self, message_text):
        """Send a simple Slack notification with custom text"""
        try:
            if not self.config.getboolean('Slack', 'enabled', fallback=False):
                return
                
            # Get Slack configuration
            webhook_url = self.config.get('Slack', 'webhook_url')
            
            # Prepare payload
            payload = {
                "text": message_text
            }
            
            # Send the notification
            response = requests.post(
                webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code != 200:
                logger.error(f"Error sending Slack notification: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"Error sending simple Slack notification: {e}")
    
    def _send_simple_telegram(self, message_text):
        """Send a simple Telegram notification with custom text"""
        try:
            if not self.config.getboolean('Telegram', 'enabled', fallback=False):
                return
                
            # Get Telegram configuration
            bot_token = self.config.get('Telegram', 'bot_token')
            chat_id = self.config.get('Telegram', 'chat_id')
            
            # Send the notification
            api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                "chat_id": chat_id,
                "text": message_text,
                "parse_mode": "Markdown"
            }
            
            response = requests.post(api_url, json=payload)
            
            if response.status_code != 200:
                logger.error(f"Error sending Telegram notification: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"Error sending simple Telegram notification: {e}")
            
    def _send_simple_teams(self, message_text):
        """Send a simple Microsoft Teams notification with custom text"""
        try:
            if not self.config.getboolean('Teams', 'enabled', fallback=False):
                return
                
            # Get Teams webhook configuration
            webhook_url = self.config.get('Teams', 'webhook_url')
            
            # Prepare payload
            payload = {
                "text": message_text
            }
            
            # Send the notification
            response = requests.post(webhook_url, json=payload, headers={'Content-Type': 'application/json'})
            
            if response.status_code != 200:
                logger.error(f"Error sending Teams notification: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"Error sending simple Teams notification: {e}")
            
    def _send_ip_scan_teams(self, ip, scan_data):
        """Send Microsoft Teams notification for a scanned IP"""
        webhook_url = self.config.get('Teams', 'webhook_url')
        if not webhook_url:
            return
        
        # Create message
        text = f"**IP Scan Completed: {ip}**\n\n"
        text += f"Scan Time: {scan_data['timestamp']}\n\n"
        
        text += "**Open Ports:**\n"
        if scan_data['port_count'] > 0:
            for port, service in scan_data['ports'].items():
                service_str = f"{service.get('name', 'unknown')} {service.get('product', '')} {service.get('version', '')}"
                text += f"• {port} - {service_str.strip()}\n"
        else:
            text += "• No open ports detected\n"
        
        # Send message
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    webhook_url,
                    json={"text": text},
                    headers={"Content-Type": "application/json"},
                    timeout=10
                )
                
                if response.status_code == 200:
                    break
                else:
                    logger.error(f"Failed to send IP scan Teams notification for {ip} (attempt {attempt+1}/{max_retries}): {response.status_code}, {response.text}")
                    if attempt < max_retries - 1:
                        time.sleep(5)  # Wait before retrying
            except Exception as e:
                logger.error(f"Error sending IP scan Teams notification for {ip} (attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(5)  # Wait before retrying
    
    def run_scan(self):
        """Run nmap scan with retry mechanism and return the output file path"""
        if self.scan_in_progress:
            logger.warning("Scan already in progress, skipping")
            return None
            
        # Generate scan ID based on timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.current_scan_id = timestamp
        self.scan_in_progress = True
        self.save_state()
        
        # Create temp directory for individual IP results
        ip_results_dir = os.path.join(self.output_dir, 'tmp', f"scan_{timestamp}")
        Path(ip_results_dir).mkdir(parents=True, exist_ok=True)
        
        xml_output = os.path.join(self.output_dir, f"scan_{timestamp}.xml")
        normal_output = os.path.join(self.output_dir, f"scan_{timestamp}.txt")
        
        # Create base nmap command
        cmd = [
            "nmap", "-sS", "-sV", "-T4", "-Pn", "-n",
            "--scan-delay", self.config.get('Scan', 'scan_delay', fallback='0.5s'),
            "--max-rate", self.config.get('Scan', 'max_rate', fallback='100'),
            "--randomize-hosts",
        ]
        
        # Add scripts if configured
        if self.config.getboolean('Scan', 'use_http_headers', fallback=False):
            cmd.extend([
                "--script", "http-headers",
                "--script-args", self.config.get('Scan', 'http_user_agent', fallback="Mozilla/5.0")
            ])
        
        # Modified: Use per-IP scan mode if individual alerts are enabled
        if self.individual_ip_alerts:
            ip_list = self._load_ip_list()
            logger.info(f"Individual IP alerts enabled: will scan {len(ip_list)} IPs separately")
            
            # Add remaining parameters but don't include the IP list file
            cmd.extend([
                "-p", self.config.get('Scan', 'ports', fallback="1-1000"),
                "--stats-every", "10s",
                "-v"
            ])
        else:
            # Standard mode: scan all IPs at once
            cmd.extend([
                "-p", self.config.get('Scan', 'ports', fallback="1-1000"),
                "--stats-every", "10s",
                "-oX", xml_output,
                "-oN", normal_output,
                "-v",
                "-iL", self.ip_list_file
            ])
        
        # Run scan with retry logic
        success = False
        attempt = 0
        
        # If using individual IP scans, handle differently
        if self.individual_ip_alerts:
            return self._run_individual_ip_scans(timestamp, cmd, ip_results_dir)
        
        # Standard scan mode for all IPs at once
        while not success and attempt < self.max_retries and not SHUTDOWN_REQUESTED:
            attempt += 1
            logger.info(f"Starting nmap scan (attempt {attempt}/{self.max_retries}) with command: {' '.join(cmd)}")
            
            try:
                # Start the scan process
                process = subprocess.Popen(
                    cmd, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                
                # Monitor the scan process with timeout capability
                while process.poll() is None:
                    if SHUTDOWN_REQUESTED:
                        logger.warning("Shutdown requested during scan, terminating nmap process")
                        process.terminate()
                        try:
                            process.wait(timeout=30)  # Give it 30 seconds to terminate gracefully
                        except subprocess.TimeoutExpired:
                            process.kill()  # Force kill if it doesn't terminate
                        break
                    time.sleep(1)
                
                # Check scan result
                if process.returncode == 0 and not SHUTDOWN_REQUESTED:
                    logger.info(f"Scan completed successfully. Output saved to {xml_output} and {normal_output}")
                    success = True
                elif SHUTDOWN_REQUESTED:
                    logger.warning("Scan aborted due to shutdown request")
                    break
                else:
                    stdout, stderr = process.communicate()
                    logger.error(f"Scan failed with return code {process.returncode}")
                    logger.error(f"STDOUT: {stdout}")
                    logger.error(f"STDERR: {stderr}")
                    
                    # Exponential backoff with jitter for retry
                    if attempt < self.max_retries:
                        delay = self.retry_delay_base * (2 ** (attempt - 1)) + random.uniform(0, self.retry_delay_base)
                        logger.info(f"Retrying in {delay:.1f} seconds...")
                        time.sleep(delay)
            except Exception as e:
                logger.error(f"Exception during scan: {e}")
                # Exponential backoff with jitter for retry
                if attempt < self.max_retries and not SHUTDOWN_REQUESTED:
                    delay = self.retry_delay_base * (2 ** (attempt - 1)) + random.uniform(0, self.retry_delay_base)
                    logger.info(f"Retrying in {delay:.1f} seconds...")
                    time.sleep(delay)
        
        if success:
            # Save to history with timestamp
            try:
                history_file = os.path.join(self.history_dir, f"scan_{timestamp}.xml")
                shutil.copy2(xml_output, history_file)
                
                # Mark scan as complete
                self.scan_in_progress = False
                self.save_state()
                
                # Verify scan results if enabled
                if self.verification_enabled:
                    if not self.verify_scan_results(xml_output):
                        logger.warning("Scan verification failed, results may be incomplete")
                        # Move to failed directory if verification fails
                        failed_dir = os.path.join(self.output_dir, 'failed')
                        shutil.copy2(xml_output, os.path.join(failed_dir, f"scan_{timestamp}.xml"))
                        return None
                    else:
                        # Copy to verified directory if verification passes
                        verified_dir = os.path.join(self.output_dir, 'verified')
                        shutil.copy2(xml_output, os.path.join(verified_dir, f"scan_{timestamp}.xml"))
                
                return xml_output
            except Exception as e:
                logger.error(f"Error saving scan history: {e}")
        else:
            logger.error("Scan failed after all retry attempts")
            # Mark scan as failed/complete
            self.scan_in_progress = False
            self.save_state()
        
        return None
    
    def verify_scan_results(self, xml_file):
        """Verify scan results for consistency and accuracy"""
        logger.info(f"Verifying scan results: {xml_file}")
        
        try:
            # First check if the XML file is valid
            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()
            except Exception as e:
                logger.error(f"XML parsing failed during verification: {e}")
                return False
            
            # Check if the scan has completed successfully
            if root.get('scanner') != 'nmap':
                logger.error("Not a valid nmap XML file")
                return False
                
            # Check if we have at least one host
            hosts = root.findall('./host')
            if not hosts:
                logger.warning("No hosts found in scan results")
                return False
                
            # Verify a sample of ports on some hosts
            if self.config.getboolean('Reliability', 'deep_verification', fallback=False):
                return self.perform_deep_verification(xml_file)
            
            logger.info("Basic scan verification passed")
            return True
        
        except Exception as e:
            logger.error(f"Error during scan verification: {e}")
            return False
    
    def _load_ip_list(self):
        """Load list of IPs to scan from file"""
        # Load the list of IPs to scan
        try:
            with open(self.ip_list_file, 'r') as f:
                ips_to_scan = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            logger.info(f"Loaded {len(ips_to_scan)} IPs from {self.ip_list_file}")
            return ips_to_scan
        except Exception as e:
            logger.error(f"Error loading IP list: {e}")
            return []
            
    def _run_individual_ip_scans(self, timestamp, base_cmd, ip_results_dir):
        """Run separate scans for each IP and process results immediately"""
        logger.info("Starting individual IP scans with immediate alerts")
        
        ip_list = self._load_ip_list()
        if not ip_list:
            logger.error("No IPs to scan")
            return None
            
        successful_scans = 0
        main_xml_file = os.path.join(self.output_dir, f"scan_{timestamp}.xml")
        
        # Create a root XML for the combined results
        combined_root = ET.Element('nmaprun')
        combined_root.set('scanner', 'nmap')
        combined_root.set('start', str(int(time.time())))
        combined_root.set('version', '7.80')
        combined_tree = ET.ElementTree(combined_root)
        
        # Process each IP individually
        for ip_index, ip in enumerate(ip_list):
            if SHUTDOWN_REQUESTED:
                logger.warning("Shutdown requested, stopping IP scans")
                break
                
            ip_xml_file = os.path.join(ip_results_dir, f"{ip.replace('.', '_')}.xml")
            ip_normal_file = os.path.join(ip_results_dir, f"{ip.replace('.', '_')}.txt")
            
            # Create the IP-specific command
            ip_cmd = base_cmd.copy()
            ip_cmd.extend([
                "-oX", ip_xml_file,
                "-oN", ip_normal_file,
                ip
            ])
            
            logger.info(f"Scanning IP {ip_index+1}/{len(ip_list)}: {ip}")
            
            # Run the scan for this IP
            attempt = 0
            ip_success = False
            
            while not ip_success and attempt < self.max_retries and not SHUTDOWN_REQUESTED:
                attempt += 1
                try:
                    logger.debug(f"Starting scan for IP {ip} (attempt {attempt}/{self.max_retries})")
                    
                    # Send notification that scan is starting for this IP
                    self.send_ip_scan_started_notification(ip, attempt, self.max_retries)
                    
                    process = subprocess.Popen(
                        ip_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        universal_newlines=True
                    )
                    
                    # Wait for the process to complete
                    stdout, stderr = process.communicate()
                    
                    if process.returncode == 0:
                        logger.info(f"Scan completed successfully for IP {ip}")
                        ip_success = True
                        successful_scans += 1
                        
                        # Process this IP's results immediately
                        try:
                            if os.path.exists(ip_xml_file) and os.path.getsize(ip_xml_file) > 0:
                                # Extract the scan results for this IP
                                ip_scan_data = self.extract_scanned_ips(ip_xml_file)
                                
                                # Send notifications for this IP
                                if ip in ip_scan_data:
                                    logger.info(f"Sending immediate notification for {ip}")
                                    self.send_ip_scanned_notification(ip, ip_scan_data[ip])
                                else:
                                    logger.warning(f"IP {ip} not found in scan results")
                                    
                                # Add this IP's results to the combined XML
                                try:
                                    ip_tree = ET.parse(ip_xml_file)
                                    ip_root = ip_tree.getroot()
                                    for host in ip_root.findall('./host'):
                                        combined_root.append(host)
                                except Exception as e:
                                    logger.error(f"Error merging XML for IP {ip}: {e}")
                            else:
                                logger.warning(f"Scan file for IP {ip} is missing or empty")
                        except Exception as e:
                            logger.error(f"Error processing scan results for IP {ip}: {e}")
                    else:
                        logger.error(f"Scan for IP {ip} failed with return code {process.returncode}")
                        logger.error(f"STDOUT: {stdout}")
                        logger.error(f"STDERR: {stderr}")
                        
                        # Retry with delay if not the last attempt
                        if attempt < self.max_retries:
                            delay = self.retry_delay_base * (2 ** (attempt - 1)) + random.uniform(0, self.retry_delay_base)
                            logger.info(f"Retrying IP {ip} scan in {delay:.1f} seconds...")
                            time.sleep(delay)
                            
                except Exception as e:
                    logger.error(f"Exception during scan of IP {ip}: {e}")
                    # Retry with delay if not the last attempt
                    if attempt < self.max_retries and not SHUTDOWN_REQUESTED:
                        delay = self.retry_delay_base * (2 ** (attempt - 1)) + random.uniform(0, self.retry_delay_base)
                        logger.info(f"Retrying IP {ip} scan in {delay:.1f} seconds...")
                        time.sleep(delay)
        
        # Save the combined results
        logger.info(f"Completed individual scans of {successful_scans}/{len(ip_list)} IPs")
        
        # Write the combined XML file
        try:
            combined_root.set('end', str(int(time.time())))
            combined_tree.write(main_xml_file)
            logger.info(f"Saved combined scan results to {main_xml_file}")
            
            # Mark scan as complete
            self.scan_in_progress = False
            self.save_state()
            
            if successful_scans > 0:
                # Also copy to history directory
                history_file = os.path.join(self.history_dir, f"scan_{timestamp}.xml")
                shutil.copy2(main_xml_file, history_file)
                return main_xml_file
            else:
                logger.error("No IPs were successfully scanned")
                return None
        except Exception as e:
            logger.error(f"Error saving combined scan results: {e}")
            self.scan_in_progress = False
            self.save_state()
            return None
    
    def perform_deep_verification(self, xml_file):
        """Perform a deeper verification by directly checking a sample of ports"""
        logger.info("Performing deep verification by checking sample ports")
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            hosts = root.findall('./host')
            
            # Get a sample of hosts to verify (max 3)
            sample_size = min(3, len(hosts))
            sample_hosts = random.sample(hosts, sample_size)
            
            verification_ports = self.verification_ports.split(',')
            if not verification_ports:
                logger.warning("No verification ports specified")
                return True  # Skip deep verification
            
            success_count = 0
            
            for host_elem in sample_hosts:
                addr_elem = host_elem.find('./address')
                if addr_elem is None or addr_elem.get('addrtype') != 'ipv4':
                    continue
                    
                ip = addr_elem.get('addr')
                logger.info(f"Verifying host {ip}")
                
                # Check if the host is reported as up
                status_elem = host_elem.find('./status')
                if status_elem is None or status_elem.get('state') != 'up':
                    logger.warning(f"Host {ip} is reported as down, skipping verification")
                    continue
                
                # Find ports reported as open
                ports_elem = host_elem.find('./ports')
                if ports_elem is None:
                    logger.warning(f"No ports information for host {ip}")
                    continue
                
                port_elems = ports_elem.findall('./port')
                open_ports = []
                
                for port_elem in port_elems:
                    state_elem = port_elem.find('./state')
                    if state_elem is not None and state_elem.get('state') == 'open':
                        open_ports.append(port_elem.get('portid'))
                
                # If no open ports, skip this host
                if not open_ports:
                    logger.info(f"No open ports reported for host {ip}")
                    continue
                
                # Check a random open port to verify it's actually open
                for _ in range(2):  # Try up to 2 ports
                    if not open_ports:
                        break
                        
                    test_port = open_ports.pop(random.randrange(len(open_ports)))
                    
                    try:
                        logger.info(f"Testing connectivity to {ip}:{test_port}")
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(self.verification_timeout)
                        result = s.connect_ex((ip, int(test_port)))
                        s.close()
                        
                        if result == 0:
                            logger.info(f"Verified open port {test_port} on {ip}")
                            success_count += 1
                            break
                        else:
                            logger.warning(f"Port {test_port} on {ip} is reported open but connection failed")
                    except Exception as e:
                        logger.warning(f"Error verifying port {test_port} on {ip}: {e}")
            
            # Consider verification successful if at least one port was verified
            if success_count > 0:
                logger.info(f"Deep verification passed ({success_count} ports verified)")
                return True
            else:
                logger.warning("Deep verification failed - could not verify any ports")
                return False
                
        except Exception as e:
            logger.error(f"Error during deep verification: {e}")
            return False
    
    def extract_scanned_ips(self, xml_file):
        """Extract information about individual IPs from the scan results"""
        logger.info(f"Extracting IP information from scan file: {xml_file}")
        
        if not os.path.exists(xml_file):
            logger.error(f"Scan file does not exist: {xml_file}")
            return {}
            
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            hosts_total = len(root.findall('./host'))
            logger.info(f"Found {hosts_total} hosts in scan file")
            
            ip_results = {}
            for host in root.findall('./host'):
                addr_elem = host.find('./address')
                if addr_elem is None:
                    logger.debug("Found host without address element, skipping")
                    continue
                    
                if addr_elem.get('addrtype') != 'ipv4':
                    logger.debug(f"Skipping non-IPv4 address of type {addr_elem.get('addrtype')}")
                    continue
                    
                ip = addr_elem.get('addr')
                logger.debug(f"Processing IP: {ip}")
                ip_results[ip] = {'ports': {}}
                
                # Get host status
                status_elem = host.find('./status')
                if status_elem is not None:
                    ip_results[ip]['status'] = status_elem.get('state')
                else:
                    ip_results[ip]['status'] = 'unknown'
                
                # Process ports
                for port in host.findall('./ports/port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    
                    state_elem = port.find('state')
                    if state_elem is None or state_elem.get('state') != 'open':
                        continue
                        
                    service_info = {
                        'state': state_elem.get('state'),
                        'reason': state_elem.get('reason')
                    }
                    
                    service_elem = port.find('service')
                    if service_elem is not None:
                        service_info['name'] = service_elem.get('name', '')
                        service_info['product'] = service_elem.get('product', '')
                        service_info['version'] = service_elem.get('version', '')
                        service_info['extrainfo'] = service_elem.get('extrainfo', '')
                    
                    key = f"{port_id}/{protocol}"
                    ip_results[ip]['ports'][key] = service_info
            
            return ip_results
        except Exception as e:
            logger.error(f"Error extracting IP information from scan: {e}")
            return {}
    
    def parse_scan_results(self, xml_file):
        """Parse nmap XML output and return structured data"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            results = {}
            for host in root.findall('./host'):
                addr_elem = host.find('./address')
                if addr_elem is None:
                    continue
                    
                addr = addr_elem.get('addr')
                results[addr] = {'ports': {}}
                
                # Record host status
                status_elem = host.find('./status')
                if status_elem is not None:
                    results[addr]['status'] = status_elem.get('state')
                else:
                    results[addr]['status'] = 'unknown'
                
                # Get hostname if available
                hostname = None
                for hostname_elem in host.findall('./hostnames/hostname'):
                    if hostname_elem.get('type') == 'user':
                        hostname = hostname_elem.get('name')
                        break
                    elif hostname_elem.get('type') == 'PTR' and not hostname:
                        hostname = hostname_elem.get('name')
                
                if hostname:
                    results[addr]['hostname'] = hostname
                
                # Process ports
                for port in host.findall('./ports/port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    
                    state_elem = port.find('state')
                    if state_elem is None:
                        continue
                        
                    state = state_elem.get('state')
                    reason = state_elem.get('reason')
                    
                    if state == "open":
                        service_info = {
                            'state': state,
                            'reason': reason
                        }
                        
                        service_elem = port.find('service')
                        if service_elem is not None:
                            service_info['name'] = service_elem.get('name', '')
                            service_info['product'] = service_elem.get('product', '')
                            service_info['version'] = service_elem.get('version', '')
                            service_info['extrainfo'] = service_elem.get('extrainfo', '')
                        
                        key = f"{port_id}/{protocol}"
                        results[addr]['ports'][key] = service_info
            
            return results
        except ET.ParseError as e:
            logger.error(f"XML parse error in scan results: {e}")
            return None
        except Exception as e:
            logger.error(f"Error parsing scan results: {e}")
            return None
    
    def get_latest_history_file(self):
        """Get the latest history file (excluding the current scan)"""
        try:
            history_files = sorted([f for f in os.listdir(self.history_dir) 
                                 if f.startswith("scan_") and f.endswith(".xml")])
            if not history_files:
                return None
                
            if len(history_files) > 1:
                return os.path.join(self.history_dir, history_files[-1])
            return None
        except Exception as e:
            logger.error(f"Error getting latest history file: {e}")
            return None
    
    def compare_scans(self, current_scan, previous_scan):
        """Compare current scan with previous scan to find differences"""
        if not previous_scan:
            # If no previous scan, all ports are considered new
            changes = {"new_hosts": {}, "new_ports": {}, "closed_ports": {}}
            for host, data in current_scan.items():
                changes["new_hosts"][host] = data
            return changes
        
        changes = {
            "new_hosts": {},
            "new_ports": {},
            "closed_ports": {}
        }
        
        # Check for new hosts and new ports
        for host, data in current_scan.items():
            if host not in previous_scan:
                changes["new_hosts"][host] = data
                continue
            
            for port, service in data["ports"].items():
                if port not in previous_scan[host]["ports"]:
                    if host not in changes["new_ports"]:
                        changes["new_ports"][host] = {}
                    changes["new_ports"][host][port] = service
        
        # Check for closed ports
        for host, data in previous_scan.items():
            if host not in current_scan:
                changes["closed_ports"][host] = {"all": True}
                continue
            
            for port in data["ports"]:
                if port not in current_scan[host]["ports"]:
                    if host not in changes["closed_ports"]:
                        changes["closed_ports"][host] = {}
                    changes["closed_ports"][host][port] = True
        
        return changes
    
    def send_email_notification(self, changes):
        """Send email notification with changes"""
        if not self.config.getboolean('Email', 'enabled', fallback=False):
            return
        
        smtp_server = self.config.get('Email', 'smtp_server')
        smtp_port = self.config.getint('Email', 'smtp_port')
        smtp_user = self.config.get('Email', 'smtp_user')
        smtp_password = self.config.get('Email', 'smtp_password')
        sender_email = self.config.get('Email', 'sender_email')
        recipient_emails = self.config.get('Email', 'recipient_emails').split(',')
        
        if not (smtp_server and smtp_port and sender_email and recipient_emails):
            logger.error("Email configuration incomplete, cannot send notification")
            return
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = ", ".join(recipient_emails)
        msg['Subject'] = f"[PORT MONITOR] Port Changes Detected - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        
        body = self._format_changes_for_email(changes)
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
                logger.info("Email notification sent successfully")
                break
            except Exception as e:
                logger.error(f"Failed to send email notification (attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(5)  # Wait before retrying
                else:
                    logger.error("Maximum email retry attempts reached")
    
    def send_slack_notification(self, changes):
        """Send Slack notification with changes"""
        if not self.config.getboolean('Slack', 'enabled', fallback=False):
            return
        
        webhook_url = self.config.get('Slack', 'webhook_url')
        if not webhook_url:
            logger.error("Slack webhook URL not configured, cannot send notification")
            return
        
        message = self._format_changes_for_slack(changes)
        
        # Implement retry logic for Slack notification
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
                    logger.info("Slack notification sent successfully")
                    break
                else:
                    logger.error(f"Failed to send Slack notification (attempt {attempt+1}/{max_retries}): {response.status_code}, {response.text}")
                    if attempt < max_retries - 1:
                        time.sleep(5)  # Wait before retrying
            except Exception as e:
                logger.error(f"Error sending Slack notification (attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(5)  # Wait before retrying
                else:
                    logger.error("Maximum Slack retry attempts reached")
    
    def send_telegram_notification(self, changes):
        """Send Telegram notification with changes"""
        if not self.config.getboolean('Telegram', 'enabled', fallback=False):
            return
        
        bot_token = self.config.get('Telegram', 'bot_token')
        chat_id = self.config.get('Telegram', 'chat_id')
        
        if not bot_token or not chat_id:
            logger.error("Telegram bot token or chat ID not configured, cannot send notification")
            return
        
        message = self._format_changes_for_telegram(changes)
        
        # Implement retry logic for Telegram notification
        max_retries = 3
        for attempt in range(max_retries):
            try:
                url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                response = requests.post(
                    url,
                    json={
                        "chat_id": chat_id,
                        "text": message,
                        "parse_mode": "Markdown"
                    },
                    timeout=10
                )
                
                if response.status_code == 200:
                    logger.info("Telegram notification sent successfully")
                    break
                else:
                    logger.error(f"Failed to send Telegram notification (attempt {attempt+1}/{max_retries}): {response.status_code}, {response.text}")
                    if attempt < max_retries - 1:
                        time.sleep(5)  # Wait before retrying
            except Exception as e:
                logger.error(f"Error sending Telegram notification (attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(5)  # Wait before retrying
                else:
                    logger.error("Maximum Telegram retry attempts reached")
    
    def _format_changes_for_email(self, changes):
        """Format changes for email notification"""
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
        <p>Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>System: {os.uname().nodename}</p>
        <p>User: {os.environ.get('USER', 'unknown')}</p>
        """
        
        html += "</body></html>"
        return html
    
    def _format_changes_for_slack(self, changes):
        """Format changes for Slack notification"""
        text = "*Port Monitoring Alert*\n"
        text += "The following changes were detected in the latest scan:\n\n"
        
        # New hosts
        text += "*New Hosts Detected:*\n"
        if changes["new_hosts"]:
            for host, data in changes["new_hosts"].items():
                ports_str = ", ".join(data["ports"].keys())
                text += f"• {host} - Ports: {ports_str}\n"
        else:
            text += "• None\n"
        
        # New ports
        text += "\n*New Open Ports:*\n"
        if changes["new_ports"]:
            for host, ports in changes["new_ports"].items():
                for port, service in ports.items():
                    service_str = f"{service.get('name', 'unknown')} {service.get('product', '')} {service.get('version', '')}"
                    text += f"• {host} - {port} ({service_str.strip()})\n"
        else:
            text += "• None\n"
        
        # Closed ports
        text += "\n*Closed Ports:*\n"
        if changes["closed_ports"]:
            for host, ports in changes["closed_ports"].items():
                if "all" in ports:
                    text += f"• {host} - All ports (host down)\n"
                else:
                    for port in ports:
                        if port != "all":
                            text += f"• {host} - {port}\n"
        else:
            text += "• None\n"
        
        # Add scan information
        text += f"\nScan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        return text
        
    def _format_changes_for_telegram(self, changes):
        """Format changes for Telegram notification"""
        text = "*Port Monitoring Alert*\n"
        text += "The following changes were detected in the latest scan:\n\n"
        
        # New hosts
        text += "*New Hosts Detected:*\n"
        if changes["new_hosts"]:
            for host, data in changes["new_hosts"].items():
                ports_str = ", ".join(data["ports"].keys())
                text += f"• {host} - Ports: {ports_str}\n"
        else:
            text += "• None\n"
        
        # New ports
        text += "\n*New Open Ports:*\n"
        if changes["new_ports"]:
            for host, ports in changes["new_ports"].items():
                for port, service in ports.items():
                    service_str = f"{service.get('name', 'unknown')} {service.get('product', '')} {service.get('version', '')}"
                    text += f"• {host} - {port} ({service_str.strip()})\n"
        else:
            text += "• None\n"
        
        # Closed ports
        text += "\n*Closed Ports:*\n"
        if changes["closed_ports"]:
            for host, ports in changes["closed_ports"].items():
                if "all" in ports:
                    text += f"• {host} - All ports (host down)\n"
                else:
                    for port in ports:
                        if port != "all":
                            text += f"• {host} - {port}\n"
        else:
            text += "• None\n"
        
        # Add scan information
        text += f"\nScan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        return text
        
    def _format_changes_for_teams(self, changes):
        """Format changes for Microsoft Teams notification"""
        text = "**Port Monitoring Alert**\n\n"
        text += "The following changes were detected in the latest scan:\n\n"
        
        # New hosts
        text += "**New Hosts Detected:**\n"
        if changes["new_hosts"]:
            for host, data in changes["new_hosts"].items():
                ports_str = ", ".join(data["ports"].keys())
                text += f"• {host} - Ports: {ports_str}\n"
        else:
            text += "• None\n"
        
        # New ports
        text += "\n**New Open Ports:**\n"
        if changes["new_ports"]:
            for host, ports in changes["new_ports"].items():
                for port, service in ports.items():
                    service_str = f"{service.get('name', 'unknown')} {service.get('product', '')} {service.get('version', '')}"
                    text += f"• {host} - {port} ({service_str.strip()})\n"
        else:
            text += "• None\n"
        
        # Closed ports
        text += "\n**Closed Ports:**\n"
        if changes["closed_ports"]:
            for host, ports in changes["closed_ports"].items():
                if "all" in ports:
                    text += f"• {host} - All ports (host down)\n"
                else:
                    for port in ports:
                        if port != "all":
                            text += f"• {host} - {port}\n"
        else:
            text += "• None\n"
        
        # Add scan information
        text += f"\nScan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        return text
    
    def send_teams_notification(self, changes):
        """Send Microsoft Teams notification with changes"""
        if not self.config.getboolean('Teams', 'enabled', fallback=False):
            return
        
        webhook_url = self.config.get('Teams', 'webhook_url')
        if not webhook_url:
            logger.error("Teams webhook URL not configured, cannot send notification")
            return
        
        message = self._format_changes_for_teams(changes)
        
        # Implement retry logic for Teams notification
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
                    logger.info("Teams notification sent successfully")
                    break
                else:
                    logger.error(f"Failed to send Teams notification (attempt {attempt+1}/{max_retries}): {response.status_code}, {response.text}")
                    if attempt < max_retries - 1:
                        time.sleep(5)  # Wait before retrying
            except Exception as e:
                logger.error(f"Error sending Teams notification (attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(5)  # Wait before retrying
                else:
                    logger.error("Maximum Teams retry attempts reached")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Port Monitor")
    parser.add_argument("-c", "--config", help="Path to configuration file", default="port_monitor.conf")
    parser.add_argument("--test-ip-alert", help="Test IP alert by sending a notification for the specified IP", type=str)
    parser.add_argument("--debug", help="Enable debug logging", action="store_true")
    args = parser.parse_args()
    
    # Set debug logging if requested
    if args.debug:
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    monitor = PortMonitor(args.config)
    
    # Test mode for IP alerts
    if args.test_ip_alert:
        logger.info(f"TEST MODE: Sending test notification for IP {args.test_ip_alert}")
        # Create a minimal test scan for the specified IP
        test_data = {
            'status': 'up',
            'ports': {
                '80/tcp': {
                    'state': 'open',
                    'reason': 'syn-ack',
                    'name': 'http',
                    'product': 'Test Web Server',
                    'version': '1.0',
                    'extrainfo': 'Test Mode'
                },
                '443/tcp': {
                    'state': 'open',
                    'reason': 'syn-ack',
                    'name': 'https',
                    'product': 'Test SSL Server',
                    'version': '1.0',
                    'extrainfo': 'Test Mode'
                }
            }
        }
        # Send test notification
        monitor.send_ip_scanned_notification(args.test_ip_alert, test_data)
        logger.info("Test complete. Exiting.")
        sys.exit(0)
    
    while not SHUTDOWN_REQUESTED:
        try:
            xml_file = monitor.run_scan()
            if xml_file:
                # For standard scan mode, process IP alerts if needed
                # (In individual scan mode, alerts are already sent during the scan)
                if monitor.individual_ip_alerts and not hasattr(monitor, '_run_individual_ip_scans'):
                    logger.info("Individual IP alerts are enabled, processing IP scan results")
                    
                    # Extract individual IP data from the scan results
                    ip_results = monitor.extract_scanned_ips(xml_file)
                    ip_count = len(ip_results)
                    logger.info(f"Extracted data for {ip_count} IPs from scan results")
                    
                    if ip_count == 0:
                        logger.warning("No IP data was extracted from the scan results")
                    
                    # Send notifications for each scanned IP
                    for ip, scan_data in ip_results.items():
                        monitor.send_ip_scanned_notification(ip, scan_data)
                elif not monitor.individual_ip_alerts:
                    logger.info("Individual IP alerts are disabled in configuration")
                
                # Continue with existing functionality to detect changes
                current_scan = monitor.parse_scan_results(xml_file)
                previous_scan_file = monitor.get_latest_history_file()
                if previous_scan_file:
                    previous_scan = monitor.parse_scan_results(previous_scan_file)
                else:
                    previous_scan = None
                
                changes = monitor.compare_scans(current_scan, previous_scan)
                
                if changes["new_hosts"] or changes["new_ports"] or changes["closed_ports"]:
                    logger.info("Changes detected, sending notifications")
                    monitor.send_email_notification(changes)
                    monitor.send_slack_notification(changes)
                    monitor.send_telegram_notification(changes)
                    monitor.send_teams_notification(changes)
                else:
                    logger.info("No changes detected")
        except Exception as e:
            logger.error(f"Error during main loop: {e}")
        
        # Wait for the next scan interval
        time.sleep(monitor.scan_interval)