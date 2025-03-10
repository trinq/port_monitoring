#!/usr/bin/env python3
"""
Minimal test script to verify Telegram notification functionality.
This script directly tests the Telegram notification code without relying on other project components.
"""

import os
import sys
import logging
import configparser
import json
import requests
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def send_telegram_message(token, chat_id, message, parse_mode="HTML"):
    """Send a message to Telegram chat directly"""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    
    data = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": parse_mode
    }
    
    logging.info(f"Sending message to Telegram chat {chat_id}")
    try:
        response = requests.post(url, data=data, timeout=10)
        response_json = response.json()
        
        if response.status_code == 200 and response_json.get('ok'):
            logging.info("Message sent successfully")
            return True
        else:
            logging.error(f"Failed to send message: {response_json}")
            return False
    except Exception as e:
        logging.error(f"Error sending Telegram message: {e}")
        return False

def create_sample_message(scan_id):
    """Create a sample scan completion message"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    message = f"<b>🏁 Port Scan Completed ✅ Successfully</b>\n\n"
    message += f"The port scan has completed.\n"
    message += f"<b>Scan ID:</b> {scan_id}\n"
    message += f"<b>Completion Status:</b> Success\n"
    message += f"<b>Scanned:</b> 36/36 IP addresses (100.0%)\n"
    message += f"<b>Completion Time:</b> {timestamp}\n"
    
    message += "\n<b>📊 Port Monitoring Summary</b>\n"
    message += "\n<b>All Scanned Hosts:</b>\n"
    message += "• <b>192.168.1.1</b> - Ports: 22/tcp, 80/tcp, 443/tcp\n"
    message += "• <b>10.0.0.1</b> - Ports: 3306/tcp\n"
    message += "• <b>58.186.11.249</b> - Ports: 443/tcp\n"
    
    message += "\n<b>Port Monitoring Alert</b>\n"
    message += "The following changes were detected in the latest scan:\n"
    
    message += "\n<b>New Hosts Detected:</b>\n• None\n"
    
    message += "\n<b>New Open Ports:</b>\n"
    message += "• <b>192.168.1.1</b> - Ports: 443/tcp\n"
    
    message += "\n<b>Closed Ports:</b>\n"
    message += "• <b>10.0.0.1</b> - Ports: 5432/tcp\n"
    
    return message

def main():
    # Read config file
    config = configparser.ConfigParser()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    
    # Try multiple potential config file locations
    config_paths = [
        os.path.join(script_dir, 'port_monitor.conf'),
        os.path.join(parent_dir, 'port_monitor.conf'),
        '/etc/port_monitor.conf'
    ]
    
    config_file = None
    for path in config_paths:
        if os.path.exists(path):
            config_file = path
            break
    
    if not config_file:
        logging.error("Could not find configuration file")
        return False
    
    config.read(config_file)
    logging.info(f"Read configuration from {config_file}")
    
    # Check if Telegram is enabled
    try:
        telegram_enabled = config.getboolean('Telegram', 'enabled')
    except (configparser.NoSectionError, configparser.NoOptionError):
        telegram_enabled = False
    
    if not telegram_enabled:
        logging.error("Telegram notifications are not enabled in the configuration")
        return False
    
    # Get bot token and chat ID
    try:
        bot_token = config.get('Telegram', 'bot_token')
        chat_id = config.get('Telegram', 'chat_id')
    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        logging.error(f"Missing Telegram configuration: {e}")
        return False
    
    if not bot_token or not chat_id:
        logging.error("Bot token or chat ID is missing or empty")
        return False
    
    logging.info("Telegram notification is enabled")
    logging.info(f"Bot token: {bot_token[:4]}...{bot_token[-4:] if len(bot_token) > 8 else ''}")
    logging.info(f"Chat ID: {chat_id}")
    
    # Create a sample scan ID
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create and send a test message
    message = create_sample_message(scan_id)
    logging.info("Sending test notification...")
    
    result = send_telegram_message(bot_token, chat_id, message)
    
    return result

if __name__ == "__main__":
    result = main()
    if result:
        print("\n✅ Test completed successfully! Check your Telegram for the notification.")
    else:
        print("\n❌ Test failed. Please check the error messages above.")
    
    sys.exit(0 if result else 1)
