#!/usr/bin/env python3
"""
Debug utility to test Telegram notifications with sample scan data
"""

import logging
import sys
import os
import json
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import notification components
# Use a direct import instead of a package import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from notification.telegram_notifier import TelegramNotifier

def create_test_scan_results():
    """Create sample scan results for testing"""
    return {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'hosts': {
            '192.168.1.1': {
                'status': 'up',
                'ports': {
                    '22/tcp': {
                        'state': 'open',
                        'name': 'ssh',
                        'product': 'OpenSSH',
                        'version': '8.2p1'
                    },
                    '80/tcp': {
                        'state': 'open',
                        'name': 'http',
                        'product': 'nginx',
                        'version': '1.18.0'
                    }
                }
            },
            '192.168.1.2': {
                'status': 'up',
                'ports': {
                    '443/tcp': {
                        'state': 'open',
                        'name': 'https',
                        'product': 'Apache',
                        'version': '2.4.41'
                    }
                }
            }
        }
    }

def create_test_changes():
    """Create sample changes for testing"""
    return {
        'new_ports': {
            '192.168.1.1': {
                '443/tcp': {
                    'state': 'open',
                    'name': 'https',
                    'product': 'nginx'
                }
            }
        },
        'closed_ports': {
            '192.168.1.2': {
                '22/tcp': {
                    'state': 'closed',
                    'name': 'ssh'
                }
            }
        }
    }

def main():
    """Run a test Telegram notification"""
    import configparser
    import os
    
    # Load configuration directly from the port_monitor.conf file
    config = configparser.ConfigParser()
    conf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'port_monitor.conf')
    
    if not os.path.exists(conf_path):
        logging.error(f"Configuration file not found: {conf_path}")
        return False
        
    config.read(conf_path)
    logging.info(f"Loaded configuration from {conf_path}")
    
    # Check if Telegram configuration exists
    if not config.has_section('telegram'):
        logging.error("No Telegram section found in configuration file")
        return False
    
    # Get Telegram configuration
    telegram_config = {
        'bot_token': config.get('telegram', 'bot_token', fallback=''),
        'chat_id': config.get('telegram', 'chat_id', fallback='')
    }
    
    # Check if Telegram configuration is valid
    if not telegram_config['bot_token'] or not telegram_config['chat_id']:
        logging.error("Invalid Telegram configuration: missing bot_token or chat_id")
        return False
    
    # Create a Telegram notifier
    notifier = TelegramNotifier(telegram_config)
    
    # Create test data
    scan_results = create_test_scan_results()
    changes = create_test_changes()
    
    # Log the test data
    logging.info(f"Test scan results: {json.dumps(scan_results, indent=2)}")
    logging.info(f"Test changes: {json.dumps(changes, indent=2)}")
    
    # Send a test notification
    logging.info("Sending test notification to Telegram...")
    success = notifier.notify_scan_completed(
        scan_id="TEST_SCAN_001",
        success=True,
        scanned=2,
        total=2,
        scan_results=scan_results,
        changes=changes
    )
    
    # Log result
    if success:
        logging.info("Test notification sent successfully!")
    else:
        logging.error("Failed to send test notification")

if __name__ == "__main__":
    main()
