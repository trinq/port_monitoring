#!/usr/bin/env python3
"""
Simple direct test script for the Telegram notifier's scan completion notification.
"""

import os
import sys
import logging
import configparser
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Fix import paths - add parent directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

# Get the telegram_notifier module directly
from port_monitor.notification.telegram_notifier import TelegramNotifier

def create_test_scan_data():
    """Create test data for notification testing"""
    # Sample scan results with ports in different formats
    scan_results = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'hosts': {
            '192.168.1.1': {
                'status': 'up',
                'ports': {
                    '22/tcp': {
                        'state': 'open',
                        'service': {
                            'name': 'ssh',
                            'product': 'OpenSSH',
                            'version': '7.4'
                        }
                    },
                    '80/tcp': {
                        'state': 'open',
                        'service': {
                            'name': 'http',
                            'product': 'nginx',
                            'version': '1.18.0'
                        }
                    }
                },
                'port_count': 2
            },
            '10.0.0.1': {
                'status': 'up',
                'ports': {
                    '3306/tcp': {
                        'state': 'open',
                        'service': {
                            'name': 'mysql',
                            'product': 'MySQL',
                            'version': '5.7'
                        }
                    },
                    'all/tcp': {  # Special case to test handling of non-numeric ports
                        'state': 'open',
                        'service': {
                            'name': 'unknown',
                            'product': '',
                            'version': ''
                        }
                    }
                },
                'port_count': 2
            }
        }
    }
    
    # Sample changes data
    changes = {
        'new_hosts': {
            '10.0.0.2': {
                'status': 'up',
                'ports': {
                    '22/tcp': {
                        'state': 'open',
                        'service': {
                            'name': 'ssh',
                            'product': 'OpenSSH',
                            'version': '8.0'
                        }
                    }
                },
                'port_count': 1
            }
        },
        'new_ports': {
            '192.168.1.1': {
                '443/tcp': {
                    'state': 'open',
                    'service': {
                        'name': 'https',
                        'product': 'nginx',
                        'version': '1.18.0'
                    }
                }
            }
        },
        'closed_ports': {
            '10.0.0.1': {
                '5432/tcp': {
                    'state': 'closed',
                    'service': {
                        'name': 'postgresql',
                        'product': '',
                        'version': ''
                    }
                },
                'all/udp': {  # Another special case
                    'state': 'closed',
                    'service': {
                        'name': 'unknown',
                        'product': '',
                        'version': ''
                    }
                }
            }
        }
    }
    
    return scan_results, changes

def main():
    # Read the config file
    config = configparser.ConfigParser()
    config_file = os.path.join(current_dir, 'port_monitor.conf')
    if not os.path.exists(config_file):
        config_file = os.path.join(parent_dir, 'port_monitor.conf')
        
    if not os.path.exists(config_file):
        logging.error(f"Configuration file not found at {config_file}")
        return False
        
    config.read(config_file)
    logging.info(f"Read configuration from {config_file}")
    
    # Create scan data
    scan_results, changes = create_test_scan_data()
    
    # Create the Telegram notifier
    telegram_notifier = TelegramNotifier(config)
    
    # Check if Telegram is enabled
    if not telegram_notifier.is_enabled():
        logging.error("Telegram notifications are not enabled in the configuration")
        logging.info("Make sure 'enabled = true' is set in the [Telegram] section")
        return False
    
    logging.info("Telegram notifier is enabled")
    logging.info(f"Bot token: {telegram_notifier.bot_token[:4]}...{telegram_notifier.bot_token[-4:] if len(telegram_notifier.bot_token) > 8 else ''}")
    logging.info(f"Chat ID: {telegram_notifier.chat_id}")
    
    # Generate a scan ID
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Test the scan completion notification
    try:
        logging.info("Sending test scan completion notification...")
        success = telegram_notifier.notify_scan_completed(
            scan_id=scan_id,
            success=True,
            scanned=3,
            total=3,
            scan_results=scan_results,
            changes=changes
        )
        
        if success:
            logging.info("✅ Telegram notification sent successfully")
        else:
            logging.error("❌ Failed to send Telegram notification")
            
        return success
    except Exception as e:
        logging.error(f"❌ Error sending Telegram notification: {e}", exc_info=True)
        return False

if __name__ == "__main__":
    result = main()
    if result:
        print("\n✅ Test completed successfully. Check your Telegram for the notification.")
    else:
        print("\n❌ Test failed. Please check the error messages above.")
    
    sys.exit(0 if result else 1)
