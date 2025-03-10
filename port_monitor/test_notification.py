#!/usr/bin/env python3
import os
import sys
import json
import logging
import configparser
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Add the parent directory to the path to import modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from notification.notification_manager import NotificationManager
from notification.telegram_notifier import TelegramNotifier

def load_config(config_file='port_monitor.conf'):
    """Load configuration from the specified file"""
    config = configparser.ConfigParser()
    config.read(config_file)
    return config

def create_test_data():
    """Create test data for notification testing"""
    # Sample scan results with a mix of different port formats
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
                    },
                    '443/tcp': {
                        'state': 'open',
                        'service': {
                            'name': 'https',
                            'product': 'nginx',
                            'version': '1.18.0'
                        }
                    }
                },
                'port_count': 3
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
                '8080/tcp': {
                    'state': 'open',
                    'service': {
                        'name': 'http-proxy',
                        'product': '',
                        'version': ''
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
                'all/udp': {  # Another special case to test handling
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
    """Main function to test the Telegram notification"""
    # Load the configuration
    config = load_config()
    
    # Create test data
    scan_results, changes = create_test_data()
    
    # Create the notification manager
    notification_manager = NotificationManager(config)
    
    # Test if the Telegram notifier is correctly initialized
    telegram_notifier = None
    for notifier in notification_manager.notifiers:
        if isinstance(notifier, TelegramNotifier):
            telegram_notifier = notifier
            break
    
    if telegram_notifier:
        logging.info("Telegram notifier is enabled")
        logging.info(f"Bot token: {telegram_notifier.bot_token[:4]}...{telegram_notifier.bot_token[-4:]}")
        logging.info(f"Chat ID: {telegram_notifier.chat_id}")
    else:
        logging.warning("Telegram notifier is not enabled in the configuration")
        return
    
    # Generate a scan ID
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Test the scan completion notification
    try:
        logging.info("Testing scan completion notification")
        success = telegram_notifier.notify_scan_completed(
            scan_id=scan_id,
            success=True,
            scanned=2,
            total=2,
            scan_results=scan_results,
            changes=changes
        )
        
        if success:
            logging.info("Telegram notification sent successfully")
        else:
            logging.error("Failed to send Telegram notification")
    except Exception as e:
        logging.error(f"Error sending Telegram notification: {e}", exc_info=True)

if __name__ == "__main__":
    main()
