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

# Import directly from local directories
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import only the TelegramNotifier to avoid dependency issues
from port_monitor.notification.telegram_notifier import TelegramNotifier

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
    
    # Create Telegram notifier directly
    if not config.has_section('Telegram'):
        logging.error("No Telegram section found in the config file")
        return
        
    if not config.getboolean('Telegram', 'enabled', fallback=False):
        logging.warning("Telegram notifications are disabled in the config")
        return
        
    bot_token = config.get('Telegram', 'bot_token', fallback='')
    chat_id = config.get('Telegram', 'chat_id', fallback='')
    
    if not bot_token or not chat_id:
        logging.error("Missing Telegram configuration (bot_token or chat_id)")
        return
        
    telegram_notifier = TelegramNotifier(config)
    
    logging.info("Telegram notifier is enabled")
    logging.info(f"Bot token: {bot_token[:4]}...{bot_token[-4:] if len(bot_token) > 8 else ''}")
    logging.info(f"Chat ID: {chat_id}")
    
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
