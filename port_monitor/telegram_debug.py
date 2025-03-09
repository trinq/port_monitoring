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
from port_monitor.notification.telegram_notifier import TelegramNotifier

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
    from port_monitor.config.app_config import AppConfig
    
    # Load configuration
    config = AppConfig()
    config_data = config.get_config()
    
    # Create a Telegram notifier
    notifier = TelegramNotifier(config_data)
    
    # Create test data
    scan_results = create_test_scan_results()
    changes = create_test_changes()
    
    # Log the test data
    logging.info(f"Test scan results: {json.dumps(scan_results, indent=2)}")
    logging.info(f"Test changes: {json.dumps(changes, indent=2)}")
    
    # Send a test notification
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
