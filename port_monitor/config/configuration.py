"""
Configuration management for the Port Monitor system.
Handles loading, validating, and accessing configuration.
"""

import os
import configparser
import logging
from typing import Any, Dict, List, Optional, Union

class ConfigManager:
    """Handles all configuration-related operations"""
    
    DEFAULT_CONFIG = {
        'General': {
            'output_dir': './port_monitor_output'
        },
        'Scan': {
            'ip_list_file': 'unique_ips.txt',
            'scan_interval_minutes': '240',
            'scan_delay': '0.5s',
            'max_rate': '100',
            'ports': '1-1000,1022-1099,1433-1434,1521,2222,3306-3310,3389,5432,5900-5910,8000-8999',
            'use_http_headers': 'true',
            'http_user_agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
        },
        'Reliability': {
            'max_retries': '3',
            'retry_delay_base_seconds': '60',
            'verify_scan_results': 'true',
            'verification_ports': '22,80,443',
            'verification_timeout_seconds': '5',
            'state_file': 'port_monitor_state.json',
            'deep_verification': 'false'
        },
        'Notification': {
            'enabled': 'true',
            'plugin_dir': 'plugins/notification'
        }
    }
    
    def __init__(self, config_file: str):
        """Initialize the configuration manager with a config file"""
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self._load_config()
        self._validate_config()
        
    def _load_config(self) -> None:
        """Load configuration from file with default fallback values"""
        # Start with default configuration
        self.config.read_dict(self.DEFAULT_CONFIG)
        
        # Then try to load from file
        if os.path.exists(self.config_file):
            try:
                self.config.read(self.config_file)
                logging.info(f"Configuration loaded from {self.config_file}")
            except Exception as e:
                logging.error(f"Error loading configuration from {self.config_file}: {e}")
                logging.warning("Using default configuration values")
        else:
            logging.warning(f"Configuration file {self.config_file} not found, using defaults")
            
    def _validate_config(self) -> None:
        """Validate critical configuration options"""
        try:
            # Check if IP list file exists
            ip_list_file = self.get_ip_list_file()
            if not os.path.exists(ip_list_file):
                logging.warning(f"IP list file {ip_list_file} not found")
            
            # Ensure output directory exists
            output_dir = self.get_output_dir()
            os.makedirs(output_dir, exist_ok=True)
            
            # Create subdirectories
            for subdir in ['history', 'tmp', 'verified', 'failed']:
                os.makedirs(os.path.join(output_dir, subdir), exist_ok=True)
                
            # Create plugins directory
            plugin_dir = self.get_plugin_dir()
            os.makedirs(plugin_dir, exist_ok=True)
                
        except Exception as e:
            logging.error(f"Error validating configuration: {e}")
            
    def get(self, section: str, option: str, fallback: Any = None) -> str:
        """Get a configuration value"""
        return self.config.get(section, option, fallback=fallback)
    
    def getint(self, section: str, option: str, fallback: int = None) -> int:
        """Get an integer configuration value"""
        return self.config.getint(section, option, fallback=fallback)
    
    def getboolean(self, section: str, option: str, fallback: bool = None) -> bool:
        """Get a boolean configuration value"""
        return self.config.getboolean(section, option, fallback=fallback)
    
    def getfloat(self, section: str, option: str, fallback: float = None) -> float:
        """Get a float configuration value"""
        return self.config.getfloat(section, option, fallback=fallback)
    
    def get_ip_list_file(self) -> str:
        """Get the IP list file path"""
        return self.get('Scan', 'ip_list_file')
    
    def get_output_dir(self) -> str:
        """Get the output directory path"""
        return self.get('General', 'output_dir')
    
    def get_history_dir(self) -> str:
        """Get the history directory path"""
        return os.path.join(self.get_output_dir(), 'history')
    
    def get_scan_interval(self) -> int:
        """Get the scan interval in seconds"""
        return self.getint('Scan', 'scan_interval_minutes') * 60
    
    def get_plugin_dir(self) -> str:
        """Get the plugin directory path"""
        return self.get('Notification', 'plugin_dir')
    
    def get_state_file(self) -> str:
        """Get the state file path"""
        return os.path.join(self.get_output_dir(), self.get('Reliability', 'state_file'))
    
    def get_notification_plugins(self) -> List[str]:
        """Get the list of enabled notification plugins"""
        plugins = []
        for section in self.config.sections():
            if section.startswith('Notification.') and self.getboolean(section, 'enabled', fallback=False):
                plugins.append(section.replace('Notification.', ''))
        return plugins