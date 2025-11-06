"""
Logging utilities for the Port Monitor system
"""

import logging
import sys
from datetime import datetime


def setup_logging(level=logging.INFO, log_file='port_monitor.log'):
    """
    Setup logging configuration for the application

    Args:
        level: Logging level (default: INFO)
        log_file: Path to log file (default: port_monitor.log)
    """
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    root_logger.handlers = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler
    try:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    except Exception as e:
        logging.warning(f"Could not create log file {log_file}: {e}")

    logging.info("Logging initialized")
