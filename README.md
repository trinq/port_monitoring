# 🔍 Port Monitoring System

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![Code Style](https://img.shields.io/badge/code%20style-black-black)](https://github.com/psf/black)
[![Contributions](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

A comprehensive solution for continuous monitoring of network ports across multiple IP addresses. Automatically detects changes in port status and sends notifications through multiple channels (Email, Slack, Teams, and Telegram).

## 📋 Table of Contents

* [Overview](#overview)
* [Features](#features)
* [Installation](#installation)
* [Quick Start](#quick-start)
* [Configuration](#configuration-file-port_monitorconf)
* [Command Line Options](#command-line-options)
* [Running as a Service](#running-as-a-service)

## ✨ Features

- **Continuous Port Scanning**: Automatically scans IP addresses at configurable intervals
- **Change Detection**: Identifies new hosts, new open ports, and closed ports
- **Multi-Channel Notifications**: Supports Email, Slack, Teams, and Telegram
- **Detailed Reporting**: Provides comprehensive summaries of scan results
- **Sequential Scanning**: Scans IPs one by one to avoid network congestion
- **Robust Error Handling**: Includes retry mechanisms and detailed logging

## 🔧 Installation

```bash
pip install -r requirements.txt
```

## 🚀 Quick Start

1. **Configure the System**:
   - Copy `port_monitor.conf.example` to `port_monitor.conf`
   - Edit the configuration file with your settings
   - Create an IP list file (default: `unique_ips.txt`)

2. **Run the Monitor**:
   ```bash
   python -m port_monitor
   ```

## ⚙️ Configuration File (port_monitor.conf)

The system is configured through a single configuration file with the following sections:

### General Settings

```ini
[General]
# Directory for storing scan results and history
output_dir = ./port_monitor_output
# Log level (DEBUG, INFO, WARNING, ERROR)
log_level = INFO
```

### Scan Settings

```ini
[Scan]
# File containing list of IP addresses to scan (one per line)
ip_list_file = unique_ips.txt

# Scan interval in minutes (how often to run scans)
# Default: 240 (4 hours)
scan_interval_minutes = 240

# Scan parameters
# Delay between probes (in seconds or with units like 0.5s)
scan_delay = 0.5s
# Maximum packet transmission rate
max_rate = 100
# Port ranges to scan (comma-separated)
ports = 1-1000,1022-1099,1433-1434,1521,2222,3306-3310,3389,5432,5900-5910,8000-8999
# Scan timing template (0-5, higher is faster but less reliable)
timing_template = 3
# Additional nmap arguments
additional_args = 
```

### Notification Settings

```ini
[Notification]
# Enable or disable all notifications
enabled = true

# Enable notifications for each individual IP scan
individual_ip_alerts = true

# Enable notifications when IP scans begin
send_scan_start_alerts = false
```

### Email Notifications

```ini
[Email]
# Enable or disable email notifications
enabled = false

# SMTP server configuration
smtp_server = smtp.example.com
smtp_port = 587
smtp_user = username
smtp_password = password
use_tls = true

# Email addresses
sender_email = alerts@example.com
recipient_emails = admin@example.com,security@example.com

# Email content
subject_prefix = [Port Monitor]
```

### Slack Notifications

```ini
[Slack]
# Enable or disable Slack notifications
enabled = false

# Slack webhook URL (from Slack API)
webhook_url = https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
```

### Teams Notifications

```ini
[Teams]
# Enable or disable Microsoft Teams notifications
enabled = false

# Teams webhook URL
webhook_url = https://outlook.office.com/webhook/YOUR/TEAMS/WEBHOOK
```

### Telegram Notifications

```ini
[Telegram]
# Enable or disable Telegram notifications
enabled = false

# Telegram bot token (from BotFather)
bot_token = YOUR_BOT_TOKEN

# Chat ID to send messages to
chat_id = YOUR_CHAT_ID

# Maximum retries for failed API calls
max_retries = 3
```

## 💻 Command Line Options

The system supports various command line options:

```
Usage: python -m port_monitor [OPTIONS]

Options:
  -c, --config FILE       Path to configuration file (default: port_monitor.conf)
  -d, --debug             Enable debug logging
  -t, --test              Run in test mode (scan only one IP)
  --test-ip IP            Specify IP to test
  --test-notification     Test the notification system
  --test-ip-alert IP      Test IP scan notification for a specific IP
  --version               Show version information
  -h, --help              Show this help message
```

## 🔄 Running as a Service

### 🐧 Using Systemd (Linux)

1. Create a systemd service file:
   ```bash
   sudo nano /etc/systemd/system/port-monitor.service
   ```

2. Add the following content:
   ```ini
   [Unit]
   Description=Port Monitoring Service
   After=network.target

   [Service]
   User=your_username
   WorkingDirectory=/path/to/port_monitor
   ExecStart=/usr/bin/python3 -m port_monitor
   Restart=on-failure

   [Install]
   WantedBy=multi-user.target
   ```

3. Enable and start the service:
   ```bash
   sudo systemctl enable port-monitor.service
   sudo systemctl start port-monitor.service
   ```

### ⏱️ Using Cron

1. Edit your crontab:
   ```bash
   crontab -e
   ```

2. Add a line to run the monitor at your desired interval:
   ```
   0 */4 * * * cd /path/to/port_monitor && python3 -m port_monitor >> port_monitor.log 2>&1
   ```

## Notification Types

The system provides three types of notifications:

### 1. Scan Completion Notifications

Sent after all IPs have been scanned, including:
- Scan ID and completion status
- Summary of all hosts with their open ports
- New hosts detected since the last scan
- New open ports on existing hosts
- Ports that have been closed since the last scan

### 2. Individual IP Scan Notifications

Sent immediately after each IP is scanned (when `individual_ip_alerts = true`):
- IP address scanned
- List of all open ports found
- Service details for each port

### 3. Scan Start Notifications

Sent when a scan begins for an IP (when `send_scan_start_alerts = true`):
- IP address being scanned
- Scan ID
- Start time

## Troubleshooting

### Common Issues

1. **No notifications received**:
   - Check that notifications are enabled in the configuration
   - Verify credentials for the notification service
   - Check the log file for error messages

2. **Scan interval too long**:
   - Adjust `scan_interval_minutes` in the configuration file

3. **Missing scan results**:
   - Ensure the output directory is writable
   - Check for network connectivity issues

### Logs

Logs are stored in `port_monitor.log` in the application directory. For more detailed logs, run with the `--debug` flag.

## Security Considerations

- The system stores scan results which may contain sensitive information about your network
- Credentials for notification services are stored in plain text in the configuration file
- Consider running the system with limited privileges
- Restrict access to the configuration file and output directory

## License

This project is licensed under the MIT License - see the LICENSE file for details.
- IP address being scanned
- Attempt number and max retries
- Timestamp

All notifications are sent through the enabled notification channels (Email, Slack, and/or Telegram).

## Advanced Options

For advanced configuration options, refer to the comments in the `port_monitor.conf` file.

## Troubleshooting

Common issues:
- If scan results are not being saved, check write permissions for the output directory
- If notifications are not being sent, verify your notification settings
- For Telegram notifications, ensure the bot is added to the chat and has permission to send messages
- Check `port_monitor.log` for detailed error messages

## Security Considerations

- The scanner requires network access to target IPs
- Consider using a dedicated user to run the scans
- Sensitive notification credentials should be protected
- Be mindful of scan frequency and intensity to avoid network disruption

## License

This project is provided as-is for educational and operational purposes.