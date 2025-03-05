# Port Monitoring System

This is a 24/7 port monitoring solution that performs regular port scans on a list of IP addresses, compares results with historical data, and alerts on changes such as newly opened ports.

## Features

- Continuous port scanning based on configurable intervals
- Detection of new hosts, new open ports, and closed ports
- Email, Slack, and Telegram notifications for detected changes
- Historical data storage for comparison
- Configurable scan parameters
- Detailed logging
- Retry mechanisms for reliability
- Scan result verification

## Prerequisites

- Python 3.6+
- nmap
- Network access to target IPs
- (Optional) SMTP server for email alerts
- (Optional) Slack webhook for Slack alerts
- (Optional) Telegram bot for Telegram alerts

## Installation

1. Clone/download this repository or copy the provided files.
2. Run the setup script:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

## Configuration

Edit the `port_monitor.conf` file to customize your monitoring setup:

### General Configuration

```ini
[General]
output_dir = ./port_monitor_output

[Scan]
# File containing list of IP addresses to scan
ip_list_file = unique_ips.txt
# How often to run scans (in minutes)
scan_interval_minutes = 240
# Scan delay between probes
scan_delay = 0.5s
# Maximum rate of packet transmission
max_rate = 100
# Port ranges to scan
ports = 1-1000,1022-1099,1433-1434,1521,2222,3306-3310,3389,5432,5900-5910,8000-8999
```

### IP Address List

Create a file named `unique_ips.txt` containing one IP address per line:
```
192.168.1.1
10.0.0.1
172.16.1.1
```

### Notification Configuration

Enable or disable notifications globally:
```ini
[Notification]
enabled = true
```

#### Email Notifications

```ini
[Email]
enabled = false
smtp_server = smtp.example.com
smtp_port = 587
smtp_user = username
smtp_password = password
sender_email = alerts@example.com
recipient_emails = admin@example.com,security@example.com
```

To enable email notifications:
1. Set `enabled = true` in the Email section
2. Configure your SMTP server details
3. Specify sender and recipient email addresses

#### Slack Notifications

```ini
[Slack]
enabled = false
webhook_url = https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
```

To enable Slack notifications:
1. Set `enabled = true` in the Slack section
2. Create a Slack webhook at https://api.slack.com/messaging/webhooks
3. Add the webhook URL to the configuration

#### Telegram Notifications

```ini
[Telegram]
enabled = false
bot_token = YOUR_BOT_TOKEN
chat_id = YOUR_CHAT_ID
```

To enable Telegram notifications:
1. Set `enabled = true` in the Telegram section
2. Create a Telegram bot by messaging [@BotFather](https://t.me/botfather) on Telegram
3. Get your bot token from BotFather
4. Start a chat with your bot
5. Get your chat ID (you can use [@getidsbot](https://t.me/getidsbot) or other methods)
6. Add the bot token and chat ID to the configuration

## Usage

### Running Manually

Run the port monitor manually with:
```bash
python3 port_monitor.py
```

Or with a custom configuration file:
```bash
python3 port_monitor.py -c /path/to/custom_config.conf
```

### Running as a Service

During installation, you can choose to set up a cron job that will run the monitor automatically according to your configured schedule.

To set up a cron job manually:
```bash
crontab -e
```

Add a line like:
```
0 */4 * * * cd /path/to/port_monitor && ./port_monitor.py >> port_monitor.log 2>&1
```

This example runs the monitor every 4 hours.

## Output and Logs

- Scan results are stored in the `output_dir` specified in the configuration
- Historical scans are kept in the `history` subdirectory for comparison
- Logs are written to `port_monitor.log`

## Notifications

When changes are detected (new hosts, new open ports, or closed ports), notifications will be sent through all enabled notification channels.

Notifications include:
- List of new hosts and their open ports
- List of new open ports on existing hosts
- List of ports that have been closed since the last scan
- Scan metadata (time, system information)

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