#!/bin/bash
# Setup script for port monitoring system

set -e

echo "Setting up port monitoring system..."

# Check for sudo if needed for package installation
if [ "$(id -u)" -ne 0 ]; then
    echo "This script will install required packages. Do you have sudo privileges? (y/n)"
    read -r has_sudo
    if [[ "$has_sudo" != "y" && "$has_sudo" != "Y" ]]; then
        echo "You need sudo privileges to install required packages."
        exit 1
    fi
else
    has_sudo="y"
fi

# Install dependencies
echo "Installing dependencies..."
if [ "$has_sudo" = "y" ] || [ "$has_sudo" = "Y" ]; then
    sudo apt-get update
    sudo apt-get install -y nmap python3 python3-pip
else
    apt-get update
    apt-get install -y nmap python3 python3-pip
fi

pip3 install requests

# Create directories
mkdir -p port_monitor_output/history

# Make scripts executable
chmod +x port_monitor.py

# Check if IP list exists
if [ ! -f "unique_ips.txt" ]; then
    echo "Please create 'unique_ips.txt' file containing one IP address per line."
    echo "Example IP file format:"
    echo "192.168.1.1"
    echo "192.168.1.2"
    echo "10.0.0.5"
fi

# Create crontab entry
echo "Would you like to set up a cron job to run the monitor automatically? (y/n)"
read -r setup_cron
if [[ "$setup_cron" == "y" || "$setup_cron" == "Y" ]]; then
    dir=$(pwd)
    
    # Default to run every 4 hours based on config
    default_interval=240
    interval=$(grep -E "scan_interval_minutes" port_monitor.conf | cut -d'=' -f2 | tr -d ' ')
    interval=${interval:-$default_interval}
    
    # Convert minutes to cron format
    if [ "$interval" -eq 60 ]; then
        cron_time="0 * * * *"  # Every hour
    elif [ "$interval" -eq 240 ]; then
        cron_time="0 */4 * * *"  # Every 4 hours
    elif [ "$interval" -eq 1440 ]; then
        cron_time="0 0 * * *"  # Daily at midnight
    else
        # Default to every 4 hours if custom schedule
        cron_time="0 */4 * * *"
    fi
    
    cron_line="$cron_time cd $dir && ./port_monitor.py >> port_monitor.log 2>&1"
    
    # Add to crontab
    (crontab -l 2>/dev/null || echo "") | grep -v "port_monitor.py" | { cat; echo "$cron_line"; } | crontab -
    
    echo "Cron job added. The monitor will run at: $cron_time"
fi

echo -e "\nSetup complete!"
echo "1. Edit port_monitor.conf to customize settings."
echo "2. Make sure your unique_ips.txt file is populated with target IPs."
echo "3. Run ./port_monitor.py to start monitoring."
echo "4. Check port_monitor.log for output."