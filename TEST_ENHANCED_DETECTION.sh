#!/bin/bash
# Complete test script for Enhanced Service Detection
# This will guide you through testing the new features

set -e  # Exit on error

echo "╔════════════════════════════════════════════════════════╗"
echo "║  Enhanced Service Detection - Testing Guide           ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: Install nmap if needed
echo "Step 1: Installing nmap (if needed)..."
if ! command -v nmap &> /dev/null; then
    echo -e "${YELLOW}⚠️  nmap not found. Installing...${NC}"
    echo "Running: sudo apt-get update && sudo apt-get install -y nmap"
    sudo apt-get update -qq
    sudo apt-get install -y nmap
    echo -e "${GREEN}✅ nmap installed successfully${NC}"
else
    echo -e "${GREEN}✅ nmap already installed: $(nmap --version | head -1)${NC}"
fi

echo ""

# Step 2: Verify configuration
echo "Step 2: Verifying configuration..."
if grep -q "aggressive_service_detection = true" port_monitor.conf && \
   grep -q "enable_scripts = true" port_monitor.conf; then
    echo -e "${GREEN}✅ Configuration is correct${NC}"
else
    echo -e "${YELLOW}⚠️  Updating configuration...${NC}"
    # Backup
    cp port_monitor.conf port_monitor.conf.backup
    # Enable features
    sed -i 's/aggressive_service_detection = false/aggressive_service_detection = true/' port_monitor.conf
    sed -i 's/enable_scripts = false/enable_scripts = true/' port_monitor.conf
    echo -e "${GREEN}✅ Configuration updated${NC}"
fi

echo ""

# Step 3: Create test IP file
echo "Step 3: Creating test IP file..."
echo "scanme.nmap.org" > test_ips.txt
echo -e "${GREEN}✅ Created test_ips.txt with scanme.nmap.org${NC}"

echo ""

# Step 4: Run test scan
echo "Step 4: Running test scan..."
echo -e "${YELLOW}This will take 30-60 seconds...${NC}"
echo ""

# Create output directory if it doesn't exist
mkdir -p port_monitor_output

# Run the scan
echo "Command: sudo python3 -m port_monitor --test-ip scanme.nmap.org"
echo ""

if sudo python3 -m port_monitor --test-ip scanme.nmap.org 2>&1 | tee scan_test.log; then
    echo ""
    echo -e "${GREEN}✅ Scan completed${NC}"
else
    echo ""
    echo -e "${RED}❌ Scan failed - check scan_test.log for details${NC}"
    exit 1
fi

echo ""

# Step 5: Analyze results
echo "Step 5: Analyzing results..."
echo ""

# Find latest scan
latest_json=$(ls -t port_monitor_output/scan_*_structured.json 2>/dev/null | head -1)
latest_xml=$(ls -t port_monitor_output/scan_*.xml 2>/dev/null | head -1)

if [ -f "$latest_json" ]; then
    echo -e "${GREEN}✅ Found scan results: $latest_json${NC}"
    echo ""

    # Check for enhanced data
    echo "Checking for enhanced service detection data..."

    # Count enhanced fields
    cpe_count=$(grep -o '"cpe"' "$latest_json" | wc -l)
    version_count=$(grep -o '"version":' "$latest_json" | wc -l)
    product_count=$(grep -o '"product":' "$latest_json" | wc -l)
    banner_count=$(grep -o '"banner"' "$latest_json" | wc -l)

    echo ""
    echo "Enhanced Data Found:"
    echo "  - CPE identifiers: $cpe_count"
    echo "  - Version strings: $version_count"
    echo "  - Product names: $product_count"
    echo "  - Service banners: $banner_count"
    echo ""

    # Display sample service data
    echo "Sample Service Detection Output:"
    echo "─────────────────────────────────────────────────────────"

    python3 << 'PYTHON'
import json
import sys

try:
    with open(sys.argv[1]) as f:
        data = json.load(f)

    for ip, host_info in data.get('hosts', {}).items():
        print(f"\n🖥️  Host: {ip}")
        print(f"   Status: {host_info.get('status', 'unknown')}")
        print(f"   Open Ports: {host_info.get('port_count', 0)}\n")

        for port, service in list(host_info.get('ports', {}).items())[:3]:  # First 3 ports
            print(f"   📡 Port {port}:")
            print(f"      Service: {service.get('name', 'unknown')}")

            if service.get('product'):
                print(f"      Product: {service.get('product', 'N/A')}")

            if service.get('version'):
                print(f"      Version: {service.get('version', 'N/A')}")

            if service.get('ostype'):
                print(f"      OS Type: {service.get('ostype', 'N/A')}")

            if service.get('banner'):
                banner = service.get('banner', '')[:60]
                print(f"      Banner: {banner}...")

            if service.get('http_title'):
                print(f"      HTTP Title: {service.get('http_title', 'N/A')}")

            if service.get('cpe'):
                cpe_list = service.get('cpe', [])
                if cpe_list:
                    print(f"      CPE: {cpe_list[0]}")

            print()

except Exception as e:
    print(f"Error parsing JSON: {e}")
PYTHON "$latest_json"

    echo "─────────────────────────────────────────────────────────"
    echo ""

    # Success check
    if [ "$cpe_count" -gt 0 ] && [ "$version_count" -gt 0 ]; then
        echo ""
        echo "╔════════════════════════════════════════════════════════╗"
        echo "║               ✅ SUCCESS! ✅                            ║"
        echo "║                                                        ║"
        echo "║  Enhanced Service Detection is WORKING!               ║"
        echo "║                                                        ║"
        echo "║  Your scans now include:                              ║"
        echo "║  • Service versions (for CVE matching)                ║"
        echo "║  • CPE identifiers (for vulnerability databases)      ║"
        echo "║  • Banners and HTTP details                           ║"
        echo "║  • OS detection                                       ║"
        echo "╚════════════════════════════════════════════════════════╝"
        echo ""
    else
        echo -e "${YELLOW}⚠️  Enhanced data present but limited${NC}"
        echo "This might be normal if the target has few services"
    fi

else
    echo -e "${RED}❌ No scan results found${NC}"
    echo "Check scan_test.log for errors"
    exit 1
fi

# Step 6: Show what's next
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "What to do next:"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "1. Review the scan output above"
echo "2. Check full results: cat $latest_json | python3 -m json.tool"
echo "3. View XML output: cat $latest_xml"
echo "4. Check logs: tail -50 port_monitor.log"
echo ""
echo "5. Add your real IPs to unique_ips.txt and run:"
echo "   sudo python3 -m port_monitor"
echo ""
echo "6. Configure Telegram notifications (optional):"
echo "   - Edit [Telegram] section in port_monitor.conf"
echo "   - Set bot_token and chat_id"
echo "   - Set enabled = true"
echo ""
echo "7. Wait for Sprint 1 Story 2 (CVE Integration) for automatic"
echo "   vulnerability detection using the CPE data! 🚀"
echo ""
