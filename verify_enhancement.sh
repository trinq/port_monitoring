#!/bin/bash
# Quick verification script for Enhanced Service Detection

echo "=================================="
echo "Enhanced Service Detection Check"
echo "=================================="
echo ""

# Check 1: Configuration
echo "✓ Step 1: Checking configuration..."
if grep -q "aggressive_service_detection = true" port_monitor.conf; then
    echo "  ✅ Aggressive detection: ENABLED"
else
    echo "  ⚠️  Aggressive detection: DISABLED"
    echo "     Fix: Set 'aggressive_service_detection = true' in port_monitor.conf"
fi

if grep -q "enable_scripts = true" port_monitor.conf; then
    echo "  ✅ Nmap scripts: ENABLED"
else
    echo "  ⚠️  Nmap scripts: DISABLED"
    echo "     Fix: Set 'enable_scripts = true' in port_monitor.conf"
fi

echo ""

# Check 2: nmap installation
echo "✓ Step 2: Checking nmap installation..."
if command -v nmap &> /dev/null; then
    version=$(nmap --version | head -1)
    echo "  ✅ nmap found: $version"
else
    echo "  ❌ nmap NOT FOUND"
    echo "     Fix: sudo apt-get install nmap"
    exit 1
fi

echo ""

# Check 3: nmap scripts
echo "✓ Step 3: Checking nmap scripts..."
scripts_found=0
for script in banner http-title http-server-header ssl-cert; do
    if ls /usr/share/nmap/scripts/${script}.nse &> /dev/null; then
        ((scripts_found++))
    fi
done
echo "  ✅ Found $scripts_found/4 required scripts"

echo ""

# Check 4: Recent scans
echo "✓ Step 4: Checking for recent scans..."
if ls port_monitor_output/scan_*_structured.json &> /dev/null 2>&1; then
    latest=$(ls -t port_monitor_output/scan_*_structured.json 2>/dev/null | head -1)
    echo "  ✅ Latest scan: $(basename $latest)"

    # Check for enhanced data
    has_cpe=$(grep -c '"cpe"' "$latest" 2>/dev/null || echo 0)
    has_version=$(grep -c '"version"' "$latest" 2>/dev/null || echo 0)
    has_product=$(grep -c '"product"' "$latest" 2>/dev/null || echo 0)

    echo "  📊 Enhanced data in scan:"
    echo "     - CPE identifiers: $has_cpe"
    echo "     - Version strings: $has_version"
    echo "     - Product names: $has_product"

    if [ "$has_cpe" -gt 0 ] && [ "$has_version" -gt 0 ]; then
        echo "  ✅ Enhanced detection IS WORKING!"
    else
        echo "  ⚠️  Enhanced data not found - may need to run a new scan"
    fi
else
    echo "  ⚠️  No scans found yet"
    echo "     Run a test scan to verify"
fi

echo ""
echo "=================================="
echo "Summary"
echo "=================================="

# Overall status
if command -v nmap &> /dev/null && grep -q "aggressive_service_detection = true" port_monitor.conf; then
    echo "✅ System is configured correctly!"
    echo ""
    echo "🚀 Ready to test! Run one of these:"
    echo ""
    echo "   # Quick test with safe public server:"
    echo "   sudo python3 -m port_monitor --test-ip scanme.nmap.org --debug"
    echo ""
    echo "   # Test with localhost:"
    echo "   sudo python3 -m port_monitor --test-ip 127.0.0.1 --debug"
    echo ""
else
    echo "⚠️  Some configuration needed - see messages above"
fi

echo ""
