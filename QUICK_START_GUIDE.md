# Quick Start Guide - Testing Enhanced Service Detection

## ✅ Prerequisites Check

Before running, let's verify everything is ready:

### 1. Check nmap is installed
```bash
nmap --version
```
Expected: Version 7.0 or higher

### 2. Check Python dependencies
```bash
python3 -m port_monitor --version 2>/dev/null || echo "Module is ready"
```

### 3. Verify configuration file exists
```bash
cat port_monitor.conf | grep "aggressive_service_detection"
```
Should show: `aggressive_service_detection = true`

---

## 🚀 How to Test It (3 Methods)

### Method 1: Quick Test with scanme.nmap.org (Recommended)
```bash
# Create a test IP file
echo "scanme.nmap.org" > test_ips.txt

# Run test scan
sudo python3 -m port_monitor --config port_monitor.conf --test-ip scanme.nmap.org
```

### Method 2: Test with Local IP
```bash
# Test your local machine or a server you control
sudo python3 -m port_monitor --test-ip 127.0.0.1
```

### Method 3: Test with your IP list
```bash
# Create/edit your IP list
nano unique_ips.txt

# Add IPs (one per line):
# 192.168.1.1
# 192.168.1.100
# scanme.nmap.org

# Run full scan
sudo python3 -m port_monitor --config port_monitor.conf
```

---

## 🔍 How to Know It's Working

### Check 1: Watch the Scan Progress
You should see logs like:
```
INFO - Starting nmap scan for 192.168.1.100 (attempt 1/3)
INFO - Scan completed successfully for 192.168.1.100
DEBUG - Found open port 22/tcp: {'state': 'open', 'name': 'ssh', 'product': 'OpenSSH', 'version': '8.2p1', ...}
```

### Check 2: Look for Enhanced Data in Output

#### Old output (before):
```
22/tcp - ssh
80/tcp - http
```

#### New output (after enhancement):
```
22/tcp - ssh OpenSSH 8.2p1 Ubuntu-4ubuntu0.5
  Banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
  CPE: cpe:/a:openbsd:openssh:8.2p1

80/tcp - http Apache httpd 2.4.41
  HTTP Title: Apache2 Ubuntu Default Page
  Server: Apache/2.4.41 (Ubuntu)
  CPE: cpe:/a:apache:http_server:2.4.41
```

### Check 3: Verify Structured JSON Output
```bash
# Find the latest scan
ls -lt port_monitor_output/scan_*_structured.json | head -1

# View the JSON (should have rich service data)
python3 -c "import json; data=json.load(open('$(ls -t port_monitor_output/scan_*_structured.json | head -1)')); print(json.dumps(data, indent=2))" | head -50
```

**Look for these fields in the JSON:**
- `"product"` - should not be empty
- `"version"` - version numbers
- `"cpe"` - CPE identifiers array
- `"banner"` - service banners
- `"http_title"` - web page titles
- `"scripts"` - script outputs

### Check 4: Verify Telegram Notifications (if enabled)

Your Telegram notification should show:
```
📊 IP Scan Results: 192.168.1.100

Open Ports:
• 22/tcp
  ssh: OpenSSH 8.2p1 | OS: Linux | Banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5

• 80/tcp
  http: Apache httpd 2.4.41 | OS: Linux | 📄 Apache2 Ubuntu Default Page | 🔍 CPE: cpe:/a:apache:http_server:2.4.41
```

---

## 📋 Step-by-Step Test Example

Let's do a complete test together:

```bash
# Step 1: Create test directory and navigate
cd /home/user/port_monitoring

# Step 2: Create a simple test IP file
echo "scanme.nmap.org" > test_ips.txt

# Step 3: Update config to use test file (temporary)
cp port_monitor.conf port_monitor.conf.backup
sed -i 's/ip_list_file = .*/ip_list_file = test_ips.txt/' port_monitor.conf

# Step 4: Run the scan (requires sudo for SYN scan)
sudo python3 -m port_monitor --test-ip scanme.nmap.org --debug

# Step 5: Check the output
echo "=== Checking scan results ==="
ls -lth port_monitor_output/ | head -10

# Step 6: View the text output
echo "=== Text Output ==="
cat port_monitor_output/scan_*.txt | grep -A 5 "PORT\|SERVICE\|VERSION"

# Step 7: View structured JSON
echo "=== JSON Output (first port) ==="
python3 << 'PYTHON'
import json
import glob

files = glob.glob('port_monitor_output/scan_*_structured.json')
if files:
    with open(sorted(files)[-1]) as f:
        data = json.load(f)
        for ip, info in data.get('hosts', {}).items():
            print(f"\nIP: {ip}")
            for port, service in list(info.get('ports', {}).items())[:2]:  # First 2 ports
                print(f"\n  Port: {port}")
                print(f"  Name: {service.get('name', 'N/A')}")
                print(f"  Product: {service.get('product', 'N/A')}")
                print(f"  Version: {service.get('version', 'N/A')}")
                print(f"  Banner: {service.get('banner', 'N/A')[:50]}")
                print(f"  CPE: {service.get('cpe', ['N/A'])}")
                break
else:
    print("No scan results found yet")
PYTHON

# Step 8: Restore original config
mv port_monitor.conf.backup port_monitor.conf
```

---

## ✅ What Success Looks Like

### ✅ Enhanced Detection is Working If You See:

1. **Product Names**: `Apache httpd`, `OpenSSH`, `nginx`, `MySQL`
2. **Version Numbers**: `2.4.41`, `8.2p1`, `1.18.0`, `5.7.31`
3. **CPE Identifiers**: `cpe:/a:apache:http_server:2.4.41`
4. **Banners**: `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4`
5. **HTTP Titles**: `Apache2 Ubuntu Default Page`
6. **OS Detection**: `Linux`, `Windows`

### ❌ NOT Working If You See:

1. Only port numbers without service names
2. Empty product/version fields
3. No CPE identifiers
4. No banners or HTTP titles
5. Generic service names only (http, ssh) without details

---

## 🐛 Troubleshooting

### Issue 1: "Permission denied" or "Operation not permitted"

**Solution**: Run with sudo (required for SYN scans)
```bash
sudo python3 -m port_monitor --test-ip scanme.nmap.org
```

### Issue 2: No enhanced data showing up

**Check config:**
```bash
grep -E "aggressive_service_detection|enable_scripts" port_monitor.conf
```

Should show:
```
aggressive_service_detection = true
enable_scripts = true
```

**If false, enable them:**
```bash
sed -i 's/aggressive_service_detection = false/aggressive_service_detection = true/' port_monitor.conf
sed -i 's/enable_scripts = false/enable_scripts = true/' port_monitor.conf
```

### Issue 3: Scans taking too long

**Reduce intensity:**
```ini
[Scan]
aggressive_service_detection = false  # Use intensity 5 instead of 7
timing_template = 4                   # Faster scans
```

### Issue 4: nmap scripts not found

**Install nmap scripts:**
```bash
# Ubuntu/Debian
sudo apt-get install nmap nmap-common

# Verify scripts exist
ls /usr/share/nmap/scripts/banner.nse
ls /usr/share/nmap/scripts/http-title.nse
```

### Issue 5: No Telegram notifications

**Check Telegram config:**
```bash
grep -A 3 "\[Telegram\]" port_monitor.conf
```

**Test notification:**
```bash
python3 port_monitor/test_notification.py
```

---

## 📊 Real-World Example Output

Here's what you should see for a real scan:

### Terminal Output:
```
2025-11-06 10:30:15 INFO - Starting nmap scan for scanme.nmap.org
2025-11-06 10:30:45 INFO - Scan completed successfully
2025-11-06 10:30:45 DEBUG - Found open port 22/tcp: {
  'name': 'ssh',
  'product': 'OpenSSH',
  'version': '6.6.1p1',
  'extrainfo': 'Ubuntu-2ubuntu2',
  'ostype': 'Linux',
  'cpe': ['cpe:/a:openbsd:openssh:6.6.1p1'],
  'banner': 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2'
}
```

### JSON Output (scan_XXXXXX_structured.json):
```json
{
  "timestamp": "2025-11-06 10:30:45",
  "hosts": {
    "scanme.nmap.org": {
      "status": "up",
      "ports": {
        "22/tcp": {
          "state": "open",
          "name": "ssh",
          "product": "OpenSSH",
          "version": "6.6.1p1",
          "extrainfo": "Ubuntu-2ubuntu2",
          "ostype": "Linux",
          "cpe": ["cpe:/a:openbsd:openssh:6.6.1p1"],
          "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2",
          "conf": "10"
        },
        "80/tcp": {
          "state": "open",
          "name": "http",
          "product": "Apache httpd",
          "version": "2.4.7",
          "extrainfo": "(Ubuntu)",
          "ostype": "Linux",
          "cpe": ["cpe:/a:apache:http_server:2.4.7"],
          "http_title": "Go ahead and ScanMe!",
          "http_server": "Apache/2.4.7 (Ubuntu)"
        }
      },
      "port_count": 2
    }
  }
}
```

---

## 🎯 Quick Verification Checklist

Run this to verify everything:

```bash
#!/bin/bash
echo "=== Enhanced Service Detection Verification ==="
echo ""

echo "✓ Step 1: Check config"
if grep -q "aggressive_service_detection = true" port_monitor.conf; then
    echo "  ✅ Aggressive detection enabled"
else
    echo "  ❌ Aggressive detection disabled"
fi

if grep -q "enable_scripts = true" port_monitor.conf; then
    echo "  ✅ Scripts enabled"
else
    echo "  ❌ Scripts disabled"
fi

echo ""
echo "✓ Step 2: Check nmap"
if command -v nmap &> /dev/null; then
    echo "  ✅ nmap installed: $(nmap --version | head -1)"
else
    echo "  ❌ nmap not found"
fi

echo ""
echo "✓ Step 3: Check recent scans"
if ls port_monitor_output/scan_*.json &> /dev/null; then
    latest=$(ls -t port_monitor_output/scan_*_structured.json 2>/dev/null | head -1)
    if [ -f "$latest" ]; then
        echo "  ✅ Found scan output: $latest"
        # Check for enhanced data
        if grep -q '"cpe"' "$latest" 2>/dev/null; then
            echo "  ✅ CPE data present"
        fi
        if grep -q '"version"' "$latest" 2>/dev/null; then
            echo "  ✅ Version data present"
        fi
    fi
else
    echo "  ⚠️  No scans found yet - run a test scan"
fi

echo ""
echo "=== Ready to test! Run: ==="
echo "sudo python3 -m port_monitor --test-ip scanme.nmap.org --debug"
```

Save this as `verify_enhancement.sh` and run:
```bash
chmod +x verify_enhancement.sh
./verify_enhancement.sh
```

---

## 📞 Need Help?

If you're still having issues:

1. **Check logs**: `tail -f port_monitor.log`
2. **Run with debug**: `sudo python3 -m port_monitor --test-ip scanme.nmap.org --debug`
3. **Verify permissions**: Make sure you're using `sudo` for scans
4. **Check nmap**: `nmap -sV -sS --script banner scanme.nmap.org` (manual test)

---

## 🎓 Next Steps After Verification

Once you confirm it's working:

1. **Add your real IPs** to `unique_ips.txt`
2. **Configure Telegram** for notifications (optional)
3. **Schedule regular scans** with cron or systemd
4. **Review the enhanced data** for security insights
5. **Wait for Sprint 1 Story 2** (CVE integration) for automatic vulnerability detection!

---

Good luck! 🚀
