# nmap_scanner.py - Complete Workflow Explanation

## 📋 Overview

`nmap_scanner.py` is the core scanning engine that orchestrates the entire network port scanning process. It uses nmap (Network Mapper) to scan IP addresses and extract detailed service information.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      NmapScanner Class                      │
├─────────────────────────────────────────────────────────────┤
│  Responsibilities:                                          │
│  1. Build nmap commands with enhanced detection flags       │
│  2. Execute scans sequentially (IP by IP)                   │
│  3. Parse XML results in real-time                          │
│  4. Send notifications for each IP scanned                  │
│  5. Combine results into final output                       │
│  6. Handle retries and error recovery                       │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔄 Main Workflow

### High-Level Flow:

```
Start
  │
  ├─> Initialize Scanner (load config)
  │
  ├─> Read IP List File
  │
  ├─> For Each IP:
  │   │
  │   ├─> 1. Send "Scan Started" Notification
  │   │
  │   ├─> 2. Build nmap Command
  │   │      └─> Add service detection flags
  │   │      └─> Add scripts (banner, http-title, ssl-cert)
  │   │      └─> Add timing/rate parameters
  │   │
  │   ├─> 3. Execute nmap Scan (with retry logic)
  │   │      └─> Attempt 1
  │   │      └─> If fail: Wait & Retry (exponential backoff)
  │   │      └─> Max 3 attempts
  │   │
  │   ├─> 4. Parse XML Output
  │   │      └─> Extract: product, version, banner, CPE
  │   │      └─> Extract: scripts, SSL info, HTTP titles
  │   │      └─> Structure data as JSON
  │   │
  │   ├─> 5. Send "Scan Completed" Notification
  │   │      └─> Include all port/service details
  │   │
  │   └─> 6. Store Individual Results
  │
  ├─> Combine All Results
  │   └─> Merge XML files
  │   └─> Create structured JSON
  │
  ├─> Save to History
  │
  └─> Return Final Results
```

---

## 📊 Detailed Workflow (Step by Step)

### **Phase 1: Initialization**

```python
class NmapScanner(BaseScanner):
    def __init__(self, config: ConfigManager):
        self.config = config
        self.output_dir = config.get_output_dir()
        self.history_dir = config.get_history_dir()
        self.max_retries = 3
        self.retry_delay_base = 60  # seconds
```

**What happens:**
1. Load configuration settings
2. Set output directories
3. Configure retry parameters
4. Set up verification settings

---

### **Phase 2: Read IP List**

```python
ip_list_file = self.config.get_ip_list_file()  # e.g., unique_ips.txt
with open(ip_list_file, 'r') as f:
    ips = [line.strip() for line in f
           if line.strip() and not line.strip().startswith('#')]
```

**Example IP list file:**
```
# Production servers
192.168.1.100
192.168.1.101
masvn.com

# Test servers
10.0.0.50
```

**Result:** `ips = ['192.168.1.100', '192.168.1.101', 'masvn.com', '10.0.0.50']`

---

### **Phase 3: Sequential Scanning (Main Loop)**

```python
for idx, ip in enumerate(ips, 1):  # idx starts at 1
    # For IP 1/4, 2/4, 3/4, 4/4
```

#### **Step 3.1: Send "Scan Started" Notification**

```python
notification_manager.notify_ip_scan_started(ip, scan_id, position=idx, total=total_ips)
```

**Telegram notification sent:**
```
🔍 IP Scan Started: 192.168.1.100
Starting scan of the 1st IP address out of 4 total.
Scan ID: 20251106_054500
```

---

#### **Step 3.2: Build nmap Command**

```python
cmd = [
    'nmap',
    '-sS',                      # SYN scan (requires root)
    '-sV',                      # Version detection
    '--version-intensity', '7', # Aggressive version probing
    '-T3',                      # Timing template (normal)
    '-Pn',                      # Skip ping (assume host is up)
    '-n',                       # No DNS resolution
    '--scan-delay', '0.5s',     # 0.5 second delay between probes
    '--max-rate', '100',        # Max 100 packets/second
    '--randomize-hosts',        # Random order (doesn't matter for single IP)
    '-p', '1-1000,3306,8080',  # Ports to scan
    '-oX', '/path/to/output.xml',  # XML output
    '-oN', '/path/to/output.txt',  # Text output
    '--script', 'banner,http-server-header,http-title,ssl-cert',  # NSE scripts
    '-iL', '/tmp/ip_file.txt'   # Input file with single IP
]
```

**What each flag does:**

| Flag | Purpose | Example |
|------|---------|---------|
| `-sS` | SYN scan (stealth) | Half-open TCP connections |
| `-sV` | Service version detection | Identifies nginx 1.18.0 |
| `--version-intensity 7` | Aggressive probing | More probes = better accuracy |
| `-T3` | Timing template | 0=slow, 3=normal, 5=fast |
| `-Pn` | Skip host discovery | Assume host is online |
| `-n` | No DNS lookup | Faster scanning |
| `--scan-delay` | Delay between probes | Avoid rate limiting |
| `--max-rate` | Packet rate limit | Avoid flooding |
| `-p` | Port specification | Which ports to scan |
| `-oX` | XML output | Machine-readable results |
| `-oN` | Normal output | Human-readable results |
| `--script` | NSE scripts | Banner grabbing, HTTP info |

---

#### **Step 3.3: Execute Scan with Retry Logic**

```python
attempt = 0
success = False

while not success and attempt < self.max_retries:  # Max 3 attempts
    attempt += 1

    try:
        # Run nmap
        process = subprocess.Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            success = True
        else:
            # Failed - retry with exponential backoff
            delay = 60 * (2 ** (attempt - 1))  # 60s, 120s, 240s
            time.sleep(delay)
    except Exception as e:
        logging.error(f"Scan failed: {e}")
        # Retry...
```

**Retry Logic:**
```
Attempt 1: Run scan → Fail → Wait 60 seconds
Attempt 2: Run scan → Fail → Wait 120 seconds
Attempt 3: Run scan → Success ✓
```

**What nmap is doing during the scan:**
1. Send SYN packets to each port
2. If port responds with SYN-ACK → Port is OPEN
3. For open ports: Connect and probe service
4. Send specific payloads to identify service/version
5. Run NSE scripts (banner, http-title, etc.)
6. Write results to XML file

---

#### **Step 3.4: Parse XML Output (Real-time)**

```python
import xml.etree.ElementTree as ET

tree = ET.parse(ip_xml_output)
root = tree.getroot()

# Find host element
hosts_found = root.findall('./host')
host_element = hosts_found[0]

# Get IP address
addr_elem = host_element.find('./address')
actual_ip = addr_elem.get('addr')  # e.g., "192.168.1.100"

# Get status
status_elem = host_element.find('./status')
status = status_elem.get('state')  # "up" or "down"

# Get all open ports
ports_dict = {}
for port_elem in host_element.findall('./ports/port'):
    port_id = port_elem.get('portid')      # "80"
    protocol = port_elem.get('protocol')   # "tcp"
    port_key = f"{port_id}/{protocol}"     # "80/tcp"

    # Check if port is open
    state_elem = port_elem.find('./state')
    if state_elem.get('state') == 'open':
        # Extract service details
        service_info = extract_service_details(port_elem)
        ports_dict[port_key] = service_info
```

**Example XML structure:**
```xml
<nmaprun>
  <host>
    <address addr="192.168.1.100" addrtype="ipv4"/>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0" ostype="Linux">
          <cpe>cpe:/a:igor_sysoev:nginx:1.18.0</cpe>
        </service>
        <script id="http-title" output="Welcome Page"/>
        <script id="http-server-header" output="nginx/1.18.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
```

**Parsed result:**
```python
{
    "80/tcp": {
        "state": "open",
        "name": "http",
        "product": "nginx",
        "version": "1.18.0",
        "ostype": "Linux",
        "cpe": ["cpe:/a:igor_sysoev:nginx:1.18.0"],
        "http_title": "Welcome Page",
        "http_server": "nginx/1.18.0"
    }
}
```

---

#### **Step 3.5: Extract Enhanced Service Details**

This is the **Sprint 1 enhancement** - extracting rich service data:

```python
service_info = {
    # Basic info
    'state': 'open',
    'reason': 'syn-ack',
    'name': 'http',

    # Version info (Sprint 1 enhancement)
    'product': 'nginx',
    'version': '1.18.0',
    'extrainfo': '(Ubuntu)',

    # OS detection (Sprint 1 enhancement)
    'ostype': 'Linux',

    # Detection metadata (Sprint 1 enhancement)
    'method': 'probed',
    'conf': '10',  # Confidence: 0-10

    # CPE for CVE matching (Sprint 1 enhancement)
    'cpe': ['cpe:/a:igor_sysoev:nginx:1.18.0'],

    # Script outputs (Sprint 1 enhancement)
    'http_title': 'Welcome to nginx!',
    'http_server': 'nginx/1.18.0',
    'banner': 'nginx/1.18.0',

    # All scripts
    'scripts': {
        'http-title': 'Welcome to nginx!',
        'http-server-header': 'nginx/1.18.0'
    }
}
```

**Why this matters:**
- `product` + `version` → Can check for vulnerabilities
- `cpe` → Standard identifier for CVE databases
- `banner` → Helps verify service identity
- `http_title` → Identifies web applications
- `conf` → Know how reliable the detection is

---

#### **Step 3.6: Send "Scan Completed" Notification**

```python
scan_data = {
    'timestamp': '2025-11-06 05:45:00',
    'ports': ports_dict,
    'port_count': len(ports_dict),
    'status': 'up'
}

notification_manager.notify_ip_scanned(ip, scan_data, position=idx, total=total_ips)
```

**Telegram notification sent:**
```
📊 IP Scan Results: 192.168.1.100

Completed scan of the 1st IP address out of 4 total.

Open Ports:
• 80/tcp
  http: nginx 1.18.0 | OS: Linux | 📄 Welcome to nginx! | 🔍 CPE: cpe:/a:igor_sysoev:nginx:1.18.0

• 22/tcp
  ssh: OpenSSH 8.2p1 | OS: Linux | Banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4
```

---

### **Phase 4: Combine Results**

After scanning all IPs, combine the results:

```python
# Store all host data
all_hosts_data = []
combined_hosts_dict = {}

for ip, xml_file, txt_file in individual_results:
    # Parse each XML file
    tree = ET.parse(xml_file)
    root = tree.getroot()
    host_elements = root.findall('./host')

    # Store for XML combination
    all_hosts_data.append((ip, host_elements[0]))

    # Store structured data for JSON
    combined_hosts_dict[ip] = {
        'status': 'up',
        'ports': ports_dict,
        'port_count': len(ports_dict)
    }
```

**Create combined XML:**
```python
with open(final_xml_output, 'w') as f:
    f.write('<?xml version="1.0"?>\n')
    f.write('<nmaprun scanner="nmap">\n')

    # Add all host elements
    for ip, host_element in all_hosts_data:
        host_xml = ET.tostring(host_element, encoding='unicode')
        f.write(f'  {host_xml}\n')

    f.write('  <runstats>\n')
    f.write(f'    <hosts up="{successful_scans}" total="{total_ips}"/>\n')
    f.write('  </runstats>\n')
    f.write('</nmaprun>\n')
```

**Create structured JSON:**
```python
combined_data = {
    'timestamp': '2025-11-06 05:45:00',
    'hosts': combined_hosts_dict
}

with open(json_output, 'w') as f:
    json.dump(combined_data, f, indent=2)
```

---

### **Phase 5: Save to History**

```python
# Copy to history directory with timestamp
history_file = os.path.join(history_dir, f"scan_{scan_id}.xml")
shutil.copy2(final_xml_output, history_file)
```

**History directory structure:**
```
port_monitor_output/
├── history/
│   ├── scan_20251106_054500.xml
│   ├── scan_20251106_094500.xml
│   └── scan_20251106_134500.xml
├── scan_20251106_134500.xml        (latest)
├── scan_20251106_134500.txt        (latest)
└── scan_20251106_134500_structured.json  (latest)
```

---

## 🔍 Key Features Explained

### **1. Sequential Scanning (Why?)**

```python
for idx, ip in enumerate(ips, 1):
    # Scan IP 1
    # Complete before moving to IP 2
    # Scan IP 2
    # Complete before moving to IP 3
```

**Why sequential instead of parallel?**
- ✅ Avoid network congestion
- ✅ More reliable detection
- ✅ Better rate limiting control
- ✅ Easier to track progress
- ✅ Individual IP notifications

---

### **2. Retry Logic with Exponential Backoff**

```python
# Attempt 1: Fail → Wait 60s
delay = 60 * (2 ** 0) = 60 seconds

# Attempt 2: Fail → Wait 120s
delay = 60 * (2 ** 1) = 120 seconds

# Attempt 3: Fail → Wait 240s
delay = 60 * (2 ** 2) = 240 seconds
```

**Why exponential backoff?**
- If network is congested, waiting longer helps
- Avoids hammering the target
- Industry best practice

---

### **3. Enhanced Service Detection (Sprint 1)**

**Old flow:**
```
nmap → Find open port → Store "80/tcp - http"
```

**New flow (enhanced):**
```
nmap → Find open port → Probe service → Run scripts → Extract:
  - Product: nginx
  - Version: 1.18.0
  - Banner: nginx/1.18.0
  - HTTP Title: Welcome
  - CPE: cpe:/a:igor_sysoev:nginx:1.18.0
  - OS: Linux
```

---

### **4. Real-time Notifications**

```
IP 1: Scan Start → Scanning... → Scan Complete ✓
IP 2: Scan Start → Scanning... → Scan Complete ✓
IP 3: Scan Start → Scanning... → Scan Complete ✓
```

Each step sends a Telegram notification so you can track progress in real-time!

---

## 📊 Data Flow Diagram

```
┌──────────────┐
│ unique_ips.txt│
│ - IP 1       │
│ - IP 2       │
│ - IP 3       │
└───────┬──────┘
        │
        ▼
┌────────────────────┐
│  NmapScanner       │
│  .run_scan()       │
└─────────┬──────────┘
          │
          ▼
    ┌─────────────────┐
    │ For each IP:    │
    │                 │
    │ 1. Build cmd    │
    │ 2. Run nmap     │
    │ 3. Parse XML    │
    │ 4. Extract data │
    │ 5. Notify       │
    └────────┬────────┘
             │
             ▼
    ┌──────────────────┐
    │ Combine Results  │
    └────────┬─────────┘
             │
             ├──────────────────────────────┐
             │                              │
             ▼                              ▼
    ┌───────────────┐            ┌────────────────────┐
    │ scan_ID.xml   │            │ scan_ID_structured │
    │ (raw nmap)    │            │ .json (enhanced)   │
    └───────┬───────┘            └─────────┬──────────┘
            │                              │
            ▼                              ▼
    ┌────────────────┐           ┌─────────────────┐
    │ history/       │           │ Notifications   │
    │ scan_ID.xml    │           │ (Telegram)      │
    └────────────────┘           └─────────────────┘
```

---

## 🎯 Example: Scanning 2 IPs

### Input: `unique_ips.txt`
```
192.168.1.100
masvn.com
```

### Execution Timeline:

```
00:00 - Read IP list: 2 IPs found
00:01 - Starting scan 1/2: 192.168.1.100
00:01 - 📱 Notification: "Scan Started - 192.168.1.100"
00:02 - Running nmap on 192.168.1.100
00:45 - Scan complete (45 seconds)
00:46 - Parsing XML results
00:46 - Found ports: 22/tcp (SSH), 80/tcp (HTTP), 443/tcp (HTTPS)
00:47 - 📱 Notification: "Scan Complete - 192.168.1.100 (3 ports open)"
00:47 - Starting scan 2/2: masvn.com
00:47 - 📱 Notification: "Scan Started - masvn.com"
00:48 - Running nmap on masvn.com
01:30 - Scan complete (42 seconds)
01:31 - Parsing XML results
01:31 - Found ports: 22/tcp (SSH), 80/tcp (HTTP), 443/tcp (HTTPS), 3306/tcp (MySQL)
01:32 - 📱 Notification: "Scan Complete - masvn.com (4 ports open)"
01:33 - Combining all results
01:34 - Creating final XML and JSON
01:35 - Saving to history
01:36 - Done! Total time: 1 minute 36 seconds
```

---

## 💡 Key Takeaways

1. **Sequential Processing**: One IP at a time for reliability
2. **Retry Logic**: 3 attempts with exponential backoff
3. **Real-time Notifications**: Progress updates for each IP
4. **Enhanced Detection**: Rich service data (Sprint 1 feature)
5. **Multiple Outputs**: XML (raw), JSON (structured), TXT (readable)
6. **History Tracking**: All scans saved for comparison

---

## 🔧 Configuration Impact

```ini
[Scan]
ports = 1-1000,3306,8080              # What ports to scan
scan_delay = 0.5s                     # Delay between probes
max_rate = 100                        # Max packets/second
timing_template = 3                   # Speed (0-5)
aggressive_service_detection = true   # Use --version-intensity 7
enable_scripts = true                 # Run NSE scripts
```

Each setting affects the nmap command that gets built!

---

This is the complete workflow of `nmap_scanner.py` - from reading IPs to delivering rich service intelligence! 🚀
