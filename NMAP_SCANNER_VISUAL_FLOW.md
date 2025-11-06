# nmap_scanner.py - Visual Workflow Diagrams

## 🎯 Quick Visual Guide

### **1. Overall System Flow**

```
┌─────────────────────────────────────────────────────────────────┐
│                        PORT MONITOR SYSTEM                       │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │   Read Configuration   │
                    │   (port_monitor.conf)  │
                    └────────────┬───────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │   Read IP List File    │
                    │   (unique_ips.txt)     │
                    └────────────┬───────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │    NmapScanner         │
                    │    .run_scan()         │
                    └────────────┬───────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 │  Sequential IP Processing     │
                 └───────────────┬───────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
        ▼                        ▼                        ▼
   ┌─────────┐            ┌─────────┐            ┌─────────┐
   │  IP 1   │            │  IP 2   │            │  IP 3   │
   │  Scan   │            │  Scan   │            │  Scan   │
   └────┬────┘            └────┬────┘            └────┬────┘
        │                      │                      │
        └──────────────────────┴──────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │   Combine All Results  │
                    └────────────┬───────────┘
                                 │
                    ┌────────────┴───────────┐
                    │                        │
                    ▼                        ▼
           ┌────────────────┐      ┌────────────────┐
           │  XML Output    │      │  JSON Output   │
           │  scan_ID.xml   │      │  scan_ID.json  │
           └────────────────┘      └────────────────┘
```

---

## 📊 Single IP Scan Workflow

```
┌────────────────────────────────────────────────────────┐
│              Scanning IP: 192.168.1.100                │
└────────────────────────────────────────────────────────┘

    Step 1: Notification
    ┌─────────────────────┐
    │ 📱 Telegram:        │
    │ "Scan Started"      │
    └──────────┬──────────┘
               │
               ▼
    Step 2: Build nmap Command
    ┌─────────────────────────────────────────┐
    │ nmap -sS -sV --version-intensity 7      │
    │      -T3 -Pn -n                         │
    │      --scan-delay 0.5s                  │
    │      --max-rate 100                     │
    │      -p 1-1000,3306,8080               │
    │      --script banner,http-title         │
    │      -oX output.xml                     │
    │      192.168.1.100                      │
    └──────────┬──────────────────────────────┘
               │
               ▼
    Step 3: Execute Scan (with retries)
    ┌─────────────────────────────────────────┐
    │  Attempt 1                              │
    │  ├─> nmap running... ████████░░ 80%     │
    │  └─> Success! ✓                         │
    │                                         │
    │  (If failed, retry 2 more times)        │
    └──────────┬──────────────────────────────┘
               │
               ▼
    Step 4: Parse XML Output
    ┌─────────────────────────────────────────┐
    │  <host>                                 │
    │    <address addr="192.168.1.100"/>      │
    │    <ports>                              │
    │      <port portid="80">                 │
    │        <service name="http"             │
    │                product="nginx"          │
    │                version="1.18.0"/>       │
    │      </port>                            │
    │    </ports>                             │
    │  </host>                                │
    └──────────┬──────────────────────────────┘
               │
               ▼
    Step 5: Extract Service Details
    ┌─────────────────────────────────────────┐
    │  Port 80/tcp:                           │
    │  {                                      │
    │    "name": "http",                      │
    │    "product": "nginx",                  │
    │    "version": "1.18.0",                 │
    │    "ostype": "Linux",                   │
    │    "cpe": ["cpe:/a:...:nginx:1.18.0"],│
    │    "http_title": "Welcome Page",        │
    │    "http_server": "nginx/1.18.0"        │
    │  }                                      │
    └──────────┬──────────────────────────────┘
               │
               ▼
    Step 6: Send Results Notification
    ┌─────────────────────────────────────────┐
    │ 📱 Telegram:                            │
    │ "Scan Complete - 192.168.1.100"         │
    │                                         │
    │ Open Ports:                             │
    │ • 80/tcp                                │
    │   http: nginx 1.18.0 | OS: Linux        │
    │   📄 Welcome Page                       │
    │   🔍 CPE: cpe:/a:...:nginx:1.18.0      │
    └─────────────────────────────────────────┘
```

---

## 🔄 Retry Logic Flow

```
┌────────────────────────────────────────────────────┐
│              Execute nmap Scan                     │
└────────────────────────────────────────────────────┘

    Attempt 1
    ┌──────────────────┐
    │  Run nmap scan   │
    └────────┬─────────┘
             │
             ├─> Success? ──> ✓ Continue to parsing
             │
             └─> Failed? ──> Wait 60 seconds
                             │
                             ▼
                         Attempt 2
                         ┌──────────────────┐
                         │  Run nmap scan   │
                         └────────┬─────────┘
                                  │
                                  ├─> Success? ──> ✓ Continue
                                  │
                                  └─> Failed? ──> Wait 120 seconds
                                                  │
                                                  ▼
                                              Attempt 3 (FINAL)
                                              ┌──────────────────┐
                                              │  Run nmap scan   │
                                              └────────┬─────────┘
                                                       │
                                                       ├─> Success? ──> ✓ Continue
                                                       │
                                                       └─> Failed? ──> ✗ Give up
                                                                       │
                                                                       ▼
                                                           Log error & skip IP
```

**Exponential Backoff:**
- Attempt 1 → Fail → Wait `60 × 2⁰ = 60s`
- Attempt 2 → Fail → Wait `60 × 2¹ = 120s`
- Attempt 3 → Final attempt

---

## 📦 Data Extraction Flow

```
┌────────────────────────────────────────────────────────┐
│                  XML Parsing Pipeline                  │
└────────────────────────────────────────────────────────┘

    Raw nmap XML
    ┌─────────────────────────────────────┐
    │ <port portid="80" protocol="tcp">   │
    │   <state state="open"/>             │
    │   <service name="http"              │
    │            product="nginx"          │
    │            version="1.18.0"         │
    │            ostype="Linux">          │
    │     <cpe>cpe:/a:...:nginx:1.18</cpe>│
    │   </service>                        │
    │   <script id="http-title"           │
    │          output="Welcome"/>         │
    │   <script id="banner"               │
    │          output="nginx/1.18.0"/>    │
    │ </port>                             │
    └──────────────┬──────────────────────┘
                   │
                   ▼
    Extract Basic Info
    ┌─────────────────────────────────────┐
    │ port_id = "80"                      │
    │ protocol = "tcp"                    │
    │ state = "open"                      │
    │ name = "http"                       │
    └──────────────┬──────────────────────┘
                   │
                   ▼
    Extract Service Info (Sprint 1 Enhancement)
    ┌─────────────────────────────────────┐
    │ product = "nginx"                   │
    │ version = "1.18.0"                  │
    │ ostype = "Linux"                    │
    │ method = "probed"                   │
    │ conf = "10"                         │
    └──────────────┬──────────────────────┘
                   │
                   ▼
    Extract CPE (Sprint 1 Enhancement)
    ┌─────────────────────────────────────┐
    │ cpe = [                             │
    │   "cpe:/a:igor_sysoev:nginx:1.18.0" │
    │ ]                                   │
    └──────────────┬──────────────────────┘
                   │
                   ▼
    Extract Scripts (Sprint 1 Enhancement)
    ┌─────────────────────────────────────┐
    │ scripts = {                         │
    │   "http-title": "Welcome",          │
    │   "banner": "nginx/1.18.0",         │
    │   "http-server-header": "nginx/..."│
    │ }                                   │
    │                                     │
    │ http_title = "Welcome"              │
    │ banner = "nginx/1.18.0"             │
    └──────────────┬──────────────────────┘
                   │
                   ▼
    Final Service Object
    ┌─────────────────────────────────────┐
    │ {                                   │
    │   "state": "open",                  │
    │   "name": "http",                   │
    │   "product": "nginx",               │
    │   "version": "1.18.0",              │
    │   "ostype": "Linux",                │
    │   "cpe": ["cpe:/a:...:nginx:..."],  │
    │   "http_title": "Welcome",          │
    │   "banner": "nginx/1.18.0",         │
    │   "scripts": { ... }                │
    │ }                                   │
    └─────────────────────────────────────┘
```

---

## 🎭 State Machine View

```
┌──────────────────────────────────────────────────────────┐
│             NmapScanner State Machine                    │
└──────────────────────────────────────────────────────────┘

    [IDLE]
      │
      │ run_scan() called
      ▼
    [READING IP LIST]
      │
      │ IPs loaded
      ▼
    [SCANNING IP 1]
      │
      ├─> [NOTIFY START] ─────> Telegram notification
      │
      ├─> [BUILD COMMAND] ────> Create nmap command
      │
      ├─> [EXECUTE SCAN] ─────> Run nmap subprocess
      │    │
      │    ├─> [RETRY?] ──────> If failed, retry
      │    │
      │    └─> [SUCCESS] ─────> Continue
      │
      ├─> [PARSE XML] ────────> Extract service data
      │
      └─> [NOTIFY COMPLETE] ──> Telegram notification
          │
          ▼
    [SCANNING IP 2]
      │
      └─> (Same flow as IP 1)
          │
          ▼
    [SCANNING IP N]
      │
      └─> (Same flow)
          │
          ▼
    [COMBINING RESULTS]
      │
      ├─> Merge all XML files
      ├─> Create structured JSON
      └─> Save to history
          │
          ▼
    [COMPLETE]
```

---

## 📊 Multi-IP Timeline

```
Time    IP 1                IP 2                IP 3
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
00:00   📱 Start notify
00:05   🔍 Scanning...
00:40   ✓ Complete
00:41   📱 Result notify
00:42                       📱 Start notify
00:47                       🔍 Scanning...
01:22                       ✓ Complete
01:23                       📱 Result notify
01:24                                           📱 Start notify
01:29                                           🔍 Scanning...
02:04                                           ✓ Complete
02:05                                           📱 Result notify
02:06   ═══════════════════════════════════════════════════
        🔧 Combining all results
        💾 Saving to history
        ✅ DONE

Total Time: ~2 minutes
```

**Note:** IPs are scanned **sequentially**, not in parallel!

---

## 🔍 Configuration to nmap Command Mapping

```
port_monitor.conf                    nmap Command
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[Scan]
ports = 1-1000,3306,8080       →    -p 1-1000,3306,8080

scan_delay = 0.5s              →    --scan-delay 0.5s

max_rate = 100                 →    --max-rate 100

timing_template = 3            →    -T3

aggressive_service_detection   →    --version-intensity 7
  = true                            (if false: --version-intensity 5)

enable_scripts = true          →    --script banner,http-server-header,
                                            http-title,ssl-cert,
                                            tls-nextprotoneg

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Final Command:
nmap -sS -sV --version-intensity 7 -T3 -Pn -n \
     --scan-delay 0.5s --max-rate 100 \
     -p 1-1000,3306,8080 \
     --script banner,http-server-header,http-title,ssl-cert \
     -oX output.xml -oN output.txt \
     -iL ip_list.txt
```

---

## 🎯 Decision Points

```
                    Start Scan
                        │
                        ▼
                 ┌──────────────┐
                 │ IP reachable?│
                 └──────┬───────┘
                        │
           ┌────────────┴────────────┐
           │                         │
          YES                       NO
           │                         │
           ▼                         ▼
    ┌─────────────┐          ┌─────────────┐
    │ Scan ports  │          │ Mark as down│
    └──────┬──────┘          └─────────────┘
           │
           ▼
    ┌──────────────┐
    │ Port open?   │
    └──────┬───────┘
           │
    ┌──────┴───────┐
    │              │
   YES            NO
    │              │
    ▼              ▼
┌──────────┐  ┌──────────┐
│ Probe    │  │ Skip     │
│ service  │  │ port     │
└────┬─────┘  └──────────┘
     │
     ▼
┌─────────────────┐
│ Service         │
│ identified?     │
└────┬────────────┘
     │
  ┌──┴──┐
  │     │
 YES   NO
  │     │
  ▼     ▼
Record  Generic
details service
```

---

## 📈 Performance Characteristics

```
Number of IPs: 10
Ports per IP: 1000
Scan delay: 0.5s
Max rate: 100 pkt/s

Estimated Time per IP:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Port probing:      ~30-45 seconds
Service detection: ~15-30 seconds
Script execution:  ~5-10 seconds
Total per IP:      ~50-85 seconds
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total for 10 IPs: ~8-14 minutes
(Sequential scanning)

With aggressive detection (+30%):
Total: ~10-18 minutes

With parallel (not implemented):
Total: ~1-2 minutes
(but less reliable)
```

---

## 💡 Key Points

1. **Sequential = Reliable**: One IP at a time, no race conditions
2. **Retry = Resilient**: Network hiccups don't kill the scan
3. **Real-time Feedback**: Telegram notifications for each step
4. **Rich Data**: 15+ fields per service (vs 4 in old version)
5. **Multiple Outputs**: XML, JSON, TXT for different use cases

---

This visual guide should make it much clearer how nmap_scanner.py works! 🚀
