<div align="center">

# ⬡ NPS-IDS

### Network Packet Sniffer & Intrusion Detection / Prevention System

**Real-time packet capture · 16 attack signatures · Auto-blocking · Email alerts · SQLite logging · PCAP evidence**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-1F8ACB?style=flat-square)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?style=flat-square&logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-22%20passing-brightgreen?style=flat-square)

</div>

---

## What is NPS-IDS?

NPS-IDS is a host-based **Intrusion Detection and Prevention System** built entirely in Python. It captures live network traffic using [Scapy](https://scapy.net/), runs every packet through 16 signature-based detection engines, and responds in real-time by alerting, logging, blocking attackers, and saving packet evidence.

It was built as a **security engineering portfolio project** — production-grade architecture, a complete 6-tab GUI dashboard, a formal pentest audit with 12 fixed vulnerabilities, and 22 unit tests.

---

## Dashboard Preview

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ⬡  NPS-IDS    Intrusion Detection & Prevention System       ● LIVE    │
├─────────────────────────────────────────────────────────────────────────┤
│  CRITICAL: 3    HIGH: 12    MEDIUM: 8    LOW: 5    INFO: 0    ERROR: 0  │
├─────────────────────────────────────────────────────────────────────────┤
│  [🔴 Live Alerts] [📊 Analytics] [🎯 Top Threats] [🛡 IPS] [📧 Email] [⚙ Settings] │
│                                                                         │
│  [10:42:01] [CRITICAL] 192.168.1.55    SYN flood – rate >150 SYNs/win  │
│  [10:42:03] [HIGH    ] 10.0.0.22       Port scan – 17 unique ports      │
│  [10:42:05] [MEDIUM  ] 172.16.0.8      Failed login flood – 10 attempts │
│  [10:42:09] [HIGH    ] 10.0.0.22       HTTP brute force – 20 POSTs      │
│  [10:42:11] [CRITICAL] 192.168.1.55    DoS flood – rate >200 pkts/win   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Features

| Category | Details |
|---|---|
| **Packet capture** | Scapy `AsyncSniffer` — IP, TCP, UDP, ICMP, DNS, ARP |
| **Detections** | 16 signature types, sliding-window counters, per-IP state |
| **IPS** | Auto-block in-process + `iptables DROP` rule on Linux |
| **Email alerts** | Gmail SSL:465 / STARTTLS:587 fallback · throttled (5 min cooldown, 50/day cap) |
| **SQLite log** | Every alert persisted to `nps_ids.db` · survives restarts |
| **PCAP capture** | Saves pre-trigger + trigger packets as `.pcap` for Wireshark |
| **Daily report** | Auto-generated HTML report · optionally emailed at midnight |
| **Dashboard** | 6-tab Tkinter GUI · live chart · threat table · IPS panel |
| **Security** | 12 pentest vulnerabilities found and fixed (see `SECURITY_AUDIT.md`) |
| **Tests** | 22 pytest unit tests · no root · no network required |

---

## Attack Detections

| Severity | Detection | Trigger |
|---|---|---|
| 🔴 CRITICAL | SYN Flood | ≥150 SYN-only packets / 10 sec from one IP |
| 🔴 CRITICAL | DoS Flood | ≥200 packets / 10 sec from one IP |
| 🔴 CRITICAL | ARP Spoofing | Same IP announced from 2+ MAC addresses |
| 🟠 HIGH | Port Scan | ≥15 unique destination ports / 5 sec |
| 🟠 HIGH | ICMP Flood | ≥100 Echo Requests / 5 sec from one IP |
| 🟠 HIGH | UDP Flood | ≥300 UDP packets / 10 sec from one IP |
| 🟠 HIGH | HTTP Brute Force | ≥20 POSTs to login endpoints / 30 sec |
| 🟡 MEDIUM | Failed Login | ≥10 hits on auth ports (22/23/3389…) / 60 sec |
| 🟡 MEDIUM | NULL Scan | TCP packet with no flags set |
| 🟡 MEDIUM | FIN Scan | TCP packet with only FIN flag |
| 🟡 MEDIUM | XMAS Scan | TCP FIN+PSH+URG flags |
| 🟡 MEDIUM | DNS Amplification | DNS response > 512 bytes |
| 🟡 MEDIUM | ICMP Large Payload | ICMP payload > 1024 bytes (ping-of-death) |
| 🔵 LOW | ACK Scan | TCP packet with only ACK flag |
| 🔵 LOW | Malformed IP Header | IHL field outside valid range 5–15 |
| 🔵 LOW | Suspicious Fragmentation | MF flag + offset 0 + tiny payload |

---

## Project Structure

```
nps-ids/
│
├── main.py               Entry point — config loader, sniffer launcher, GUI
├── sniffer.py            Packet capture — Scapy AsyncSniffer, all 6 protocols
├── detections.py         16 detection functions — bounded sliding-window state
├── ips.py                Block/unblock engine — in-process + iptables
├── mailer.py             SMTP email — SSL/STARTTLS, throttle, header injection fix
├── gui.py                6-tab Tkinter dashboard — 880 lines
├── logger.py             SQLite alert persistence — nps_ids.db
├── pcap.py               Packet evidence capture — .pcap files for Wireshark
├── report.py             HTML daily report generator + midnight email scheduler
├── config.json           User settings — loaded on startup, saved by GUI
│
├── test_detections.py    22 pytest unit tests — no root, no network needed
├── requirements.txt      pip dependencies
├── README.md             This file
├── SECURITY_AUDIT.md     Full pentest audit — 12 vulnerabilities found & fixed
│
├── captures/             Auto-created — saved .pcap files
├── reports/              Auto-created — saved HTML reports
└── nps_ids.db            Auto-created — SQLite alert database
```

---

## Architecture

```
Network Traffic
      │
      ▼  BPF filter: "ip or arp"
┌─────────────┐
│  sniffer.py │  AsyncSniffer — non-blocking, thread-safe
│  (Scapy)    │
└──────┬──────┘
       │  packet_callback() fires per packet
       ▼
┌──────────────────┐   IPS gate: blocked IPs dropped here
│  detections.py   │   16 signature functions
│  (16 signatures) │   Bounded per-IP sliding windows
└──────┬───────────┘
       │  alert tuple: (kind, src_ip, message)
       ▼
┌─────────────┐    ┌───────────┐    ┌──────────┐    ┌──────────┐
│ alert_queue │    │  ips.py   │    │ logger.py│    │  pcap.py │
│  (thread-   │    │ auto-block│    │  SQLite  │    │  .pcap   │
│   safe)     │    │ +iptables │    │  nps_ids │    │ evidence │
└──────┬──────┘    └───────────┘    └──────────┘    └──────────┘
       │
       ▼  300ms poll — batch insert, ONE state toggle
┌─────────────────────────────────────────────────────┐
│                      gui.py                         │
│  Tab 1: Live Alerts  Tab 2: Analytics chart         │
│  Tab 3: Top Threats  Tab 4: IPS table               │
│  Tab 5: Email config Tab 6: Settings & thresholds   │
└──────────────────┬──────────────────────────────────┘
                   │  email_on = True
                   ▼
            ┌────────────┐
            │ mailer.py  │  SSL:465 → STARTTLS:587 fallback
            │ (throttled)│  4 anti-spam rules
            └────────────┘
```

---

## Requirements

- **Python 3.10+**
- **Root / Administrator privileges** (raw packet capture)
- **Linux** — full support including iptables auto-blocking
- **macOS** — full support, in-process IPS only
- **Windows** — requires [Npcap](https://npcap.com), in-process IPS only

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/nps-ids.git
cd nps-ids

# 2. Install Python dependencies
pip install -r requirements.txt

# Ubuntu/Debian — if pip complains about system packages:
pip install -r requirements.txt --break-system-packages

# Ubuntu/Debian — install tkinter if not present:
sudo apt install python3-tk

# 3. Run the unit tests (no root needed)
pytest test_detections.py -v
# Expected: 22 passed
```

---

## Running

```bash
# Standard — GUI mode, sniff all interfaces
sudo python main.py

# Specific interface
sudo python main.py --iface eth0

# List available interfaces
sudo python main.py --list-ifaces

# Headless / server mode (no GUI, logs to SQLite)
sudo python main.py --no-gui

# Generate a manual report from logged data
python report.py

# Generate and email the report
python report.py --send

# Run unit tests (no root, no network)
pytest test_detections.py -v
```

---

## Email Setup (Gmail)

1. Log into your **sender** Gmail account
2. Go to **myaccount.google.com → Security**
3. Enable **2-Step Verification**
4. Go to **myaccount.google.com/apppasswords**
5. Click **Create** → name it `NPS-IDS` → copy the 16-character code
6. In the GUI → **Email** tab, fill in:

| Field | Value |
|---|---|
| SMTP Server | `smtp.gmail.com` |
| SMTP Port | `465` |
| Sender Email | `your_sender@gmail.com` |
| App Password | *(16-character code from step 5)* |
| Receiver Email | `your_receiver@gmail.com` |

7. Click **Save Config** → **Test Connection** → **Send Test Email**

> The mailer automatically falls back to STARTTLS port 587 if SSL port 465 is blocked by your network or firewall.

### Email Throttle Rules

| Rule | Limit |
|---|---|
| Same detection type | 1 email per 5 minutes |
| Same source IP | 1 email per 2 minutes |
| LOW severity alerts | Never emailed |
| Daily hard cap | 50 emails per day |

---

## Security

This project underwent a full internal pentest. **12 vulnerabilities** were identified and fixed:

| ID | Severity | Description |
|---|---|---|
| V01 | 🔴 CRITICAL | Shell injection via unsanitised IP in iptables |
| V02 | 🔴 CRITICAL | Arbitrary attribute injection via config.json |
| V03 | 🟠 HIGH | Path traversal in `.pcap` filenames |
| V04 | 🟠 HIGH | SMTP header injection via detection data |
| V05 | 🟠 HIGH | SQLite DB readable by all local users |
| V06 | 🟠 HIGH | Unbounded memory growth in block log |
| V07 | 🟡 MEDIUM | Password readable from `/proc/self/environ` |
| V08 | 🟡 MEDIUM | Silent exception swallowing in logger |
| V09 | 🟡 MEDIUM | Memory exhaustion via IP spoofing (unbounded state) |
| V10 | 🟡 MEDIUM | Unbounded PCAP ring-buffer per IP |
| V11 | 🔵 LOW | Config file loaded without integrity check |
| V12 | 🔵 LOW | XSS in HTML report via unsanitised network data |

Full details in [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md).

---

## Testing

```bash
pytest test_detections.py -v
```

22 tests covering every detection function, false-positive scenarios, and state isolation — no root access or network connection required.

```
test_port_scan_triggers              PASSED
test_port_scan_no_false_positive     PASSED
test_dos_triggers                    PASSED
test_dos_no_false_positive           PASSED
test_syn_flood_triggers              PASSED
test_syn_flood_ack_not_flagged       PASSED
test_null_scan                       PASSED
test_fin_scan                        PASSED
test_xmas_scan                       PASSED
test_ack_scan                        PASSED
test_normal_tcp_no_false_positive    PASSED
test_icmp_flood_triggers             PASSED
test_udp_flood_triggers              PASSED
test_failed_login_triggers           PASSED
test_dns_amplification_large         PASSED
test_dns_amplification_small         PASSED
test_arp_spoofing_two_macs           PASSED
test_arp_spoofing_same_mac           PASSED
test_http_brute_triggers             PASSED
test_http_brute_non_login_path       PASSED
test_malformed_ip_header_too_small   PASSED
test_state_isolation                 PASSED

22 passed
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.10+ |
| Packet capture | Scapy `AsyncSniffer` |
| GUI | Tkinter (built-in, 6 tabs) |
| Database | SQLite3 (built-in) |
| Email | smtplib + ssl (built-in) |
| Firewall | iptables (Linux) |
| Testing | pytest |
| Evidence | `.pcap` via Scapy `wrpcap` |
| Reports | Self-contained HTML |
| Config | JSON |

---

## License

MIT License — free to use, modify, and distribute with attribution.

---

<div align="center">
Built as a security engineering portfolio project · Python · Scapy · Tkinter · SQLite
</div>
