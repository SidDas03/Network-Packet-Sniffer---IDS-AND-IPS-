"""
Tests inject synthetic inputs directly into the detection functions —
no real packets, no network, no root required.

Coverage
--------
  1.  Port scan detection
  2.  Port scan below threshold (no false positive)
  3.  DoS packet-rate detection
  4.  DoS below threshold (no false positive)
  5.  SYN flood detection
  6.  SYN flood — ACK not flagged
  7.  NULL scan detection
  8.  FIN scan detection
  9.  XMAS scan detection
 10.  ACK scan detection
 11.  Normal TCP flags — no false positive
 12.  ICMP flood detection
 13.  UDP flood detection
 14.  Failed login detection
 15.  DNS amplification — large response flagged
 16.  DNS amplification — small response not flagged
 17.  ARP spoofing — same IP, two MACs
 18.  ARP spoofing — same IP, same MAC (no false positive)
 19.  HTTP brute force detection
 20.  HTTP brute — non-login path not flagged
 21.  Malformed IP header detection (via mock object)
 22.  Detection state isolation (each IP tracked separately)
"""

import importlib
import sys
import time
import pytest


# ── reload detections between tests so state is fresh ────────────────────────

def _fresh():
    """Return a freshly imported detections module with clean state."""
    if "detections" in sys.modules:
        del sys.modules["detections"]
    return importlib.import_module("detections")

# 1–2  Port scan

def test_port_scan_triggers():
    D = _fresh()
    D.PORT_SCAN_PORT_THRESHOLD = 5
    D.PORT_SCAN_WINDOW = 60
    result = None
    for port in range(1, 6):
        result = D.on_new_connection_attempt("10.0.0.1", port)
    assert result is not None
    assert result[0] == "port_scan"
    assert result[1] == "10.0.0.1"
    assert result[2] >= 5


def test_port_scan_no_false_positive():
    D = _fresh()
    D.PORT_SCAN_PORT_THRESHOLD = 15
    for port in range(1, 5):
        r = D.on_new_connection_attempt("10.0.0.2", port)
        assert r is None, f"False positive on port {port}"

# 3–4  DoS

def test_dos_triggers():
    D = _fresh()
    D.DOS_PACKET_THRESHOLD = 10
    D.DOS_WINDOW = 60
    result = None
    for _ in range(12):
        result = D.on_new_packet_from("10.1.1.1")
    assert result is not None
    assert result[0] == "dos"
    assert result[1] == "10.1.1.1"


def test_dos_no_false_positive():
    D = _fresh()
    D.DOS_PACKET_THRESHOLD = 200
    for _ in range(50):
        r = D.on_new_packet_from("10.1.1.2")
        assert r is None

# 5–6  SYN flood

def test_syn_flood_triggers():
    D = _fresh()
    D.SYN_FLOOD_THRESHOLD = 10
    D.SYN_FLOOD_WINDOW = 60
    SYN = 0x02
    result = None
    for _ in range(12):
        result = D.check_syn_flood("10.2.0.1", SYN)
    assert result is not None
    assert result[0] == "syn_flood"


def test_syn_flood_ack_not_flagged():
    D = _fresh()
    D.SYN_FLOOD_THRESHOLD = 5
    SYN_ACK = 0x12   # SYN + ACK — normal handshake reply, should not trigger
    for _ in range(20):
        r = D.check_syn_flood("10.2.0.2", SYN_ACK)
        assert r is None, "SYN+ACK should not trigger SYN flood"

# 7–11  Stealth scans

def test_null_scan():
    D = _fresh()
    r = D.check_stealth_scan("10.3.0.1", 0x00)
    assert r is not None and r[0] == "null_scan"


def test_fin_scan():
    D = _fresh()
    r = D.check_stealth_scan("10.3.0.2", 0x01)
    assert r is not None and r[0] == "fin_scan"


def test_xmas_scan():
    D = _fresh()
    r = D.check_stealth_scan("10.3.0.3", 0x29)  # FIN+PSH+URG
    assert r is not None and r[0] == "xmas_scan"


def test_ack_scan():
    D = _fresh()
    r = D.check_stealth_scan("10.3.0.4", 0x10)
    assert r is not None and r[0] == "ack_scan"


def test_normal_tcp_no_false_positive():
    D = _fresh()
    SYN_ACK = 0x12
    PUSH_ACK = 0x18
    for flags in (SYN_ACK, PUSH_ACK):
        r = D.check_stealth_scan("10.3.0.5", flags)
        assert r is None, f"flags=0x{flags:02x} should not be a stealth scan"

# 12  ICMP flood

def test_icmp_flood_triggers():
    D = _fresh()
    D.ICMP_FLOOD_THRESHOLD = 8
    D.ICMP_FLOOD_WINDOW = 60
    result = None
    for _ in range(10):
        result = D.check_icmp_flood("10.4.0.1")
    assert result is not None and result[0] == "icmp_flood"

# 13  UDP flood

def test_udp_flood_triggers():
    D = _fresh()
    D.UDP_FLOOD_THRESHOLD = 8
    D.UDP_FLOOD_WINDOW = 60
    result = None
    for _ in range(10):
        result = D.check_udp_flood("10.5.0.1")
    assert result is not None and result[0] == "udp_flood"

# 14  Failed login

def test_failed_login_triggers():
    D = _fresh()
    D.FAILED_LOGIN_THRESHOLD = 5
    D.FAILED_LOGIN_WINDOW = 60
    D.PORT_SCAN_PORT_THRESHOLD = 100   # disable port-scan to isolate test
    result = None
    for _ in range(6):
        result = D.on_new_connection_attempt("10.6.0.1", 22)
    assert result is not None and result[0] == "failed_login"

# 15–16  DNS amplification

def test_dns_amplification_large():
    D = _fresh()
    r = D.check_dns_amplification("8.8.8.8", 600, is_response=True)
    assert r is not None and r[0] == "dns_amplification"


def test_dns_amplification_small():
    D = _fresh()
    r = D.check_dns_amplification("8.8.8.8", 100, is_response=True)
    assert r is None

# 17–18  ARP spoofing

def test_arp_spoofing_two_macs():
    D = _fresh()
    D.check_arp_spoofing("192.168.1.1", "aa:bb:cc:dd:ee:01")
    r = D.check_arp_spoofing("192.168.1.1", "aa:bb:cc:dd:ee:02")
    assert r is not None and r[0] == "arp_spoofing"


def test_arp_spoofing_same_mac():
    D = _fresh()
    D.check_arp_spoofing("192.168.1.2", "aa:bb:cc:dd:ee:ff")
    r = D.check_arp_spoofing("192.168.1.2", "aa:bb:cc:dd:ee:ff")
    assert r is None

# 19–20  HTTP brute force

def test_http_brute_triggers():
    D = _fresh()
    D.HTTP_BRUTE_THRESHOLD = 5
    D.HTTP_BRUTE_WINDOW = 60
    result = None
    for _ in range(6):
        result = D.check_http_brute("10.7.0.1", "POST", "/login")
    assert result is not None and result[0] == "http_brute_force"


def test_http_brute_non_login_path():
    D = _fresh()
    D.HTTP_BRUTE_THRESHOLD = 3
    for _ in range(10):
        r = D.check_http_brute("10.7.0.2", "POST", "/api/data")
        assert r is None, "/api/data should not trigger HTTP brute"

# 21  Malformed IP header (mock packet)

class _FakeIP:
    def __init__(self, ihl, src="10.8.0.1"):
        self.ihl = ihl
        self.src = src
        self.flags = 0
        self.frag  = 0

class _FakePkt:
    def __init__(self, ihl):
        self._ip = _FakeIP(ihl)
    def haslayer(self, name):
        return name == "IP"
    def getlayer(self, name):
        return self._ip
    def __len__(self):
        return 100


def test_malformed_ip_header_too_small():
    D = _fresh()
    pkt = _FakePkt(ihl=3)   # IHL < 5 → invalid
    r = D.check_malformed(pkt)
    assert r is not None and r[0] == "malformed_ip_header"


def test_malformed_ip_header_valid():
    D = _fresh()
    pkt = _FakePkt(ihl=5)   # IHL == 5 → normal
    r = D.check_malformed(pkt)
    assert r is None

# 22  State isolation — two IPs tracked independently

def test_state_isolation():
    D = _fresh()
    D.DOS_PACKET_THRESHOLD = 5
    D.DOS_WINDOW = 60
    # drive ip_a to threshold
    result_a = None
    for _ in range(7):
        result_a = D.on_new_packet_from("10.9.0.1")
    # ip_b should still be clean
    result_b = D.on_new_packet_from("10.9.0.2")
    assert result_a is not None and result_a[0] == "dos"
    assert result_b is None, "ip_b should not be affected by ip_a's counter"