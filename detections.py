"""
detections.py  –  NPS-IDS signature & anomaly detection engine
---------------------------------------------------------------
SECURITY FIX applied:
  V09 – Unbounded per-IP state memory exhaustion:
        Each per-IP tracking dict now has a hard cap (MAX_TRACKED_IPS).
        When the cap is reached the oldest entry is evicted (LRU-lite).
        An attacker sending packets from millions of spoofed source IPs
        could previously exhaust RAM; now memory is bounded.
"""

import time
from collections import defaultdict, deque, OrderedDict

PORT_SCAN_PORT_THRESHOLD  = 15
PORT_SCAN_WINDOW          = 5
DOS_PACKET_THRESHOLD      = 200
DOS_WINDOW                = 10
FAILED_LOGIN_THRESHOLD    = 10
FAILED_LOGIN_WINDOW       = 60
ICMP_FLOOD_THRESHOLD      = 100
ICMP_FLOOD_WINDOW         = 5
SYN_FLOOD_THRESHOLD       = 150
SYN_FLOOD_WINDOW          = 10
UDP_FLOOD_THRESHOLD       = 300
UDP_FLOOD_WINDOW          = 10
HTTP_BRUTE_THRESHOLD      = 20
HTTP_BRUTE_WINDOW         = 30
DNS_AMP_RESPONSE_SIZE     = 512
ICMP_LARGE_PAYLOAD        = 1024

# V09: maximum unique IPs tracked per detection state dict
MAX_TRACKED_IPS = 50_000

class _BoundedDict:
    """
    OrderedDict capped at `maxsize` entries.
    When full, the oldest (first-inserted) entry is evicted.
    Access is O(1); eviction is O(1).
    """
    __slots__ = ("_d", "_max")

    def __init__(self, maxsize: int = MAX_TRACKED_IPS):
        self._d: OrderedDict = OrderedDict()
        self._max = maxsize

    def __getitem__(self, key):
        return self._d[key]

    def __setitem__(self, key, value):
        if key in self._d:
            self._d.move_to_end(key)
        self._d[key] = value
        if len(self._d) > self._max:
            self._d.popitem(last=False)   # evict oldest

    def __contains__(self, key):
        return key in self._d

    def get(self, key, default=None):
        return self._d.get(key, default)

    def setdefault(self, key, default):
        if key not in self._d:
            self[key] = default
        return self._d[key]


def _new_bd():
    return _BoundedDict(MAX_TRACKED_IPS)

_port_history   = defaultdict(deque)
_packet_times   = defaultdict(deque)
_failed_login   = defaultdict(deque)
_icmp_times     = defaultdict(deque)
_syn_times      = defaultdict(deque)
_udp_times      = defaultdict(deque)
_http_post      = defaultdict(deque)
_arp_ip_to_macs : _BoundedDict = _BoundedDict()


def _trim(dq: deque, window: float, now: float) -> None:
    while dq and now - dq[0] > window:
        dq.popleft()


def _get_bounded(store: defaultdict, key: str) -> deque:
    """
    Fetch deque from a defaultdict, evicting the oldest entry if the
    dict has grown beyond MAX_TRACKED_IPS.
    """
    if key not in store and len(store) >= MAX_TRACKED_IPS:
        # evict the first key (arbitrary but consistent)
        try:
            oldest = next(iter(store))
            del store[oldest]
        except StopIteration:
            pass
    return store[key]

def on_new_connection_attempt(src_ip: str, dst_port: int):
    now = time.time()
    dq = _get_bounded(_port_history, src_ip)
    dq.append((now, dst_port))
    while dq and now - dq[0][0] > PORT_SCAN_WINDOW:
        dq.popleft()
    unique_ports = {p for (_, p) in dq}
    if len(unique_ports) >= PORT_SCAN_PORT_THRESHOLD:
        dq.clear()
        return ("port_scan", src_ip, len(unique_ports))

    auth_ports = {21, 22, 23, 3389, 3306, 5432, 6379, 27017}
    if dst_port in auth_ports:
        q = _get_bounded(_failed_login, src_ip)
        q.append(now)
        _trim(q, FAILED_LOGIN_WINDOW, now)
        if len(q) >= FAILED_LOGIN_THRESHOLD:
            q.clear()
            return ("failed_login", src_ip, FAILED_LOGIN_THRESHOLD)
    return None


def on_new_packet_from(src_ip: str):
    now = time.time()
    dq = _get_bounded(_packet_times, src_ip)
    dq.append(now)
    _trim(dq, DOS_WINDOW, now)
    if len(dq) > DOS_PACKET_THRESHOLD:
        dq.clear()
        return ("dos", src_ip, DOS_PACKET_THRESHOLD)
    return None


def check_icmp_flood(src_ip: str):
    now = time.time()
    dq = _get_bounded(_icmp_times, src_ip)
    dq.append(now)
    _trim(dq, ICMP_FLOOD_WINDOW, now)
    if len(dq) > ICMP_FLOOD_THRESHOLD:
        dq.clear()
        return ("icmp_flood", src_ip, ICMP_FLOOD_THRESHOLD)
    return None


def check_syn_flood(src_ip: str, flags: int):
    SYN = 0x02
    ACK = 0x10
    if (flags & SYN) and not (flags & ACK):
        now = time.time()
        dq = _get_bounded(_syn_times, src_ip)
        dq.append(now)
        _trim(dq, SYN_FLOOD_WINDOW, now)
        if len(dq) > SYN_FLOOD_THRESHOLD:
            dq.clear()
            return ("syn_flood", src_ip, SYN_FLOOD_THRESHOLD)
    return None


def check_stealth_scan(src_ip: str, flags: int):
    FIN = 0x01; PSH = 0x08; URG = 0x20; ACK = 0x10
    if flags == 0:              return ("null_scan",  src_ip, flags)
    if flags == FIN:            return ("fin_scan",   src_ip, flags)
    if flags == (FIN|PSH|URG):  return ("xmas_scan",  src_ip, flags)
    if flags == ACK:            return ("ack_scan",   src_ip, flags)
    return None


def check_udp_flood(src_ip: str):
    now = time.time()
    dq = _get_bounded(_udp_times, src_ip)
    dq.append(now)
    _trim(dq, UDP_FLOOD_WINDOW, now)
    if len(dq) > UDP_FLOOD_THRESHOLD:
        dq.clear()
        return ("udp_flood", src_ip, UDP_FLOOD_THRESHOLD)
    return None


def check_dns_amplification(src_ip: str, pkt_len: int, is_response: bool):
    if is_response and pkt_len > DNS_AMP_RESPONSE_SIZE:
        return ("dns_amplification", src_ip, pkt_len)
    return None


def check_arp_spoofing(src_ip: str, src_mac: str):
    macs = _arp_ip_to_macs.setdefault(src_ip, set())
    macs.add(src_mac)
    if len(macs) > 1:
        return ("arp_spoofing", src_ip, len(macs))
    return None


def check_http_brute(src_ip: str, method: str, path: str):
    login_paths = {"/login", "/signin", "/auth", "/wp-login.php",
                   "/admin", "/account/login", "/session"}
    if method.upper() == "POST" and any(path.lower().startswith(p) for p in login_paths):
        now = time.time()
        dq = _get_bounded(_http_post, src_ip)
        dq.append(now)
        _trim(dq, HTTP_BRUTE_WINDOW, now)
        if len(dq) >= HTTP_BRUTE_THRESHOLD:
            dq.clear()
            return ("http_brute_force", src_ip, HTTP_BRUTE_THRESHOLD)
    return None


def check_malformed(pkt):
    try:
        if pkt.haslayer("IP"):
            ip  = pkt.getlayer("IP")
            ihl = getattr(ip, "ihl", None)
            if ihl is not None and (ihl < 5 or ihl > 15):
                return ("malformed_ip_header", ip.src)
            frag_flags = getattr(ip, "flags", 0)
            frag_off   = getattr(ip, "frag",  0)
            if (int(frag_flags) & 0x1) and frag_off == 0 and len(pkt) < 28:
                return ("suspicious_fragmentation", ip.src)
            if pkt.haslayer("ICMP"):
                if len(bytes(pkt["ICMP"].payload)) > ICMP_LARGE_PAYLOAD:
                    return ("icmp_large_payload", ip.src)
    except Exception:
        return ("malformed_packet_parse_error", None)
    return None
