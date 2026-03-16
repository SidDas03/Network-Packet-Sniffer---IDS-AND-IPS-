"""
pcap.py  –  NPS-IDS suspicious packet capture
----------------------------------------------
SECURITY FIXES applied:
  V03 – Path traversal: kind and src_ip are sanitised through a strict
        allowlist / regex before being embedded in the filename.
  V10 – Unbounded ring-buffer: global cap on number of IPs tracked.
"""

import re
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

try:
    from scapy.all import wrpcap
    _SCAPY = True
except ImportError:
    _SCAPY = False

CAPTURE_DIR  = Path(__file__).parent / "captures"
PRE_BUFFER   = 10
MAX_FILES    = 100
CAPTURE_SEVS = {"CRITICAL", "HIGH"}

# V10: cap the number of IPs we buffer to prevent memory exhaustion
MAX_TRACKED_IPS = 2_000

_lock = threading.Lock()
_ring: dict = defaultdict(lambda: deque(maxlen=PRE_BUFFER))

# V03: allowlist of safe kind strings (must match detections.py exactly)
_SAFE_KINDS = frozenset({
    "port_scan", "dos", "syn_flood", "icmp_flood", "udp_flood",
    "failed_login", "http_brute_force", "null_scan", "fin_scan",
    "xmas_scan", "ack_scan", "dns_amplification", "arp_spoofing",
    "malformed_ip_header", "icmp_large_payload", "suspicious_fragmentation",
    "error",
})

# V03: only alphanumeric, dots, colons, hyphens allowed in IPs
_SAFE_IP_RE = re.compile(r"^[a-fA-F0-9.:]{3,45}$")


def _safe_filename_part(s: str, fallback: str) -> str:
    """Strip any character that could escape the captures/ directory."""
    s = str(s).strip()
    # allow only alphanumerics, underscore, hyphen, dot
    cleaned = re.sub(r"[^a-zA-Z0-9._-]", "_", s)
    # prevent leading dots (hidden files / relative path tricks)
    cleaned = cleaned.lstrip(".")
    return cleaned[:40] if cleaned else fallback


def _ensure_dir() -> None:
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)


def feed(src_ip: str, pkt) -> None:
    if not _SCAPY:
        return
    with _lock:
        # V10: evict oldest IP if cap reached
        if src_ip not in _ring and len(_ring) >= MAX_TRACKED_IPS:
            oldest = next(iter(_ring))
            del _ring[oldest]
        _ring[src_ip].append(pkt)


def save_trigger(kind: str, src_ip: str, pkt,
                 severity: str = "HIGH") -> Path | None:
    if not _SCAPY or severity not in CAPTURE_SEVS:
        return None

    # V03: validate and sanitise both parts before embedding in filename
    safe_kind = kind if kind in _SAFE_KINDS else "unknown"
    if not _SAFE_IP_RE.match(str(src_ip)):
        safe_ip = "unknown"
    else:
        safe_ip = _safe_filename_part(src_ip, "unknown").replace(".", "_")

    _ensure_dir()

    ts       = time.strftime("%Y%m%d_%H%M%S")
    filename = CAPTURE_DIR / f"{ts}_{safe_kind}_{safe_ip}.pcap"

    # V03: verify the resolved path is still inside CAPTURE_DIR
    try:
        filename.resolve().relative_to(CAPTURE_DIR.resolve())
    except ValueError:
        print(f"[pcap] Path traversal blocked: {filename}")
        return None

    with _lock:
        pre_pkts = list(_ring.get(src_ip, []))

    packets = pre_pkts + [pkt]
    try:
        wrpcap(str(filename), packets)
        print(f"[pcap] Saved {len(packets)} pkts → {filename.name}")
        _prune()
        return filename
    except Exception as e:
        print(f"[pcap] Save failed: {e}")
        return None


def list_captures() -> list[Path]:
    _ensure_dir()
    return sorted(CAPTURE_DIR.glob("*.pcap"), reverse=True)


def _prune() -> None:
    files = sorted(CAPTURE_DIR.glob("*.pcap"))
    for old in files[:-MAX_FILES]:
        try:
            old.unlink()
        except Exception:
            pass
