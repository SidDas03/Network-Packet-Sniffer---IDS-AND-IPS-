"""
ips.py  –  NPS-IDS Intrusion Prevention System
------------------------------------------------
SECURITY FIXES applied:
  V01 – iptables shell injection: IP is now validated against a strict
        IPv4/IPv6 regex before being passed to subprocess. Any IP that
        does not match is rejected — the in-process block still applies.
  V06 – _block_log unbounded growth: capped at MAX_LOG_ENTRIES (10 000).
"""

import re
import subprocess
import threading
import time

_lock        = threading.Lock()
_blocked: dict[str, dict] = {}
_block_log: list[dict]    = []

IPS_ENABLED    = True
MAX_LOG_ENTRIES = 10_000   # V06: cap log to prevent memory exhaustion

# V01: strict IP validation — rejects anything that isn't a bare IPv4 or IPv6
_IPV4_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_IPV6_RE = re.compile(
    r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
)


def _is_valid_ip(ip: str) -> bool:
    """Return True only for bare IPv4 or IPv6 addresses — no shells, no ranges."""
    if not ip or not isinstance(ip, str):
        return False
    ip = ip.strip()
    return bool(_IPV4_RE.match(ip) or _IPV6_RE.match(ip))


def _iptables(action: str, ip: str) -> None:
    """
    Fire-and-forget iptables rule.
    V01 FIX: IP is validated before being passed to subprocess.
    action must be one of the two literal strings we use — never user input.
    """
    if action not in ("append", "delete"):
        return                              # paranoia — only accept known actions
    if not _is_valid_ip(ip):
        print(f"[ips] Rejected invalid IP for iptables: {ip!r}")
        return
    try:
        cmd = ["iptables", f"--{action}", "INPUT", "-s", ip, "-j", "DROP"]
        subprocess.run(cmd, check=True, capture_output=True, timeout=3)
    except Exception:
        pass


def block_ip(ip: str, reason: str = "manual", auto: bool = False) -> bool:
    """
    Block an IP address. Returns True if newly blocked, False if already blocked.
    Rejects IPs that fail validation (V01).
    """
    if not _is_valid_ip(ip):
        print(f"[ips] block_ip: invalid IP rejected: {ip!r}")
        return False

    # Sanitise reason string — strip control characters (defence in depth)
    reason = re.sub(r"[\x00-\x1f\x7f]", "", str(reason))[:120]

    with _lock:
        if ip in _blocked:
            return False
        entry = {
            "ip":           ip,
            "reason":       reason,
            "auto":         auto,
            "time_blocked": time.strftime("%H:%M:%S"),
            "ts":           time.time(),
        }
        _blocked[ip] = entry
        _block_log.append(entry)
        # V06: prune oldest entries if log grows too large
        if len(_block_log) > MAX_LOG_ENTRIES:
            del _block_log[:len(_block_log) - MAX_LOG_ENTRIES]

    _iptables("append", ip)
    return True


def unblock_ip(ip: str) -> bool:
    """Unblock an IP. Returns True if it was blocked."""
    if not _is_valid_ip(ip):
        return False
    with _lock:
        if ip not in _blocked:
            return False
        del _blocked[ip]
    _iptables("delete", ip)
    return True


def is_blocked(ip: str) -> bool:
    return ip in _blocked


def list_blocked() -> list[dict]:
    with _lock:
        return sorted(_blocked.values(), key=lambda e: e["ts"])


def get_log() -> list[dict]:
    with _lock:
        return list(_block_log)


def auto_block(kind: str, src_ip: str) -> None:
    if not IPS_ENABLED:
        return
    AUTO_BLOCK_KINDS = {
        "syn_flood", "dos", "arp_spoofing",
        "icmp_flood", "udp_flood", "port_scan",
        "http_brute_force", "xmas_scan", "null_scan", "fin_scan",
    }
    if kind in AUTO_BLOCK_KINDS and src_ip and src_ip != "unknown":
        block_ip(src_ip, reason=kind, auto=True)
