"""
main.py  –  NPS-IDS entry point
--------------------------------
SECURITY FIXES applied:
  V02 – Arbitrary attribute injection via config.json: threshold keys are
        now validated against an explicit allowlist before setattr() is called.
  V11 – Config file integrity: permissions are checked; world-writable
        config is refused.
"""

import argparse
import json
import os
import sys
import stat
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "config.json"

# V02: explicit allowlist — only these names may be written to detections module
_ALLOWED_THRESHOLDS = frozenset({
    "PORT_SCAN_PORT_THRESHOLD", "PORT_SCAN_WINDOW",
    "DOS_PACKET_THRESHOLD",     "DOS_WINDOW",
    "SYN_FLOOD_THRESHOLD",      "SYN_FLOOD_WINDOW",
    "ICMP_FLOOD_THRESHOLD",     "ICMP_FLOOD_WINDOW",
    "UDP_FLOOD_THRESHOLD",      "UDP_FLOOD_WINDOW",
    "FAILED_LOGIN_THRESHOLD",   "FAILED_LOGIN_WINDOW",
    "HTTP_BRUTE_THRESHOLD",     "HTTP_BRUTE_WINDOW",
    "DNS_AMP_RESPONSE_SIZE",    "ICMP_LARGE_PAYLOAD",
})


def _load_config() -> dict:
    """
    Load config.json.
    V11: Refuse world-writable config files on Unix — they could be tampered
    with by a lower-privilege process to inject malicious threshold names.
    """
    if not CONFIG_PATH.exists():
        return {}
    try:
        # V11: check permissions on Unix
        if hasattr(os, "stat"):
            mode = CONFIG_PATH.stat().st_mode
            if mode & stat.S_IWOTH:
                print(f"[main] WARNING: {CONFIG_PATH} is world-writable — ignoring it.")
                print("[main] Fix with:  chmod o-w config.json")
                return {}
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"[main] config.json is not valid JSON: {e}")
        return {}
    except Exception as e:
        print(f"[main] Could not load config: {e}")
        return {}


def _safe_int(val, default: int, lo: int, hi: int) -> int:
    """Clamp a config integer to a safe range."""
    try:
        return max(lo, min(hi, int(val)))
    except (TypeError, ValueError):
        return default


def _apply_config(cfg: dict) -> None:
    """Push config values into relevant modules."""
    # SMTP credentials — read-only from environment
    smtp = cfg.get("smtp", {})
    for env, key in [
        ("IDS_SMTP_SERVER",    "server"),
        ("IDS_SMTP_PORT",      "port"),
        ("IDS_EMAIL_SENDER",   "sender"),
        ("IDS_EMAIL_PASSWORD", "password"),
        ("IDS_EMAIL_RECEIVER", "receiver"),
    ]:
        val = smtp.get(key)
        if val:
            os.environ.setdefault(env, str(val))

    # V02: validate threshold keys against allowlist before setattr
    thresh = cfg.get("thresholds", {})
    if thresh:
        try:
            import detections as D
            for attr, val in thresh.items():
                if attr not in _ALLOWED_THRESHOLDS:
                    print(f"[main] config.json: unknown threshold '{attr}' ignored")
                    continue
                if not isinstance(val, (int, float)) or val <= 0:
                    print(f"[main] config.json: invalid value for '{attr}': {val!r} ignored")
                    continue
                setattr(D, attr, val)
        except Exception as e:
            print(f"[main] Could not apply thresholds: {e}")

    # IPS toggle
    ips_cfg = cfg.get("ips", {})
    if not ips_cfg.get("enabled", True):
        try:
            import ips
            ips.IPS_ENABLED = False
        except Exception:
            pass


def list_interfaces() -> None:
    try:
        from scapy.all import get_if_list
        print("Available network interfaces:")
        for i in get_if_list():
            print(f"  {i}")
    except Exception as e:
        print(f"Could not list interfaces: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NPS-IDS – Network Packet Sniffer & Intrusion Detection System"
    )
    parser.add_argument("--iface",       default=None,
                        help="Network interface to sniff (default: all)")
    parser.add_argument("--list-ifaces", action="store_true",
                        help="List available interfaces and exit")
    parser.add_argument("--no-gui",      action="store_true",
                        help="Run headless — logs to SQLite, no GUI window")
    args = parser.parse_args()

    if args.list_ifaces:
        list_interfaces()
        sys.exit(0)

    cfg = _load_config()
    _apply_config(cfg)

    iface = args.iface or cfg.get("sniffer", {}).get("interface") or None

    print("=" * 55)
    print("  ⬡ NPS-IDS  –  Intrusion Detection System")
    print("=" * 55)
    print(f"  Interface : {iface or 'ALL'}")
    print(f"  Config    : {CONFIG_PATH}")
    print(f"  Mode      : {'headless' if args.no_gui else 'GUI'}")
    print("  Requires  : admin / root privileges")
    print("=" * 55)

    from sniffer import start_sniffer, alert_queue
    sniffer = start_sniffer(interface=iface)

    rep_cfg = cfg.get("reports", {})
    if rep_cfg.get("auto_daily", False):
        try:
            from report import schedule_daily
            schedule_daily(hour=rep_cfg.get("daily_hour", 0))
        except Exception as e:
            print(f"[main] Report scheduler failed: {e}")

    try:
        if args.no_gui:
            print("Running headless. Press Ctrl+C to stop.")
            import signal
            signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
            while True:
                import time; time.sleep(1)
        else:
            from gui import run_gui
            run_gui(alert_queue)
    finally:
        print("\nShutting down sniffer…")
        sniffer.stop()
        print("Done.")


if __name__ == "__main__":
    main()
