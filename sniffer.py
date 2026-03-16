"""
sniffer.py  –  NPS-IDS packet capture & dispatch layer
-------------------------------------------------------
Protocols: IP, TCP (+ HTTP payload), UDP, ICMP, DNS, ARP
IPS:       Blocked IPs are dropped before any detection runs.
"""

from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, ARP, DNS, Raw
import queue
import ips as IPS_MODULE
import logger
import pcap as PCAP

from detections import (
    on_new_connection_attempt,
    on_new_packet_from,
    check_icmp_flood,
    check_syn_flood,
    check_stealth_scan,
    check_udp_flood,
    check_dns_amplification,
    check_arp_spoofing,
    check_http_brute,
    check_malformed,
)

alert_queue: queue.Queue = queue.Queue()

HTTP_PORTS = {80, 8080, 8000, 443}

_ALERT_MESSAGES = {
    "port_scan":                "Port scan – {val} unique ports",
    "dos":                      "DoS flood – rate >{val} pkts/window",
    "failed_login":             "Failed login flood – {val} attempts",
    "icmp_flood":               "ICMP flood – rate >{val} pkts/window",
    "syn_flood":                "SYN flood – rate >{val} SYNs/window",
    "null_scan":                "NULL scan (stealth)",
    "fin_scan":                 "FIN scan (stealth)",
    "xmas_scan":                "XMAS scan (stealth)",
    "ack_scan":                 "ACK scan (firewall probe)",
    "udp_flood":                "UDP flood – rate >{val} pkts/window",
    "dns_amplification":        "DNS amplification – {val}B response",
    "arp_spoofing":             "ARP spoofing – seen from {val} MACs",
    "http_brute_force":         "HTTP brute force – {val} POSTs to login",
    "malformed_ip_header":      "Malformed IP header",
    "suspicious_fragmentation": "Suspicious IP fragmentation",
    "icmp_large_payload":       "Oversized ICMP payload (ping-of-death?)",
    "malformed_packet_parse_error": "Malformed packet – parse error",
}


_KIND_SEV = {
    "syn_flood":"CRITICAL","dos":"CRITICAL","arp_spoofing":"CRITICAL",
    "icmp_flood":"HIGH","udp_flood":"HIGH","port_scan":"HIGH","http_brute_force":"HIGH",
    "failed_login":"MEDIUM","xmas_scan":"MEDIUM","null_scan":"MEDIUM",
    "fin_scan":"MEDIUM","dns_amplification":"MEDIUM","icmp_large_payload":"MEDIUM",
    "ack_scan":"LOW","malformed_ip_header":"LOW","suspicious_fragmentation":"LOW",
    "error":"ERROR",
}


def _emit(result, pkt=None):
    if result is None:
        return
    kind = result[0]
    src  = result[1] if len(result) > 1 else "unknown"
    val  = result[2] if len(result) > 2 else ""
    template = _ALERT_MESSAGES.get(kind, "{kind}")
    msg = template.format(val=val, kind=kind, src=src)
    sev = _KIND_SEV.get(kind, "INFO")

    alert_queue.put((kind, src, msg))
    IPS_MODULE.auto_block(kind, src)

    # persist to SQLite
    blocked = IPS_MODULE.is_blocked(src)
    logger.log_alert(kind, src, msg, sev, blocked)

    # save .pcap for HIGH/CRITICAL if packet available
    if pkt is not None and sev in ("CRITICAL", "HIGH"):
        PCAP.save_trigger(kind, src, pkt, severity=sev)


def packet_callback(pkt):
    src = None
    try:
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            if arp.op == 2:
                _emit(check_arp_spoofing(arp.psrc, arp.hwsrc))
            return

        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        src = ip_layer.src

        # feed ring-buffer for pre-trigger pcap context
        PCAP.feed(src, pkt)

        if IPS_MODULE.is_blocked(src):
            return

        _emit(on_new_packet_from(src), pkt)
        _emit(check_malformed(pkt), pkt)

        if pkt.haslayer(ICMP):
            if pkt[ICMP].type == 8:
                _emit(check_icmp_flood(src), pkt)

        if pkt.haslayer(TCP):
            tcp      = pkt[TCP]
            dst_port = tcp.dport
            flags    = int(tcp.flags)
            _emit(check_syn_flood(src, flags), pkt)
            _emit(check_stealth_scan(src, flags), pkt)
            _emit(on_new_connection_attempt(src, dst_port), pkt)
            if dst_port in HTTP_PORTS and pkt.haslayer(Raw):
                try:
                    first = pkt[Raw].load.decode("utf-8", errors="ignore").split("\r\n")[0].split()
                    if len(first) >= 2:
                        _emit(check_http_brute(src, first[0], first[1]), pkt)
                except Exception:
                    pass

        if pkt.haslayer(UDP):
            _emit(check_udp_flood(src), pkt)
            udp = pkt[UDP]
            if udp.sport == 53 and pkt.haslayer(DNS) and pkt[DNS].qr == 1:
                _emit(check_dns_amplification(src, len(pkt), is_response=True), pkt)

    except Exception as e:
        alert_queue.put(("error", src or "unknown", f"Parse error from {src}: {e}"))


def start_sniffer(interface=None):
    sniffer = AsyncSniffer(
        iface=interface,
        prn=packet_callback,
        store=False,
        filter="ip or arp",
    )
    sniffer.start()
    return sniffer
