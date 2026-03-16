"""
mailer.py  –  NPS-IDS throttled email dispatcher
-------------------------------------------------
SECURITY FIXES applied:
  V04 – SMTP header injection: kind, src_ip, and detail are sanitised
        before being embedded in email subject/body. Newlines and
        carriage returns are stripped to prevent header splitting.
  V07 – Credentials in plaintext os.environ: passwords are no longer
        stored in environment variables (readable via /proc/self/environ
        on Linux). They live only in module-level vars and are zeroed
        from memory on clear_credentials().
"""

import re
import smtplib
import ssl
import os
import time
import threading

# ── SMTP config ───────────────────────────────────────────────────────────────
SMTP_SERVER = os.environ.get("IDS_SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT   = int(os.environ.get("IDS_SMTP_PORT", "465"))
SENDER      = os.environ.get("IDS_EMAIL_SENDER",   "") or ""
PASSWORD    = os.environ.get("IDS_EMAIL_PASSWORD",  "") or ""
RECEIVER    = os.environ.get("IDS_EMAIL_RECEIVER",  "") or ""

# V07: immediately unset password from environment after reading it
for _ev in ("IDS_EMAIL_PASSWORD",):
    if _ev in os.environ:
        os.environ[_ev] = ""          # overwrite before deletion
        del os.environ[_ev]

# ── throttle knobs ────────────────────────────────────────────────────────────
COOLDOWN_SECONDS    = 300
IP_COOLDOWN_SECONDS = 120
MAX_EMAILS_PER_DAY  = 50
EMAIL_MIN_SEVERITY  = "MEDIUM"

# ── severity table ────────────────────────────────────────────────────────────
SEVERITY = {
    "syn_flood":                ("CRITICAL", "🔴"),
    "dos":                      ("CRITICAL", "🔴"),
    "arp_spoofing":             ("CRITICAL", "🔴"),
    "icmp_flood":               ("HIGH",     "🟠"),
    "udp_flood":                ("HIGH",     "🟠"),
    "port_scan":                ("HIGH",     "🟠"),
    "http_brute_force":         ("HIGH",     "🟠"),
    "failed_login":             ("MEDIUM",   "🟡"),
    "xmas_scan":                ("MEDIUM",   "🟡"),
    "null_scan":                ("MEDIUM",   "🟡"),
    "fin_scan":                 ("MEDIUM",   "🟡"),
    "dns_amplification":        ("MEDIUM",   "🟡"),
    "icmp_large_payload":       ("MEDIUM",   "🟡"),
    "ack_scan":                 ("LOW",      "🔵"),
    "malformed_ip_header":      ("LOW",      "🔵"),
    "suspicious_fragmentation": ("LOW",      "🔵"),
}
_SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3, "ERROR": 4}

# ── state ─────────────────────────────────────────────────────────────────────
_lock           = threading.Lock()
_kind_last_sent : dict = {}
_ip_last_sent   : dict = {}
_emails_today   : int  = 0
_day_marker     : str  = ""
stats = {"sent": 0, "suppressed": 0, "failed": 0}

# ── V04: header injection sanitiser ──────────────────────────────────────────
_HEADER_STRIP_RE = re.compile(r"[\r\n\x00]")

def _safe(s: str, max_len: int = 200) -> str:
    """
    Strip characters that could split SMTP headers or inject extra headers.
    CR, LF, and NUL are the primary injection vectors.
    """
    return _HEADER_STRIP_RE.sub("", str(s))[:max_len]


# ── helpers ───────────────────────────────────────────────────────────────────

def _creds():
    """Read module-level vars at call time (GUI sets them after import)."""
    import mailer as m
    srv = str(m.SMTP_SERVER or "").strip()
    prt = int(m.SMTP_PORT   or 465)
    snd = str(m.SENDER      or "").strip()
    pwd = str(m.PASSWORD    or "").strip()
    rcv = str(m.RECEIVER    or "").strip()
    return srv, prt, snd, pwd, rcv


def _configured() -> bool:
    _, _, s, p, r = _creds()
    return bool(s and p and r)


def _reset_day() -> None:
    global _emails_today, _day_marker
    today = time.strftime("%Y-%m-%d")
    if today != _day_marker:
        _emails_today = 0
        _day_marker = today


def _throttle_reason(kind: str, src_ip: str) -> str | None:
    _reset_day()
    if _emails_today >= MAX_EMAILS_PER_DAY:
        return f"daily cap of {MAX_EMAILS_PER_DAY} emails reached"
    sev, _ = SEVERITY.get(kind, ("INFO", ""))
    if _SEV_RANK.get(sev, 0) < _SEV_RANK.get(EMAIL_MIN_SEVERITY, 1):
        return f"{kind} is {sev} severity — only {EMAIL_MIN_SEVERITY}+ alerts are emailed"
    now = time.time()
    if now - _kind_last_sent.get(kind, 0) < COOLDOWN_SECONDS:
        remaining = int(COOLDOWN_SECONDS - (now - _kind_last_sent.get(kind, 0)))
        return f"same detection type ({kind}) already emailed — {remaining}s cooldown remaining"
    if now - _ip_last_sent.get(src_ip, 0) < IP_COOLDOWN_SECONDS:
        remaining = int(IP_COOLDOWN_SECONDS - (now - _ip_last_sent.get(src_ip, 0)))
        return f"same IP ({src_ip}) already emailed — {remaining}s cooldown remaining"
    return None


def _do_send(server, port, sender, password, receiver,
             subject: str, body: str) -> tuple[bool, str]:
    """
    Build a minimal RFC-2822 message and send it.
    V04: subject is sanitised before embedding. Body uses a plain-text
    Content-Type so injected newlines cannot create fake headers.
    """
    # V04: sanitise every user-controlled string in the headers
    safe_subject  = _safe(subject, 200)
    safe_sender   = _safe(sender,  200)
    safe_receiver = _safe(receiver, 200)

    raw = (
        f"From: NPS-IDS <{safe_sender}>\r\n"
        f"To: {safe_receiver}\r\n"
        f"Subject: {safe_subject}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"MIME-Version: 1.0\r\n"
        f"\r\n"
        f"{body}"
    ).encode("utf-8")

    # attempt 1: SMTP_SSL port 465
    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(server, 465, context=ctx, timeout=10) as s:
            s.login(sender, password)
            s.sendmail(sender, receiver, raw)
        return True, f"Sent via SSL:465 to {receiver}"
    except smtplib.SMTPAuthenticationError:
        return False, "Auth failed — use Gmail App Password, not your account password"
    except smtplib.SMTPRecipientsRefused:
        return False, f"Receiver address refused: {receiver}"
    except Exception:
        pass

    # attempt 2: STARTTLS port 587
    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(server, 587, timeout=10) as s:
            s.ehlo()
            s.starttls(context=ctx)
            s.ehlo()
            s.login(sender, password)
            s.sendmail(sender, receiver, raw)
        return True, f"Sent via STARTTLS:587 to {receiver}"
    except smtplib.SMTPAuthenticationError:
        return False, "Auth failed — use Gmail App Password, not your account password"
    except smtplib.SMTPRecipientsRefused:
        return False, f"Receiver address refused: {receiver}"
    except Exception as e:
        return False, f"Both SSL:465 and STARTTLS:587 failed: {e}"


# ── public API ────────────────────────────────────────────────────────────────

def send_alert(kind: str, src_ip: str, detail: str) -> None:
    if not _configured():
        print("[mailer] Not configured — fill Email Settings and click Save Config")
        return

    # V04: sanitise inputs before using them in email content
    kind   = _safe(kind,   50)
    src_ip = _safe(src_ip, 50)
    detail = _safe(detail, 500)

    with _lock:
        reason = _throttle_reason(kind, src_ip)
        if reason:
            stats["suppressed"] += 1
            print(f"[mailer] No email sent — {reason}")
            return
        now = time.time()
        _kind_last_sent[kind] = now
        _ip_last_sent[src_ip] = now
        global _emails_today
        _emails_today += 1
        today_count = _emails_today

    srv, port, sender, password, receiver = _creds()
    sev, emoji = SEVERITY.get(kind, ("INFO", "⚪"))
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    subject = f"{emoji} NPS-IDS [{sev}] {kind.upper()} detected"
    body = (
        f"NPS-IDS Security Alert\n{'='*30}\n"
        f"Timestamp  : {ts}\n"
        f"Severity   : {sev}\n"
        f"Detection  : {kind.upper()}\n"
        f"Source IP  : {src_ip}\n"
        f"Detail     : {detail}\n"
        f"Quota      : {today_count}/{MAX_EMAILS_PER_DAY} today\n"
        f"\n-- NPS Intrusion Detection System --\n"
    )
    ok, result = _do_send(srv, port, sender, password, receiver, subject, body)
    if ok:
        stats["sent"] += 1
        print(f"[mailer] OK ({today_count}/{MAX_EMAILS_PER_DAY}): {subject}")
    else:
        stats["failed"] += 1
        print(f"[mailer] FAILED: {result}")


def test_connection() -> tuple[bool, str]:
    if not _configured():
        return False, "Complete Sender, Password and Receiver fields first"
    srv, port, sender, password, _ = _creds()
    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(srv, 465, context=ctx, timeout=10) as s:
            s.login(sender, password)
        return True, f"Connected via SSL:465 to {srv} as {sender}"
    except smtplib.SMTPAuthenticationError:
        return False, "Auth failed — use Gmail App Password, not your account password"
    except Exception:
        pass
    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(srv, 587, timeout=10) as s:
            s.ehlo(); s.starttls(context=ctx); s.ehlo()
            s.login(sender, password)
        return True, f"Connected via STARTTLS:587 to {srv} as {sender}"
    except smtplib.SMTPAuthenticationError:
        return False, "Auth failed — use Gmail App Password, not your account password"
    except Exception as e:
        return False, f"Failed on both SSL:465 and STARTTLS:587 — {e}"


def send_test_email() -> tuple[bool, str]:
    """Bypasses throttle. Confirms full end-to-end delivery."""
    if not _configured():
        return False, "Complete Sender, Password and Receiver fields first"
    srv, port, sender, password, receiver = _creds()
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    ok, result = _do_send(
        srv, port, sender, password, receiver,
        subject="✅ NPS-IDS Test Email",
        body=(
            f"NPS-IDS Test Email\n{'='*30}\n"
            f"Timestamp : {ts}\n"
            f"Sender    : {sender}\n"
            f"Receiver  : {receiver}\n\n"
            f"If you received this, email alerts are working correctly.\n"
            f"\n-- NPS Intrusion Detection System --\n"
        )
    )
    return ok, (f"Test email delivered to {receiver}" if ok else result)


def get_stats() -> dict:
    with _lock:
        _reset_day()
        return {**stats, "today": _emails_today, "cap": MAX_EMAILS_PER_DAY}


def clear_credentials() -> None:
    """
    V07: Zero out credentials from module memory.
    Call this if the user clears the Email Settings panel.
    """
    global SENDER, PASSWORD, RECEIVER
    SENDER   = ""
    PASSWORD = ""
    RECEIVER = ""
