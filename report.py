"""
report.py  –  NPS-IDS daily HTML report generator
--------------------------------------------------
Generates a self-contained HTML report from the SQLite alert log
and optionally emails it.

Usage
-----
  Standalone:
    python report.py               # generate report for last 24h, save to reports/
    python report.py --hours 48    # last 48 hours
    python report.py --send        # generate + email via mailer.py

  From code:
    from report import generate, email_report
    path = generate(hours=24)
    email_report(path)

The report includes:
  • Summary counts by severity
  • Top 10 attacker IPs (table)
  • Alert breakdown by detection type (bar chart via inline SVG)
  • Full alert log table (last 500 rows)
  • Timestamp and system info
"""

import argparse
import html
import time
from pathlib import Path
from collections import defaultdict

REPORT_DIR = Path(__file__).parent / "reports"

# ── HTML template pieces ──────────────────────────────────────────────────────

_CSS = """
body{font-family:Consolas,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:24px}
h1{color:#58a6ff;margin-bottom:4px}
h2{color:#8b949e;font-size:14px;font-weight:normal;margin-top:0}
h3{color:#58a6ff;margin:28px 0 8px}
.meta{color:#6a737d;font-size:12px;margin-bottom:24px}
.stat-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:28px}
.stat{background:#161b22;border:1px solid;border-radius:6px;padding:14px 20px;min-width:110px;text-align:center}
.stat .num{font-size:28px;font-weight:bold;display:block}
.stat .lbl{font-size:11px;margin-top:4px;opacity:.7}
.CRITICAL{border-color:#ff4d4d;color:#ff4d4d}
.HIGH    {border-color:#ff922b;color:#ff922b}
.MEDIUM  {border-color:#ffd43b;color:#ffd43b}
.LOW     {border-color:#74c0fc;color:#74c0fc}
.INFO    {border-color:#8b949e;color:#8b949e}
table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:24px}
th{background:#161b22;color:#8b949e;text-align:left;padding:8px 12px;border-bottom:1px solid #30363d}
td{padding:6px 12px;border-bottom:1px solid #21262d}
tr:hover td{background:#161b22}
.bar-row{display:flex;align-items:center;gap:10px;margin:5px 0}
.bar-lbl{min-width:200px;font-size:12px;text-align:right;color:#8b949e}
.bar-bg{flex:1;background:#21262d;border-radius:3px;height:16px}
.bar-fill{height:16px;border-radius:3px;transition:width .3s}
.bar-val{min-width:36px;font-size:11px;color:#8b949e}
"""

_SEV_CLR = {
    "CRITICAL": "#ff4d4d",
    "HIGH":     "#ff922b",
    "MEDIUM":   "#ffd43b",
    "LOW":      "#74c0fc",
    "INFO":     "#8b949e",
    "ERROR":    "#f85149",
}

_KIND_SEV = {
    "syn_flood":"CRITICAL","dos":"CRITICAL","arp_spoofing":"CRITICAL",
    "icmp_flood":"HIGH","udp_flood":"HIGH","port_scan":"HIGH","http_brute_force":"HIGH",
    "failed_login":"MEDIUM","xmas_scan":"MEDIUM","null_scan":"MEDIUM",
    "fin_scan":"MEDIUM","dns_amplification":"MEDIUM","icmp_large_payload":"MEDIUM",
    "ack_scan":"LOW","malformed_ip_header":"LOW","suspicious_fragmentation":"LOW",
}


def _sev_color(sev: str) -> str:
    return _SEV_CLR.get(sev, "#8b949e")


def _kind_color(kind: str) -> str:
    return _sev_color(_KIND_SEV.get(kind, "INFO"))


def generate(hours: int = 24) -> Path:
    """
    Generate an HTML report covering the last `hours` hours.
    Returns the path to the saved .html file.
    """
    try:
        import logger
        summary = logger.get_summary(hours=hours)
        recent  = logger.get_recent(limit=500)
    except Exception as e:
        print(f"[report] logger unavailable: {e}")
        summary = {}
        recent  = []

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts_str    = time.strftime("%Y-%m-%d %H:%M:%S")
    ts_file   = time.strftime("%Y%m%d_%H%M%S")
    filename  = REPORT_DIR / f"nps_ids_report_{ts_file}.html"

    sev_counts  = summary.get("severity_counts", {})
    kind_counts = summary.get("kind_counts", {})
    top_ips     = summary.get("top_ips", [])
    total       = summary.get("total", 0)

    # ── severity stat cards ────────────────────────────────────────────────────
    stat_cards = ""
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = sev_counts.get(sev, 0)
        stat_cards += (
            f'<div class="stat {sev}">'
            f'<span class="num">{n}</span>'
            f'<span class="lbl">{sev}</span></div>'
        )
    stat_cards += (
        f'<div class="stat" style="border-color:#58a6ff;color:#58a6ff">'
        f'<span class="num">{total}</span>'
        f'<span class="lbl">TOTAL</span></div>'
    )

    # ── kind bar chart ─────────────────────────────────────────────────────────
    bars = ""
    if kind_counts:
        max_v = max(kind_counts.values()) or 1
        for kind, cnt in sorted(kind_counts.items(), key=lambda x: x[1], reverse=True)[:15]:
            pct = int(cnt / max_v * 100)
            col = _kind_color(kind)
            # V12: escape kind string — it came from the DB which came from the network
            safe_kind = html.escape(kind.replace("_", " "))
            bars += (
                f'<div class="bar-row">'
                f'<span class="bar-lbl">{safe_kind}</span>'
                f'<div class="bar-bg"><div class="bar-fill" style="width:{pct}%;background:{col}"></div></div>'
                f'<span class="bar-val">{cnt}</span></div>'
            )
    else:
        bars = "<p style='color:#6a737d'>No data for this period.</p>"

    # ── top IPs table ──────────────────────────────────────────────────────────
    ip_rows = ""
    for rank, (ip, cnt) in enumerate(top_ips, 1):
        # V12: escape IP — attacker could craft a packet with a weird src
        ip_rows += (
            f"<tr><td>{rank}</td>"
            f"<td>{html.escape(str(ip))}</td>"
            f"<td>{int(cnt)}</td></tr>"
        )
    if not ip_rows:
        ip_rows = "<tr><td colspan='3' style='color:#6a737d'>No data.</td></tr>"

    # ── full alert log ─────────────────────────────────────────────────────────
    alert_rows = ""
    for row in recent:
        sev = row.get("severity", "INFO")
        col = _sev_color(sev)
        blk = "&#10004;" if row.get("blocked") else ""
        # V12: escape every field that originated from network traffic
        alert_rows += (
            f"<tr>"
            f"<td>{html.escape(str(row.get('ts_str','')))}</td>"
            f"<td style='color:{col}'>{html.escape(sev)}</td>"
            f"<td>{html.escape(str(row.get('kind','')))}</td>"
            f"<td>{html.escape(str(row.get('src_ip','')))}</td>"
            f"<td>{html.escape(str(row.get('message','')))}</td>"
            f"<td style='color:#ff4d4d;text-align:center'>{blk}</td>"
            f"</tr>"
        )
    if not alert_rows:
        alert_rows = "<tr><td colspan='6' style='color:#6a737d'>No alerts logged.</td></tr>"

    # ── assemble ───────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NPS-IDS Report — {ts_str}</title>
<style>{_CSS}</style>
</head>
<body>
<h1>⬡ NPS-IDS Security Report</h1>
<h2>Intrusion Detection &amp; Prevention System</h2>
<p class="meta">Generated: {ts_str} &nbsp;|&nbsp; Period: last {hours} hours &nbsp;|&nbsp; Total alerts: {total}</p>

<h3>Alert Counts by Severity</h3>
<div class="stat-row">{stat_cards}</div>

<h3>Top 10 Attacker IPs</h3>
<table>
  <tr><th>#</th><th>Source IP</th><th>Alert Count</th></tr>
  {ip_rows}
</table>

<h3>Alerts by Detection Type</h3>
{bars}

<h3>Recent Alert Log (last {len(recent)})</h3>
<table>
  <tr><th>Timestamp</th><th>Severity</th><th>Kind</th><th>Source IP</th><th>Message</th><th>Blocked</th></tr>
  {alert_rows}
</table>

<p class="meta" style="margin-top:32px">— NPS Intrusion Detection System — nps_ids.db —</p>
</body>
</html>"""

    filename.write_text(html, encoding="utf-8")
    print(f"[report] Saved → {filename}")
    return filename


def email_report(path: Path) -> tuple[bool, str]:
    """Email the HTML report as an attachment via mailer credentials."""
    try:
        import mailer
        import smtplib, ssl
        from email.mime.multipart import MIMEMultipart
        from email.mime.text      import MIMEText
        from email.mime.base      import MIMEBase
        from email                import encoders

        srv, port, sender, password, receiver = mailer._creds()
        if not (sender and password and receiver):
            return False, "Email not configured in mailer.py"

        ts_str = time.strftime("%Y-%m-%d %H:%M:%S")
        msg    = MIMEMultipart()
        msg["From"]    = sender
        msg["To"]      = receiver
        msg["Subject"] = f"📊 NPS-IDS Daily Report — {ts_str}"

        msg.attach(MIMEText(
            f"NPS-IDS daily security report attached.\nGenerated: {ts_str}\n\n"
            f"-- NPS Intrusion Detection System --",
            "plain"
        ))

        with open(path, "rb") as f:
            part = MIMEBase("text", "html")
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition",
                        f'attachment; filename="{path.name}"')
        msg.attach(part)

        raw = msg.as_bytes()

        # try SSL 465 then STARTTLS 587
        try:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(srv, 465, context=ctx, timeout=15) as s:
                s.login(sender, password)
                s.sendmail(sender, receiver, raw)
            return True, f"Report emailed to {receiver}"
        except Exception:
            pass
        ctx = ssl.create_default_context()
        with smtplib.SMTP(srv, 587, timeout=15) as s:
            s.ehlo(); s.starttls(context=ctx); s.ehlo()
            s.login(sender, password)
            s.sendmail(sender, receiver, raw)
        return True, f"Report emailed to {receiver}"

    except Exception as e:
        return False, str(e)


def schedule_daily(hour: int = 0):
    """
    Start a background thread that generates + emails a report at `hour` each day.
    Call once from main.py after the GUI starts.
    """
    import threading

    def _loop():
        while True:
            now   = time.localtime()
            # seconds until next occurrence of `hour`:00:00
            secs  = ((hour - now.tm_hour) % 24) * 3600 - now.tm_min * 60 - now.tm_sec
            if secs <= 0:
                secs += 86400
            time.sleep(secs)
            try:
                path = generate(hours=24)
                ok, msg = email_report(path)
                print(f"[report] Scheduled report: {msg}")
            except Exception as e:
                print(f"[report] Scheduled report failed: {e}")

    t = threading.Thread(target=_loop, daemon=True, name="ReportScheduler")
    t.start()
    print(f"[report] Daily report scheduled at {hour:02d}:00")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NPS-IDS report generator")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--send",  action="store_true", help="Email the report")
    args = parser.parse_args()

    p = generate(hours=args.hours)
    print(f"Report saved: {p}")
    if args.send:
        ok, msg = email_report(p)
        print(f"Email: {msg}")
