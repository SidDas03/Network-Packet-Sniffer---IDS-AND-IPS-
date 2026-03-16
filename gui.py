"""
gui.py  –  NPS-IDS  •  Full Dashboard
=======================================
Tabs:
  1. Live Alerts   – colour-coded feed, severity filter, search, export
  2. Analytics     – live bar chart of alert counts per type (canvas-drawn)
  3. Top Threats   – ranked table of most-active attacker IPs
  4. IPS           – blocked-IP table, manual block/unblock
  5. Email         – SMTP config, test, send test email, refresh credentials
  6. Settings      – thresholds, interface selector, about

Hang fix:
  _poll() batches ALL queued items → ONE text state-toggle per 300ms tick.

Thread safety:
  Background threads NEVER touch widgets. They post via root.after(0, fn).
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading, time, os, csv, tempfile
from collections import defaultdict

import mailer
import ips as IPS_MODULE

# ── palette ────────────────────────────────────────────────────────────────────
BG      = "#0b0f14"
PANEL   = "#141920"
PANEL2  = "#1c2330"
BORDER  = "#2a3444"
FG      = "#cdd6e0"
ACCENT  = "#4fa3f7"
MUTED   = "#6a7a8e"
GREEN   = "#3ecf60"
RED     = "#f05050"
YELLOW  = "#f5c542"
ORANGE  = "#f5832a"

SEV_CLR = {
    "CRITICAL": "#f05050",
    "HIGH":     "#f5832a",
    "MEDIUM":   "#f5c542",
    "LOW":      "#4fa3f7",
    "INFO":     "#6a7a8e",
    "ERROR":    "#f05050",
}
KIND_SEV = {
    "syn_flood":"CRITICAL","dos":"CRITICAL","arp_spoofing":"CRITICAL",
    "icmp_flood":"HIGH","udp_flood":"HIGH","port_scan":"HIGH","http_brute_force":"HIGH",
    "failed_login":"MEDIUM","xmas_scan":"MEDIUM","null_scan":"MEDIUM",
    "fin_scan":"MEDIUM","dns_amplification":"MEDIUM","icmp_large_payload":"MEDIUM",
    "ack_scan":"LOW","malformed_ip_header":"LOW","suspicious_fragmentation":"LOW",
    "error":"ERROR",
}

FM      = ("Consolas", 10)
FM_SM   = ("Consolas", 9)
FM_LG   = ("Consolas", 13, "bold")
FM_HDR  = ("Consolas", 15, "bold")
FM_TITLE= ("Consolas", 11, "bold")

def _sev(kind): return KIND_SEV.get(kind, "INFO")


# ── App ────────────────────────────────────────────────────────────────────────
class App:
    def __init__(self, root, alert_queue):
        self.root        = root
        self.alert_queue = alert_queue
        self.email_on    = tk.BooleanVar(value=False)
        self.ips_on      = tk.BooleanVar(value=True)
        self.autoscroll  = tk.BooleanVar(value=True)
        self.filter_vars = {s: tk.BooleanVar(value=True) for s in SEV_CLR}
        self.counters    = {s: 0 for s in SEV_CLR}
        self.all_alerts  = []               # (ts, kind, src, msg, sev)
        self.kind_counts = defaultdict(int) # for analytics bar chart
        self.ip_counts   = defaultdict(int) # for top-threats table
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._rebuild_feed())

        self._build()
        self.root.after(300,  self._poll)
        self.root.after(2000, self._refresh_ips_table)
        self.root.after(1500, self._refresh_chart)
        self.root.after(2000, self._refresh_threats)

    # ── layout ─────────────────────────────────────────────────────────────────

    def _build(self):
        r = self.root
        r.title("NPS-IDS  •  Intrusion Detection & Prevention System")
        r.geometry("1200x760")
        r.configure(bg=BG)
        r.minsize(1000, 640)
        self._style()
        self._build_header()
        self._build_stat_bar()
        self._build_notebook()
        self._build_statusbar()

    def _style(self):
        s = ttk.Style()
        s.theme_use("clam")
        base = dict(background=BG, foreground=FG, fieldbackground=PANEL,
                    bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER,
                    troughcolor=PANEL, font=FM)
        for w, kw in [
            (".", base),
            ("TFrame",           dict(background=BG)),
            ("TLabel",           dict(background=BG, foreground=FG)),
            ("TLabelframe",      dict(background=BG, bordercolor=BORDER)),
            ("TLabelframe.Label",dict(background=BG, foreground=MUTED, font=FM_SM)),
            ("TNotebook",        dict(background=BG, bordercolor=BORDER, tabmargins=[0,0,0,0])),
            ("TNotebook.Tab",    dict(background=PANEL, foreground=MUTED, padding=[16,7], font=FM_SM)),
            ("TButton",          dict(background=PANEL2, foreground=FG, borderwidth=1,
                                      relief="flat", padding=(12,5), font=FM_SM)),
            ("TCheckbutton",     dict(background=BG, foreground=FG, font=FM_SM)),
            ("TEntry",           dict(fieldbackground=PANEL2, foreground=FG,
                                      insertcolor=FG, font=FM_SM)),
            ("Treeview",         dict(background=PANEL, foreground=FG,
                                      fieldbackground=PANEL, bordercolor=BORDER, font=FM_SM,
                                      rowheight=22)),
            ("Treeview.Heading", dict(background=PANEL2, foreground=MUTED,
                                      relief="flat", font=FM_SM)),
            ("TCombobox",        dict(fieldbackground=PANEL2, foreground=FG,
                                      selectbackground=PANEL2, font=FM_SM)),
            ("TScale",           dict(background=BG, troughcolor=PANEL2)),
        ]:
            s.configure(w, **kw)
        s.map("TNotebook.Tab",
              background=[("selected", BG)], foreground=[("selected", ACCENT)])
        s.map("TButton",
              background=[("active", BORDER)], foreground=[("active", ACCENT)])
        s.map("Treeview",
              background=[("selected", BORDER)], foreground=[("selected", ACCENT)])

    def _build_header(self):
        h = tk.Frame(self.root, bg=PANEL, height=54)
        h.pack(fill="x"); h.pack_propagate(False)
        # left
        tk.Label(h, text="⬡", bg=PANEL, fg=ACCENT,
                 font=("Consolas", 22, "bold")).pack(side="left", padx=(16,4))
        tk.Label(h, text="NPS-IDS", bg=PANEL, fg=FG,
                 font=FM_HDR).pack(side="left")
        sep = tk.Frame(h, bg=BORDER, width=1, height=28)
        sep.pack(side="left", padx=14)
        tk.Label(h, text="Intrusion Detection & Prevention System",
                 bg=PANEL, fg=MUTED, font=FM_SM).pack(side="left")
        # right
        self._uptime_lbl = tk.Label(h, text="Uptime: 00:00:00",
                                     bg=PANEL, fg=MUTED, font=FM_SM)
        self._uptime_lbl.pack(side="right", padx=16)
        self._uptime_start = time.time()
        self._live_dot = tk.Label(h, text="● LIVE", bg=PANEL,
                                   fg=GREEN, font=FM)
        self._live_dot.pack(side="right", padx=4)
        self._blink(); self._uptime_tick()

    def _blink(self):
        c = self._live_dot.cget("fg")
        self._live_dot.config(fg=GREEN if c != GREEN else PANEL)
        self.root.after(800, self._blink)

    def _uptime_tick(self):
        elapsed = int(time.time() - self._uptime_start)
        h, r = divmod(elapsed, 3600); m, s = divmod(r, 60)
        self._uptime_lbl.config(text=f"Uptime: {h:02d}:{m:02d}:{s:02d}")
        self.root.after(1000, self._uptime_tick)

    def _build_stat_bar(self):
        bar = tk.Frame(self.root, bg=BG, pady=7)
        bar.pack(fill="x", padx=14)
        self._cnt_labels = {}
        for sev, col in SEV_CLR.items():
            box = tk.Frame(bar, bg=PANEL, padx=16, pady=6,
                           highlightbackground=col, highlightthickness=1)
            box.pack(side="left", padx=4)
            tk.Label(box, text=sev, bg=PANEL, fg=col,
                     font=("Consolas", 7, "bold")).pack()
            lbl = tk.Label(box, text="0", bg=PANEL, fg=col,
                           font=("Consolas", 18, "bold"))
            lbl.pack()
            self._cnt_labels[sev] = lbl

        # total packets label on right
        self._pkt_lbl = tk.Label(bar, text="Alerts: 0", bg=BG,
                                  fg=MUTED, font=FM_SM)
        self._pkt_lbl.pack(side="right", padx=12)

    def _build_notebook(self):
        self._nb = ttk.Notebook(self.root)
        self._nb.pack(fill="both", expand=True, padx=10, pady=(2,0))
        tabs = [
            ("  🔴 Live Alerts  ", "_tab_alerts"),
            ("  📊 Analytics  ",   "_tab_chart"),
            ("  🎯 Top Threats  ", "_tab_threats"),
            ("  🛡 IPS  ",         "_tab_ips"),
            ("  📧 Email  ",       "_tab_email"),
            ("  ⚙ Settings  ",    "_tab_settings"),
        ]
        for label, attr in tabs:
            f = ttk.Frame(self._nb)
            setattr(self, attr, f)
            self._nb.add(f, text=label)
        self._build_alerts_tab()
        self._build_chart_tab()
        self._build_threats_tab()
        self._build_ips_tab()
        self._build_email_tab()
        self._build_settings_tab()

    # ── Tab 1: Live Alerts ─────────────────────────────────────────────────────

    def _build_alerts_tab(self):
        p = self._tab_alerts

        # toolbar row
        tb = tk.Frame(p, bg=BG, pady=6)
        tb.pack(fill="x", padx=10)

        tk.Label(tb, text="Filter:", bg=BG, fg=MUTED, font=FM_SM).pack(side="left", padx=(0,4))
        for sev, var in self.filter_vars.items():
            col = SEV_CLR.get(sev, FG)
            tk.Checkbutton(tb, text=sev, variable=var,
                bg=BG, fg=col, selectcolor=PANEL,
                activebackground=BG, activeforeground=col,
                font=FM_SM, command=self._rebuild_feed,
            ).pack(side="left", padx=2)

        # search
        tk.Label(tb, text="Search:", bg=BG, fg=MUTED, font=FM_SM).pack(side="left", padx=(12,4))
        se = ttk.Entry(tb, textvariable=self._search_var, width=20)
        se.pack(side="left")

        ttk.Button(tb, text="Export CSV", command=self._export_csv).pack(side="right", padx=4)
        ttk.Button(tb, text="Clear",      command=self._clear_alerts).pack(side="right", padx=4)
        ttk.Checkbutton(tb, text="Auto-scroll", variable=self.autoscroll).pack(side="right", padx=8)

        # feed
        wrap = tk.Frame(p, bg=BG)
        wrap.pack(fill="both", expand=True, padx=10, pady=(0,6))
        self._feed = tk.Text(wrap, bg=PANEL, fg=FG, font=FM, relief="flat",
                              wrap="none", state="disabled", cursor="arrow",
                              insertbackground=FG)
        vsb = ttk.Scrollbar(wrap, orient="vertical",   command=self._feed.yview)
        hsb = ttk.Scrollbar(wrap, orient="horizontal", command=self._feed.xview)
        self._feed.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self._feed.pack(fill="both", expand=True)
        for sev, col in SEV_CLR.items():
            self._feed.tag_configure(sev, foreground=col)
        self._feed.tag_configure("TS",  foreground=MUTED)
        self._feed.tag_configure("SRC", foreground=ACCENT)

        # ── copy support on the feed ──────────────────────────────────────────
        # state="disabled" blocks Ctrl+C by default — re-bind it explicitly
        self._feed.bind("<Control-c>", self._feed_copy)
        self._feed.bind("<Control-C>", self._feed_copy)
        # right-click context menu on the alert feed
        self._feed_menu = tk.Menu(self.root, tearoff=0, bg=PANEL2, fg=FG,
                                   activebackground=BORDER, activeforeground=ACCENT,
                                   font=FM_SM)
        self._feed_menu.add_command(label="Copy selected text",
                                    command=self._feed_copy)
        self._feed_menu.add_command(label="Copy IP from this line",
                                    command=self._feed_copy_ip)
        self._feed_menu.add_separator()
        self._feed_menu.add_command(label="Send IP to IPS block field",
                                    command=self._feed_ip_to_ips)
        self._feed.bind("<Button-3>", self._feed_right_click)   # Linux/Win
        self._feed.bind("<Button-2>", self._feed_right_click)   # macOS

    # ── Tab 2: Analytics chart ─────────────────────────────────────────────────

    def _build_chart_tab(self):
        p = self._tab_chart
        tk.Label(p, text="Alert Frequency by Detection Type",
                 bg=BG, fg=ACCENT, font=FM_TITLE).pack(pady=(10,4))
        tk.Label(p, text="Updates every 2 seconds  •  shows top 12 detection kinds",
                 bg=BG, fg=MUTED, font=FM_SM).pack()

        self._chart_canvas = tk.Canvas(p, bg=PANEL, highlightthickness=0)
        self._chart_canvas.pack(fill="both", expand=True, padx=14, pady=(6,10))

    def _refresh_chart(self):
        c = self._chart_canvas
        c.delete("all")
        w = c.winfo_width(); h = c.winfo_height()
        if w < 10 or h < 10:
            self.root.after(2000, self._refresh_chart); return

        data = sorted(self.kind_counts.items(), key=lambda x: x[1], reverse=True)[:12]
        if not data:
            c.create_text(w//2, h//2, text="No alerts yet — data will appear here",
                          fill=MUTED, font=FM_SM)
            self.root.after(2000, self._refresh_chart); return

        pad_l, pad_r, pad_t, pad_b = 180, 30, 30, 50
        max_val = max(v for _, v in data) or 1
        bar_area_w = w - pad_l - pad_r
        bar_h      = max(16, (h - pad_t - pad_b) // len(data) - 6)
        spacing    = (h - pad_t - pad_b) // len(data)

        for i, (kind, val) in enumerate(data):
            y = pad_t + i * spacing + spacing // 2
            sev = _sev(kind)
            col = SEV_CLR.get(sev, MUTED)
            bar_w = int(bar_area_w * val / max_val)

            # bar background track
            c.create_rectangle(pad_l, y - bar_h//2, pad_l + bar_area_w,
                                y + bar_h//2, fill=PANEL2, outline="")
            # filled bar
            if bar_w > 0:
                c.create_rectangle(pad_l, y - bar_h//2, pad_l + bar_w,
                                   y + bar_h//2, fill=col, outline="")
            # label left
            c.create_text(pad_l - 8, y, text=kind.replace("_", " "),
                          anchor="e", fill=FG, font=FM_SM)
            # count right
            c.create_text(pad_l + bar_w + 6, y, text=str(val),
                          anchor="w", fill=col, font=FM_SM)

        self.root.after(2000, self._refresh_chart)

    # ── Tab 3: Top Threats ─────────────────────────────────────────────────────

    def _build_threats_tab(self):
        p = self._tab_threats
        hdr = tk.Frame(p, bg=BG)
        hdr.pack(fill="x", padx=12, pady=(10,4))
        tk.Label(hdr, text="Top Attacker IPs", bg=BG, fg=ACCENT,
                 font=FM_TITLE).pack(side="left")
        ttk.Button(hdr, text="Block Selected IP",
                   command=self._block_from_threats).pack(side="right")

        cols = ("rank","ip","alerts","kinds","last_seen","blocked")
        self._threats_tree = ttk.Treeview(p, columns=cols,
                                           show="headings", selectmode="browse")
        for col, hdr_txt, w in [
            ("rank",     "#",            50),
            ("ip",       "Source IP",   160),
            ("alerts",   "Alert Count", 100),
            ("kinds",    "Attack Types",300),
            ("last_seen","Last Seen",   110),
            ("blocked",  "Blocked",      80),
        ]:
            self._threats_tree.heading(col, text=hdr_txt)
            self._threats_tree.column(col, width=w, minwidth=40)

        vsb = ttk.Scrollbar(p, orient="vertical", command=self._threats_tree.yview)
        self._threats_tree.configure(yscrollcommand=vsb.set)
        self._threats_tree.pack(side="left", fill="both", expand=True,
                                padx=(12,0), pady=(0,8))
        vsb.pack(side="left", fill="y", pady=(0,8), padx=(0,12))
        self._threats_tree.tag_configure("blocked", foreground=SEV_CLR["CRITICAL"])
        self._threats_tree.tag_configure("active",  foreground=SEV_CLR["HIGH"])

        # per-IP detail (right panel)
        self._ip_detail_var = tk.StringVar(value="Click a row to see IP details")
        tk.Label(p, textvariable=self._ip_detail_var, bg=PANEL2, fg=FG,
                 font=FM_SM, justify="left", anchor="nw", wraplength=220,
                 padx=12, pady=10).pack(side="right", fill="y", padx=(0,12), pady=(0,8))

        self._threats_tree.bind("<<TreeviewSelect>>", self._on_threat_select)

        # right-click context menu on threats table
        self._threats_menu = tk.Menu(self.root, tearoff=0, bg=PANEL2, fg=FG,
                                      activebackground=BORDER, activeforeground=ACCENT,
                                      font=FM_SM)
        self._threats_menu.add_command(label="Copy IP address",
                                       command=self._threats_copy_ip)
        self._threats_menu.add_command(label="Send to IPS block field",
                                       command=self._threats_ip_to_ips)
        self._threats_menu.add_separator()
        self._threats_menu.add_command(label="Block this IP",
                                       command=self._block_from_threats)
        self._threats_tree.bind("<Button-3>", self._threats_right_click)
        self._threats_tree.bind("<Button-2>", self._threats_right_click)

        # ip → {count, kinds, last_seen}
        self._ip_data: dict = {}

    def _refresh_threats(self):
        for row in self._threats_tree.get_children():
            self._threats_tree.delete(row)
        ranked = sorted(self._ip_data.items(),
                        key=lambda x: x[1]["count"], reverse=True)[:25]
        for rank, (ip, d) in enumerate(ranked, 1):
            blocked = "Yes" if IPS_MODULE.is_blocked(ip) else "No"
            tag = "blocked" if blocked == "Yes" else "active"
            kinds_str = ", ".join(sorted(d["kinds"]))[:45]
            self._threats_tree.insert("", "end", tags=(tag,), values=(
                rank, ip, d["count"], kinds_str, d["last_seen"], blocked,
            ))
        self.root.after(3000, self._refresh_threats)

    def _on_threat_select(self, _event=None):
        sel = self._threats_tree.selection()
        if not sel: return
        vals = self._threats_tree.item(sel[0])["values"]
        if len(vals) < 2: return
        ip = str(vals[1])
        d  = self._ip_data.get(ip, {})
        txt = (
            f"IP: {ip}\n"
            f"Total alerts: {d.get('count',0)}\n"
            f"Last seen: {d.get('last_seen','—')}\n"
            f"Blocked: {'Yes' if IPS_MODULE.is_blocked(ip) else 'No'}\n\n"
            f"Attack types:\n" +
            "\n".join(f"  • {k}" for k in sorted(d.get("kinds", [])))
        )
        self._ip_detail_var.set(txt)

    def _block_from_threats(self):
        sel = self._threats_tree.selection()
        if not sel:
            messagebox.showinfo("Block", "Select a row first.")
            return
        ip = str(self._threats_tree.item(sel[0])["values"][1])
        IPS_MODULE.block_ip(ip, reason="manual_from_threats", auto=False)
        self._refresh_threats()

    # ── Tab 4: IPS ─────────────────────────────────────────────────────────────

    def _build_ips_tab(self):
        p = self._tab_ips

        ctrl = tk.Frame(p, bg=BG, pady=8)
        ctrl.pack(fill="x", padx=12)

        tk.Checkbutton(
            ctrl, text="  IPS Active — auto-block detected threats",
            variable=self.ips_on, bg=BG, fg=GREEN, selectcolor=PANEL,
            activebackground=BG, activeforeground=GREEN,
            font=("Consolas", 10, "bold"), command=self._toggle_ips,
        ).pack(side="left", padx=(0, 24))

        tk.Label(ctrl, text="IP Address:", bg=BG, fg=MUTED, font=FM_SM).pack(side="left")
        self._block_entry = ttk.Entry(ctrl, width=20)
        self._block_entry.pack(side="left", padx=6)
        ttk.Button(ctrl, text="Block",   command=self._manual_block).pack(side="left", padx=2)
        ttk.Button(ctrl, text="Unblock", command=self._manual_unblock).pack(side="left", padx=2)
        ttk.Button(ctrl, text="Unblock All", command=self._unblock_all).pack(side="left", padx=8)

        self._ips_status = tk.Label(ctrl, text="", bg=BG, fg=MUTED, font=FM_SM)
        self._ips_status.pack(side="left", padx=8)

        cols = ("ip","reason","auto","time")
        self._ips_tree = ttk.Treeview(p, columns=cols, show="headings", selectmode="browse")
        for col, hdr_txt, w in [
            ("ip",     "Blocked IP",    180),
            ("reason", "Reason",        220),
            ("auto",   "Auto-blocked",  110),
            ("time",   "Blocked At",    120),
        ]:
            self._ips_tree.heading(col, text=hdr_txt)
            self._ips_tree.column(col, width=w, minwidth=50)
        vsb = ttk.Scrollbar(p, orient="vertical", command=self._ips_tree.yview)
        self._ips_tree.configure(yscrollcommand=vsb.set)
        self._ips_tree.pack(side="left", fill="both", expand=True, padx=(12,0), pady=(0,8))
        vsb.pack(side="left", fill="y", pady=(0,8), padx=(0,12))
        self._ips_tree.tag_configure("auto",   foreground=SEV_CLR["HIGH"])
        self._ips_tree.tag_configure("manual", foreground=SEV_CLR["LOW"])

        # right-click context menu on IPS table
        self._ips_menu = tk.Menu(self.root, tearoff=0, bg=PANEL2, fg=FG,
                                  activebackground=BORDER, activeforeground=ACCENT,
                                  font=FM_SM)
        self._ips_menu.add_command(label="Copy IP address",
                                   command=self._ips_copy_ip)
        self._ips_menu.add_command(label="Paste IP into block field",
                                   command=self._ips_ip_to_entry)
        self._ips_menu.add_separator()
        self._ips_menu.add_command(label="Unblock this IP",
                                   command=self._manual_unblock)
        self._ips_tree.bind("<Button-3>", self._ips_right_click)
        self._ips_tree.bind("<Button-2>", self._ips_right_click)

    # ── copy helpers ──────────────────────────────────────────────────────────

    def _clip(self, text: str) -> None:
        """Write text to the system clipboard."""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()   # flush — required on some platforms

    def _show_menu(self, menu: tk.Menu, event) -> None:
        """Display a context menu at the mouse position."""
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    # ── Feed (Live Alerts) copy handlers ──────────────────────────────────────

    def _feed_copy(self, _event=None) -> str:
        """Ctrl+C on the feed: copy whatever is selected."""
        try:
            selected = self._feed.get(tk.SEL_FIRST, tk.SEL_LAST)
            self._clip(selected)
        except tk.TclError:
            pass   # nothing selected — silently ignore
        return "break"   # prevent default disabled-widget bell

    def _feed_copy_ip(self) -> None:
        """Extract the IP address column from the current line and copy it."""
        ip = self._feed_ip_under_cursor()
        if ip:
            self._clip(ip)
            self._ips_status.config(text=f"Copied {ip}", fg=ACCENT)

    def _feed_ip_to_ips(self) -> None:
        """Extract IP from current line and paste it into the IPS block field."""
        ip = self._feed_ip_under_cursor()
        if ip:
            self._block_entry.delete(0, "end")
            self._block_entry.insert(0, ip)
            self._nb.select(self._tab_ips)   # switch to IPS tab

    def _feed_ip_under_cursor(self) -> str:
        """
        Return the IP address from whichever line the cursor is on (or the
        last-clicked line).  The feed format is:
          [HH:MM:SS] [SEVERITY] <src_ip padded to 17>  message
        Column 3 (index 2) in a split on whitespace is the IP.
        """
        try:
            # get the line at the insertion cursor (updated on click)
            idx  = self._feed.index("insert linestart")
            line = self._feed.get(idx, idx + " lineend")
            parts = line.split()
            # parts[0]="[HH:MM:SS]" parts[1]="[SEVERITY]" parts[2]=IP
            if len(parts) >= 3:
                candidate = parts[2].strip()
                # basic sanity: must contain a dot or colon (IPv4 / IPv6)
                if "." in candidate or ":" in candidate:
                    return candidate
        except Exception:
            pass
        return ""

    def _feed_right_click(self, event) -> None:
        """Select the line under the right-click, then show context menu."""
        self._feed.config(state="normal")
        self._feed.mark_set("insert", f"@{event.x},{event.y}")
        self._feed.config(state="disabled")
        self._show_menu(self._feed_menu, event)

    # ── Threats tab copy handlers ──────────────────────────────────────────────

    def _threats_selected_ip(self) -> str:
        sel = self._threats_tree.selection()
        if not sel:
            return ""
        vals = self._threats_tree.item(sel[0])["values"]
        return str(vals[1]) if len(vals) >= 2 else ""

    def _threats_copy_ip(self) -> None:
        ip = self._threats_selected_ip()
        if ip:
            self._clip(ip)
            self._ips_status.config(text=f"Copied {ip}", fg=ACCENT)

    def _threats_ip_to_ips(self) -> None:
        ip = self._threats_selected_ip()
        if ip:
            self._block_entry.delete(0, "end")
            self._block_entry.insert(0, ip)
            self._nb.select(self._tab_ips)

    def _threats_right_click(self, event) -> None:
        """Select the row under the cursor, then show context menu."""
        row = self._threats_tree.identify_row(event.y)
        if row:
            self._threats_tree.selection_set(row)
        self._show_menu(self._threats_menu, event)

    # ── IPS tab copy handlers ──────────────────────────────────────────────────

    def _ips_selected_ip(self) -> str:
        sel = self._ips_tree.selection()
        if not sel:
            return ""
        vals = self._ips_tree.item(sel[0])["values"]
        return str(vals[0]) if vals else ""

    def _ips_copy_ip(self) -> None:
        ip = self._ips_selected_ip()
        if ip:
            self._clip(ip)
            self._ips_status.config(text=f"Copied {ip}", fg=ACCENT)

    def _ips_ip_to_entry(self) -> None:
        ip = self._ips_selected_ip()
        if ip:
            self._block_entry.delete(0, "end")
            self._block_entry.insert(0, ip)

    def _ips_right_click(self, event) -> None:
        row = self._ips_tree.identify_row(event.y)
        if row:
            self._ips_tree.selection_set(row)
        self._show_menu(self._ips_menu, event)

    # ── IPS action callbacks ───────────────────────────────────────────────────

    def _toggle_ips(self):
        IPS_MODULE.IPS_ENABLED = self.ips_on.get()
        s, c = ("ACTIVE", GREEN) if IPS_MODULE.IPS_ENABLED else ("DISABLED", RED)
        self._ips_status.config(text=f"IPS {s}", fg=c)

    def _manual_block(self):
        ip = self._block_entry.get().strip()
        if not ip: return
        added = IPS_MODULE.block_ip(ip, reason="manual", auto=False)
        self._ips_status.config(
            text=f"Blocked {ip}" if added else f"{ip} already blocked",
            fg=SEV_CLR["HIGH"] if added else MUTED)
        self._refresh_ips_table()

    def _manual_unblock(self):
        sel = self._ips_tree.selection()
        ip  = (self._ips_tree.item(sel[0])["values"][0]
               if sel else self._block_entry.get().strip())
        if not ip: return
        ok = IPS_MODULE.unblock_ip(ip)
        self._ips_status.config(
            text=f"Unblocked {ip}" if ok else f"{ip} not in list",
            fg=SEV_CLR["LOW"] if ok else MUTED)
        self._refresh_ips_table()

    def _unblock_all(self):
        for entry in IPS_MODULE.list_blocked():
            IPS_MODULE.unblock_ip(entry["ip"])
        self._ips_status.config(text="All IPs unblocked", fg=SEV_CLR["LOW"])
        self._refresh_ips_table()

    def _refresh_ips_table(self):
        for row in self._ips_tree.get_children():
            self._ips_tree.delete(row)
        for entry in IPS_MODULE.list_blocked():
            tag = "auto" if entry["auto"] else "manual"
            self._ips_tree.insert("", "end", tags=(tag,), values=(
                entry["ip"], entry["reason"],
                "Yes" if entry["auto"] else "No",
                entry["time_blocked"],
            ))
        self.root.after(2000, self._refresh_ips_table)

    # ── Tab 5: Email ───────────────────────────────────────────────────────────

    def _build_email_tab(self):
        p = self._tab_email

        # two-column layout: config card left, status panel right
        left  = tk.Frame(p, bg=BG); left.pack(side="left", fill="both", expand=True, padx=(12,6), pady=12)
        right = tk.Frame(p, bg=PANEL2, padx=18, pady=18); right.pack(side="right", fill="y", padx=(0,12), pady=12)

        # ── config card ────────────────────────────────────────────────────────
        card = tk.Frame(left, bg=PANEL, padx=26, pady=22)
        card.pack(fill="x")

        tk.Label(card, text="Email Alert Configuration", bg=PANEL,
                 fg=ACCENT, font=FM_TITLE).grid(row=0, column=0, columnspan=3,
                 sticky="w", pady=(0,14))

        fields = [
            ("SMTP Server",    "IDS_SMTP_SERVER",   "smtp.gmail.com", False),
            ("SMTP Port",      "IDS_SMTP_PORT",      "465",            False),
            ("Sender Email",   "IDS_EMAIL_SENDER",   "",               False),
            ("App Password",   "IDS_EMAIL_PASSWORD", "",               True),
            ("Receiver Email", "IDS_EMAIL_RECEIVER", "",               False),
        ]
        self._email_entries = {}
        for i, (lbl, env, dflt, pwd) in enumerate(fields, 1):
            tk.Label(card, text=lbl, bg=PANEL, fg=MUTED,
                     font=FM_SM, width=15, anchor="e").grid(
                     row=i, column=0, sticky="e", pady=5, padx=(0,10))
            e = ttk.Entry(card, width=32, show="*" if pwd else "")
            e.insert(0, os.environ.get(env, dflt))
            e.grid(row=i, column=1, sticky="w", pady=5)
            # refresh / clear button per field
            ttk.Button(card, text="✕", width=2,
                       command=lambda en=env, entry=e: self._clear_field(en, entry)
                       ).grid(row=i, column=2, padx=(6,0))
            self._email_entries[env] = e

        hint = ("  Gmail: generate an App Password at\n"
                "  myaccount.google.com → Security → App passwords\n"
                "  Use that 16-char code, NOT your account password.")
        tk.Label(card, text=hint, bg=PANEL, fg=MUTED,
                 font=("Consolas", 8), justify="left").grid(
                 row=len(fields)+1, column=0, columnspan=3,
                 sticky="w", pady=(10,4))

        btn_row = tk.Frame(card, bg=PANEL)
        btn_row.grid(row=len(fields)+2, column=0, columnspan=3, sticky="w", pady=(10,0))
        ttk.Button(btn_row, text="💾  Save Config",       command=self._save_email).pack(side="left", padx=(0,8))
        ttk.Button(btn_row, text="🔌  Test Connection",   command=self._test_email).pack(side="left", padx=(0,8))
        ttk.Button(btn_row, text="📨  Send Test Email",   command=self._send_test_email).pack(side="left", padx=(0,16))
        ttk.Button(btn_row, text="↺  Reset All Fields",  command=self._reset_email_fields).pack(side="left")

        self._email_status = tk.Label(card, text="", bg=PANEL,
                                       fg=MUTED, font=FM_SM, wraplength=460, justify="left")
        self._email_status.grid(row=len(fields)+3, column=0,
                                columnspan=3, sticky="w", pady=(8,0))

        # enable toggle
        toggle_row = tk.Frame(card, bg=PANEL)
        toggle_row.grid(row=len(fields)+4, column=0, columnspan=3, sticky="w", pady=(10,0))
        tk.Checkbutton(
            toggle_row, text="  Enable live email alerts",
            variable=self.email_on, bg=PANEL, fg=FG, selectcolor=BG,
            activebackground=PANEL, activeforeground=ACCENT, font=FM,
        ).pack(side="left")

        # ── right panel: throttle rules + live stats ───────────────────────────
        tk.Label(right, text="Throttle Rules", bg=PANEL2,
                 fg=ACCENT, font=FM_TITLE).pack(anchor="w", pady=(0,10))

        rules = [
            ("Same detection kind", "1 email / 5 min"),
            ("Same source IP",      "1 email / 2 min"),
            ("LOW severity",        "Never emailed"),
            ("Daily hard cap",      "50 emails / day"),
        ]
        for rule, val in rules:
            row = tk.Frame(right, bg=PANEL2)
            row.pack(fill="x", pady=3)
            tk.Label(row, text=rule, bg=PANEL2, fg=MUTED,
                     font=FM_SM, width=22, anchor="w").pack(side="left")
            tk.Label(row, text=val,  bg=PANEL2, fg=FG,
                     font=FM_SM).pack(side="left")

        tk.Frame(right, bg=BORDER, height=1).pack(fill="x", pady=14)

        tk.Label(right, text="Live Stats", bg=PANEL2,
                 fg=ACCENT, font=FM_TITLE).pack(anchor="w", pady=(0,8))
        self._mail_stats_labels = {}
        for key, label in [("sent","Sent"),("suppressed","Suppressed"),
                            ("failed","Failed"),("today","Today / Cap")]:
            row = tk.Frame(right, bg=PANEL2)
            row.pack(fill="x", pady=3)
            tk.Label(row, text=label, bg=PANEL2, fg=MUTED,
                     font=FM_SM, width=14, anchor="w").pack(side="left")
            lbl = tk.Label(row, text="0", bg=PANEL2, fg=FG, font=FM_SM)
            lbl.pack(side="left")
            self._mail_stats_labels[key] = lbl
        self._update_mail_stats()

    def _clear_field(self, env_key, entry):
        entry.delete(0, "end")
        os.environ[env_key] = ""

    def _reset_email_fields(self):
        defaults = {
            "IDS_SMTP_SERVER":   "smtp.gmail.com",
            "IDS_SMTP_PORT":     "465",
            "IDS_EMAIL_SENDER":  "",
            "IDS_EMAIL_PASSWORD":"",
            "IDS_EMAIL_RECEIVER":"",
        }
        for env, entry in self._email_entries.items():
            entry.delete(0, "end")
            entry.insert(0, defaults.get(env, ""))
        self._email_status.config(text="Fields reset to defaults.", fg=MUTED)

    def _update_mail_stats(self):
        s = mailer.get_stats()
        for key, lbl in self._mail_stats_labels.items():
            if key == "today":
                lbl.config(text=f"{s['today']} / {s['cap']}")
            else:
                lbl.config(text=str(s.get(key, 0)))
        self.root.after(4000, self._update_mail_stats)

    def _save_email(self):
        for env, entry in self._email_entries.items():
            os.environ[env] = entry.get().strip()
        mailer.SMTP_SERVER = os.environ.get("IDS_SMTP_SERVER", "smtp.gmail.com")
        mailer.SMTP_PORT   = int(os.environ.get("IDS_SMTP_PORT", "465") or 465)
        mailer.SENDER      = os.environ.get("IDS_EMAIL_SENDER",   "").strip() or None
        mailer.PASSWORD    = os.environ.get("IDS_EMAIL_PASSWORD",  "").strip() or None
        mailer.RECEIVER    = os.environ.get("IDS_EMAIL_RECEIVER",  "").strip() or None
        ok = bool(mailer.SENDER and mailer.PASSWORD and mailer.RECEIVER)
        self._email_status.config(
            text=("✔  Config saved — click Send Test Email to verify." if ok
                  else "⚠  Saved, but Sender / Password / Receiver are incomplete."),
            fg=GREEN if ok else YELLOW)

    def _test_email(self):
        self._save_email()
        self._email_status.config(text="Testing SMTP connection…", fg=MUTED)
        self.root.update_idletasks()
        def _w():
            ok, msg = mailer.test_connection()
            self.root.after(0, lambda: self._email_status.config(
                text=("✔  " if ok else "✘  ") + msg, fg=GREEN if ok else RED))
        threading.Thread(target=_w, daemon=True).start()

    def _send_test_email(self):
        self._save_email()
        self._email_status.config(text="Sending test email…", fg=MUTED)
        self.root.update_idletasks()
        def _w():
            ok, msg = mailer.send_test_email()
            self.root.after(0, lambda: self._email_status.config(
                text=("✔  " if ok else "✘  ") + msg, fg=GREEN if ok else RED))
        threading.Thread(target=_w, daemon=True).start()

    # ── Tab 6: Settings ────────────────────────────────────────────────────────

    def _build_settings_tab(self):
        p = self._tab_settings

        # two columns
        left  = tk.Frame(p, bg=BG); left.pack(side="left", fill="both", expand=True, padx=(14,6), pady=12)
        right = tk.Frame(p, bg=BG); right.pack(side="right", fill="both", expand=True, padx=(6,14), pady=12)

        # ── Threshold tuning ────────────────────────────────────────────────
        th_card = tk.Frame(left, bg=PANEL, padx=20, pady=16)
        th_card.pack(fill="x", pady=(0,12))
        tk.Label(th_card, text="Detection Thresholds", bg=PANEL,
                 fg=ACCENT, font=FM_TITLE).pack(anchor="w", pady=(0,10))

        try:
            import detections as D
        except Exception:
            D = None

        self._threshold_vars = {}
        thresholds = [
            ("Port Scan – unique ports",  "PORT_SCAN_PORT_THRESHOLD",  D),
            ("Port Scan – window (sec)",  "PORT_SCAN_WINDOW",           D),
            ("DoS – packets/window",      "DOS_PACKET_THRESHOLD",       D),
            ("DoS – window (sec)",        "DOS_WINDOW",                 D),
            ("SYN Flood – SYNs/window",   "SYN_FLOOD_THRESHOLD",        D),
            ("ICMP Flood – pkts/window",  "ICMP_FLOOD_THRESHOLD",       D),
            ("Failed Login – attempts",   "FAILED_LOGIN_THRESHOLD",     D),
        ]
        for label, attr, mod in thresholds:
            row = tk.Frame(th_card, bg=PANEL); row.pack(fill="x", pady=3)
            tk.Label(row, text=label, bg=PANEL, fg=MUTED,
                     font=FM_SM, width=28, anchor="w").pack(side="left")
            current = str(getattr(mod, attr, "—")) if mod else "—"
            var = tk.StringVar(value=current)
            self._threshold_vars[attr] = (var, mod)
            e = ttk.Entry(row, textvariable=var, width=8)
            e.pack(side="left", padx=6)

        ttk.Button(th_card, text="Apply Thresholds",
                   command=self._apply_thresholds).pack(anchor="w", pady=(12,0))
        self._thresh_status = tk.Label(th_card, text="", bg=PANEL,
                                        fg=MUTED, font=FM_SM)
        self._thresh_status.pack(anchor="w")

        # ── Interface selector ────────────────────────────────────────────────
        iface_card = tk.Frame(left, bg=PANEL, padx=20, pady=16)
        iface_card.pack(fill="x")
        tk.Label(iface_card, text="Network Interface", bg=PANEL,
                 fg=ACCENT, font=FM_TITLE).pack(anchor="w", pady=(0,8))
        tk.Label(iface_card,
                 text="Restart the sniffer to apply an interface change.",
                 bg=PANEL, fg=MUTED, font=FM_SM).pack(anchor="w")

        ifaces = self._get_ifaces()
        iface_row = tk.Frame(iface_card, bg=PANEL); iface_row.pack(fill="x", pady=(8,0))
        self._iface_var = tk.StringVar(value=ifaces[0] if ifaces else "all")
        combo = ttk.Combobox(iface_row, textvariable=self._iface_var,
                             values=ifaces, width=24, state="readonly")
        combo.pack(side="left")
        tk.Label(iface_row, text="(restart required)", bg=PANEL,
                 fg=MUTED, font=FM_SM).pack(side="left", padx=8)

        # ── About panel ────────────────────────────────────────────────────────
        about = tk.Frame(right, bg=PANEL, padx=20, pady=20)
        about.pack(fill="both", expand=True)
        tk.Label(about, text="About NPS-IDS", bg=PANEL,
                 fg=ACCENT, font=FM_TITLE).pack(anchor="w", pady=(0,12))

        info = [
            ("Project",   "NPS-IDS"),
            ("Version",   "2.0.0"),
            ("Language",  "Python 3.13"),
            ("Capture",   "Scapy AsyncSniffer"),
            ("Protocols", "IP, TCP, UDP, ICMP, DNS, ARP"),
            ("Detections","13 signature types"),
            ("IPS",       "Auto-block + iptables"),
            ("Email",     "SSL:465 / STARTTLS:587"),
            ("GUI",       "Tkinter (6 tabs)"),
            ("Exports",   "CSV"),
        ]
        for k, v in info:
            row = tk.Frame(about, bg=PANEL); row.pack(fill="x", pady=2)
            tk.Label(row, text=k, bg=PANEL, fg=MUTED,
                     font=FM_SM, width=14, anchor="w").pack(side="left")
            tk.Label(row, text=v, bg=PANEL, fg=FG,
                     font=FM_SM).pack(side="left")

        tk.Frame(about, bg=BORDER, height=1).pack(fill="x", pady=12)

        deps = [("scapy", "Packet capture"),("tkinter","GUI"),
                ("smtplib","Email"),("ssl","TLS")]
        tk.Label(about, text="Dependencies", bg=PANEL,
                 fg=ACCENT, font=FM_TITLE).pack(anchor="w", pady=(0,8))
        for lib, purpose in deps:
            row = tk.Frame(about, bg=PANEL); row.pack(fill="x", pady=2)
            tk.Label(row, text=lib,     bg=PANEL, fg=ACCENT,
                     font=FM_SM, width=14, anchor="w").pack(side="left")
            tk.Label(row, text=purpose, bg=PANEL, fg=MUTED,
                     font=FM_SM).pack(side="left")

    def _get_ifaces(self):
        try:
            from scapy.all import get_if_list
            return ["all"] + get_if_list()
        except Exception:
            return ["all"]

    def _apply_thresholds(self):
        applied = []
        for attr, (var, mod) in self._threshold_vars.items():
            if mod is None: continue
            try:
                val = int(var.get())
                setattr(mod, attr, val)
                applied.append(attr)
            except ValueError:
                pass
        self._thresh_status.config(
            text=f"Applied {len(applied)} threshold(s)" if applied else "Nothing changed",
            fg=GREEN if applied else MUTED)

    # ── Status bar ─────────────────────────────────────────────────────────────

    def _build_statusbar(self):
        sb = tk.Frame(self.root, bg=PANEL, height=22)
        sb.pack(fill="x", side="bottom"); sb.pack_propagate(False)
        self._sb_text = tk.Label(sb, text="Initialising…", bg=PANEL,
                                  fg=MUTED, font=FM_SM, anchor="w")
        self._sb_text.pack(side="left", padx=10)
        self._clock = tk.Label(sb, text="", bg=PANEL, fg=MUTED, font=FM_SM)
        self._clock.pack(side="right", padx=10)
        self._tick()

    def _tick(self):
        self._clock.config(text=time.strftime("%Y-%m-%d  %H:%M:%S"))
        self.root.after(1000, self._tick)

    # ── Core poll loop ─────────────────────────────────────────────────────────

    def _poll(self):
        batch = []
        while True:
            try: batch.append(self.alert_queue.get_nowait())
            except Exception: break

        if batch:
            new_rows = []
            q = self._search_var.get().lower()
            for item in batch:
                kind, src, msg = (item if isinstance(item, tuple) and len(item)==3
                                  else ("error", "unknown", str(item)))
                sev = _sev(kind)
                ts  = time.strftime("%H:%M:%S")
                entry = (ts, kind, src, msg, sev)
                self.all_alerts.append(entry)
                self.counters[sev] = self.counters.get(sev, 0) + 1
                self.kind_counts[kind] += 1

                # update IP data for threats tab
                d = self._ip_data.setdefault(src, {"count":0,"kinds":set(),"last_seen":""})
                d["count"] += 1
                d["kinds"].add(kind)
                d["last_seen"] = ts

                if self.filter_vars.get(sev, tk.BooleanVar(value=True)).get():
                    if not q or q in msg.lower() or q in src.lower() or q in kind.lower():
                        new_rows.append(entry)

                if self.email_on.get():
                    threading.Thread(target=mailer.send_alert,
                                     args=(kind, src, msg), daemon=True).start()

            for sev, lbl in self._cnt_labels.items():
                lbl.config(text=str(self.counters[sev]))
            total = sum(self.counters.values())
            self._pkt_lbl.config(text=f"Alerts: {total}")

            if new_rows:
                self._feed.config(state="normal")
                for ts, kind, src, msg, sev in new_rows:
                    self._feed.insert("end", f"[{ts}] ", "TS")
                    self._feed.insert("end", f"[{sev:<8}] ", sev)
                    self._feed.insert("end", f"{src:<17}  ", "SRC")
                    self._feed.insert("end", msg + "\n")
                if self.autoscroll.get():
                    self._feed.see("end")
                self._feed.config(state="disabled")

            if batch:
                last = batch[-1]
                self._sb_text.config(
                    text=f"Last: [{_sev(last[0] if isinstance(last,tuple) else 'info')}]  "
                         f"{last[2][:80] if len(last)>2 else str(last)}")

        self.root.after(300, self._poll)

    # ── Alert tab helpers ──────────────────────────────────────────────────────

    def _rebuild_feed(self):
        q = self._search_var.get().lower()
        self._feed.config(state="normal")
        self._feed.delete("1.0", "end")
        for ts, kind, src, msg, sev in self.all_alerts:
            if not self.filter_vars.get(sev, tk.BooleanVar(value=True)).get():
                continue
            if q and q not in msg.lower() and q not in src.lower() and q not in kind.lower():
                continue
            self._feed.insert("end", f"[{ts}] ", "TS")
            self._feed.insert("end", f"[{sev:<8}] ", sev)
            self._feed.insert("end", f"{src:<17}  ", "SRC")
            self._feed.insert("end", msg + "\n")
        if self.autoscroll.get():
            self._feed.see("end")
        self._feed.config(state="disabled")

    def _clear_alerts(self):
        self.all_alerts.clear()
        self.counters = {s: 0 for s in SEV_CLR}
        self.kind_counts.clear()
        self._ip_data.clear()
        for lbl in self._cnt_labels.values(): lbl.config(text="0")
        self._pkt_lbl.config(text="Alerts: 0")
        self._feed.config(state="normal")
        self._feed.delete("1.0", "end")
        self._feed.config(state="disabled")

    def _export_csv(self):
        if not self.all_alerts:
            messagebox.showinfo("Export", "No alerts to export."); return
        path = os.path.join(tempfile.gettempdir(), "nps_ids_alerts.csv")
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["timestamp","kind","src_ip","message","severity"])
            w.writerows(self.all_alerts)
        messagebox.showinfo("Export CSV", f"Saved to:\n{path}")


# ── entry point ────────────────────────────────────────────────────────────────

def run_gui(alert_queue):
    root = tk.Tk()
    App(root, alert_queue)
    root.mainloop()
