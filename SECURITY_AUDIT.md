# NPS-IDS Security Audit Report
Auditor: Pentester  
Date: 2026-03-14

## Findings Summary

| ID  | Severity | File            | Vulnerability                                      | Status  |
|-----|----------|-----------------|----------------------------------------------------|---------|
| V01 | CRITICAL | ips.py          | Shell injection via unsanitised IP in iptables     | FIXED   |
| V02 | CRITICAL | main.py         | Arbitrary attribute injection via config.json      | FIXED   |
| V03 | HIGH     | pcap.py         | Path traversal in .pcap filename via kind/src_ip   | FIXED   |
| V04 | HIGH     | mailer.py       | SMTP header injection via kind/src_ip in subject   | FIXED   |
| V05 | HIGH     | logger.py       | DB path traversal — DB_PATH writable by any user   | FIXED   |
| V06 | HIGH     | ips.py          | Unbounded memory growth — _block_log never pruned  | FIXED   |
| V07 | MEDIUM   | mailer.py       | Credentials stored in plaintext os.environ         | FIXED   |
| V08 | MEDIUM   | sniffer.py      | Exception swallowed silently — errors invisible    | FIXED   |
| V09 | MEDIUM   | detections.py   | Unbounded per-IP state — memory exhaustion via     | FIXED   |
|     |          |                 | IP spoofing (millions of unique source IPs)        |         |
| V10 | MEDIUM   | pcap.py         | Unbounded ring-buffer memory — no global IP cap    | FIXED   |
| V11 | LOW      | main.py         | Config file read without integrity check           | FIXED   |
| V12 | LOW      | report.py       | HTML report contains unsanitised IP/kind strings   | FIXED   |
