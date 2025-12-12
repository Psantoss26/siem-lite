from __future__ import annotations
import re
from typing import Optional, Dict

# ====== Patrones ======
# 1) Syslog genérico: "Oct 10 12:34:56 host proc[123]: message"
SYSLOG_RE = re.compile(
    r"^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[^\s]+)\s+"
    r"(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# 2) auth.log (mismo patrón que syslog; detectamos proceso para etiquetar tipo)
AUTH_PROC_HINTS = ("sshd", "sudo", "su")

# 3) Nginx/Apache access log (formato combinado)
# 127.0.0.1 - - [10/Oct/2025:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "curl/7.68.0"
ACCESS_RE = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<dt>[^\]]+)\]\s+\"(?P<method>[A-Z]+)\s+(?P<path>[^\s]+)\s+(?P<proto>[^\"]+)\"\s+"
    r"(?P<status>\d{3})\s+(?P<size>\d+|-)\s+\"(?P<ref>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\"$"
)

# ====== Funciones de parseo ======
def parse_syslog(line: str) -> Optional[Dict]:
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    d = m.groupdict()
    proc = d.get("proc") or ""
    event_type = "syslog/generic"
    if any(h in proc for h in AUTH_PROC_HINTS):
        event_type = f"auth/{proc.split('/')[-1]}"
    return {
        "month": d["month"],
        "day": int(d["day"]),
        "time": d["time"],
        "host": d["host"],
        "process": proc,
        "pid": int(d["pid"]) if d.get("pid") else None,
        "message": d["message"],
        "event_type": event_type,
        "source": "syslog",
    }

def parse_access(line: str) -> Optional[Dict]:
    m = ACCESS_RE.match(line)
    if not m:
        return None
    d = m.groupdict()
    return {
        "ip": d["ip"],
        "dt": d["dt"],
        "method": d["method"],
        "path": d["path"],
        "proto": d["proto"],
        "status": int(d["status"]),
        "size": None if d["size"] == "-" else int(d["size"]),
        "referrer": d["ref"],
        "user_agent": d["ua"],
        "event_type": "http/access",
        "source": "access.log",
    }

def parse_line_by_best_effort(line: str) -> Optional[Dict]:
    p = parse_syslog(line)
    if p:
        return p
    p = parse_access(line)
    if p:
        return p
    return None
