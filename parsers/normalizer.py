from __future__ import annotations
import json
import datetime as dt
import re
from typing import Dict, Optional

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

def _infer_year(month: int, now: Optional[dt.datetime] = None) -> int:
    now = now or dt.datetime.now(dt.timezone.utc)
    year = now.year
    if now.month == 1 and month == 12:
        year -= 1
    return year

def _compose_timestamp_syslog(month: str, day: int, time_s: str, tz: dt.tzinfo) -> str:
    hh, mm, ss = map(int, time_s.split(":"))
    m = MONTHS[month]
    year = _infer_year(m)
    ts = dt.datetime(year, m, day, hh, mm, ss, tzinfo=tz)
    return ts.isoformat()

DT_ACCESS_RE = re.compile(
    r"(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\s+(?P<tz>[+\-]\d{4})"
)

def _compose_timestamp_access(dt_str: str) -> str:
    m = DT_ACCESS_RE.match(dt_str)
    if not m:
        return dt.datetime.now(dt.timezone.utc).isoformat()
    d = m.groupdict()
    day = int(d["day"]); mon = MONTHS[d["mon"]]; year = int(d["year"])
    h = int(d["h"]); mi = int(d["m"]); s = int(d["s"]); tzs = d["tz"]
    sign = 1 if tzs.startswith("+") else -1
    tzh = int(tzs[1:3]); tzm = int(tzs[3:5])
    offset = dt.timedelta(hours=sign*tzh, minutes=sign*tzm)
    tz = dt.timezone(offset)
    return dt.datetime(year, mon, day, h, mi, s, tzinfo=tz).isoformat()

class Normalizer:
    """Convierte dicts parseados en eventos JSON normalizados."""

    def __init__(self, default_tz: dt.tzinfo | None = None) -> None:
        self.tz = default_tz or dt.timezone.utc

    def normalize(self, parsed: Dict, raw_line: str) -> Dict:
        source = parsed.get("source", "unknown")
        event_type = parsed.get("event_type", "unknown")
        host = parsed.get("host")
        severity = "info"

        if source in ("syslog", "auth.log"):
            ts = _compose_timestamp_syslog(parsed["month"], parsed["day"], parsed["time"], self.tz)
            message = parsed.get("message", "")
            fields = {
                "process": parsed.get("process"),
                "pid": parsed.get("pid"),
            }
        elif source == "access.log":
            ts = _compose_timestamp_access(parsed["dt"])
            message = f"{parsed['method']} {parsed['path']} {parsed['status']}"
            fields = {
                "client_ip": parsed.get("ip"),
                "method": parsed.get("method"),
                "path": parsed.get("path"),
                "protocol": parsed.get("proto"),
                "status": parsed.get("status"),
                "bytes": parsed.get("size"),
                "referrer": parsed.get("referrer"),
                "user_agent": parsed.get("user_agent"),
            }
            host = host or "localhost"
        else:
            ts = dt.datetime.now(self.tz).isoformat()
            message = parsed.get("message", "")
            fields = {k: v for k, v in parsed.items() if k not in {"event_type", "source"}}

        event = {
            "timestamp": ts,
            "host": host,
            "source": source,
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "fields": fields,
            "raw": raw_line,
        }
        return event

    def to_json(self, event: Dict) -> str:
        return json.dumps(event, ensure_ascii=False)
