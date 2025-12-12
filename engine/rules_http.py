from __future__ import annotations
from collections import defaultdict, deque
from typing import Dict, Any, Iterable, Set
import datetime as dt

from .rules_base import Rule, Alert, parse_iso

class HTTPLoginBruteforce(Rule):
    """
    Muchos 401 sobre /login desde la misma IP en ventana corta.
    """
    name = "http_login_bruteforce"
    severity = "high"

    def __init__(self, threshold:int=6, window_sec:int=60) -> None:
        self.threshold = threshold
        self.window = dt.timedelta(seconds=window_sec)
        self.by_ip: Dict[str, deque] = defaultdict(deque)

    def _prune(self, dq, now):
        while dq and (now - dq[0]) > self.window:
            dq.popleft()

    def process(self, event: Dict[str, Any]):
        if event.get("event_type") != "http/access":
            return []
        f = event.get("fields", {})
        status = int(f.get("status", 0) or 0)
        path = (f.get("path") or "").lower()
        ip = f.get("client_ip") or ""
        if status != 401 or "/login" not in path:
            return []

        ts = parse_iso(event["timestamp"])
        dq = self.by_ip[ip]
        dq.append(ts)
        self._prune(dq, ts)

        if len(dq) >= self.threshold:
            return [Alert(
                timestamp=event["timestamp"],
                rule=self.name,
                severity=self.severity,
                description=f"Posible fuerza bruta web desde {ip} sobre {path}: {len(dq)} respuestas 401 en {self.window.seconds}s",
                indicators={"ip": ip, "count_401": len(dq), "path": path},
                source_event_type=event["event_type"]
            )]
        return []

class HTTP404Scanner(Rule):
    """
    Muchos 404 a rutas distintas por IP → posible escaneo/dirbusting.
    """
    name = "http_404_scanner"
    severity = "medium"

    def __init__(self, distinct_threshold:int=20, window_sec:int=120) -> None:
        self.distinct_threshold = distinct_threshold
        self.window = dt.timedelta(seconds=window_sec)
        self.by_ip_paths: Dict[str, deque] = defaultdict(deque)  # guarda (ts, path)

    def _prune(self, dq, now):
        while dq and (now - dq[0][0]) > self.window:
            dq.popleft()

    def process(self, event: Dict[str, Any]):
        if event.get("event_type") != "http/access":
            return []
        f = event.get("fields", {})
        status = int(f.get("status", 0) or 0)
        if status != 404:
            return []

        ts = parse_iso(event["timestamp"])
        ip = f.get("client_ip") or ""
        path = f.get("path") or ""

        dq = self.by_ip_paths[ip]
        dq.append((ts, path))
        self._prune(dq, ts)

        # distintas rutas en ventana
        distinct: Set[str] = set(p for _, p in dq)
        if len(distinct) >= self.distinct_threshold:
            return [Alert(
                timestamp=event["timestamp"],
                rule=self.name,
                severity=self.severity,
                description=f"Posible escaneo web desde {ip}: {len(distinct)} rutas 404 diferentes en {self.window.seconds}s",
                indicators={"ip": ip, "distinct_404_paths": len(distinct)},
                source_event_type=event["event_type"]
            )]
        return []
