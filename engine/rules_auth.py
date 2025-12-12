from __future__ import annotations
from collections import defaultdict, deque
from typing import Dict, Any, Iterable, Tuple
import re
import datetime as dt

from .rules_base import Rule, Alert, parse_iso

# Regex comunes para SSH
FAILED_RE = re.compile(
    r"Failed password for (?:(?:invalid user )?)(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


class SSHBruteForceRule(Rule):
    """
    Dispara alerta si hay >= N fallos en ventana T por (ip) o (ip, user).
    """
    name = "ssh_bruteforce"
    severity = "high"

    def __init__(self, threshold: int = 5, window_sec: int = 60) -> None:
        self.threshold = threshold
        self.window = dt.timedelta(seconds=window_sec)
        # Ventanas por clave
        self.by_ip: Dict[str, deque] = defaultdict(deque)
        self.by_pair: Dict[Tuple[str, str], deque] = defaultdict(deque)

    def _prune(self, dq: deque, now: dt.datetime) -> None:
        while dq and (now - dq[0]) > self.window:
            dq.popleft()

    def process(self, event: Dict[str, Any]) -> Iterable[Alert]:
        if event.get("event_type") != "auth/sshd":
            return []

        msg = event.get("message", "")
        ts = parse_iso(event["timestamp"])

        alerts: list[Alert] = []

        m = FAILED_RE.search(msg)
        if m:
            user = m.group("user")
            ip = m.group("ip")

            dq_ip = self.by_ip[ip]
            dq_ip.append(ts)
            self._prune(dq_ip, ts)

            dq_pair = self.by_pair[(ip, user)]
            dq_pair.append(ts)
            self._prune(dq_pair, ts)

            if len(dq_ip) >= self.threshold:
                alerts.append(
                    Alert(
                        timestamp=event["timestamp"],
                        rule=self.name,
                        severity=self.severity,
                        description=(
                            f"Posible fuerza bruta SSH desde {ip}: "
                            f"{len(dq_ip)} fallos en {self.window.seconds}s"
                        ),
                        indicators={"ip": ip, "fail_count_ip": len(dq_ip)},
                        source_event_type=event["event_type"],
                    )
                )

            if len(dq_pair) >= self.threshold:
                alerts.append(
                    Alert(
                        timestamp=event["timestamp"],
                        rule=self.name,
                        severity=self.severity,
                        description=(
                            f"Posible fuerza bruta SSH a usuario {user} desde {ip}: "
                            f"{len(dq_pair)} fallos en {self.window.seconds}s"
                        ),
                        indicators={"ip": ip, "user": user, "fail_count_user": len(dq_pair)},
                        source_event_type=event["event_type"],
                    )
                )

        # Opcional: reset por "Accepted password" (ataque finalizado/exitoso)
        m2 = ACCEPTED_RE.search(msg)
        if m2:
            user = m2.group("user")
            ip = m2.group("ip")
            self.by_ip[ip].clear()
            self.by_pair[(ip, user)].clear()

        return alerts


class SudoBurstRule(Rule):
    """
    Muchos usos de sudo hacia root en ventana corta.
    """
    name = "sudo_burst"
    severity = "medium"

    def __init__(self, threshold: int = 8, window_sec: int = 60) -> None:
        self.threshold = threshold
        self.window = dt.timedelta(seconds=window_sec)
        self.by_user: Dict[str, deque] = defaultdict(deque)

    def _prune(self, dq: deque, now: dt.datetime) -> None:
        while dq and (now - dq[0]) > self.window:
            dq.popleft()

    def process(self, event: Dict[str, Any]) -> Iterable[Alert]:
        if event.get("event_type") != "auth/sudo":
            return []

        msg = event.get("message", "")
        # Línea típica sudo: "pablo : TTY=pts/0 ; PWD=/home/pablo ; USER=root ; COMMAND=/bin/ls"
        user = msg.split(":", 1)[0].strip() or "unknown"
        is_root = "USER=root" in msg
        ts = parse_iso(event["timestamp"])

        alerts: list[Alert] = []

        if is_root:
            dq = self.by_user[user]
            dq.append(ts)
            self._prune(dq, ts)
            if len(dq) >= self.threshold:
                alerts.append(
                    Alert(
                        timestamp=event["timestamp"],
                        rule=self.name,
                        severity=self.severity,
                        description=(
                            f"Uso intensivo de sudo a root por '{user}': "
                            f"{len(dq)} veces en {self.window.seconds}s"
                        ),
                        indicators={"user": user, "count": len(dq)},
                        source_event_type=event["event_type"],
                    )
                )
        return alerts


class SSHCompromiseRule(Rule):
    """
    Regla de correlación multi-etapa para detectar posible compromiso SSH.

    Patrón:
      1) Muchos "Failed password" desde una misma IP en una ventana corta.
      2) Un "Accepted password" para algún usuario desde esa IP.
      3) Uso de sudo con USER=root por ese mismo usuario poco después.
    """
    name = "ssh_compromise"
    severity = "critical"

    def __init__(
        self,
        fail_threshold: int = 5,
        fail_window_sec: int = 120,
        sudo_window_sec: int = 120,
    ) -> None:
        # Umbral y ventanas temporales
        self.fail_threshold = fail_threshold
        self.fail_window = dt.timedelta(seconds=fail_window_sec)
        self.sudo_window = dt.timedelta(seconds=sudo_window_sec)

        # Ventana deslizante de fallos por IP
        self.fail_by_ip: Dict[str, deque] = defaultdict(deque)

        # Sesiones sospechosas por usuario:
        # deque de tuplas (ts_accepted, ip, fail_count)
        self.sessions_by_user: Dict[str, deque] = defaultdict(deque)

    def _prune_fail(self, dq: deque, now: dt.datetime) -> None:
        while dq and (now - dq[0]) > self.fail_window:
            dq.popleft()

    def _prune_sessions(self, dq: deque, now: dt.datetime) -> None:
        # No mantener sesiones viejas indefinidamente.
        max_window = max(self.fail_window, self.sudo_window)
        while dq and (now - dq[0][0]) > max_window:
            dq.popleft()

    def process(self, event: Dict[str, Any]) -> Iterable[Alert]:
        ev_type = event.get("event_type")
        msg = event.get("message", "") or ""
        try:
            ts = parse_iso(event["timestamp"])
        except Exception:
            # Si el timestamp no es parseable, no intentamos correlacionar.
            return []

        alerts: list[Alert] = []

        # 1/2) Procesamos eventos SSH (fallos y aceptaciones)
        if ev_type == "auth/sshd":
            m_fail = FAILED_RE.search(msg)
            if m_fail:
                ip = m_fail.group("ip")
                dq = self.fail_by_ip[ip]
                dq.append(ts)
                self._prune_fail(dq, ts)

            m_acc = ACCEPTED_RE.search(msg)
            if m_acc:
                user = m_acc.group("user")
                ip = m_acc.group("ip")
                dq_fail = self.fail_by_ip[ip]
                self._prune_fail(dq_fail, ts)
                fail_count = len(dq_fail)

                # Solo consideramos sospechoso si previamente hubo suficientes fallos
                if fail_count >= self.fail_threshold:
                    dq_sess = self.sessions_by_user[user]
                    dq_sess.append((ts, ip, fail_count))
                    self._prune_sessions(dq_sess, ts)

        # 3) Procesamos sudo hacia root
        elif ev_type == "auth/sudo":
            fields = event.get("fields") or {}
            msg_lower = msg.lower()

            # --- Extracción robusta de usuario (igual que SudoBurstRule + extras) ---
            user = (fields.get("user") or "").strip()

            # 1) Intento con regex "sudo: user :"
            if not user:
                m_user = re.search(r"sudo:\s+(?P<user>\S+)\s*:", msg)
                if m_user:
                    user = m_user.group("user")

            # 2) Fallback estilo SudoBurstRule: "pablo : TTY=..."
            if not user and ":" in msg:
                first_part = msg.split(":", 1)[0].strip()
                if first_part:
                    user = first_part

            if not user:
                # Si no conseguimos usuario, no podemos correlacionar con sesiones SSH
                return []

            # Comprobamos si el sudo es hacia root
            is_root = (
                "user=root" in msg_lower
                or fields.get("target_user") == "root"
                or "USER=root" in msg  # por si el log mantiene mayúsculas
            )
            if not is_root:
                return []

            dq_sess = self.sessions_by_user.get(user)
            if not dq_sess:
                return []

            self._prune_sessions(dq_sess, ts)

            for accepted_ts, ip, fail_count in list(dq_sess):
                if (ts - accepted_ts) <= self.sudo_window:
                    # Correlación completa: fallos + login + sudo.
                    alerts.append(
                        Alert(
                            timestamp=event["timestamp"],
                            rule=self.name,
                            severity=self.severity,
                            description=(
                                f"Posible compromiso SSH para '{user}' desde {ip}: "
                                f"{fail_count} fallos previos, login aceptado y uso de sudo a root"
                            ),
                            indicators={
                                "user": user,
                                "ip": ip,
                                "fail_count_ip": fail_count,
                                "accepted_at": accepted_ts.isoformat(),
                            },
                            source_event_type=event["event_type"],
                        )
                    )
                    # Limpiamos la sesión para no alertar una y otra vez
                    dq_sess.clear()
                    break

        return alerts
