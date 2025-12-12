from __future__ import annotations
from typing import Iterable, Dict, Any, List, Optional
import sqlite3
import json
import threading
import os

from siem_lite.engine.rules_base import Alert


class SQLiteAlertStore:
    """
    Almacena alertas en una base de datos SQLite ligera.

    - Una fila por alerta.
    - Campos principales indexados (timestamp, rule, severity).
    - Extrae campos frecuentes de indicadores ("ip", "user"/"username") para facilitar búsquedas.
    """

    def __init__(self, path: str) -> None:
        # Aseguramos que el directorio existe
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        # Ajustes básicos para uso "embebido"
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._create_schema()

    def _create_schema(self) -> None:
        cur = self._conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                source_event_type TEXT NOT NULL,
                indicators_json TEXT NOT NULL,
                ip TEXT,
                user TEXT
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(ip)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_user ON alerts(user)")
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # --- Inserción ---

    def store_alert(self, alert: Alert) -> None:
        indicators = alert.indicators or {}
        indicators_json = json.dumps(indicators, ensure_ascii=False, sort_keys=True)
        ip = indicators.get("ip")
        user = indicators.get("user") or indicators.get("username")

        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO alerts (
                    timestamp, rule, severity, description,
                    source_event_type, indicators_json, ip, user
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.timestamp,
                    alert.rule,
                    alert.severity,
                    alert.description,
                    alert.source_event_type,
                    indicators_json,
                    ip,
                    user,
                ),
            )

    def store_alerts(self, alerts: Iterable[Alert]) -> None:
        with self._lock, self._conn:
            rows = []
            for alert in alerts:
                indicators = alert.indicators or {}
                indicators_json = json.dumps(indicators, ensure_ascii=False, sort_keys=True)
                ip = indicators.get("ip")
                user = indicators.get("user") or indicators.get("username")
                rows.append(
                    (
                        alert.timestamp,
                        alert.rule,
                        alert.severity,
                        alert.description,
                        alert.source_event_type,
                        indicators_json,
                        ip,
                        user,
                    )
                )
            if rows:
                self._conn.executemany(
                    """
                    INSERT INTO alerts (
                        timestamp, rule, severity, description,
                        source_event_type, indicators_json, ip, user
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )

    # --- Consultas ---

    def query_alerts(
        self,
        *,
        since: Optional[str] = None,
        until: Optional[str] = None,
        rule: Optional[str] = None,
        severity: Optional[str] = None,
        ip: Optional[str] = None,
        user: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Devuelve una lista de alertas como diccionarios, aplicando filtros simples.
        Timestamps deben ir en formato ISO-8601 (compatible con los que genera el pipeline).
        """
        sql = """
            SELECT
                id,
                timestamp,
                rule,
                severity,
                description,
                source_event_type,
                indicators_json,
                ip,
                user
            FROM alerts
            WHERE 1=1
        """
        params: list[Any] = []

        if since:
            sql += " AND timestamp >= ?"
            params.append(since)
        if until:
            sql += " AND timestamp <= ?"
            params.append(until)
        if rule:
            sql += " AND rule = ?"
            params.append(rule)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if ip:
            sql += " AND ip = ?"
            params.append(ip)
        if user:
            sql += " AND user = ?"
            params.append(user)

        sql += " ORDER BY timestamp DESC"
        if limit and limit > 0:
            sql += " LIMIT ?"
            params.append(limit)

        cur = self._conn.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall()

        results: List[Dict[str, Any]] = []
        for row in rows:
            (
                alert_id,
                timestamp,
                rule,
                severity,
                description,
                source_event_type,
                indicators_json,
                ip_val,
                user_val,
            ) = row
            try:
                indicators = json.loads(indicators_json)
            except Exception:
                indicators = {"_raw": indicators_json}

            results.append(
                {
                    "id": alert_id,
                    "timestamp": timestamp,
                    "rule": rule,
                    "severity": severity,
                    "description": description,
                    "source_event_type": source_event_type,
                    "indicators": indicators,
                    "ip": ip_val,
                    "user": user_val,
                }
            )
        return results

    def stats_by_rule(
        self,
        *,
        since: Optional[str] = None,
        until: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Devuelve estadísticas agregadas: número de alertas por regla.
        """
        sql = """
            SELECT rule, COUNT(*) as count
            FROM alerts
            WHERE 1=1
        """
        params: list[Any] = []

        if since:
            sql += " AND timestamp >= ?"
            params.append(since)
        if until:
            sql += " AND timestamp <= ?"
            params.append(until)

        sql += " GROUP BY rule ORDER BY count DESC"

        cur = self._conn.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall()

        return [{"rule": r, "count": c} for (r, c) in rows]
