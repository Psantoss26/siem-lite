from __future__ import annotations
from typing import List, Dict, Any, Tuple
import json
import datetime as dt

from .rules_base import Rule, Alert, parse_iso


class DetectionEngine:
    """Motor de correlación muy ligero.

    Además de iterar sobre las reglas registradas, implementa una capa opcional
    de deduplicación de alertas para evitar floods cuando una misma condición
    se cumple repetidamente en una ventana corta.
    """

    def __init__(self, rules: List[Rule], dedup_window_sec: int | None = None) -> None:
        self.rules = rules
        # Ventana de supresión de alertas duplicadas
        self._dedup_window = (
            dt.timedelta(seconds=dedup_window_sec)
            if dedup_window_sec and dedup_window_sec > 0
            else None
        )
        # (regla, indicadores_json) -> último timestamp visto
        self._last_alert_ts: Dict[Tuple[str, str], dt.datetime] = {}

    def _fingerprint(self, alert: Alert) -> Tuple[str, str]:
        """Construye una clave estable a partir de la regla y sus indicadores."""
        indicators_str = json.dumps(alert.indicators, sort_keys=True, ensure_ascii=False)
        return (alert.rule, indicators_str)

    def _apply_dedup(self, alerts: List[Alert]) -> List[Alert]:
        if not self._dedup_window:
            return alerts

        filtered: List[Alert] = []
        for a in alerts:
            try:
                ts = parse_iso(a.timestamp)
            except Exception:
                # Si el timestamp no es parseable, dejamos pasar la alerta.
                filtered.append(a)
                continue

            key = self._fingerprint(a)
            last_ts = self._last_alert_ts.get(key)
            if last_ts and (ts - last_ts) <= self._dedup_window:
                # Misma alerta dentro de la ventana: la suprimimos.
                continue

            self._last_alert_ts[key] = ts
            filtered.append(a)

        return filtered

    def process_event(self, event: Dict[str, Any]) -> List[Alert]:
        """Procesa un evento normalizado y devuelve la lista de alertas."""
        alerts: List[Alert] = []
        for r in self.rules:
            try:
                alerts.extend(r.process(event) or [])
            except Exception:
                # Mejor que una regla rota no tumbe todo el pipeline.
                continue

        return self._apply_dedup(alerts)
