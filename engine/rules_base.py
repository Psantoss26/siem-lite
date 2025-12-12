from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Any, List, Iterable
import datetime as dt

def parse_iso(ts: str) -> dt.datetime:
    # Soporta timestamps con tz (ISO-8601)
    return dt.datetime.fromisoformat(ts)

@dataclass
class Alert:
    timestamp: str
    rule: str
    severity: str
    description: str
    indicators: Dict[str, Any]
    source_event_type: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": "alert",
            "timestamp": self.timestamp,
            "rule": self.rule,
            "severity": self.severity,
            "description": self.description,
            "indicators": self.indicators,
            "source_event_type": self.source_event_type,
        }

class Rule:
    name: str = "base"
    severity: str = "low"

    def process(self, event: Dict[str, Any]) -> Iterable[Alert]:
        """Recibe un evento normalizado y puede devolver 0..n alertas."""
        return []
