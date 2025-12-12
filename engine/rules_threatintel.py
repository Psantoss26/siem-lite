from __future__ import annotations
from typing import Dict, Any, Iterable, Set
import re

from .rules_base import Rule, Alert, parse_iso


IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


class IPBlacklistRule(Rule):
    """
    Regla de enriquecimiento de Threat Intel.

    Genera una alerta crítica cuando cualquier evento contiene una IP
    incluida en una lista negra configurada externamente.

    - La lista de IPs se pasa en el constructor como un set de strings.
    - Se buscan IPs en:
        * campos normalizados comunes: src_ip, source_ip, client_ip,
          remote_addr, ip
        * el propio mensaje (búsqueda por regex)
    """

    name = "ip_blacklist_hit"
    severity = "critical"

    def __init__(self, blacklisted_ips: Set[str]) -> None:
        # Normalizamos a strings sin espacios
        self.blacklisted_ips = {ip.strip() for ip in blacklisted_ips if ip.strip()}

    def _extract_ips(self, event: Dict[str, Any]) -> set[str]:
        ips: set[str] = set()

        fields = event.get("fields") or {}
        # Campos típicos donde podrían venir IPs
        for key in ("src_ip", "source_ip", "client_ip", "remote_addr", "ip"):
            val = fields.get(key)
            if val:
                ips.add(str(val))

        # Como último recurso, buscar IPs en el propio mensaje
        msg = event.get("message", "") or ""
        for m in IP_RE.finditer(msg):
            ips.add(m.group(0))

        return ips

    def process(self, event: Dict[str, Any]) -> Iterable[Alert]:
        # Si no tenemos lista negra, no hacemos nada
        if not self.blacklisted_ips:
            return []

        try:
            # Forzamos parseo del timestamp para evitar datos basura
            _ = parse_iso(event["timestamp"])
        except Exception:
            return []

        event_ips = self._extract_ips(event)
        hits = event_ips & self.blacklisted_ips
        if not hits:
            return []

        # Por simplicidad, emitimos una alerta por evento, con la(s) IP(s) que han matcheado
        hit_list = sorted(hits)
        description = f"Evento desde IP en lista negra: {', '.join(hit_list)}"

        return [
            Alert(
                timestamp=event["timestamp"],
                rule=self.name,
                severity=self.severity,
                description=description,
                indicators={
                    "blacklisted_ips": hit_list,
                },
                source_event_type=event.get("event_type", "unknown"),
            )
        ]
