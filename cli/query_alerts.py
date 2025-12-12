from __future__ import annotations
import argparse
import sys
import json

from siem_lite.storage.alert_store import SQLiteAlertStore

# Pretty printing opcional con rich
_RICH_AVAILABLE = False
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    _RICH_AVAILABLE = True
    _console = Console()
except Exception:
    _RICH_AVAILABLE = False
    _console = None  # type: ignore


def _pretty_print_alert(row: dict) -> None:
    if not _RICH_AVAILABLE:
        sys.stdout.write(json.dumps(row, ensure_ascii=False) + "\n")
        return

    table = Table.grid(expand=True)
    table.add_column()
    table.add_column(justify="right")

    sev = (row.get("severity") or "").lower()
    if sev in ("critical", "high"):
        sev_color = "red"
    elif sev == "medium":
        sev_color = "yellow"
    else:
        sev_color = "green"

    header = f"[bold {sev_color}]ALERT #{row.get('id')} — {row.get('rule')}[/bold {sev_color}]"
    table.add_row(header, f"[{sev_color}]{row.get('severity')}[/{sev_color}]")
    table.add_row("time", f"[dim]{row.get('timestamp')}[/dim]")
    table.add_row("desc", row.get("description", ""))

    inds = row.get("indicators") or {}
    if inds:
        inds_str = "\n".join(f"{k}: {v}" for k, v in inds.items())
        table.add_row("indicators", inds_str)

    if row.get("ip") or row.get("user"):
        extra = []
        if row.get("ip"):
            extra.append(f"ip={row['ip']}")
        if row.get("user"):
            extra.append(f"user={row['user']}")
        table.add_row("extras", ", ".join(extra))

    _console.print(Panel(table, box=box.ROUNDED, padding=(1, 1)))


def _pretty_print_stats(stats: list[dict]) -> None:
    if not _RICH_AVAILABLE:
        sys.stdout.write(json.dumps({"stats": stats}, ensure_ascii=False) + "\n")
        return

    table = Table(title="Alertas por regla", box=box.SIMPLE_HEAVY)
    table.add_column("Regla", style="bold")
    table.add_column("Alertas", justify="right")

    for row in stats:
        table.add_row(str(row.get("rule")), str(row.get("count")))

    _console.print(table)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Consulta de alertas almacenadas en la base de datos SQLite del SIEM-Lite."
    )
    ap.add_argument(
        "--db",
        required=True,
        help="Ruta al fichero SQLite de alertas (creado por run_pipeline con --alert-db).",
    )

    # Filtros de consulta
    ap.add_argument("--rule", help="Filtrar por nombre de regla (exacto).")
    ap.add_argument("--severity", help="Filtrar por severidad (low/medium/high/critical).")
    ap.add_argument("--ip", help="Filtrar por IP (campo 'ip' de indicators).")
    ap.add_argument("--user", help="Filtrar por usuario (campo 'user' o 'username').")
    ap.add_argument(
        "--since",
        help="Timestamp mínimo (ISO-8601, ej. 2025-05-01T00:00:00). Debe usar el mismo formato que los eventos.",
    )
    ap.add_argument(
        "--until",
        help="Timestamp máximo (ISO-8601).",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Máximo número de alertas a devolver (por defecto 100).",
    )

    # Estadísticas agregadas
    ap.add_argument(
        "--stats",
        action="store_true",
        help="Mostrar solo estadísticas agregadas por regla en lugar de listar alertas.",
    )

    # Salida
    ap.add_argument(
        "--pretty",
        action="store_true",
        help="Salida formateada con 'rich' (si está instalado). Si no, JSON plano.",
    )

    args = ap.parse_args()

    store = SQLiteAlertStore(args.db)

    if args.stats:
        stats = store.stats_by_rule(since=args.since, until=args.until)
        if args.pretty:
            _pretty_print_stats(stats)
        else:
            sys.stdout.write(json.dumps({"stats": stats}, ensure_ascii=False) + "\n")
        return 0

    alerts = store.query_alerts(
        since=args.since,
        until=args.until,
        rule=args.rule,
        severity=args.severity,
        ip=args.ip,
        user=args.user,
        limit=args.limit,
    )

    if args.pretty:
        for row in alerts:
            _pretty_print_alert(row)
    else:
        for row in alerts:
            sys.stdout.write(json.dumps(row, ensure_ascii=False) + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
