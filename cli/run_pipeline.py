from __future__ import annotations
import argparse
import sys
import json
import signal

from siem_lite.collectors.file_collector import FileCollector
from siem_lite.parsers.regex_parsers import parse_line_by_best_effort
from siem_lite.parsers.normalizer import Normalizer

from siem_lite.engine.detection_engine import DetectionEngine
from siem_lite.engine.rules_auth import (
    SSHBruteForceRule,
    SudoBurstRule,
    SSHCompromiseRule,
)
from siem_lite.engine.rules_http import HTTPLoginBruteforce, HTTP404Scanner
from siem_lite.engine.rules_threatintel import IPBlacklistRule
from siem_lite.storage.alert_store import SQLiteAlertStore

# -------- Pretty printing (rich) opcional --------
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


def pretty_print_event(event: dict):
    """Imprime un evento con formato bonito (si rich está disponible)."""
    if not _RICH_AVAILABLE:
        sys.stdout.write(json.dumps({"kind": "event", **event}, ensure_ascii=False) + "\n")
        return

    t = Table.grid(expand=True)
    t.add_column(justify="left")
    t.add_column(justify="right")
    t.add_row("[bold cyan]EVENT[/bold cyan]", f"[dim]{event.get('timestamp')}[/dim]")
    meta = f"{event.get('host') or 'unknown'} · {event.get('source')}"
    t.add_row("type", f"[green]{event.get('event_type')}[/green]")
    t.add_row("meta", meta)
    t.add_row("message", event.get("message", ""))

    fields = event.get("fields") or {}
    if fields:
        fld = "\n".join(f"{k}: {v}" for k, v in fields.items())
        t.add_row("fields", fld)

    _console.print(Panel(t, box=box.ROUNDED, padding=(1, 1)))


def pretty_print_alert(alert: dict):
    """Imprime una alerta con formato bonito (si rich está disponible)."""
    if not _RICH_AVAILABLE:
        sys.stdout.write(json.dumps({"kind": "alert", **alert}, ensure_ascii=False) + "\n")
        return

    sev = (alert.get("severity") or "").lower()
    if sev in ("critical", "high"):
        sev_color = "red"
    elif sev == "medium":
        sev_color = "yellow"
    else:
        sev_color = "green"

    table = Table.grid(expand=True)
    table.add_column()
    table.add_column(justify="right")
    table.add_row(
        f"[bold {sev_color}]ALERT — {alert.get('rule')}[/bold {sev_color}]",
        f"[{sev_color}]{alert.get('severity')}[/{sev_color}]",
    )
    table.add_row("time", f"[dim]{alert.get('timestamp')}[/dim]")
    table.add_row("desc", alert.get("description"))
    inds = alert.get("indicators") or {}
    if inds:
        table.add_row("indicators", "\n".join(f"{k}: {v}" for k, v in inds.items()))

    _console.print(Panel(table, box=box.DOUBLE, padding=(1, 1)))


def main() -> int:
    ap = argparse.ArgumentParser(
        description="SIEM-Lite: collector + parser + normalizador + detección → JSONL/pretty/SQLite"
    )
    ap.add_argument("paths", nargs="+", help="Rutas a ficheros de log")
    ap.add_argument("-f", "--follow", action="store_true", help="Sigue nuevos eventos (tail)")
    ap.add_argument("-b", "--from-beginning", action="store_true", help="Leer desde el principio del fichero")
    ap.add_argument("--idle-exit", type=float, default=None, help="(follow) Salir si no hay datos durante N segundos")
    ap.add_argument("--max-events", type=int, default=None, help="Salir tras procesar N eventos")

    ap.add_argument("--no-events", action="store_true", help="No imprimir eventos (solo alertas)")
    ap.add_argument("--emit-alerts", action="store_true", help="Imprimir alertas detectadas")
    ap.add_argument("--alert-file", type=str, default="", help="Guardar alertas en fichero JSONL")
    ap.add_argument(
        "--alert-db",
        type=str,
        default="",
        help="Ruta a base de datos SQLite para almacenar alertas de forma persistente.",
    )

    # Fichero de lista negra de IPs
    ap.add_argument(
        "--ip-blacklist-file",
        type=str,
        default="",
        help="Fichero de texto con IPs en lista negra (una IP por línea, se ignoran líneas vacías y comentarios '#').",
    )

    # Salida bonita
    ap.add_argument("--pretty", action="store_true", help="Salida con formato y colores (usa 'rich' si está instalado)")

    # Umbrales de reglas existentes
    ap.add_argument("--ssh-threshold", type=int, default=5)
    ap.add_argument("--ssh-window", type=int, default=60)
    ap.add_argument("--sudo-threshold", type=int, default=8)
    ap.add_argument("--sudo-window", type=int, default=60)
    ap.add_argument("--web401-threshold", type=int, default=6)
    ap.add_argument("--web401-window", type=int, default=60)
    ap.add_argument("--web404-distinct", type=int, default=20)
    ap.add_argument("--web404-window", type=int, default=120)

    # Regla de compromiso SSH
    ap.add_argument(
        "--ssh-comp-fail-threshold",
        type=int,
        default=5,
        help="Fallos mínimos previos desde una IP para considerar sospechoso un login SSH (ssh_compromise).",
    )
    ap.add_argument(
        "--ssh-comp-fail-window",
        type=int,
        default=120,
        help="Ventana en segundos para contar fallos previos (ssh_compromise).",
    )
    ap.add_argument(
        "--ssh-comp-sudo-window",
        type=int,
        default=120,
        help="Ventana en segundos entre login aceptado y sudo a root (ssh_compromise).",
    )

    # Deduplicación de alertas
    ap.add_argument(
        "--dedup-window",
        type=int,
        default=0,
        help="Segundos para suprimir alertas duplicadas (0 = sin deduplicación).",
    )

    args = ap.parse_args()

    # Aviso si piden pretty pero no está rich
    if args.pretty and not _RICH_AVAILABLE:
        sys.stderr.write("[warn] 'rich' no está instalado. Usando salida JSON.\n")

    # Salida limpia con Ctrl+C
    stop_flag = {"stop": False}

    def _sigint(_sig, _frm):
        stop_flag["stop"] = True

    signal.signal(signal.SIGINT, _sigint)

    collector = FileCollector(
        args.paths,
        poll_interval=0.5,
        start_at_end=not args.from_beginning,
        follow=args.follow,
        idle_exit_sec=args.idle_exit,
        max_events=args.max_events,
    )
    normalizer = Normalizer()

    # Carga opcional de lista negra de IPs
    ip_blacklist: set[str] = set()
    if args.ip_blacklist_file:
        try:
            with open(args.ip_blacklist_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    ip_blacklist.add(line)
        except FileNotFoundError:
            sys.stderr.write(f"[warn] No se pudo abrir el fichero de blacklist: {args.ip_blacklist_file}\n")

    # Construcción de reglas
    rules = [
        SSHBruteForceRule(
            threshold=args.ssh_threshold,
            window_sec=args.ssh_window,
        ),
        SudoBurstRule(
            threshold=args.sudo_threshold,
            window_sec=args.sudo_window,
        ),
        HTTPLoginBruteforce(
            threshold=args.web401_threshold,
            window_sec=args.web401_window,
        ),
        HTTP404Scanner(
            distinct_threshold=args.web404_distinct,
            window_sec=args.web404_window,
        ),
        SSHCompromiseRule(
            fail_threshold=args.ssh_comp_fail_threshold,
            fail_window_sec=args.ssh_comp_fail_window,
            sudo_window_sec=args.ssh_comp_sudo_window,
        ),
    ]

    # Regla de blacklist solo si hay IPs cargadas
    if ip_blacklist:
        rules.append(IPBlacklistRule(ip_blacklist))

    engine = DetectionEngine(
        rules,
        dedup_window_sec=args.dedup_window,
    )

    alert_fp = open(args.alert_file, "a", encoding="utf-8") if args.alert_file else None
    alert_store = SQLiteAlertStore(args.alert_db) if args.alert_db else None

    try:
        for item in collector.lines():
            if stop_flag["stop"]:
                break

            raw = item["line"]
            parsed = parse_line_by_best_effort(raw)
            if not parsed:
                parsed = {"event_type": "unknown", "source": "unknown", "message": raw}
            event = normalizer.normalize(parsed, raw)

            # Eventos
            if not args.no_events:
                if args.pretty:
                    pretty_print_event(event)
                else:
                    sys.stdout.write(json.dumps({"kind": "event", **event}, ensure_ascii=False) + "\n")

            # Alertas
            if args.emit_alerts:
                alerts = engine.process_event(event)
                for a in alerts:
                    a_dict = a.to_dict()
                    if args.pretty:
                        pretty_print_alert(a_dict)
                    else:
                        line = json.dumps({"kind": "alert", **a_dict}, ensure_ascii=False)
                        sys.stdout.write(line + "\n")

                    # Persistencia opcional
                    if alert_fp:
                        alert_fp.write(json.dumps(a_dict, ensure_ascii=False) + "\n")
                    if alert_store:
                        alert_store.store_alert(a)

            sys.stdout.flush()
    finally:
        if alert_fp:
            alert_fp.close()
        if alert_store:
            alert_store.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
