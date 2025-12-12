#!/usr/bin/env python3
"""
generate_logs_varied.py

Generador sintético de logs más variado y realista para SIEM-Lite.

Características:
- Mezcla de eventos: SSH (fail/accept), sudo, HTTP (200,401,404).
- Varias IPs atacantes y clientes legítimos.
- Parámetros para controlar ruido y agresividad de ataques.
- Modo batch (escribe y sale) y stream (append lento, ideal para tail).
- Timestamps con jitter y avance temporal.

Uso (ejemplos):
# Batch variado (2000 líneas, ruido ligero, probabilidad de ataque 0.2)
python tools/generate_logs_varied.py --mode batch --out siem_lite/examples/varied_combined.log \
  --lines 2000 --noise-level 0.85 --attack-prob 0.20 --attack-intensity 0.6

# Stream para tail (útil para pruebas en tiempo real)
python tools/generate_logs_varied.py --mode stream --out /tmp/auth_stream.log --lines 1000 \
  --delay 0.02 --noise-level 0.9 --attack-prob 0.15
"""

from __future__ import annotations
import argparse
import random
import time
import datetime as dt
from pathlib import Path
from typing import List

MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]

# Helpers -------------------------------------------------------------------
def iso_now():
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "+00:00"

def syslog_time(ts: dt.datetime):
    # Format: "Oct 10 12:34:56"
    return f"{MONTHS[ts.month-1]} {ts.day} {ts.strftime('%H:%M:%S')}"

def access_time(ts: dt.datetime):
    return ts.strftime("%d/%b/%Y:%H:%M:%S +0000")

# Generators ---------------------------------------------------------------
def gen_ssh_line(ts: dt.datetime, host="myhost", success=True, user="pablo", ip=None, port=None, pid=1):
    ip = ip or f"192.0.2.{random.randint(2,254)}"
    port = port or random.randint(1024,65535)
    t = syslog_time(ts)
    if success:
        return f"{t} {host} sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2\n"
    else:
        if random.random() < 0.18:
            return f"{t} {host} sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2\n"
        else:
            return f"{t} {host} sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2\n"

def gen_sudo_line(ts: dt.datetime, host="myhost", user="pablo", pid=1):
    t = syslog_time(ts)
    return f"{t} {host} sudo:   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/ls\n"

def gen_access_line(ts: dt.datetime, ip=None, method="GET", path="/", status=200, size=1234, ref="-", ua="curl/7.68.0", host="localhost"):
    ip = ip or f"203.0.113.{random.randint(2,254)}"
    dtstr = access_time(ts)
    return f'{ip} - - [{dtstr}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"\n'

# Higher-level patterns -----------------------------------------------------
def random_user():
    return random.choice(["alice","bob","carol","dave","eve","frank","pablo","user1","user2","srv"])

def random_path():
    base = random.choice(["/","/index.html","/login","/admin","/api/login","/wp-login.php","/robots.txt","/favicon.ico","/dashboard"])
    if random.random() < 0.1:
        # append random id
        return base + ("" if base.endswith("/") else "") + str(random.randint(1,500))
    return base

def generate_varied_line(ts: dt.datetime, cfg: dict):
    """Generates one line of mixed logs according to probabilities in cfg."""
    # cfg keys:
    #  - noise_level: float [0..1] probability of benign event
    #  - attack_prob: probability to trigger an attack cluster
    #  - attack_intensity: how aggressive is the attack (0..1)
    #  - attacker_ips: list[str]
    #  - client_pool: list[str]
    r = random.random()
    # decide type: ssh (30%), http (55%), sudo (5%), misc (10%)
    p = random.random()
    if p < 0.30:
        # SSH
        # decide if attack from an attacker ip
        if r > cfg["noise_level"] and random.random() < cfg["attack_prob"]:
            # Attack attempt (fail more likely)
            ip = random.choice(cfg["attacker_ips"])
            success = random.random() > cfg["attack_intensity"] * 0.2  # mostly fails
            user = random_user()
            return gen_ssh_line(ts, success=success, user=user, ip=ip)
        else:
            # normal SSH auth/noise
            ip = random.choice(cfg["client_pool"])
            success = random.random() < 0.9
            user = random_user()
            return gen_ssh_line(ts, success=success, user=user, ip=ip)
    elif p < 0.85:
        # HTTP access
        if r > cfg["noise_level"] and random.random() < cfg["attack_prob"]:
            # web attack scenario: either 401 burst or 404 scan
            if random.random() < 0.6:
                # 401 attempt to /login
                ip = random.choice(cfg["attacker_ips"])
                method = "POST"
                path = "/login"
                status = 401 if random.random() < 0.95 else 200
                ua = random.choice(["Mozilla/5.0","curl/7.68.0","python-requests/2.25"])
                return gen_access_line(ts, ip=ip, method=method, path=path, status=status, ua=ua)
            else:
                # 404 scan
                ip = random.choice(cfg["attacker_ips"])
                path = "/" + random.choice(["admin","backup","wp-login.php","old","config",".git"]) + str(random.randint(1,500))
                return gen_access_line(ts, ip=ip, method="GET", path=path, status=404, size=0, ua="curl/7.68.0")
        else:
            # normal HTTP browsing
            ip = random.choice(cfg["client_pool"])
            path = random_path()
            status = 200 if not path.startswith("/login") else (200 if random.random() < 0.9 else 401)
            ua = random.choice(["curl/7.68.0","Mozilla/5.0","Googlebot/2.1"])
            return gen_access_line(ts, ip=ip, method=random.choice(["GET","GET","POST"]), path=path, status=status, ua=ua)
    elif p < 0.90:
        # sudo events (less frequent)
        if random.random() < 0.6:
            user = random_user()
            return gen_sudo_line(ts, user=user)
        else:
            # occasional system message
            return f"{syslog_time(ts)} myhost CRON[1]: (root) CMD (/usr/bin/backup)\n"
    else:
        # misc noise: heartbeat, service logs
        return f"{syslog_time(ts)} myhost kernel: [0.000000] eth0: link up\n"

# Batch / streaming writers -------------------------------------------------
def write_batch(path: Path, lines: List[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line)

def stream_append(path: Path, gen_func, total: int, delay: float):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for i in range(total):
            line = gen_func()
            f.write(line)
            f.flush()
            time.sleep(delay)

# Runner ---------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["batch","stream"], default="batch")
    ap.add_argument("--out", required=True)
    ap.add_argument("--lines", type=int, default=1000)
    ap.add_argument("--delay", type=float, default=0.02)  # for stream
    ap.add_argument("--noise-level", type=float, default=0.9, help="Fraction of events that are benign (0..1)")
    ap.add_argument("--attack-prob", type=float, default=0.12, help="Probabilidad general de 'cluster' atacante por evento")
    ap.add_argument("--attack-intensity", type=float, default=0.6, help="Agresividad de ataque (0..1)")
    ap.add_argument("--attacker-count", type=int, default=3, help="Número de IPs atacantes distintas")
    ap.add_argument("--client-count", type=int, default=40, help="Número de IPs clientes legítimos")
    args = ap.parse_args()

    outp = Path(args.out)
    now = dt.datetime.utcnow()
    cfg = {
        "noise_level": float(args.noise_level),
        "attack_prob": float(args.attack_prob),
        "attack_intensity": float(args.attack_intensity),
        "attacker_ips": [f"198.51.100.{i+2}" for i in range(args.attacker_count)],
        "client_pool": [f"203.0.113.{(i % 250) + 2}" for i in range(args.client_count)],
    }

    # create generator closure that advances time and adds jitter
    ts = now
    def gen_one():
        nonlocal ts
        # advance time by small random delta
        ts_delta = dt.timedelta(seconds=random.uniform(0.1, 1.5))
        ts += ts_delta
        # jitter seconds for realism
        jitter = dt.timedelta(seconds=random.uniform(-0.2, 0.2))
        return generate_varied_line(ts + jitter, cfg)

    if args.mode == "batch":
        lines = [gen_one() for _ in range(args.lines)]
        write_batch(outp, lines)
        print(f"Wrote {len(lines)} lines to {outp}")
    else:
        # streaming: append lines with delay, useful for follow mode
        stream_append(outp, gen_one, args.lines, args.delay)
        print(f"Streamed {args.lines} lines to {outp}")

if __name__ == "__main__":
    main()
