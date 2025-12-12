#!/usr/bin/env python3
"""
generate_logs.py

Generador sintético de logs para pruebas del SIEM-Lite.

Modo de uso:
# Generar ficheros batch (escribe N líneas y sale)
python tools/generate_logs.py --mode batch --out examples/sample_auth_big.log --type auth --lines 200

# Generar en streaming (append lento, ideal para tail)
python tools/generate_logs.py --mode stream --out /tmp/auth_stream.log --type auth --lines 500 --delay 0.05

# Generar ataques concretos: ssh_bruteforce, web401_burst, web404_scan
python tools/generate_logs.py --mode batch --out examples/attack_auth.log --type auth --pattern ssh_bruteforce --lines 100
python tools/generate_logs.py --mode batch --out examples/attack_access.log --type access --pattern web401_burst --lines 80
"""
from __future__ import annotations
import argparse
import random
import time
import datetime as dt
from pathlib import Path

MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]

def rand_time(ts_base=None):
    now = ts_base or dt.datetime.utcnow()
    month = MONTHS[now.month-1]
    day = now.day
    t = now.strftime("%H:%M:%S")
    return f"{month} {day} {t}"

def gen_auth_line(success=True, user="pablo", ip=None, port=None):
    ip = ip or f"192.0.2.{random.randint(2,254)}"
    port = port or random.randint(1024,65535)
    ts = rand_time()
    if success:
        return f"{ts} myhost sshd[1]: Accepted password for {user} from {ip} port {port} ssh2\n"
    else:
        # some variants including invalid user
        if random.random() < 0.2:
            return f"{ts} myhost sshd[1]: Failed password for invalid user {user} from {ip} port {port} ssh2\n"
        else:
            return f"{ts} myhost sshd[1]: Failed password for {user} from {ip} port {port} ssh2\n"

def gen_sudo_line(user="pablo"):
    ts = rand_time()
    return f"{ts} myhost sudo:   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/ls\n"

def gen_access_line(ip=None, method="GET", path="/", status=200, size=1234, ref="-", ua="curl/7.68.0"):
    ip = ip or f"203.0.113.{random.randint(2,254)}"
    now = dt.datetime.utcnow()
    dtstr = now.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{dtstr}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"\n'

def generate_auth(lines, pattern=None):
    out = []
    if pattern == "ssh_bruteforce":
        # choose an attacker IP and generate bursts of failures then accepted
        attacker = f"198.51.100.{random.randint(2,254)}"
        for i in range(lines):
            # produce many failures in short sequence
            if i % 4 != 0:
                out.append(gen_auth_line(success=False, user=f"user{i%6}", ip=attacker))
            else:
                # occasional noise
                out.append(gen_auth_line(success=random.random() < 0.2, ip=f"192.0.2.{random.randint(2,254)}"))
    else:
        for i in range(lines):
            if random.random() < 0.08:
                out.append(gen_sudo_line(user=f"user{random.randint(1,6)}"))
            else:
                out.append(gen_auth_line(success=random.random() < 0.9, user=f"user{random.randint(1,8)}"))
    return out

def generate_access(lines, pattern=None):
    out = []
    if pattern == "web401_burst":
        attacker = f"203.0.113.{random.randint(2,254)}"
        for i in range(lines):
            if i % 3 != 0:
                out.append(gen_access_line(ip=attacker, method="POST", path="/login", status=401, size=512, ua="Mozilla/5.0"))
            else:
                out.append(gen_access_line(path="/index.html", status=200))
    elif pattern == "web404_scan":
        scanner = f"203.0.113.{random.randint(2,254)}"
        for i in range(lines):
            if i % 2 == 0:
                path = f"/{random.choice(['admin','wp-login.php','backup','old','config','.git'])}{random.randint(1,500)}"
                out.append(gen_access_line(ip=scanner, method="GET", path=path, status=404, size=0))
            else:
                out.append(gen_access_line(path="/index.html", status=200))
    else:
        for i in range(lines):
            if random.random() < 0.05:
                out.append(gen_access_line(method="POST", path="/api/login", status=401, size=512, ua="Mozilla/5.0"))
            else:
                out.append(gen_access_line(path=random.choice(["/","/index.html","/about","/contact"]), status=200))
    return out

def write_lines(path:Path, lines_list, mode="w", delay=0.0):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, mode, encoding="utf-8") as f:
        for line in lines_list:
            f.write(line)
            if delay:
                f.flush()
                time.sleep(delay)

def stream_append(path:Path, gen_func, total, delay):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for line in gen_func(total):
            f.write(line)
            f.flush()
            time.sleep(delay)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["batch","stream"], default="batch")
    ap.add_argument("--out", required=True)
    ap.add_argument("--type", choices=["auth","access"], default="auth")
    ap.add_argument("--lines", type=int, default=200)
    ap.add_argument("--delay", type=float, default=0.01)
    ap.add_argument("--pattern", choices=["ssh_bruteforce","web401_burst","web404_scan",None], default=None)
    args = ap.parse_args()

    outp = Path(args.out)
    if args.mode == "batch":
        if args.type == "auth":
            lines = generate_auth(args.lines, args.pattern)
        else:
            lines = generate_access(args.lines, args.pattern)
        write_lines(outp, lines, mode="w", delay=0.0)
        print(f"Wrote {len(lines)} lines to {outp}")
    else:
        # stream: append slower (useful for tailing)
        if args.type == "auth":
            gen = lambda n=args.lines: generate_auth(1, args.pattern)  # produce single-line generator repeated
        else:
            gen = lambda n=args.lines: generate_access(1, args.pattern)
        # we will stream 'lines' times calling generator of single lines
        path = outp
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            for i in range(args.lines):
                if args.type == "auth":
                    l = generate_auth(1, args.pattern)[0]
                else:
                    l = generate_access(1, args.pattern)[0]
                f.write(l)
                f.flush()
                time.sleep(args.delay)
        print(f"Streamed {args.lines} lines to {outp}")

if __name__ == "__main__":
    main()
