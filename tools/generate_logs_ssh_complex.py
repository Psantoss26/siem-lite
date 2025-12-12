#!/usr/bin/env python3
# generate_logs_ssh_complex.py
# Generador avanzado de logs SSH variados y con escenarios (brute, spray, éxito, post-compromise).
from __future__ import annotations
import argparse
import random
import time
import datetime as dt
from pathlib import Path
from typing import List

MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]

def syslog_time(ts: dt.datetime):
    return f"{MONTHS[ts.month-1]} {ts.day} {ts.strftime('%H:%M:%S')}"

# SSH patterns
def ssh_failed(ts, host, user, ip, port, pid):
    return f"{syslog_time(ts)} {host} sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2\n"

def ssh_invalid_user(ts, host, user, ip, port, pid):
    return f"{syslog_time(ts)} {host} sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2\n"

def ssh_accepted(ts, host, user, ip, port, pid):
    return f"{syslog_time(ts)} {host} sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2\n"

def ssh_disconnect(ts, host, reason, user, ip, port, pid):
    # normalized to include reason and user/ip for clarity
    return f"{syslog_time(ts)} {host} sshd[{pid}]: {reason} for {user} from {ip} port {port}\n"

def ssh_session_open(ts, host, user, pid):
    return f"{syslog_time(ts)} {host} sshd[{pid}]: pam_unix(sshd:session): session opened for user {user} by (uid=0)\n"

def ssh_session_close(ts, host, user, pid):
    return f"{syslog_time(ts)} {host} sshd[{pid}]: pam_unix(sshd:session): session closed for user {user}\n"

def ssh_keyboard_interactive(ts, host, user, ip, port, pid):
    return f"{syslog_time(ts)} {host} sshd[{pid}]: keyboard-interactive for {user} from {ip} port {port}\n"

def sudo_use(ts, host, user):
    return f"{syslog_time(ts)} {host} sudo:   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/ls\n"

# sequences
def attacker_bruteforce_sequence(start_ts, host, attacker_ip, users, pid_start, attempts=8, spacing=1.0):
    lines=[]
    pid = pid_start
    ts = start_ts
    port = random.randint(20000,60000)
    for i in range(attempts):
        u = random.choice(users)
        # more invalid user early if spray-like
        if random.random() < 0.15:
            lines.append(ssh_invalid_user(ts, host, u, attacker_ip, port+i, pid))
        else:
            lines.append(ssh_failed(ts, host, u, attacker_ip, port+i, pid))
        ts += dt.timedelta(seconds=random.uniform(0.2, spacing*1.5))
    # sometimes success after several failures
    if random.random() < 0.2:
        success_user = random.choice(users)
        lines.append(ssh_accepted(ts, host, success_user, attacker_ip, port+999, pid))
        ts += dt.timedelta(seconds=0.5)
        lines.append(ssh_session_open(ts, host, success_user, pid))
        # post compromise actions: sudo occasionally
        if random.random() < 0.6:
            ts += dt.timedelta(seconds=1.0)
            lines.append(sudo_use(ts, host, success_user))
        ts += dt.timedelta(seconds=random.uniform(1,3))
        lines.append(ssh_session_close(ts, host, success_user, pid))
    else:
        # disconnect with some reason text
        ts += dt.timedelta(seconds=0.5)
        lines.append(ssh_disconnect(ts, host, "Disconnected", "unknown", attacker_ip, port, pid))
    return lines

def password_spray_sequence(start_ts, host, attacker_ip, users, pid_start, attempts=6, spacing=30.0):
    # low-rate spray: same password across many users with large spacing -> avoids brute thresholds
    lines=[]
    pid = pid_start
    ts = start_ts
    port = random.randint(20000,60000)
    sample_users = users[:attempts] if len(users) >= attempts else users
    for u in sample_users:
        lines.append(ssh_failed(ts, host, u, attacker_ip, port+random.randint(1,1000), pid))
        ts += dt.timedelta(seconds=random.uniform(spacing*0.8, spacing*1.2))
    return lines

def legitimate_user_activity(start_ts, host, client_ip, users, pid_start):
    lines=[]
    ts = start_ts
    pid = pid_start
    u = random.choice(users)
    if random.random() < 0.85:
        lines.append(ssh_accepted(ts, host, u, client_ip, random.randint(1024,65535), pid))
        ts += dt.timedelta(seconds=0.4)
        lines.append(ssh_session_open(ts, host, u, pid))
        # maybe sudo
        if random.random() < 0.2:
            ts += dt.timedelta(seconds=1.0)
            lines.append(sudo_use(ts, host, u))
        ts += dt.timedelta(seconds=random.uniform(0.5,4.0))
        lines.append(ssh_session_close(ts, host, u, pid))
    else:
        # failed attempt from client
        lines.append(ssh_failed(ts, host, random.choice(users), client_ip, random.randint(1024,65535), pid))
    return lines

def generate_ssh_complex(out_path: Path, lines:int=1000, delay:float=0.02,
                         attacker_count:int=3, client_count:int=30,
                         attack_prob:float=0.15, spray_prob:float=0.25):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.utcnow()
    attackers = [f"198.51.100.{i+2}" for i in range(attacker_count)]
    clients = [f"203.0.113.{(i%250)+2}" for i in range(client_count)]
    users = ["alice","bob","carol","dave","eve","frank","pablo","user1","user2","svc-acct"]
    pid = 1000
    ts = now
    with open(out_path, "w", encoding="utf-8") as f:
        i = 0
        while i < lines:
            r = random.random()
            # choose scenario
            if r < attack_prob:
                attacker = random.choice(attackers)
                if random.random() < spray_prob:
                    seq = password_spray_sequence(ts, "myhost", attacker, random.sample(users, min(10,len(users))), pid, attempts=8, spacing=25.0)
                else:
                    seq = attacker_bruteforce_sequence(ts, "myhost", attacker, users, pid, attempts=random.randint(4,12), spacing=random.uniform(0.3,2.0))
                for l in seq:
                    f.write(l)
                    i += 1
                    ts += dt.timedelta(seconds=random.uniform(0.1,1.2))
                    if i >= lines: break
            else:
                client = random.choice(clients)
                seq = legitimate_user_activity(ts, "myhost", client, users, pid)
                for l in seq:
                    f.write(l)
                    i += 1
                    ts += dt.timedelta(seconds=random.uniform(0.2,3.0))
                    if i >= lines: break
            # occasionally insert random noise (disconnects, keyboard-interactive)
            if random.random() < 0.1 and i < lines:
                f.write(ssh_keyboard_interactive(ts, "myhost", random.choice(users), random.choice(clients), random.randint(20000,60000), pid))
                i += 1
                ts += dt.timedelta(seconds=0.2)
            # increment pid sometimes
            if random.random() < 0.2:
                pid += 1
    return out_path

def stream_mode(out_path: Path, **kwargs):
    # streaming: generate a temp full set and append it gradually
    out_path.parent.mkdir(parents=True, exist_ok=True)
    total = kwargs.get("lines", 500)
    delay = kwargs.get("delay", 0.02)
    attacker_count = kwargs.get("attacker_count", 3)
    client_count = kwargs.get("client_count", 30)
    attack_prob = kwargs.get("attack_prob", 0.15)
    spray_prob = kwargs.get("spray_prob", 0.25)

    tmp = out_path.with_suffix(".tmp")
    generate_ssh_complex(tmp, lines=total, delay=delay,
                         attacker_count=attacker_count, client_count=client_count,
                         attack_prob=attack_prob, spray_prob=spray_prob)
    with open(tmp, "r", encoding="utf-8") as src:
        lines_all = src.readlines()

    # truncate target and stream in small chunks
    with open(out_path, "w", encoding="utf-8") as f:
        f.truncate(0)

    idx = 0
    # chunking: write a few lines then sleep
    chunk_size = max(1, int(max(1, total // 20)))
    while idx < len(lines_all):
        chunk = lines_all[idx: idx + chunk_size]
        # append chunk
        with open(out_path, "a", encoding="utf-8") as f:
            f.writelines(chunk)
            f.flush()
        idx += len(chunk)
        time.sleep(delay)
    # remove tmp
    try:
        tmp.unlink()
    except Exception:
        pass
    return out_path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["batch","stream"], default="batch")
    ap.add_argument("--out", required=True)
    ap.add_argument("--lines", type=int, default=800)
    ap.add_argument("--delay", type=float, default=0.03)
    ap.add_argument("--attacker-count", type=int, default=3)
    ap.add_argument("--client-count", type=int, default=40)
    ap.add_argument("--attack-prob", type=float, default=0.18)
    ap.add_argument("--spray-prob", type=float, default=0.25)
    args = ap.parse_args()
    outp = Path(args.out)
    if args.mode == "batch":
        generate_ssh_complex(outp, lines=args.lines, delay=args.delay,
                             attacker_count=args.attacker_count, client_count=args.client_count,
                             attack_prob=args.attack_prob, spray_prob=args.spray_prob)
        print(f"Wrote {args.lines} lines to {outp}")
    else:
        stream_mode(outp, lines=args.lines, delay=args.delay,
                    attacker_count=args.attacker_count, client_count=args.client_count,
                    attack_prob=args.attack_prob, spray_prob=args.spray_prob)
        print(f"Streamed {args.lines} lines to {outp}")

if __name__ == "__main__":
    main()
