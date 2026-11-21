"""Writes realistic-looking auth/sys log lines to a file (the 'victim server').

Run:  python demo/log_generator.py --log demo/logs/auth.log
"""
import argparse
import os
import random
import time
from datetime import datetime

USERS = ["rahul", "priya", "deploy", "backup", "anita"]
IPS = ["10.0.1.12", "10.0.1.15", "10.0.2.7", "192.168.1.40"]
CUSTOMERS = [("priya.sharma@example.com", "+91 9876543210"), ("arjun.k@example.in", "9123456780"),
             ("meena.r@example.com", "+91-8899001122")]
EVENTS = [  # (weight, template)
    (5, "sshd[{pid}]: Accepted publickey for {u} from {ip} port {port} ssh2"),
    (3, "sudo: {u} : TTY=pts/0 ; PWD=/home/{u} ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"),
    (4, "sshd[{pid}]: Disconnected from user {u} {ip} port {port}"),
    (3, "CRON[{pid}]: (root) CMD (/usr/local/bin/backup.sh)"),
    (1, "sshd[{pid}]: Failed password for {u} from {ip} port {port} ssh2"),
    (4, "systemd[1]: Started Session {pid} of user {u}."),
    (3, "app[2210]: password reset requested by {email} (mobile {phone})"),
    (2, "app[2210]: KYC updated for customer {email}, Aadhaar 4521 7788 {a4}"),
]


HOSTNAME = "server-01"


def line():
    t = datetime.now().strftime("%b %d %H:%M:%S")
    email, phone = random.choice(CUSTOMERS)
    tpl = random.choices([t for _, t in EVENTS], weights=[w for w, _ in EVENTS])[0]
    msg = tpl.format(pid=random.randint(1000, 99999), u=random.choice(USERS), ip=random.choice(IPS),
                     port=random.randint(30000, 65000), email=email, phone=phone,
                     a4=random.randint(1000, 9999))
    return f"{t} {HOSTNAME} {msg}"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="demo/logs/auth.log")
    ap.add_argument("--interval", type=float, default=1.5)
    ap.add_argument("--host", default="server-01")
    a = ap.parse_args()
    HOSTNAME = a.host
    os.makedirs(os.path.dirname(a.log), exist_ok=True)
    print(f"[gen] writing to {a.log}")
    while True:
        with open(a.log, "a") as f:
            f.write(line() + "\n")
        time.sleep(a.interval * random.uniform(0.5, 1.5))
