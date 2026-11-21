"""SakshyaLog live demo: the "hacker" script (works on Windows CMD, Mac, Linux).

    python demo/attack.py               # break in, steal, wipe the evidence
    python demo/attack.py --kill-agent  # also kill the logging agent (tests the heartbeat)

Simulates an attacker who gained root, stole data, and wipes the evidence.
"""
import os
import signal
import sys
import time
from datetime import datetime

args = [a for a in sys.argv[1:] if not a.startswith("--")]
LOG = args[0] if args else "demo/logs/auth.log"
KILL_AGENT = "--kill-agent" in sys.argv
IP = "45.33.32.156"


def ts():
    return datetime.now().strftime("%b %d %H:%M:%S")


def append(line):
    with open(LOG, "a") as f:
        f.write(f"{ts()} server-01 {line}\n")


def step(msg, pause):
    print(msg)
    time.sleep(pause)


print("=" * 60 + "\n  ATTACKER TERMINAL\n" + "=" * 60)
step(f"[attacker] Guessing the root password from {IP} ...", 0)
for i, pw_port in enumerate((40112, 40113, 40114, 40115)):
    append(f"sshd[6650{i}]: Failed password for root from {IP} port {pw_port} ssh2")
    time.sleep(0.6)
step(f"[attacker] Logging in as root from {IP} ...", 0)
append(f"sshd[66601]: Accepted password for root from {IP} port 51515 ssh2")
time.sleep(2)

step("[attacker] Stealing the customer database ...", 0)
append(f"sudo: root : TTY=pts/3 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/scp /var/db/customers.sql {IP}:/tmp/")
time.sleep(3)  # ⭐1 remote witness: both lines are already in the vault

# sudo/auditd record the command line BEFORE it executes -> ⭐3 panic anchor fires
step("[attacker] Running: sed -i '/45.33.32.156/d' /var/log/auth.log", 0)
append(f"sudo: root : TTY=pts/3 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/sed -i /{IP}/d /var/log/auth.log")
time.sleep(1.5)

with open(LOG) as f:
    kept = [l for l in f if IP not in l]
with open(LOG, "w") as f:
    f.writelines(kept)
step("[attacker] Evidence erased from the server log.", 1)

step("[attacker] Planting a fake line to blame an employee ...", 0)
append("sudo: rahul : TTY=pts/1 ; PWD=/home/rahul ; USER=root ; COMMAND=/usr/bin/cp /var/db/customers.sql /mnt/usb/")

if KILL_AGENT:
    pid_file = os.path.join("data", "run", "agent.pid")
    try:
        pid = int(open(pid_file).read())
        os.kill(pid, signal.SIGTERM)
        print(f"[attacker] Killed the logging agent (pid {pid}). Nobody is watching now...")
    except (OSError, ValueError) as ex:
        print(f"[attacker] Could not kill agent ({ex}). Is run_demo.py running?")

with open(LOG) as f:
    hits = sum(IP in l for l in f)
print(f"\n[attacker] Lines on the server mentioning my IP: {hits}")
print("[attacker] Clean, right? Now look at the SakshyaLog dashboard...")
