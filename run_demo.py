"""SakshyaLog one-click launcher (Windows / Mac / Linux).

Starts the vault, the victim server (log generator + seal agent) and the
dashboard, then opens the browser. Press Ctrl+C to stop everything.

    python run_demo.py           # start (keeps old data)
    python run_demo.py --reset   # wipe data first, start fresh
    python run_demo.py --reset --quai   # anchor on Quai Network Orchard (after quai/ deploy)
"""
import os
from collections import defaultdict
import shutil
import subprocess
import sys
import time
import urllib.request
import webbrowser

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
PY = sys.executable
VAULT_PORT, DASH_PORT = 8000, 8501

def load_dotenv(path=".env"):
    """Settings from tools/deploy_contract.py (real chain). Shell variables win."""
    vals = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.strip().split("=", 1)
                vals[k.strip()] = v.strip()
    return vals


ENV = {**load_dotenv(), **os.environ}
ENV.update({
    "PYTHONUNBUFFERED": "1",
    "PYTHONIOENCODING": "utf-8",
    "PYTHONPATH": ROOT,
    "HOST_ID": "server-01",
    "AUDIT_HOST": "server-01",
    "AUDIT_LOG_PATH": os.path.join("demo", "logs", "auth.log"),
    # evidence sources the vault audits: the server log and the UPI case file (use case)
    "AUDIT_TARGETS": "server-01=" + os.path.join("demo", "logs", "auth.log") +
                     ";server-02=" + os.path.join("demo", "logs", "server02.log") +
                     ";case-UPI-001=" + os.path.join("demo", "logs", "case_upi001.log"),
    "LAB_ENABLED": "1",  # 2.0 attack lab (demo logs only)
    "ANCHOR_SECONDS": ENV.get("ANCHOR_SECONDS", "20"),
    "CHAIN_HEARTBEAT_SECONDS": ENV.get("CHAIN_HEARTBEAT_SECONDS", "30"),
    "CHAIN_MODE": ENV.get("CHAIN_MODE", "evm"),
    "VAULT_URL": f"http://127.0.0.1:{VAULT_PORT}",
})


def wait_for(url, seconds=40):
    for _ in range(seconds * 2):
        try:
            urllib.request.urlopen(url, timeout=1)
            return True
        except Exception:
            time.sleep(0.5)
    return False


def main():
    if "--reset" in sys.argv:
        for d in ("data", os.path.join("demo", "logs")):
            shutil.rmtree(d, ignore_errors=True)
        print("[run] old data wiped")
    os.makedirs("data/run", exist_ok=True)
    os.makedirs("demo/logs", exist_ok=True)

    procs = []

    specs = {}

    def start(name, args, extra_env=None, cmd=None):
        log = open(f"data/run/{name}.log", "a", encoding="utf-8")
        proc = subprocess.Popen([*(cmd or [PY]), *args], env={**ENV, **(extra_env or {})}, stdout=log, stderr=subprocess.STDOUT)
        specs[name] = (args, extra_env, cmd)
        procs[:] = [(n, p) for n, p in procs if n != name]
        procs.append((name, proc))
        with open(f"data/run/{name}.pid", "w") as pf:
            pf.write(str(proc.pid))
        print(f"[run] started {name:<10} (log: data/run/{name}.log)")

    if "--quai" in sys.argv:
        ENV["CHAIN_MODE"] = "quai"
    if ENV.get("CHAIN_MODE") == "quai" and ENV.get("QUAI_BRIDGE_EXTERNAL"):
        ENV.setdefault("QUAI_BRIDGE_URL", "http://127.0.0.1:8600")  # bridge already running elsewhere
        if not wait_for(ENV["QUAI_BRIDGE_URL"] + "/info", seconds=30):
            print("[run] ERROR: external Quai bridge not reachable at " + ENV["QUAI_BRIDGE_URL"])
            return
    elif ENV.get("CHAIN_MODE") == "quai":
        if not os.path.exists(os.path.join("quai", "deployments", "orchard-cyprus1.json")):
            print("[run] ERROR: no Quai deployment yet. Follow QUAI.md (new-wallet, faucet, preflight, deploy).")
            return
        node = shutil.which("node")
        if not node:
            print("[run] ERROR: Node.js is needed for Quai (the quais SDK). Install it from nodejs.org.")
            return
        ENV["QUAI_BRIDGE_URL"] = "http://127.0.0.1:8600"
        log = open("data/run/quai-bridge.log", "a", encoding="utf-8")
        bridge = subprocess.Popen([node, os.path.join("quai", "scripts", "bridge.js")], env=ENV,
                                  stdout=log, stderr=subprocess.STDOUT)
        procs.append(("quai-bridge", bridge))
        specs["quai-bridge"] = None
        print("[run] started quai-bridge (log: data/run/quai-bridge.log)")
        if not wait_for("http://127.0.0.1:8600/info", seconds=60):
            print("[run] ERROR: Quai bridge could not reach Orchard. See data/run/quai-bridge.log "
                  "and run:  cd quai && npm run preflight")
            return stop(procs)

    start("vault", ["-m", "uvicorn", "vault.api:app", "--host", "127.0.0.1", "--port", str(VAULT_PORT)])
    if not wait_for(f"http://127.0.0.1:{VAULT_PORT}/status", seconds=90):
        print("[run] ERROR: vault did not start. See data/run/vault.log")
        return stop(procs)
    try:
        import json
        info = json.load(urllib.request.urlopen(f"http://127.0.0.1:{VAULT_PORT}/status"))["chain_info"]
        print(f"[run] blockchain: {info['name']}" + (f", contract {info['contract']}" if info.get("contract") else ""))
        if info.get("simulated"):
            print("[run] WARNING: using the SIMULATED offline ledger. For a real chain run:"
                  "\n[run]          python -m pip install -r requirements-blockchain.txt")
    except Exception:
        pass
    start("generator", ["demo/log_generator.py", "--log", "demo/logs/auth.log"])
    start("agent", ["-m", "agent.agent", "--log", "demo/logs/auth.log"])
    # use case: a UPI fraud case file, sealed as a second evidence stream on the same vault + contract
    start("case-writer", ["demo/upi_case.py", "--log", "demo/logs/case_upi001.log"])
    start("case-agent", ["-m", "agent.agent", "--log", "demo/logs/case_upi001.log"], {"HOST_ID": "case-UPI-001"})
    # 2.0 ⑤ a second server, protected by its own agent, feeding the same vault and contract
    start("generator-2", ["demo/log_generator.py", "--log", "demo/logs/server02.log", "--host", "server-02", "--interval", "2.5"])
    start("agent-2", ["-m", "agent.agent", "--log", "demo/logs/server02.log"], {"HOST_ID": "server-02"})
    node = shutil.which("node")
    site = node and os.path.exists(os.path.join("ui", "dist", "index.html"))
    if site:  # the React website, so one window is enough
        start("website", [os.path.join("ui", "serve.cjs")], {"VAULT_URL": f"http://127.0.0.1:{VAULT_PORT}"}, cmd=[node])
    start("dashboard", ["-m", "streamlit", "run", "app/app.py", "--server.port", str(DASH_PORT),
                        "--server.headless", "true"])
    if site and wait_for("http://127.0.0.1:5173", seconds=20):
        webbrowser.open("http://localhost:5173")
    elif wait_for(f"http://127.0.0.1:{DASH_PORT}"):
        webbrowser.open(f"http://localhost:{DASH_PORT}")

    print(f"""
============================================================
  SakshyaLog 2.0 is running
  Website   : http://localhost:5173   (attack lab, fleet, auditor portal)
  Dashboard : http://localhost:{DASH_PORT}   (backup)
  Vault API : http://localhost:{VAULT_PORT}/docs
  Attack    : double-click ATTACK.bat  (or: python demo/attack.py)
  Kill test : double-click ATTACK_KILL_AGENT.bat (attack + kill the logger)
  UPI case  : double-click ATTACK_CASE.bat (insider edits the fraud case file)
  Stop      : press Ctrl+C in this window
============================================================""")
    dead, restarts = {}, defaultdict(int)
    try:
        while True:
            time.sleep(2)
            for name, p in list(procs):
                if p.poll() is not None and name not in dead:
                    dead[name] = time.time()
                    if name in ("agent", "case-agent", "agent-2"):
                        print(f"[run] ⚠️  {name} was killed. The vault's heartbeat alarm will fire in ~20 s (⭐2)."
                              "\n[run]    The supervisor restarts it in 30 s, like systemd would.")
                    elif name == "vault":
                        print("[run] vault stopped unexpectedly. See data/run/vault.log")
                        return stop(procs)
                    else:
                        print(f"[run] {name} stopped. See data/run/{name}.log (restarting it)")
            for name, t in list(dead.items()):  # supervisor: bring stopped helpers back
                wait = 30 if name.startswith(("agent", "case-agent")) else 3
                if time.time() - t >= wait and name in specs and restarts[name] < 20:
                    restarts[name] += 1
                    del dead[name]
                    if name == "quai-bridge":
                        procs[:] = [(n, q) for n, q in procs if n != name]
                        log = open("data/run/quai-bridge.log", "a", encoding="utf-8")
                        procs.append((name, subprocess.Popen([shutil.which("node"), os.path.join("quai", "scripts", "bridge.js")],
                                                             env=ENV, stdout=log, stderr=subprocess.STDOUT)))
                    else:
                        start(name, *specs[name])
                    print(f"[run] restarted {name}")
    except KeyboardInterrupt:
        pass
    stop(procs)


def stop(procs):
    print("\n[run] stopping...")
    for _, p in procs:
        if p.poll() is None:
            p.terminate()
    for _, p in procs:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
    print("[run] all stopped")


if __name__ == "__main__":
    main()
