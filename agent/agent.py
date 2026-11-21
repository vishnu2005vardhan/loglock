"""SakshyaLog Seal Agent — runs on the server being protected.

Tails a log file, seals each new line (sequence number + hash chain +
forward-secure MAC), ships it to the vault within ~1 s, and sends a
heartbeat every few seconds so the vault notices if logging is killed.

Run:  python -m agent.agent --log demo/logs/auth.log
"""
import argparse
import hashlib
import os
import socket
import threading
import time
from datetime import datetime, timezone

import requests

from agent.keystore import load_key0
from common import GENESIS, HEAL_MARKER, entry_hash, is_restored, mac, next_key, panic_reason, redact

VAULT = os.getenv("VAULT_URL", "http://localhost:8000")
KEY0_HEX = os.getenv("SEAL_KEY0", "11" * 32)  # demo only — set a real secret!
EPOCH_SECONDS = int(os.getenv("EPOCH_SECONDS", "60"))
HEARTBEAT_SECONDS = int(os.getenv("HEARTBEAT_SECONDS", "5"))
HOST = os.getenv("HOST_ID", socket.gethostname())
SELF_HEAL = os.getenv("SELF_HEAL", "1") != "0"
HEAL_SECONDS = int(os.getenv("HEAL_SECONDS", "5"))
MONITOR = os.getenv("LIVE_MONITOR", "1") != "0"
# 2.0 ⑥ the sealing key is kept in the OS key store / HSM, not in plain text
KEY0, CUSTODY = load_key0(HOST, KEY0_HEX)


class Sealer:
    def __init__(self):
        self.seq = 0
        self.prev = GENESIS
        self.epoch = 0
        self._key = KEY0  # key_0 handed to vault at setup, kept sealed at rest (keystore.py)
        self.epoch_started = time.time()
        self.lock = threading.Lock()

    def _maybe_ratchet(self):
        while time.time() - self.epoch_started >= EPOCH_SECONDS:
            self._key = next_key(self._key)  # old key is overwritten = destroyed
            self.epoch += 1
            self.epoch_started += EPOCH_SECONDS

    def seal(self, line: str) -> dict:
        with self.lock:
            self._maybe_ratchet()
            self.seq += 1
            ts = datetime.now(timezone.utc).isoformat()
            # ⭐6 personal data is replaced by salted-hash tokens BEFORE sealing
            sealed_line, reveals = redact(line)
            h = entry_hash(self.seq, ts, HOST, sealed_line, self.prev)
            e = {"seq": self.seq, "ts": ts, "host": HOST, "line": sealed_line,
                 "prev_hash": self.prev, "hash": h,
                 "epoch": self.epoch, "mac": mac(self._key, h),
                 "pii": reveals}  # sent to the vault's private store, NOT hashed/anchored
            self.prev = h
            return e


def resume_state(sealer: Sealer) -> bool:
    """Continue the chain where the vault last saw it (agent restart).
    Returns True if resuming, so we only seal lines written from now on."""
    try:
        st = requests.get(f"{VAULT}/head/{HOST}", timeout=3).json()
        if st.get("seq"):
            sealer.seq, sealer.prev, sealer.epoch = st["seq"], st["hash"], st.get("epoch", 0)
            sealer._key = KEY0
            for _ in range(sealer.epoch):
                sealer._key = next_key(sealer._key)
            print(f"[agent] resuming chain at seq {sealer.seq}")
            return True
    except requests.RequestException:
        pass
    return False


def attest(sealer):
    """Agent attestation: report the hash of this agent's own code (and a
    commitment to its current key) so the vault records it on the blockchain."""
    here = os.path.dirname(os.path.abspath(__file__))
    code = b""
    for f in (os.path.join(here, "agent.py"), os.path.join(here, "keystore.py"), os.path.join(here, "..", "common.py")):
        with open(f, "rb") as fh:
            code += fh.read().replace(b"\r\n", b"\n")  # same hash on Windows and Linux
    body = {"host": HOST, "code_hash": hashlib.sha256(code).hexdigest(),
            "key_commit": hashlib.sha256(b"sakshya-key-commit" + sealer._key).hexdigest(), "epoch": sealer.epoch,
            "custody": CUSTODY}
    try:
        r = requests.post(f"{VAULT}/attest", json=body, timeout=180).json()
        print(f"[agent] code hash {body['code_hash'][:16]}... attested on-chain {'(CHANGED!)' if r.get('changed') else ''}")
    except requests.RequestException as ex:
        print("[agent] attestation failed:", ex)


def heal_loop(path):
    """⭐8 Self-healing: every few seconds, ask the vault which sealed lines are
    missing or changed in this log, and put the originals back, clearly marked
    as restored and carrying their blockchain proof reference."""
    while True:
        time.sleep(HEAL_SECONDS)
        try:
            with open(path, errors="replace") as f:
                text = f.read()
            plan = requests.post(f"{VAULT}/heal-plan", json={"host": HOST, "text": text}, timeout=60).json()
            items = plan.get("restore", [])
            if not items:
                continue
            with open(path, "a") as f:
                for it in items:
                    proof = f"root {it['root'][:16]} tx {it['tx'][:18]}" if it.get("root") else "anchor pending"
                    f.write(f"{HEAL_MARKER} seq={it['seq']} {it['status'].lower()} sealed={it['ts'][:19]} "
                            f"proof={proof}] {it['original']}\n")
            requests.post(f"{VAULT}/self-healed", json={"host": HOST, "items": items}, timeout=30)
            print(f"[agent] SELF-HEALED {len(items)} line(s): " + ", ".join(f"#{i['seq']}" for i in items))
        except (requests.RequestException, OSError, ValueError) as ex:
            print("[agent] self-heal check failed:", ex)


def heartbeat_loop():
    while True:
        try:
            requests.post(f"{VAULT}/heartbeat", json={"host": HOST}, timeout=3)
        except requests.RequestException:
            pass
        time.sleep(HEARTBEAT_SECONDS)


POS = {"pos": None, "last": b""}  # where the agent has read up to (saved so a restart can catch up)


def _pos_file():
    return os.path.join("data", "run", f"{HOST}.agentpos")


def save_pos():
    try:
        with open(_pos_file(), "w") as f:
            f.write(f"{POS['pos']} {POS['last'].hex()}")
    except (OSError, TypeError):
        pass


def saved_pos(path):
    """Offset to resume from if the file still holds the same line at that place, else None."""
    try:
        pos, last = open(_pos_file()).read().split()
        pos, last = int(pos), bytes.fromhex(last)
        with open(path, "rb") as f:
            f.seek(pos - len(last))
            return (pos, last) if pos >= len(last) and f.read(len(last)) == last else None
    except (OSError, ValueError):
        return None


def follow(path: str, from_end: bool = False):
    """Yield new lines (or None when idle). Survives the file being replaced,
    e.g. an attacker running `sed -i` creates a new inode.
    2.0: before taking a new line, check that the line read just before it is still in
    place. If an attacker inserted or edited lines above, the content has shifted: the
    agent reports it and resyncs, instead of sealing a shifted fragment as a new line."""
    while not os.path.exists(path):
        time.sleep(0.5)
    f = open(path, "rb")
    last = b""
    resume = saved_pos(path) if from_end else None
    if resume:  # restart after a crash/kill: seal what was written while the agent was down
        f.seek(resume[0])
        last = resume[1]
        print(f"[agent] catching up from byte {resume[0]} (lines written while the agent was down)")
    elif from_end or os.getenv("FROM_END"):
        f.seek(0, os.SEEK_END)
    ino = os.fstat(f.fileno()).st_ino
    while True:
        pos = f.tell()
        raw = f.readline()
        if raw:
            if not raw.endswith(b"\n"):      # a line still being written: wait for the rest
                f.seek(pos)
                yield None
                time.sleep(0.2)
                continue
            if last and pos >= len(last):
                f.seek(pos - len(last))
                before = f.read(len(last))
                f.seek(pos + len(raw))
                if before != last:
                    print("[agent] existing lines changed above the read position — resyncing")
                    yield {"tamper": "existing log lines were edited or inserted (content shifted)"}
                    f.seek(0, os.SEEK_END)
                    last = b""
                    continue
            last = raw
            POS["pos"], POS["last"] = pos + len(raw), raw
            yield raw.decode("utf-8", "replace").rstrip("\r\n")
            continue
        yield None
        time.sleep(0.2)
        try:
            st = os.stat(path)
        except FileNotFoundError:
            continue
        if st.st_ino != ino or st.st_size < f.tell():
            # File was replaced/truncated: keep sealing NEW lines only.
            # (The old content is already safe in the vault.)
            print("[agent] log file replaced or truncated — reattaching")
            yield {"tamper": "log file truncated or replaced on disk"}
            f.close()
            f = open(path, "rb")
            f.seek(0, os.SEEK_END)
            ino = os.fstat(f.fileno()).st_ino
            last = b""


def monitor_loop(path):
    """2.0 ③ Real-time tamper monitor: watch the file itself. Appending is normal logging;
    any change to EXISTING content (delete, edit, insert, one changed character) is
    reported to the vault within about a second, with the line number."""
    prev = None
    while True:
        time.sleep(0.7)
        try:
            data = open(path, "rb").read()
            changed_at = os.stat(path).st_mtime
        except OSError:
            continue
        if prev is None or data == prev or (len(data) >= len(prev) and data[:len(prev)] == prev):
            prev = data
            continue
        old, new = prev.split(b"\n"), data.split(b"\n")
        i = next((k for k, (a, b) in enumerate(zip(old, new)) if a != b), min(len(old), len(new)))
        shown = redact(old[i].decode("utf-8", "replace").strip())[0][:70] if i < len(old) else ""  # no PII in alerts
        if len(new) < len(old):
            kind, detail = "delete", f"{len(old) - len(new)} line(s) deleted at line {i + 1}: {shown}"
        elif len(new) > len(old):
            kind, detail = "insert", f"{len(new) - len(old)} line(s) inserted at line {i + 1}"
        else:
            kind, detail = "edit", f"line {i + 1} edited in place: {shown}"
        try:
            requests.post(f"{VAULT}/tamper-signal", json={"host": HOST, "kind": kind, "detail": detail,
                                                         "line_no": i + 1, "changed_at": changed_at}, timeout=5)
            print(f"[agent] LIVE TAMPER: {detail}")
        except requests.RequestException:
            pass
        prev = data


# ---- ⭐3 Panic anchor -------------------------------------------------------
# Commands that destroy evidence. sudo / auditd write the command line to the
# log BEFORE it runs, so the agent sees it first, ships it, and asks the vault
# for an immediate out-of-cycle blockchain anchor.
# (patterns live in common.py so the vault's timeline uses the same rules)


def flush(buf):
    try:
        r = requests.post(f"{VAULT}/ingest", json=buf, timeout=5)
        r.raise_for_status()
        return []
    except requests.RequestException as ex:
        print("[agent] vault unreachable, will retry:", ex)
        return buf


def panic(sealer, reason, line, buf):
    """Ship everything NOW, then ask the vault to anchor on-chain immediately."""
    buf = flush(buf)
    try:
        r = requests.post(f"{VAULT}/panic", json={"host": HOST, "seq": sealer.seq,
                                                   "trigger": reason, "line": line}, timeout=10)
        print(f"[agent] PANIC ANCHOR requested ({reason})")
    except requests.RequestException as ex:
        print("[agent] panic anchor failed:", ex)
    return buf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="demo/logs/auth.log")
    args = ap.parse_args()

    sealer = Sealer()
    resuming = resume_state(sealer)
    attest(sealer)
    threading.Thread(target=heartbeat_loop, daemon=True).start()
    if SELF_HEAL:
        threading.Thread(target=heal_loop, args=(args.log,), daemon=True).start()
    if MONITOR:
        threading.Thread(target=monitor_loop, args=(args.log,), daemon=True).start()
    print(f"[agent] sealing key custody: {CUSTODY['label']}")

    buf, last_send = [], time.time()
    print(f"[agent] sealing {args.log} as host={HOST} -> {VAULT}")
    for item in follow(args.log, from_end=resuming):
        if isinstance(item, dict):                      # file tampered on disk
            buf = panic(sealer, item["tamper"], "", buf)
            last_send = time.time()
            continue
        if item and item.strip():
            buf.append(sealer.seal(item))
            reason = None if is_restored(item) else panic_reason(item)
            if reason:                                  # evidence-destroying command seen
                buf = panic(sealer, reason, item, buf)
                last_send = time.time()
                continue
        if buf and (time.time() - last_send > 0.5 or len(buf) >= 50):
            buf = flush(buf)
            last_send = time.time()
            if not buf:
                save_pos()


if __name__ == "__main__":
    main()
