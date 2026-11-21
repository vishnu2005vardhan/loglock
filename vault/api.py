"""SakshyaLog Vault — the off-host evidence locker.

* Accepts sealed entries from agents and checks every one (sequence, chain,
  hash, forward-secure MAC, PII commitments). Bad entries raise alerts.
* Stores entries append-only (SQLite triggers forbid UPDATE/DELETE — demo
  stand-in for S3 Object Lock / WORM storage, 180-day CERT-In retention).
* ⭐6 Keeps personal data in a separate, erasable store (DPDP Act).
* ⭐7 Adaptive anchoring: Merkle root on-chain every ANCHOR_SECONDS normally,
  every FAST_ANCHOR_SECONDS during suspicious activity, instantly on panic (⭐3).
* Heartbeat watchdog (⭐2), scheduled audit, verification, ⭐5 one-line proofs,
  attack timeline, CERT-In report, retention tracker, court evidence pack.

Run:  uvicorn vault.api:app --port 8000
"""
import difflib
import io
import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
import zipfile
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel

from common import (GENESIS, TOKEN_RE, commit, entry_hash, heal_tag, is_restored, key_for_epoch, mac,
                    merkle_proof, merkle_root, normalize_pii, panic_reason, redact, unredact, verify_proof)
from vault import reports
from vault import v2
from vault.chain import ChainError, get_ledger

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.getenv("VAULT_DB", "data/vault.db")
KEY0 = bytes.fromhex(os.getenv("SEAL_KEY0", "11" * 32))
ANCHOR_SECONDS = int(os.getenv("ANCHOR_SECONDS", "60"))
FAST_ANCHOR_SECONDS = int(os.getenv("FAST_ANCHOR_SECONDS", "2"))
HIGH_ALERT_SECONDS = int(os.getenv("HIGH_ALERT_SECONDS", "180"))
HEARTBEAT_TIMEOUT = int(os.getenv("HEARTBEAT_TIMEOUT", "20"))
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "180"))  # CERT-In
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH")              # e.g. demo/logs/auth.log
AUDIT_HOST = os.getenv("AUDIT_HOST")
# Several evidence sources can be audited: "server-01=demo/logs/auth.log;case-UPI-001=demo/logs/case_upi001.log"
AUDIT_TARGETS = dict(t.split("=", 1) for t in os.getenv("AUDIT_TARGETS", "").split(";") if "=" in t)
if AUDIT_HOST and AUDIT_LOG_PATH:
    AUDIT_TARGETS.setdefault(AUDIT_HOST, AUDIT_LOG_PATH)
CHAIN_HEARTBEAT_SECONDS = int(os.getenv("CHAIN_HEARTBEAT_SECONDS", "60"))

os.makedirs(os.path.dirname(DB) or ".", exist_ok=True)
ledger = get_ledger()
FAST_ANCHOR_SECONDS = max(FAST_ANCHOR_SECONDS, getattr(ledger, "min_fast_interval", 0))
db_lock = threading.Lock()


@asynccontextmanager
async def lifespan(_app):
    threading.Thread(target=anchor_loop, daemon=True).start()
    threading.Thread(target=watchdog_loop, daemon=True).start()
    threading.Thread(target=chain_heartbeat_loop, daemon=True).start()
    threading.Thread(target=chain_reader_loop, daemon=True).start()
    v2.start_siem()
    yield


app = FastAPI(title="SakshyaLog Vault", lifespan=lifespan)


def now():
    return datetime.now(timezone.utc).isoformat()


DBC = sqlite3.connect(DB, check_same_thread=False)
DBC.row_factory = sqlite3.Row
DBC.executescript("""
CREATE TABLE IF NOT EXISTS entries(
  host TEXT, seq INTEGER, ts TEXT, line TEXT, prev_hash TEXT, hash TEXT,
  epoch INTEGER, mac TEXT, received_at TEXT, PRIMARY KEY(host, seq));
CREATE TRIGGER IF NOT EXISTS no_update BEFORE UPDATE ON entries
  BEGIN SELECT RAISE(ABORT, 'WORM: entries are immutable'); END;
CREATE TRIGGER IF NOT EXISTS no_delete BEFORE DELETE ON entries
  BEGIN SELECT RAISE(ABORT, 'WORM: entries cannot be deleted'); END;
CREATE TABLE IF NOT EXISTS pii(
  token TEXT PRIMARY KEY, host TEXT, seq INTEGER, kind TEXT, value TEXT, salt TEXT);
CREATE TABLE IF NOT EXISTS batches(
  id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT, start_seq INTEGER,
  end_seq INTEGER, root TEXT, chain TEXT, tx TEXT, created_at TEXT, mode TEXT, gas INTEGER);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS attestations(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, host TEXT, code_hash TEXT, key_commit TEXT,
  epoch INTEGER, tx TEXT, changed INTEGER);
CREATE TABLE IF NOT EXISTS chain_txs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, host TEXT, kind TEXT, tx TEXT, gas INTEGER);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, host TEXT, kind TEXT,
  detail TEXT, UNIQUE(host, kind, detail));
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, host TEXT, kind TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS heartbeats(host TEXT PRIMARY KEY, last_seen REAL);
CREATE TABLE IF NOT EXISTS heals(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, host TEXT, seq INTEGER, status TEXT,
  original TEXT, root TEXT, tx TEXT);
CREATE TABLE IF NOT EXISTS panics(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, host TEXT, seq INTEGER,
  trigger TEXT, line TEXT, root TEXT, tx TEXT);
CREATE TABLE IF NOT EXISTS incidents(
  id INTEGER PRIMARY KEY AUTOINCREMENT, declared_at TEXT, deadline TEXT,
  host TEXT, note TEXT, snapshot_root TEXT, tx TEXT, chain_id INTEGER,
  reported_at TEXT, report_hash TEXT, report_tx TEXT, on_time INTEGER);
CREATE TABLE IF NOT EXISTS change_requests(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, host TEXT, seq INTEGER, original_line TEXT,
  original_hash TEXT, new_line TEXT, reason TEXT, ticket TEXT, approver TEXT);
CREATE TRIGGER IF NOT EXISTS cr_no_update BEFORE UPDATE ON change_requests
  BEGIN SELECT RAISE(ABORT, 'change records are immutable'); END;
CREATE TABLE IF NOT EXISTS tamper_signals(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, host TEXT, kind TEXT, detail TEXT,
  line_no INTEGER, latency_ms INTEGER);
CREATE TABLE IF NOT EXISTS lab_runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, started REAL, host TEXT, scenario TEXT,
  seq INTEGER, before TEXT, after TEXT, note TEXT);
""")
DBC.execute("INSERT OR IGNORE INTO meta VALUES('instance', ?)", (os.urandom(4).hex(),))
DBC.commit()
INSTANCE = DBC.execute("SELECT v FROM meta WHERE k='instance'").fetchone()[0]


def stream(host):
    """On-chain stream name. A fresh vault (demo reset) starts a fresh stream,
    so the contract's continuity rule starts again at line 1."""
    return f"{host}@{INSTANCE}"


def chain_tx(host, kind, tx, gas):
    q("INSERT INTO chain_txs(ts,host,kind,tx,gas) VALUES(?,?,?,?,?)", (now(), host, kind, tx, gas))


def q(sql, args=(), one=False):
    with db_lock:
        rows = DBC.execute(sql, args).fetchall()
        DBC.commit()
    return (rows[0] if rows else None) if one else rows


def alert(host, kind, detail):
    ts = now()
    with db_lock:
        cur = DBC.execute("INSERT OR IGNORE INTO alerts(ts,host,kind,detail) VALUES(?,?,?,?)", (ts, host, kind, detail))
        DBC.commit()
    if cur.rowcount:  # 2.0: every new alert also goes to the SIEM feed
        v2.siem_publish({"id": cur.lastrowid, "ts": ts, "host": host, "kind": kind, "detail": detail})


def event(host, kind, detail):
    q("INSERT INTO events(ts,host,kind,detail) VALUES(?,?,?,?)", (now(), host, kind, detail))


def head(host):
    r = q("SELECT seq, hash, epoch FROM entries WHERE host=? ORDER BY seq DESC LIMIT 1", (host,), one=True)
    return dict(r) if r else {"seq": 0, "hash": GENESIS, "epoch": 0}


def is_external(ip):
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ------------------------------------------------- ⭐7 adaptive anchoring ----
RX_FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
RX_ACCEPT = re.compile(r"Accepted (\w+) for (\S+) from (\S+)")
RX_SUDO = re.compile(r"sudo: +(\S+) : .*USER=root ; COMMAND=(.*)")
RX_EXFIL = re.compile(r"\b(scp|rsync|curl|wget|nc|ftp)\b.*|.*\.(sql|dump|bak)\b.*/(mnt|media|tmp)/|/mnt/usb", re.I)
high_until, high_reason = defaultdict(float), {}
key_custody = {}      # 2.0 ⑥ host -> how the agent's sealing key is stored
last_verdict = {}     # 2.0 ⑤ host -> latest automatic check (for the fleet view)
failed = defaultdict(deque)


def suspicion(host, line):
    """Return a reason if this line is suspicious enough to switch to HIGH ALERT anchoring."""
    if is_restored(line):  # a line SakshyaLog put back is not a new attack
        return None
    if (m := RX_FAILED.search(line)):
        dq = failed[(host, m.group(2))]
        dq.append(time.time())
        while dq and time.time() - dq[0] > 60:
            dq.popleft()
        if len(dq) >= 3:
            return f"{len(dq)} failed logins from {m.group(2)} in 60 s (brute force)"
    if (m := RX_ACCEPT.search(line)) and (m.group(2) == "root" or is_external(m.group(3))):
        return f"login as {m.group(2)} from {m.group(3)}"
    if (m := RX_SUDO.search(line)) and (m.group(1) == "root" or RX_EXFIL.search(m.group(2))):
        return f"command as root: {m.group(2)[:60]}"
    if (why := panic_reason(line)):
        return why
    return None


def raise_alert_level(host, reason):
    if time.time() > high_until[host]:
        event(host, "high-alert", f"Adaptive anchoring: HIGH ALERT, anchoring every {FAST_ANCHOR_SECONDS} s ({reason})")
    high_until[host] = time.time() + HIGH_ALERT_SECONDS
    high_reason[host] = reason


def is_high(host):
    return time.time() < high_until[host]


# ---------------------------------------------------------------- ingest ----
class Entry(BaseModel):
    seq: int
    ts: str
    host: str
    line: str
    prev_hash: str
    hash: str
    epoch: int
    mac: str
    pii: list[dict] = []


@app.post("/ingest")
def ingest(entries: list[Entry]):
    accepted, rejected = 0, []
    for e in entries:
        h = head(e.host)
        problem = None
        if e.seq != h["seq"] + 1:
            problem = ("sequence-gap", f"expected seq {h['seq'] + 1}, got {e.seq}")
        elif e.prev_hash != h["hash"]:
            problem = ("chain-break", f"seq {e.seq} does not link to seq {h['seq']}")
        elif entry_hash(e.seq, e.ts, e.host, e.line, e.prev_hash) != e.hash:
            problem = ("bad-hash", f"seq {e.seq} content does not match its hash")
        elif e.epoch < h["epoch"]:
            problem = ("epoch-rollback", f"seq {e.seq} uses old key epoch {e.epoch}")
        elif mac(key_for_epoch(KEY0, e.epoch), e.hash) != e.mac:
            problem = ("forged-seal", f"seq {e.seq} MAC invalid (forged or stolen-key replay)")
        if problem:
            alert(e.host, *problem)
            rejected.append({"seq": e.seq, "reason": problem[1]})
            continue
        q("INSERT INTO entries VALUES(?,?,?,?,?,?,?,?,?)",
          (e.host, e.seq, e.ts, e.line, e.prev_hash, e.hash, e.epoch, e.mac, now()))
        for p in e.pii:  # ⭐6 keep real values only if they match the sealed commitment
            if p["token"] in e.line and p["token"] == f"[[{p['kind']}:{commit(p['value'], p['salt'])}]]":
                q("INSERT OR IGNORE INTO pii VALUES(?,?,?,?,?,?)",
                  (p["token"], e.host, e.seq, p["kind"], p["value"], p["salt"]))
        if (reason := suspicion(e.host, e.line)):
            raise_alert_level(e.host, reason)
        accepted += 1
    return {"accepted": accepted, "rejected": rejected}


@app.get("/head/{host}")
def get_head(host: str):
    return head(host)


@app.post("/heartbeat")
def heartbeat(body: dict):
    q("INSERT INTO heartbeats VALUES(?,?) ON CONFLICT(host) DO UPDATE SET last_seen=excluded.last_seen",
      (body["host"], time.time()))
    return {"ok": True}


# ---------------------------------------------------------------- anchor ----
anchor_lock = threading.Lock()


def anchor_host(host, mode="normal"):
    with anchor_lock:
        last = q("SELECT MAX(end_seq) m FROM batches WHERE host=?", (host,), one=True)["m"] or 0
        rows = q("SELECT seq, ts, line, prev_hash, hash FROM entries WHERE host=? AND seq>? ORDER BY seq", (host, last))
        if not rows:
            return None
        root = merkle_root([r["hash"] for r in rows])
        try:
            tx, gas = ledger.anchor(stream(host), root, rows[0]["seq"], rows[-1]["seq"], mode)
        except ChainError as ex:
            alert(host, "chain-error", f"anchor of #{rows[0]['seq']}-{rows[-1]['seq']} refused: {str(ex)[:120]}")
            return None
        chain_tx(host, "anchor-" + mode, tx, gas)
        q("INSERT INTO batches(host,start_seq,end_seq,root,chain,tx,created_at,mode,gas) VALUES(?,?,?,?,?,?,?,?,?)",
          (host, rows[0]["seq"], rows[-1]["seq"], root, ledger.name, tx, now(), mode, gas))
        try:  # 2.0 ⑨ immutable copy: read-only, hash-linked file per sealed batch
            v2.worm_write(host, {"from": rows[0]["seq"], "to": rows[-1]["seq"], "root": root, "tx": tx,
                                 "chain": ledger.name, "at": now()}, [dict(r) for r in rows], RETENTION_DAYS)
        except Exception as ex:
            print("[vault] WORM copy failed:", ex)
        return {"root": root, "tx": tx, "from": rows[0]["seq"], "to": rows[-1]["seq"]}


def hosts_list():
    return [r["host"] for r in q("SELECT DISTINCT host FROM entries")]


@app.post("/anchor-now")
def anchor_now():
    return [b for h in hosts_list() if (b := anchor_host(h, "manual"))]


def anchor_loop():
    last = defaultdict(float)
    was_high = set()
    while True:
        time.sleep(1)
        try:
            for h in hosts_list():
                high = is_high(h)
                if not high and h in was_high:
                    event(h, "normal-mode", f"Adaptive anchoring: back to NORMAL (every {ANCHOR_SECONDS} s)")
                    was_high.discard(h)
                if high:
                    was_high.add(h)
                if time.time() - last[h] >= (FAST_ANCHOR_SECONDS if high else ANCHOR_SECONDS):
                    anchor_host(h, "high-alert" if high else "normal")
                    last[h] = time.time()
        except Exception as ex:  # keep running even if the chain hiccups
            print("[vault] anchor failed:", ex)


@app.post("/panic")
def panic(body: dict):
    """⭐3 Panic anchor: anchor everything received so far on-chain right now."""
    host, trigger, line = body["host"], body.get("trigger", "?"), body.get("line", "")
    alert(host, "panic-anchor", f"{trigger}: {line[:100]}" if line else trigger)
    raise_alert_level(host, trigger)
    # anchor in the background: the agent must never wait for a block to be mined
    threading.Thread(target=_panic_anchor, args=(host, trigger, line, body.get("seq")), daemon=True).start()
    return {"queued": True}


def _panic_anchor(host, trigger, line, seq):
    b = anchor_host(host, "panic")
    if b is None:  # nothing new since last anchor — the latest root already covers it
        r = q("SELECT root, tx FROM batches WHERE host=? ORDER BY id DESC LIMIT 1", (host,), one=True)
        b = dict(r) if r else {"root": "", "tx": ""}
    q("INSERT INTO panics(ts,host,seq,trigger,line,root,tx) VALUES(?,?,?,?,?,?,?)",
      (now(), host, seq, trigger, line, b["root"], b["tx"]))


# ------------------------------------------- on-chain heartbeat + attest ----
def chain_heartbeat_loop():
    """Post a public heartbeat while the agent is alive. If the agent is
    silenced, the on-chain heartbeat stops too, visible to anyone."""
    while True:
        time.sleep(CHAIN_HEARTBEAT_SECONDS)
        for r in q("SELECT host, last_seen FROM heartbeats"):
            if time.time() - r["last_seen"] < HEARTBEAT_TIMEOUT:
                try:
                    tx, gas = ledger.heartbeat(stream(r["host"]))
                    chain_tx(r["host"], "heartbeat", tx, gas)
                except ChainError as ex:
                    print("[vault] chain heartbeat failed:", ex)


@app.post("/attest")
def attest(body: dict):
    """Agent attestation: the hash of the agent's code is recorded on-chain at
    start-up. A different hash later means the agent was swapped or modified."""
    host, code_hash, key_commit = body["host"], body["code_hash"], body["key_commit"]
    if body.get("custody"):
        key_custody[host] = body["custody"]
    first = q("SELECT code_hash FROM attestations WHERE host=? ORDER BY id LIMIT 1", (host,), one=True)
    changed = bool(first and first["code_hash"] != code_hash)
    try:
        tx, gas = ledger.attest(stream(host), code_hash, key_commit)
        chain_tx(host, "attest", tx, gas)
    except ChainError as ex:
        tx = f"failed: {ex}"
    q("INSERT INTO attestations(ts,host,code_hash,key_commit,epoch,tx,changed) VALUES(?,?,?,?,?,?,?)",
      (now(), host, code_hash, key_commit, body.get("epoch", 0), tx, int(changed)))
    if changed:
        alert(host, "agent-code-changed", f"agent code hash {code_hash[:16]}... differs from first attested {first['code_hash'][:16]}...")
    else:
        event(host, "agent-attested", f"agent code hash {code_hash[:16]}... recorded on-chain")
    return {"tx": tx, "changed": changed}


# --------------------------------------------------------- ⭐8 self-heal ----
class HealPlan(BaseModel):
    host: str
    text: str


@app.post("/heal-plan")
def heal_plan(body: HealPlan):
    """Which sealed originals are missing or changed in the source, and not yet
    put back? Each comes with its blockchain proof reference."""
    res = compare(body.host, body.text)
    out = []
    for f in res["findings"]:
        if f["status"] in ("DELETED", "MODIFIED") and not f["healed"] and not is_restored(f["vault_line"] or "") \
                and not f.get("authorized"):
            # (a deleted *restore note* is not re-restored: its original is restored instead)
            p = proof_for(body.host, f["seq"])
            e = q("SELECT * FROM entries WHERE host=? AND seq=?", (body.host, f["seq"]), one=True)
            # 2.0 ④ verify the vault copy before restoring it: hash recomputes, and it is under a sealed root
            ok_hash = bool(e) and entry_hash(e["seq"], e["ts"], body.host, e["line"], e["prev_hash"]) == e["hash"]
            if not ok_hash or (p.get("anchored") and not p.get("proof_valid")):
                alert(body.host, "restore-refused", f"seq {f['seq']}: vault copy failed verification, not restored")
                continue
            out.append({"seq": f["seq"], "ts": f["ts"], "status": f["status"], "original": f["vault_line"],
                        "root": p.get("root", ""), "tx": p.get("tx", ""),
                        "verified": "hash and Merkle proof checked" if p.get("anchored") else "hash checked, seal pending"})
    return {"restore": out}


@app.post("/self-healed")
def self_healed(body: dict):
    host = body["host"]
    for it in body.get("items", []):
        q("INSERT INTO heals(ts,host,seq,status,original,root,tx) VALUES(?,?,?,?,?,?,?)",
          (now(), host, it["seq"], it["status"], it["original"], it.get("root", ""), it.get("tx", "")))
        alert(host, "self-healed", f"seq {it['seq']} {it['status'].lower()} by attacker, original restored at source"
              + (f" ({it['verified']})" if it.get("verified") else ""))
    # anchor the restored lines (and everything before them) right away
    threading.Thread(target=anchor_host, args=(host, "manual"), daemon=True).start()
    return {"ok": True}


# ------------------------------------------------------------- watchdogs ----
def watchdog_loop():
    while True:
        time.sleep(5)
        for r in q("SELECT host, last_seen FROM heartbeats"):
            if time.time() - r["last_seen"] > HEARTBEAT_TIMEOUT:
                lost = datetime.fromtimestamp(r["last_seen"], timezone.utc).astimezone().strftime("%H:%M:%S")
                alert(r["host"], "heartbeat-lost", f"agent silent since {lost}, logging may have been killed")
        for a_host, a_path in AUDIT_TARGETS.items():
            if not os.path.exists(a_path):
                continue
            try:
                with open(a_path, errors="replace") as f:
                    res = compare(a_host, f.read())
                last_verdict[a_host] = {"verdict": res["verdict"], "at": now(), "healed": res["healed"],
                                        "authorized": res.get("authorized", 0),
                                        "bad": sum(1 for x in res["findings"] if x["status"] in ("DELETED", "MODIFIED", "INJECTED")
                                                   and not x.get("authorized"))}
                for item in res["findings"]:
                    if item.get("authorized"):
                        alert(a_host, "authorized-change", f"seq {item['seq']} changed under approved ticket "
                                                           f"{item['authorized']['ticket']}: {item['authorized']['reason'][:60]}")
                        continue
                    if item["status"] == "INJECTED":
                        alert(a_host, "tamper-detected", f"fake line inserted (never sealed): {item['server_line'][:90]}")
                        continue
                    if item["status"] in ("DELETED", "MODIFIED"):
                        alert(a_host, "tamper-detected",
                              f"seq {item['seq']} {item['status']} at source: {item['sealed_line'][:90]}")
            except Exception as ex:
                print("[vault] audit failed:", ex)


# ---------------------------------------------------------------- verify ----
def pii_values(host):
    return {r["token"]: r["value"] for r in q("SELECT token, value FROM pii WHERE host=?", (host,))}


_anchor_cache = {}
_chain_hb = {}  # host -> last on-chain heartbeat (unix time), refreshed in the background


def chain_reader_loop():
    """Read slow on-chain values in the background, so /status (polled every 2 s by the
    website) never waits on the blockchain."""
    while True:
        try:
            for r in q("SELECT DISTINCT host FROM entries"):
                try:
                    _chain_hb[r["host"]] = int(ledger.last_heartbeat(stream(r["host"])))
                except Exception:
                    pass
            ledger.info()
        except Exception:
            pass
        time.sleep(10)
_chain_down_until = [0.0]  # circuit breaker: after a chain failure, skip live checks for 30 s


def chain_anchored_at(root, fallback_iso=None):
    """Seal time from the blockchain. A seal never changes once it is on-chain, so it is cached
    (fewer slow Quai calls). If the chain cannot be reached right now, fall back to the vault's
    own record of the seal, and say so, instead of failing the whole request."""
    if root in _anchor_cache:
        return _anchor_cache[root], True
    try:
        if time.time() < _chain_down_until[0]:
            raise ChainError("chain recently unreachable")
        t = int(ledger.anchored_at(root))
        if t:
            _anchor_cache[root] = t
        return t, True
    except Exception:
        _chain_down_until[0] = max(_chain_down_until[0], time.time() + 30) if time.time() >= _chain_down_until[0] else _chain_down_until[0]
        try:
            return int(datetime.fromisoformat(fallback_iso).timestamp()) if fallback_iso else 0, False
        except Exception:
            return 0, False


def proof_for(host, seq):
    b = q("SELECT * FROM batches WHERE host=? AND start_seq<=? AND end_seq>=?", (host, seq, seq), one=True)
    if not b:
        return {"anchored": False}
    leaves = [r["hash"] for r in q("SELECT hash FROM entries WHERE host=? AND seq BETWEEN ? AND ? ORDER BY seq",
                                   (host, b["start_seq"], b["end_seq"]))]
    i = seq - b["start_seq"]
    proof = merkle_proof(leaves, i)
    return {"anchored": True, "root": b["root"], "tx": b["tx"], "tx_url": ledger.tx_url(b["tx"]),
            "chain": b["chain"], "batch": [b["start_seq"], b["end_seq"]], "batch_size": len(leaves),
            "leaf": leaves[i], "proof": proof, "proof_valid": verify_proof(leaves[i], proof, b["root"]),
            "sealed_at": b["created_at"]}


def compare(host, text):
    values = pii_values(host)
    vault = [dict(r) for r in q("SELECT seq, ts, line FROM entries WHERE host=? ORDER BY seq", (host,))]
    for v in vault:
        v["full"] = unredact(v["line"], values)
    file_lines = [l for l in text.splitlines() if l.strip()]
    sm = difflib.SequenceMatcher(a=[v["full"] for v in vault], b=file_lines, autojunk=False)
    findings, ok = [], 0
    for op, a1, a2, b1, b2 in sm.get_opcodes():
        if op == "equal":
            ok += a2 - a1
            continue
        if op in ("delete", "replace"):
            for k, i in enumerate(range(a1, a2)):
                v = vault[i]
                server = file_lines[b1 + k] if op == "replace" and b1 + k < b2 else None
                if server is not None and TOKEN_RE.search(v["full"]) and normalize_pii(v["full"]) == normalize_pii(server):
                    ok += 1  # personal data was erased (DPDP) — the rest of the line matches
                    continue
                findings.append({"seq": v["seq"], "ts": v["ts"], "status": "MODIFIED" if server is not None else "DELETED",
                                 "vault_line": v["full"], "sealed_line": v["line"], "server_line": server})
        if op in ("insert", "replace"):
            extra = file_lines[b1 + (a2 - a1):b2] if op == "replace" else file_lines[b1:b2]
            for line in extra:
                trailing = b2 == len(file_lines) and a2 == len(vault)
                findings.append({"seq": None, "ts": None, "status": "NOT-YET-SEALED" if trailing else "INJECTED",
                                 "vault_line": None, "sealed_line": None, "server_line": line})
    approved = {}
    for r in q("SELECT * FROM change_requests WHERE host=? ORDER BY id", (host,)):
        approved[r["seq"]] = dict(r)
    for f in findings:  # ⭐8: has SakshyaLog already put this original back?
        f["healed"] = bool(f["seq"]) and heal_tag(f["seq"]) in text
        if f["status"] == "MODIFIED":  # 2.0 ① exactly which character / word / field changed
            f["diff"] = v2.exact_diff(f["vault_line"], f["server_line"])
        cr = approved.get(f["seq"]) if f["seq"] else None
        if cr and f["status"] in ("DELETED", "MODIFIED"):  # 2.0 ② pre-approved change?
            want = (cr["new_line"] or "").strip()
            got = (f["server_line"] or "").strip()
            if (f["status"] == "DELETED" and not want) or (f["status"] == "MODIFIED" and want == got):
                f["authorized"] = {"id": cr["id"], "ticket": cr["ticket"], "reason": cr["reason"], "approver": cr["approver"]}
            else:
                f["authorization_mismatch"] = {"ticket": cr["ticket"], "approved_text": want}
    bad = [f for f in findings if f["status"] in ("DELETED", "MODIFIED", "INJECTED") and not f.get("authorized")]
    return {"host": host, "vault_entries": len(vault), "file_lines": len(file_lines), "matching": ok,
            "findings": findings, "healed": sum(1 for f in findings if f["healed"]),
            "authorized": sum(1 for f in findings if f.get("authorized")),
            "verdict": "TAMPERED" if bad else "INTACT"}


def with_proofs(host, res, source):
    res.update(source=source, checked_at=now(), chain=ledger.name)
    for f in res["findings"]:
        if f["seq"]:
            f["proof"] = proof_for(host, f["seq"])
            if f["proof"].get("anchored"):
                t, live = chain_anchored_at(f["proof"]["root"], f["proof"].get("sealed_at"))
                f["proof"]["on_chain_since"] = t
                if not live:
                    f["proof"]["chain_unreachable"] = True
                    res["chain_unreachable"] = True
    return res


def live_result(host=None):
    host = host or next(iter(AUDIT_TARGETS), None)
    path = AUDIT_TARGETS.get(host)
    if not path or not os.path.exists(path):
        return None
    with open(path, errors="replace") as f:
        return with_proofs(host, compare(host, f.read()), path)


@app.post("/verify")
async def verify(host: str = Form(...), file: UploadFile = None):
    return with_proofs(host, compare(host, (await file.read()).decode(errors="replace")), file.filename)


@app.post("/verify-live")
def verify_live(host: str = ""):
    r = live_result(host or None)
    if r is None:
        raise HTTPException(400, f"no audited source configured for '{host or 'default'}'")
    return r


@app.get("/audit-targets")
def audit_targets():
    return list(AUDIT_TARGETS)


# ------------------------------------------- ⭐5 one-line proof + ⭐6 PII ----
@app.get("/entries/{host}")
def entries(host: str, search: str = "", limit: int = 60):
    rows = q("SELECT seq, ts, line FROM entries WHERE host=? AND line LIKE ? ORDER BY seq DESC LIMIT ?",
             (host, f"%{search}%", limit))
    return [dict(r) | {"tokens": [m.group(0) for m in TOKEN_RE.finditer(r["line"])]} for r in rows]


@app.get("/proof/{host}/{seq}")
def proof(host: str, seq: int, reveal: str = ""):
    """Self-contained proof that ONE line existed unchanged, revealing nothing else.
    Only the requested personal-data fields are disclosed (with their salts)."""
    e = q("SELECT host, seq, ts, line, prev_hash, hash FROM entries WHERE host=? AND seq=?", (host, seq), one=True)
    if not e:
        raise HTTPException(404, "no such entry")
    p = proof_for(host, seq)
    if not p.get("anchored"):
        raise HTTPException(409, "line not anchored yet, try again in a few seconds")
    wanted = [t for t in reveal.split(",") if t]
    disclosed = [dict(r) for r in q(f"SELECT token, kind, value, salt FROM pii WHERE host=? AND token IN "
                                     f"({','.join('?' * len(wanted))})", (host, *wanted))] if wanted else []
    since, live = chain_anchored_at(p["root"], p.get("sealed_at"))
    out = {"format": "sakshyalog-line-proof-v1", "entry": dict(e), "leaf": p["leaf"], "proof": p["proof"],
           "root": p["root"], "tx": p["tx"], "tx_url": p["tx_url"], "batch_size": p["batch_size"],
           "chain": ledger.info(), "on_chain_since": since, "chain_unreachable": not live, "disclosed": disclosed,
           "hidden_personal_fields": len(TOKEN_RE.findall(e["line"])) - len(disclosed),
           "how_to_verify": "python verify_pack.py <this file>   (add --rpc <url> for a live blockchain check)"}
    if ledger.info()["mode"] not in ("web3", "quai"):  # built-in/offline chain: ship the matching record
        out["ledger_rows"] = [{"root": p["root"], "ts": out["on_chain_since"], "tx": p["tx"]}]
    return out


@app.get("/pii-summary")
def pii_summary():
    rows = q("SELECT kind, COUNT(*) n, COUNT(DISTINCT value) d FROM pii GROUP BY kind")
    return {"by_kind": [dict(r) for r in rows],
            "people": [r["value"] for r in q("SELECT DISTINCT value FROM pii WHERE kind='email' ORDER BY value")]}


@app.post("/erase-pii")
def erase_pii(body: dict):
    """DPDP right to erasure: delete a person's data. Sealed lines only hold
    salted commitments, so the hash chain and blockchain proofs stay valid."""
    value = body.get("value", "").strip()
    if not value:
        raise HTTPException(400, "value required")
    tokens = [r["token"] for r in q("SELECT token FROM pii WHERE value=?", (value,))]
    hosts = {r["host"] for r in q("SELECT host FROM pii WHERE value=?", (value,))}
    q("DELETE FROM pii WHERE value=?", (value,))
    for h in hosts:
        event(h, "dpdp-erasure", f"Personal data erased on request ({len(tokens)} field(s)); hash chain unaffected")
    return {"erased_fields": len(tokens)}


# ---------------------------------------------------------- timeline -------
def timeline(host):
    out = []
    tampering_started = None
    for e in q("SELECT seq, ts, line FROM entries WHERE host=? ORDER BY seq", (host,)):
        line, item = e["line"], None
        if is_restored(line):  # restorations are listed as their own events below
            continue
        if (m := RX_FAILED.search(line)) and is_external(m.group(2)):
            item = ("med", "Failed login attempt", f"user {m.group(1)} from {m.group(2)}")
        elif (m := RX_ACCEPT.search(line)) and m.group(2) == "root":
            item = ("crit", "Became root (root login)", f"root logged in from {m.group(3)} using {m.group(1)}")
        elif (m := RX_ACCEPT.search(line)) and is_external(m.group(3)):
            item = ("high", "Login from external IP", f"{m.group(2)} from {m.group(3)}")
        elif (why := panic_reason(line)):
            item = ("crit", f"Evidence destruction: {why}", line.split("COMMAND=")[-1][:120])
            tampering_started = tampering_started or e["ts"]
        elif (m := RX_SUDO.search(line)) and RX_EXFIL.search(m.group(2)):
            item = ("crit", "Possible data exfiltration", f"{m.group(1)} ran as root: {m.group(2)[:110]}")
        elif (m := RX_SUDO.search(line)) and m.group(1) == "root":
            item = ("high", "Command run as root", m.group(2)[:120])
        if item:
            detail = item[2]
            if tampering_started and e["ts"] > tampering_started and "Evidence destruction" not in item[1]:
                detail += "  [logged AFTER evidence destruction began; may be planted]"
            out.append({"ts": e["ts"], "severity": item[0], "title": item[1], "detail": f"#{e['seq']} {detail}",
                        "source": "log", "seq": e["seq"]})
    titles = {"tamper-detected": ("crit", "Log tampering detected by audit"),
              "panic-anchor": ("crit", "Panic anchor fired"), "heartbeat-lost": ("crit", "Logging agent went silent"),
              "forged-seal": ("crit", "Forged entry rejected"), "chain-break": ("crit", "Hash chain break"),
              "sequence-gap": ("crit", "Sequence gap"), "bad-hash": ("crit", "Bad fingerprint"),
              "epoch-rollback": ("crit", "Old key reused"),
              "agent-code-changed": ("crit", "Logging agent was swapped or modified"),
              "chain-error": ("high", "Blockchain refused an anchor"),
              "self-healed": ("info", "Self-healed: original restored")}
    for a in q("SELECT * FROM alerts WHERE host=? ORDER BY id", (host,)):
        sev, title = titles.get(a["kind"], ("high", a["kind"]))
        out.append({"ts": a["ts"], "severity": sev, "title": title, "detail": a["detail"], "source": "alert"})
    for ev in q("SELECT * FROM events WHERE host=? ORDER BY id", (host,)):
        out.append({"ts": ev["ts"], "severity": "info", "title": ev["kind"].replace("-", " ").title(),
                    "detail": ev["detail"], "source": "event"})
    for i in q("SELECT * FROM incidents WHERE host=? ORDER BY id", (host,)):
        out.append({"ts": i["declared_at"], "severity": "info", "title": "Incident declared, evidence frozen",
                    "detail": f"snapshot {i['snapshot_root'][:20]}..., CERT-In deadline {reports.local(i['deadline'])}",
                    "source": "event"})
    return sorted(out, key=lambda x: x["ts"])


@app.get("/timeline/{host}")
def get_timeline(host: str):
    ev = timeline(host)
    ips = sorted({ip for e in ev for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", e["detail"]) if is_external(ip)})
    return {"host": host, "events": ev, "attacker_ips": ips}


# ------------------------------------------------- retention tracker -------
def retention(host, check_chain=True):
    r = q("SELECT COUNT(*) n, MIN(ts) o, MAX(ts) l FROM entries WHERE host=?", (host,), one=True)
    if not r or not r["n"]:
        return None
    oldest = datetime.fromisoformat(r["o"])
    kept = datetime.now(timezone.utc) - oldest
    batches = q("SELECT root FROM batches WHERE host=? ORDER BY id DESC LIMIT 50", (host,))
    total = q("SELECT COUNT(*) n FROM batches WHERE host=?", (host,), one=True)["n"]
    on_chain = None
    if check_chain:
        checks = [chain_anchored_at(b["root"]) for b in batches]
        on_chain = sum(1 for t, live in checks if t and live) if all(live for _, live in checks) else None
    return {"host": host, "entries": r["n"], "oldest": r["o"], "newest": r["l"],
            "kept_seconds": kept.total_seconds(), "kept_days": round(kept.total_seconds() / 86400, 4),
            "required_days": RETENTION_DAYS, "requirement_met_on": (oldest + timedelta(days=RETENTION_DAYS)).isoformat(),
            "locked_until": (datetime.fromisoformat(r["l"]) + timedelta(days=RETENTION_DAYS)).isoformat(),
            "anchors": total, "anchors_checked": len(batches), "anchors_on_chain": on_chain,
            "storage": "append-only (UPDATE/DELETE blocked)"}


@app.get("/retention/{host}")
def get_retention(host: str):
    r = retention(host)
    if r is None:
        raise HTTPException(404, "no entries")
    return r


# ---------------------------------------------- incident / CERT-In ---------
@app.post("/incident")
def incident(body: dict):
    """Freeze evidence: anchor everything now and start the CERT-In 6 h clock."""
    host = body.get("host", "")
    anchor_now()
    snapshot = merkle_root([r["root"] for r in q("SELECT root FROM batches WHERE host=? ORDER BY id", (host,))])
    note = body.get("note", "")
    try:  # on-chain incident registry: the contract fixes the time and the 6 h deadline
        cid, tx, gas = ledger.declare_incident(stream(host), snapshot, note)
        chain_tx(host, "incident", tx, gas)
        inc = ledger.get_incident(cid)
        declared = datetime.fromtimestamp(inc["declared_at"], timezone.utc)
        deadline = datetime.fromtimestamp(inc["deadline"], timezone.utc)
    except ChainError as ex:
        raise HTTPException(502, f"blockchain refused the incident: {ex}")
    q("INSERT INTO incidents(declared_at,deadline,host,note,snapshot_root,tx,chain_id) VALUES(?,?,?,?,?,?,?)",
      (declared.isoformat(), deadline.isoformat(), host, note, snapshot, tx, cid))
    return {"snapshot_root": snapshot, "tx": tx, "tx_url": ledger.tx_url(tx), "chain_incident_id": cid,
            "certin_deadline": deadline.isoformat()}


@app.post("/incident/{inc_id}/reported")
def incident_reported(inc_id: int, body: dict):
    """Record on-chain that the CERT-In report was filed: its fingerprint and
    whether it was on time. The contract, not the company, decides 'on time'."""
    inc = q("SELECT * FROM incidents WHERE id=?", (inc_id,), one=True)
    if not inc:
        raise HTTPException(404, "no such incident")
    report_hash = __import__("hashlib").sha256(body.get("report", "").encode()).hexdigest()
    try:
        tx, on_time = ledger.mark_reported(inc["chain_id"], report_hash)
        chain_tx(inc["host"], "reported", tx, 0)
    except ChainError as ex:
        raise HTTPException(409, str(ex))
    q("UPDATE incidents SET reported_at=?, report_hash=?, report_tx=?, on_time=? WHERE id=?",
      (now(), report_hash, tx, int(on_time), inc_id))
    event(inc["host"], "certin-reported", f"CERT-In report fingerprint {report_hash[:16]}... recorded on-chain; "
                                          f"{'ON TIME' if on_time else 'LATE'} (decided by the smart contract)")
    return {"tx": tx, "on_time": on_time, "report_hash": report_hash, "tx_url": ledger.tx_url(tx)}


def certin_data(host, form):
    tl = get_timeline(host)
    ev = tl["events"]
    titles = " ".join(e["title"] for e in ev)
    cats = []
    if "Failed login" in titles:
        cats.append("Targeted scanning/probing of critical networks/systems")
    if "root" in titles or "external IP" in titles:
        cats.append("Unauthorised access of IT systems/data")
    if "exfiltration" in titles:
        cats.append("Data Breach")
    if "Evidence destruction" in titles or "tampering" in titles:
        cats.append("Compromise of critical systems/information")
    inc = q("SELECT * FROM incidents WHERE host=? ORDER BY id DESC LIMIT 1", (host,), one=True)
    detected = next((e for e in ev if e["source"] == "alert"), None)
    deadline = inc["deadline"] if inc else (
        (datetime.fromisoformat(detected["ts"]) + timedelta(hours=6)).isoformat() if detected else None)
    latest = q("SELECT root FROM batches WHERE host=? ORDER BY id DESC LIMIT 1", (host,), one=True)
    iocs = [f"IP {ip}" for ip in tl["attacker_ips"]] + \
           [f"{e['title']}: {e['detail']}" for e in ev if e["severity"] == "crit" and e["source"] == "log"]
    summary = (f"On {host}, SakshyaLog recorded {len([e for e in ev if e['source'] == 'log'])} suspicious log events "
               f"from {', '.join(tl['attacker_ips']) or 'unknown sources'}, including "
               f"{'; '.join(sorted({e['title'] for e in ev if e['severity'] == 'crit'})) or 'none'}. "
               f"Original records were preserved off-host and anchored on blockchain before the attacker could alter them.")
    return {"generated_at": now(), "host": host, "categories": cats or ["Other (describe)"],
            "attacker_ips": tl["attacker_ips"], "iocs": iocs, "summary": summary, "timeline": ev,
            "deadline_local": reports.local(deadline) if deadline else None,
            "anchors": q("SELECT COUNT(*) n FROM batches WHERE host=?", (host,), one=True)["n"],
            "chain": ledger.name, "latest_root": latest["root"] if latest else "",
            "snapshot_root": inc["snapshot_root"] if inc else None, "snapshot_tx": inc["tx"] if inc else None,
            **{k: form.get(k, "") for k in ("org", "sector", "contact", "contact_details", "actions")}}


@app.post("/report/certin/{host}", response_class=HTMLResponse)
def report_certin(host: str, form: dict):
    return reports.certin_report(certin_data(host, form))


@app.post("/report/evidence", response_class=HTMLResponse)
def report_evidence(result: dict):
    return reports.evidence_report(privacy_safe(result), timeline(result["host"]), retention(result["host"]))


def privacy_safe(result):
    """Copy of a verification result with personal data replaced by sealed tokens / kinds."""
    r = json.loads(json.dumps(result))
    for f in r["findings"]:
        f["vault_line"] = f.get("sealed_line") or f["vault_line"]
        if f.get("server_line"):
            f["server_line"] = normalize_pii(f["server_line"])
    return r


# ------------------------------------------------- court evidence pack -----
@app.get("/evidence-pack/{host}")
def evidence_pack(host: str):
    """ZIP bundle a court or auditor can check on their own with verify_pack.py."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder = f"sakshyalog_evidence_{host}_{stamp}/"
    files = {}
    files["entries.jsonl"] = "\n".join(json.dumps(dict(r)) for r in q(
        "SELECT host, seq, ts, line, prev_hash, hash, epoch FROM entries WHERE host=? ORDER BY seq", (host,)))
    files["batches.json"] = json.dumps([dict(r) for r in q(
        "SELECT start_seq, end_seq, root, chain, tx, created_at, mode FROM batches WHERE host=? ORDER BY id", (host,))], indent=1)
    if ledger.info()["mode"] not in ("web3", "quai"):  # public chains are checked live with --rpc instead
        files["chain_record.jsonl"] = "\n".join(json.dumps(r) for r in ledger.export_rows())
    live = live_result(host) if host in AUDIT_TARGETS else None
    files["findings.json"] = json.dumps(privacy_safe(live) if live else {"verdict": "not checked"}, indent=1)
    files["timeline.json"] = json.dumps(timeline(host), indent=1)
    files["retention.json"] = json.dumps(retention(host), indent=1)
    files["incidents.json"] = json.dumps([dict(r) for r in q("SELECT * FROM incidents WHERE host=?", (host,))], indent=1)
    if live:
        files["evidence_report.html"] = reports.evidence_report(privacy_safe(live), timeline(host), retention(host))
    files["verify_pack.py"] = open(os.path.join(ROOT, "tools", "verify_pack.py")).read()
    files["README.txt"] = f"""SakshyaLog court evidence pack: {host}, generated {now()}

HOW TO CHECK THIS EVIDENCE YOURSELF (no need to trust the company):
  1. Install Python 3 (nothing else needed).
  2. Run:   python verify_pack.py {folder.rstrip('/')}.zip
     (in web3 mode add:  --rpc <public RPC URL>  to check the live blockchain)

CONTENTS
  entries.jsonl         every sealed log line (personal data replaced by salted-hash tokens)
  batches.json          Merkle roots and blockchain transaction IDs
  chain_record.jsonl    anchors read back from the chain (built-in/offline chain only)
  findings.json         what was deleted / changed on the server, with proofs
  timeline.json         attack timeline
  retention.json        180-day retention status (CERT-In)
  incidents.json        frozen-evidence snapshots and CERT-In deadlines
  evidence_report.html  human-readable report with Section 63 BSA certificate draft
  verify_pack.py        open-source verifier (Python standard library only)
  manifest.json         SHA-256 of every file above
"""
    manifest = {"host": host, "generated_at": now(), "chain": ledger.info() | {"stream": stream(host)},
                "files_sha256": {n: __import__("hashlib").sha256(c.encode()).hexdigest() for n, c in files.items()}}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(folder + "manifest.json", json.dumps(manifest, indent=1))
        for n, c in files.items():
            z.writestr(folder + n, c)
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{folder.rstrip("/")}.zip"'})


# ---------------------------------------------------------------- status ---
@app.get("/status")
def status():
    hosts = []
    for r in q("SELECT host, COUNT(*) n, MAX(seq) s FROM entries GROUP BY host"):
        h = r["host"]
        hb = q("SELECT last_seen FROM heartbeats WHERE host=?", (h,), one=True)
        lat = q("SELECT ts, received_at FROM entries WHERE host=? ORDER BY seq DESC LIMIT 20", (h,))
        delays = [(datetime.fromisoformat(x["received_at"]) - datetime.fromisoformat(x["ts"])).total_seconds()
                  for x in lat]
        hosts.append({"host": h, "entries": r["n"], "head_seq": r["s"], "key_epoch": head(h)["epoch"],
                      "witness_delay_s": round(sum(delays) / len(delays), 2) if delays else None,
                      "last_heartbeat_s": round(time.time() - hb["last_seen"], 1) if hb else None,
                      "anchor_mode": "HIGH ALERT" if is_high(h) else "NORMAL",
                      "anchor_every_s": FAST_ANCHOR_SECONDS if is_high(h) else ANCHOR_SECONDS,
                      "high_alert_reason": high_reason.get(h) if is_high(h) else None,
                      "high_alert_left_s": max(0, round(high_until[h] - time.time())),
                      "retention": retention(h, check_chain=False)})
    for hd in hosts:
        lh = _chain_hb.get(hd["host"], 0)
        hd["sealed_seq"] = (q("SELECT MAX(end_seq) m FROM batches WHERE host=?", (hd["host"],), one=True) or {"m": None})["m"]
        hd["chain_heartbeat_age_s"] = round(time.time() - lh) if lh else None
        att = q("SELECT * FROM attestations WHERE host=? ORDER BY id", (hd["host"],))
        hd["attestation"] = {"count": len(att), "code_hash": att[0]["code_hash"] if att else None,
                             "changed": any(a["changed"] for a in att), "tx": att[0]["tx"] if att else None}
    gas_rows = q("SELECT kind, COUNT(*) n, AVG(gas) g FROM chain_txs WHERE gas>0 GROUP BY kind")
    return {
        "chain": ledger.name, "chain_info": ledger.info(), "retention_days": RETENTION_DAYS, "hosts": hosts,
        "anchor_seconds": ANCHOR_SECONDS, "chain_heartbeat_seconds": CHAIN_HEARTBEAT_SECONDS,
        "gas": {r["kind"]: {"count": r["n"], "avg_gas": round(r["g"])} for r in gas_rows},
        "chain_txs": [dict(r) | {"tx_url": ledger.tx_url(r["tx"])} for r in q("SELECT * FROM chain_txs ORDER BY id DESC LIMIT 15")],
        "pii_protected": q("SELECT COUNT(*) n FROM pii", one=True)["n"],
        "pii_erased_events": q("SELECT COUNT(*) n FROM events WHERE kind='dpdp-erasure'", one=True)["n"],
        "heals": [dict(r) | {"tx_url": ledger.tx_url(r["tx"]) if r["tx"] else ""}
                  for r in q("SELECT * FROM heals ORDER BY id DESC LIMIT 30")],
        "alerts": [dict(a) for a in q("SELECT * FROM alerts ORDER BY id DESC LIMIT 50")],
        "batches": [dict(b) | {"tx_url": ledger.tx_url(b["tx"])}
                    for b in q("SELECT * FROM batches ORDER BY id DESC LIMIT 20")],
        "recent": [dict(e) for e in q("SELECT host,seq,ts,line,hash FROM entries ORDER BY seq DESC LIMIT 25")],
        "incidents": [dict(i) for i in q("SELECT * FROM incidents ORDER BY id DESC")],
        "panics": [dict(p) | {"tx_url": ledger.tx_url(p["tx"]) if p["tx"] else ""}
                   for p in q("SELECT * FROM panics ORDER BY id DESC LIMIT 20")],
    }


# ==========================================================================
# SakshyaLog 2.0
# ==========================================================================
import random  # noqa: E402
import signal  # noqa: E402

LAB_ENABLED = os.getenv("LAB_ENABLED", "0") == "1"
AGENT_PROC = {"server-01": "agent", "case-UPI-001": "case-agent", "server-02": "agent-2"}


def _t(iso):
    try:
        return datetime.fromisoformat(iso).timestamp()
    except Exception:
        return 0.0


# ---- ③ real-time tamper monitoring ---------------------------------------
@app.post("/tamper-signal")
def tamper_signal(body: dict):
    """The agent's file monitor reports a change to existing log content within ~1 s."""
    host, detail = body["host"], body.get("detail", "log file changed")
    latency = max(0, int((time.time() - float(body.get("changed_at", time.time()))) * 1000))
    q("INSERT INTO tamper_signals(ts,host,kind,detail,line_no,latency_ms) VALUES(?,?,?,?,?,?)",
      (now(), host, body.get("kind", "rewrite"), detail, body.get("line_no"), latency))
    alert(host, "live-tamper", f"{detail} (seen {latency} ms after the change)")
    raise_alert_level(host, "live tamper signal")
    threading.Thread(target=anchor_host, args=(host, "high-alert"), daemon=True).start()
    return {"ok": True, "latency_ms": latency}


# ---- ② pre-change protection ---------------------------------------------
class ChangeRequest(BaseModel):
    host: str
    seq: int
    new_line: str = ""
    reason: str
    ticket: str
    approver: str


@app.post("/change-request")
def change_request(body: ChangeRequest):
    """Register an approved change BEFORE it is made. The original is already sealed;
    this record (immutable) says exactly which new text is allowed. Anything else is tampering."""
    e = q("SELECT * FROM entries WHERE host=? AND seq=?", (body.host, body.seq), one=True)
    if not e:
        raise HTTPException(404, "no such sealed line")
    if not body.reason.strip() or not body.ticket.strip() or not body.approver.strip():
        raise HTTPException(400, "reason, ticket and approver are required")
    original = unredact(e["line"], pii_values(body.host))
    q("INSERT INTO change_requests(ts,host,seq,original_line,original_hash,new_line,reason,ticket,approver) "
      "VALUES(?,?,?,?,?,?,?,?,?)", (now(), body.host, body.seq, original, e["hash"], body.new_line.strip(),
                                     body.reason.strip(), body.ticket.strip(), body.approver.strip()))
    event(body.host, "change-approved", f"#{body.seq} change pre-approved under {body.ticket} by {body.approver}")
    return {"ok": True, "original_preserved": original, "original_hash": e["hash"]}


@app.get("/change-requests")
def change_requests(host: str = ""):
    rows = [dict(r) for r in q("SELECT * FROM change_requests WHERE host=? OR ?='' ORDER BY id DESC", (host, host))]
    live = {}
    for h in {r["host"] for r in rows}:
        res = live_result(h)
        live[h] = {f["seq"]: f for f in (res or {}).get("findings", []) if f["seq"]}
    for r in rows:
        f = live.get(r["host"], {}).get(r["seq"])
        if not f:
            r["state"], r["state_text"] = "waiting", "Not changed yet. The original is preserved."
        elif f.get("authorized"):
            r["state"], r["state_text"] = "allowed", "Changed exactly as approved. Not reverted."
        else:
            r["state"] = "flagged"
            r["state_text"] = "A DIFFERENT change was made. Flagged as tampering and reverted."
            r["actual"] = f.get("server_line")
    return rows


# ---- ⑤ multi-server protection -------------------------------------------
@app.get("/fleet")
def fleet():
    out = []
    hb = {r["host"]: r["last_seen"] for r in q("SELECT host, last_seen FROM heartbeats")}
    for h in AUDIT_TARGETS:
        n = q("SELECT COUNT(*) n, MAX(seq) m FROM entries WHERE host=?", (h,), one=True)
        sealed = q("SELECT MAX(end_seq) m, COUNT(*) c FROM batches WHERE host=?", (h,), one=True)
        age = round(time.time() - hb[h], 1) if h in hb else None
        lv = last_verdict.get(h, {})
        out.append({"host": h, "kind": "case file" if h.startswith("case-") else "server",
                    "entries": n["n"], "head_seq": n["m"], "sealed_seq": sealed["m"], "seals": sealed["c"],
                    "agent_alive": age is not None and age < HEARTBEAT_TIMEOUT, "heartbeat_age_s": age,
                    "chain_heartbeat_age_s": round(time.time() - _chain_hb[h]) if _chain_hb.get(h) else None,
                    "custody": key_custody.get(h), "high_alert": is_high(h),
                    "verdict": lv.get("verdict"), "bad": lv.get("bad", 0), "healed": lv.get("healed", 0),
                    "authorized": lv.get("authorized", 0),
                    "live_signals": q("SELECT COUNT(*) n FROM tamper_signals WHERE host=?", (h,), one=True)["n"]})
    return {"servers": out, "vault": "online", "chain": ledger.info()}


# ---- ⑥ ⑧ ⑨ hardening: key custody, SIEM, WORM ---------------------------
@app.get("/worm/{host}")
def worm(host: str):
    hashes = {r["seq"]: r["hash"] for r in q("SELECT seq, hash FROM entries WHERE host=?", (host,))}
    return v2.worm_check(host, hashes)


@app.get("/custody")
def custody():
    return {h: key_custody.get(h) for h in AUDIT_TARGETS}


@app.get("/siem/status")
def siem_status():
    return {"targets": v2.siem_targets(), **v2.siem_stats,
            "formats": ["JSON lines", "CEF (ArcSight, QRadar)", "RFC 5424 syslog"]}


@app.get("/siem/events")
def siem_events(format: str = "json", limit: int = 50):
    rows = [v2.siem_event(dict(r)) for r in q("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))]
    if format == "cef":
        return Response("\n".join(v2.to_cef(e) for e in rows), media_type="text/plain")
    if format == "syslog":
        return Response("\n".join(v2.to_syslog(e) for e in rows), media_type="text/plain")
    return rows


# ---- ⑪ evidence provenance -----------------------------------------------
@app.get("/provenance/{host}/{seq}")
def provenance(host: str, seq: int):
    e = q("SELECT * FROM entries WHERE host=? AND seq=?", (host, seq), one=True)
    if not e:
        raise HTTPException(404, "no such sealed line")
    e = dict(e)
    checks = []

    def check(name, status, detail):
        checks.append({"name": name, "status": status, "detail": detail})

    atts = q("SELECT * FROM attestations WHERE host=? ORDER BY id", (host,))
    if atts:
        changed = any(a["changed"] for a in atts)
        check("Origin", "fail" if changed else "pass",
              f"Written by the SakshyaLog agent on {host}; its code fingerprint {atts[0]['code_hash'][:12]}… is recorded "
              f"on the blockchain{' but the agent code later CHANGED' if changed else ''}."
              + (f" Sealing key kept in: {key_custody[host]['label']}." if key_custody.get(host) else ""))
    else:
        check("Origin", "warn", "No agent attestation recorded for this source.")
    mac_ok = mac(key_for_epoch(KEY0, e["epoch"] or 0), e["hash"]) == e["mac"]
    check("Sealed at the source", "pass" if mac_ok else "fail",
          f"Signed on the machine with the key for epoch {e['epoch']}. That key was destroyed afterwards, "
          f"so even root cannot re-sign old lines." if mac_ok else "The source signature does not match.")
    prev = q("SELECT hash FROM entries WHERE host=? AND seq=?", (host, seq - 1), one=True)
    nxt = q("SELECT prev_hash FROM entries WHERE host=? AND seq=?", (host, seq + 1), one=True)
    hash_ok = entry_hash(e["seq"], e["ts"], host, e["line"], e["prev_hash"]) == e["hash"]
    link_ok = (prev["hash"] == e["prev_hash"]) if prev else (seq == 1 and e["prev_hash"] == GENESIS) or not prev
    next_ok = (nxt["prev_hash"] == e["hash"]) if nxt else True
    count = q("SELECT COUNT(*) n FROM entries WHERE host=? AND seq<=?", (host, seq), one=True)["n"]
    check("History consistent", "pass" if hash_ok and link_ok and next_ok and count == seq else "fail",
          f"Fingerprint recomputes, links to line #{seq - 1} before it" + (f" and #{seq + 1} after it" if nxt else "")
          + (", and no line before it is missing." if count == seq else f", but {seq - count} earlier line(s) are missing."))
    p = proof_for(host, seq)
    if p.get("anchored"):
        t, live = chain_anchored_at(p["root"], p.get("sealed_at"))
        check("Blockchain", "pass" if p["proof_valid"] and t else "fail",
              f"Inside a batch of {p['batch_size']} lines whose fingerprint was recorded on {ledger.name} "
              f"at {datetime.fromtimestamp(t, timezone.utc).astimezone().strftime('%d %b %H:%M:%S') if t else '?'}"
              + ("" if live else " (time from the vault record; chain not reachable right now)") + ".")
    else:
        check("Blockchain", "pending", "Waiting for the next seal (a few seconds).")
    w = v2.worm_lookup(host, seq)
    if w:
        check("Read-only copy", "pass" if w["hash"] == e["hash"] else "fail",
              f"Matches the write-once copy in {w['file']}." if w["hash"] == e["hash"] else "The read-only copy differs.")
    else:
        check("Read-only copy", "pending", "Written when the line is sealed.")
    res = live_result(host)
    f = next((x for x in (res or {}).get("findings", []) if x["seq"] == seq), None)
    if res is None:
        machine = "unknown"
        check("On the machine", "warn", "This source's file is not audited live.")
    elif not f:
        machine = "same"
        check("On the machine", "pass", "The line on the machine is identical to the sealed original.")
    elif f.get("authorized"):
        machine = "authorized"
        check("On the machine", "warn", f"Changed under approved ticket {f['authorized']['ticket']}: {f['authorized']['reason']}.")
    else:
        machine = "changed"
        what = f["diff"]["summary"] if f.get("diff") else "Deleted from the machine"
        check("On the machine", "fail", f"{what}." + (" SakshyaLog restored the original, marked as restored." if f["healed"] else ""))
    agree = ["vault"] + (["read-only copy"] if w and w["hash"] == e["hash"] else []) \
        + (["blockchain"] if p.get("anchored") and p.get("proof_valid") else []) + (["machine"] if machine == "same" else [])
    if machine == "same":
        verdict = f"Authentic. All {len(agree)} independent sources agree."
    elif machine == "changed":
        verdict = f"Altered on the machine. The original is proven by {len(agree)} independent sources: {', '.join(agree)}."
    elif machine == "authorized":
        verdict = "Changed with approval. The original is preserved and proven."
    else:
        verdict = f"{len(agree)} independent sources agree on this line."
    story = [{"ts": e["ts"], "what": "Written on the machine and sealed by the agent"},
             {"ts": e["received_at"], "what": "Copied to the off-machine vault"}]
    if p.get("anchored"):
        story.append({"ts": p["sealed_at"], "what": f"Fingerprint recorded on the blockchain (tx {str(p['tx'])[:12]}…)"})
    for c in q("SELECT * FROM change_requests WHERE host=? AND seq=?", (host, seq)):
        story.append({"ts": c["ts"], "what": f"Change pre-approved: {c['ticket']} by {c['approver']}"})
    for hrow in q("SELECT * FROM heals WHERE host=? AND seq=?", (host, seq)):
        story.append({"ts": hrow["ts"], "what": f"{hrow['status'].capitalize()} on the machine; original restored"})
    story.sort(key=lambda x: _t(x["ts"]))
    return {"host": host, "seq": seq, "line": e["line"],
            "checks": checks, "agree": agree, "verdict": verdict, "machine": machine,
            "diff": f.get("diff") if f else None, "story": story, "tx_url": p.get("tx_url", "")}


# ---- ⑩ attack lab ---------------------------------------------------------
SCENARIOS = {
    "delete_line": ("Delete a line", "Removes one sealed line from the log, like an attacker hiding a login."),
    "change_char": ("Change one character", "Changes a single letter in a name, e.g. Monisha → Manisha."),
    "change_timestamp": ("Change a timestamp", "Moves a line's time by one hour to fake an alibi."),
    "fake_insert": ("Insert a fake line", "Adds a line that was never written by the system."),
    "kill_agent": ("Kill the logger", "Stops the SakshyaLog agent on the machine."),
    "authorized_change": ("Approved change", "Registers a change ticket first, then makes exactly that change."),
}
VOWEL = {"a": "e", "e": "i", "i": "o", "o": "a", "u": "a", "A": "E", "E": "I", "I": "O", "O": "A", "U": "A"}
SKIP_WORDS = {"server", "password", "failed", "accepted", "session", "sshd", "systemd", "publickey", "invalid",
              "started", "disconnected", "customer", "updated", "reset", "requested", "mobile", "account",
              "victim", "investigator", "statement", "received", "complaint", "phishing", "reported", "success",
              "evidence", "opened", "command", "cron"}


def _change_one_char(line):
    m = re.search(r"\b(?:for|user|by)\s+([A-Za-z]{4,})\b|USER=([A-Za-z]{4,})\b", line)
    named = [g for g in (m.groups() if m else ()) if g and g.lower() not in SKIP_WORDS]
    words = named + [w for w in re.findall(r"\b[A-Za-z]{5,}\b", line) if w.lower() not in SKIP_WORDS]
    for w in words:
        for i, ch in enumerate(w[1:], 1):
            if ch in VOWEL:
                out = re.sub(rf"\b{re.escape(w)}\b", w[:i] + VOWEL[ch] + w[i + 1:], line, count=1)
                if out != line:
                    return out
    d = re.search(r"(?<=INR )\d", line)
    if d:
        return line[:d.start()] + str((int(d.group(0)) + 1) % 10) + line[d.end():]
    return None


def _shift_time(line):
    m = re.search(r"\b(\d{2}):(\d{2}):(\d{2})\b", line)
    if not m:
        return None
    return line[:m.start()] + f"{(int(m.group(1)) + 1) % 24:02d}:{m.group(2)}:{m.group(3)}" + line[m.end():]


@app.get("/lab/scenarios")
def lab_scenarios():
    return {"enabled": LAB_ENABLED, "targets": list(AUDIT_TARGETS),
            "scenarios": [{"id": k, "title": v[0], "what": v[1]} for k, v in SCENARIOS.items()]}


class LabRun(BaseModel):
    host: str
    scenario: str


@app.post("/lab/run")
def lab_run(body: LabRun):
    """Run one attack against the DEMO log so detection and recovery can be measured live."""
    if not LAB_ENABLED:
        raise HTTPException(403, "The attack lab is only enabled in demo mode (run_demo.py).")
    if body.scenario not in SCENARIOS or body.host not in AUDIT_TARGETS:
        raise HTTPException(400, "unknown scenario or source")
    host, path, started = body.host, AUDIT_TARGETS[body.host], time.time()
    if body.scenario == "kill_agent":
        name = AGENT_PROC.get(host, "agent")
        try:
            with open(os.path.join("data", "run", f"{name}.pid")) as pf:
                pid = int(pf.read().strip())
            os.kill(pid, signal.SIGTERM)
        except Exception as ex:
            raise HTTPException(409, f"could not stop the agent: {ex}")
        q("INSERT INTO lab_runs(ts,started,host,scenario,seq,before,after,note) VALUES(?,?,?,?,?,?,?,?)",
          (now(), started, host, body.scenario, None, None, None, f"stopped {name} (pid {pid})"))
        return {"ok": True}
    with open(path, errors="replace") as f:
        lines = f.read().splitlines()
    values = pii_values(host)
    sealed_to = q("SELECT MAX(end_seq) m FROM batches WHERE host=?", (host,), one=True)["m"] or 0
    by_text = {}
    for r in q("SELECT seq, line FROM entries WHERE host=? AND seq<=?", (host, sealed_to)):
        by_text.setdefault(unredact(r["line"], values), r["seq"])
    used = {r["seq"] for r in q("SELECT seq FROM lab_runs WHERE host=? AND seq IS NOT NULL", (host,))}
    cands = [(i, by_text[l]) for i, l in enumerate(lines)
             if l in by_text and not is_restored(l) and by_text[l] not in used and redact(l)[0] == l]  # no personal data
    if body.scenario in ("change_char", "authorized_change"):
        cands = [c for c in cands if _change_one_char(lines[c[0]])]
    if body.scenario == "change_timestamp":
        cands = [c for c in cands if _shift_time(lines[c[0]])]
    if not cands:
        raise HTTPException(409, "No suitable sealed line on this source for that attack yet. Try again in a few "
                                 "seconds, or pick another machine.")
    i, seq = random.choice(cands[-40:])
    before, after = lines[i], None
    if body.scenario == "delete_line":
        del lines[i]
    elif body.scenario in ("change_char", "authorized_change"):
        after = _change_one_char(before)
        if body.scenario == "authorized_change":
            n = q("SELECT COUNT(*) n FROM change_requests", one=True)["n"] + 1041
            change_request(ChangeRequest(host=host, seq=seq, new_line=after, ticket=f"CHG-{n}",
                                         reason="Correct a misspelt name (customer request)", approver="A. Kumar, CISO"))
        lines[i] = after
    elif body.scenario == "change_timestamp":
        after = _shift_time(before)
        lines[i] = after
    elif body.scenario == "fake_insert":
        stamp = re.match(r"^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+", before)
        prefix = stamp.group(0) if stamp else datetime.now().strftime("%b %d %H:%M:%S")
        after = (f"{prefix} sshd[4444]: Accepted password for admin from 203.0.113.66 port 4444 ssh2"
                 if not host.startswith("case-") else
                 "NOTE | investigator INV-07 | ACC-90bc9c72 verified as legitimate merchant, no further action")
        lines.insert(i + 1, after)
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    q("INSERT INTO lab_runs(ts,started,host,scenario,seq,before,after,note) VALUES(?,?,?,?,?,?,?,?)",
      (now(), started, host, body.scenario, None if body.scenario == "fake_insert" else seq, before, after, None))
    return {"ok": True, "seq": seq, "before": before, "after": after}


@app.get("/lab/runs")
def lab_runs(limit: int = 30):
    out = []
    for r in q("SELECT * FROM lab_runs ORDER BY id DESC LIMIT ?", (limit,)):
        r = dict(r)
        host, st, seq, sc = r["host"], r["started"], r["seq"], r["scenario"]
        live = q("SELECT ts, latency_ms FROM tamper_signals WHERE host=? AND ts>=? ORDER BY id LIMIT 1",
                 (host, r["ts"]), one=True)
        det, how, recovered, outcome = None, None, None, "Watching…"
        if live and sc != "kill_agent":
            det, how = _t(live["ts"]) - st, "live file monitor"
        if sc in ("delete_line", "change_char", "change_timestamp"):
            a = q("SELECT ts FROM alerts WHERE host=? AND kind='tamper-detected' AND detail LIKE ? AND ts>=? ORDER BY id LIMIT 1",
                  (host, f"seq {seq} %", r["ts"]), one=True)
            if a and (det is None or _t(a["ts"]) - st < det):
                det, how = _t(a["ts"]) - st, "vault audit"
            hrow = q("SELECT ts FROM heals WHERE host=? AND seq=? AND ts>=? ORDER BY id LIMIT 1", (host, seq, r["ts"]), one=True)
            if hrow:
                recovered = _t(hrow["ts"]) - st
                outcome = "Detected and restored from the vault"
            elif det is not None:
                outcome = "Detected, restoring…"
        elif sc == "fake_insert":
            a = q("SELECT ts FROM alerts WHERE host=? AND kind='tamper-detected' AND detail LIKE ? AND ts>=? ORDER BY id LIMIT 1",
                  (host, f"fake line inserted%{(r['after'] or '')[:40]}%", r["ts"]), one=True)
            if a and (det is None or _t(a["ts"]) - st < det):
                det, how = _t(a["ts"]) - st, "vault audit"
            if a:
                outcome = "Flagged: this line was never sealed, so it carries no proof"
        elif sc == "kill_agent":
            a = q("SELECT ts FROM alerts WHERE host=? AND kind='heartbeat-lost' AND ts>=? ORDER BY id LIMIT 1",
                  (host, r["ts"]), one=True)
            if a:
                det, how = _t(a["ts"]) - st, "missed heartbeats"
                hb = q("SELECT last_seen FROM heartbeats WHERE host=?", (host,), one=True)
                if hb and hb["last_seen"] > _t(a["ts"]) + 1:
                    recovered, outcome = hb["last_seen"] - st, "Detected; the supervisor restarted the agent"
                else:
                    outcome = "Detected: the logger went silent"
        elif sc == "authorized_change":
            a = q("SELECT ts FROM alerts WHERE host=? AND kind='authorized-change' AND detail LIKE ? AND ts>=? ORDER BY id LIMIT 1",
                  (host, f"seq {seq} %", r["ts"]), one=True)
            if a:
                outcome = "Allowed: matched the approved ticket, original preserved, not reverted"
                det, how = _t(a["ts"]) - st, "change control"
        r.update(detected_s=round(det, 1) if det is not None else None, detected_by=how,
                 recovered_s=round(recovered, 1) if recovered is not None else None, outcome=outcome,
                 title=SCENARIOS[sc][0], diff=v2.exact_diff(r["before"], r["after"]) if r["before"] and r["after"] and sc != "fake_insert" else None)
        out.append(r)
    return out
