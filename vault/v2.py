"""SakshyaLog 2.0 helpers: exact tamper diff, WORM evidence copies, SIEM export.

Kept separate from vault/api.py so the original vault logic stays exactly as it was.
"""
import difflib
import hashlib
import json
import os
import queue
import re
import socket
import stat
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone

from common import merkle_root

# --------------------------------------------------------------------------
# 1. Exact tamper detection: which character, word and field changed
# --------------------------------------------------------------------------
TOKEN = re.compile(r"\[\[[a-z]+:[0-9a-f]+\]\]|\d{1,3}(?:\.\d{1,3}){3}|\d{2}:\d{2}:\d{2}|ACC-\w+|\w+|[^\w\s]|\s+")
MONTH = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"


def _field(tok, before):
    """Name the kind of field a changed token belongs to, from its shape and the word before it."""
    b = before.lower()
    if re.fullmatch(r"\d{2}:\d{2}:\d{2}", tok) or re.fullmatch(MONTH, tok):
        return "timestamp"
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", tok):
        return "IP address"
    if tok.startswith("ACC-"):
        return "account"
    if tok.startswith("[["):
        return "personal-data token"
    if b in ("inr", "₹", "amount"):
        return "amount"
    if b == "port":
        return "port"
    if b in ("for", "user", "by") or b.endswith("user="):
        return "user name"
    if b in ("utr",):
        return "UTR reference"
    if re.fullmatch(r"\d+", tok):
        return "number"
    if re.fullmatch(r"[^\w\s]", tok):
        return "punctuation"
    return "word"


def exact_diff(original, changed):
    """Character-level segments plus a plain-language list of changed fields."""
    if original is None or changed is None:
        return None
    sm = difflib.SequenceMatcher(a=original, b=changed, autojunk=False)
    segments = []
    for op, a1, a2, b1, b2 in sm.get_opcodes():
        if op == "equal":
            segments.append({"op": "eq", "text": original[a1:a2]})
        else:
            if a2 > a1:
                segments.append({"op": "del", "text": original[a1:a2]})
            if b2 > b1:
                segments.append({"op": "ins", "text": changed[b1:b2]})
    ta, tb = TOKEN.findall(original), TOKEN.findall(changed)
    tm = difflib.SequenceMatcher(a=ta, b=tb, autojunk=False)
    fields = []
    for op, a1, a2, b1, b2 in tm.get_opcodes():
        if op == "equal":
            continue
        old, new = "".join(ta[a1:a2]).strip(), "".join(tb[b1:b2]).strip()
        if not old and not new:
            continue
        prev_words = [t for t in ta[:a1] if t.strip()]
        kind = _field(ta[a1] if a2 > a1 and ta[a1].strip() else (tb[b1] if b2 > b1 else ""), prev_words[-1] if prev_words else "")
        chars = None
        if old and new and len(old) == len(new):
            diffs = [(i, x, y) for i, (x, y) in enumerate(zip(old, new)) if x != y]
            if 0 < len(diffs) <= 3:
                chars = [{"pos": i + 1, "from": x, "to": y} for i, x, y in diffs]
        fields.append({"field": kind, "from": old, "to": new, "chars": chars})
    changed_chars = sum(len(s["text"]) for s in segments if s["op"] != "eq")
    if fields:
        f = fields[0]
        if f["chars"]:
            c = f["chars"][0]
            summary = f"{f['field'].capitalize()} changed: {f['from']} → {f['to']} (character {c['pos']}: {c['from']} → {c['to']})"
        elif f["from"] and f["to"]:
            summary = f"{f['field'].capitalize()} changed: {f['from']} → {f['to']}"
        elif f["to"]:
            summary = f"Text added: {f['to']}"
        else:
            summary = f"Text removed: {f['from']}"
        if len(fields) > 1:
            summary += f", and {len(fields) - 1} more change{'s' if len(fields) > 2 else ''}"
    else:
        summary = "Whitespace changed"
    return {"segments": segments, "fields": fields, "changed_chars": changed_chars, "summary": summary}


# --------------------------------------------------------------------------
# 9. Immutable storage: hash-linked, read-only evidence copies (WORM)
# --------------------------------------------------------------------------
WORM_DIR = os.getenv("WORM_DIR", os.path.join("data", "worm"))
WORM_S3_BUCKET = os.getenv("WORM_S3_BUCKET", "")  # optional: S3 Object Lock (compliance mode)


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _host_dir(host):
    return os.path.join(WORM_DIR, re.sub(r"[^\w.-]", "_", host))


def worm_files(host):
    d = _host_dir(host)
    return sorted(f for f in os.listdir(d) if f.endswith(".json")) if os.path.isdir(d) else []


def worm_write(host, batch, entries, retention_days):
    """Write one sealed batch as a read-only file. Each file carries the SHA-256 of the
    previous file, so deleting or editing any copy breaks the chain and is detected."""
    d = _host_dir(host)
    os.makedirs(d, exist_ok=True)
    files = worm_files(host)
    prev = _sha(_read(os.path.join(d, files[-1]))) if files else "0" * 64
    retain = (datetime.now(timezone.utc) + timedelta(days=retention_days)).isoformat()
    doc = {"format": "sakshyalog-worm-v1", "host": host, "from_seq": batch["from"], "to_seq": batch["to"],
           "root": batch["root"], "tx": batch["tx"], "chain": batch.get("chain", ""), "written_at": batch["at"],
           "retain_until": retain, "prev_file_sha256": prev,
           "entries": [{k: e[k] for k in ("seq", "ts", "line", "prev_hash", "hash")} for e in entries]}
    body = json.dumps(doc, indent=1, ensure_ascii=True).encode()
    path = os.path.join(d, f"{batch['from']:08d}-{batch['to']:08d}.json")
    if os.path.exists(path):
        return path
    with open(path, "wb") as f:
        f.write(body)
    os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)  # read-only (Windows: read-only attribute)
    if WORM_S3_BUCKET:
        try:  # production: S3 Object Lock in COMPLIANCE mode, nobody can delete before retain_until
            import boto3
            boto3.client("s3").put_object(Bucket=WORM_S3_BUCKET, Key=f"{host}/{os.path.basename(path)}", Body=body,
                                          ObjectLockMode="COMPLIANCE",
                                          ObjectLockRetainUntilDate=datetime.fromisoformat(retain))
        except Exception as ex:
            print("[vault] WORM S3 upload failed (local copy kept):", ex)
    return path


def worm_check(host, vault_hashes):
    """Walk the read-only copies: file chain intact, Merkle roots right, entries match the vault."""
    d, problems, entries, last_to, prev = _host_dir(host), [], 0, 0, "0" * 64
    files = worm_files(host)
    for name in files:
        path = os.path.join(d, name)
        raw = _read(path)
        try:
            doc = json.loads(raw)
        except ValueError:
            problems.append(f"{name}: unreadable (edited)")
            prev = _sha(raw)
            continue
        if doc.get("prev_file_sha256") != prev:
            problems.append(f"{name}: chain broken (a previous copy was deleted or edited)")
        if doc["from_seq"] != last_to + 1:
            problems.append(f"{name}: lines #{last_to + 1}-#{doc['from_seq'] - 1} missing")
        hashes = [e["hash"] for e in doc["entries"]]
        if merkle_root(hashes) != doc["root"]:
            problems.append(f"{name}: contents do not match the sealed fingerprint")
        for e in doc["entries"]:
            if vault_hashes.get(e["seq"]) != e["hash"]:
                problems.append(f"{name}: line #{e['seq']} differs from the vault")
        entries += len(hashes)
        last_to, prev = doc["to_seq"], _sha(raw)
    read_only = all(not (os.stat(os.path.join(d, n)).st_mode & stat.S_IWUSR) for n in files) if files else True
    return {"host": host, "files": len(files), "entries": entries, "covers_to_seq": last_to, "ok": not problems,
            "problems": problems[:20], "read_only": read_only, "folder": d,
            "s3_object_lock": bool(WORM_S3_BUCKET)}


def worm_lookup(host, seq):
    for name in worm_files(host):
        a, b = (int(x) for x in name[:-5].split("-"))
        if a <= seq <= b:
            try:
                doc = json.loads(_read(os.path.join(_host_dir(host), name)))
            except ValueError:
                return None
            e = next((e for e in doc["entries"] if e["seq"] == seq), None)
            return dict(e, file=name) if e else None
    return None


# --------------------------------------------------------------------------
# 8. SIEM integration: JSON lines file, webhook, syslog (CEF)
# --------------------------------------------------------------------------
SIEM_FILE = os.getenv("SIEM_FILE", os.path.join("data", "siem", "sakshyalog_alerts.jsonl"))
SIEM_WEBHOOK = os.getenv("SIEM_WEBHOOK", "")   # e.g. Splunk HEC / Sentinel / Elastic ingest URL
SIEM_SYSLOG = os.getenv("SIEM_SYSLOG", "")     # host:port, UDP syslog with CEF payload (QRadar, ArcSight, Wazuh)
SEVERITY = {"tamper-detected": 9, "live-tamper": 9, "heartbeat-lost": 8, "panic": 9, "agent-code-changed": 8,
            "self-healed": 5, "chain-error": 4, "unauthorized-change": 9, "authorized-change": 2}
siem_stats = {"forwarded": 0, "last_error": None, "last_at": None}
_q = queue.Queue()


def siem_event(alert_row):
    return {"time": alert_row["ts"], "vendor": "SakshyaLog", "product": "SakshyaLog Vault", "version": "2.0",
            "host": alert_row["host"], "kind": alert_row["kind"], "severity": SEVERITY.get(alert_row["kind"], 5),
            "message": alert_row["detail"], "id": alert_row.get("id")}


def _cef_escape(s):
    return str(s).replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=").replace("\n", " ")


def to_cef(ev):
    return (f"CEF:0|SakshyaLog|Vault|2.0|{_cef_escape(ev['kind'])}|{_cef_escape(ev['kind'].replace('-', ' '))}|"
            f"{ev['severity']}|rt={_cef_escape(ev['time'])} dhost={_cef_escape(ev['host'])} msg={_cef_escape(ev['message'])}")


def to_syslog(ev):
    pri = 8 * 4 + (2 if ev["severity"] >= 8 else 4 if ev["severity"] >= 5 else 6)  # facility auth
    return f"<{pri}>1 {ev['time']} {ev['host']} sakshyalog - {ev['kind']} - {to_cef(ev)}"


def siem_publish(alert_row):
    _q.put(siem_event(alert_row))


def siem_targets():
    return {"file": os.path.abspath(SIEM_FILE), "webhook": SIEM_WEBHOOK or None, "syslog": SIEM_SYSLOG or None}


def siem_loop():
    os.makedirs(os.path.dirname(SIEM_FILE) or ".", exist_ok=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if SIEM_SYSLOG else None
    while True:
        ev = _q.get()
        try:
            with open(SIEM_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
            if SIEM_WEBHOOK:
                req = urllib.request.Request(SIEM_WEBHOOK, data=json.dumps(ev).encode(),
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5)
            if sock:
                h, p = SIEM_SYSLOG.rsplit(":", 1)
                sock.sendto(to_syslog(ev).encode(), (h, int(p)))
            siem_stats["forwarded"] += 1
            siem_stats["last_at"] = ev["time"]
        except Exception as ex:
            siem_stats["last_error"] = str(ex)[:200]
        time.sleep(0)


def start_siem():
    threading.Thread(target=siem_loop, daemon=True).start()
