"""Shared crypto helpers for SakshyaLog (used by agent and vault)."""
import hashlib
import hmac
import json

GENESIS = "0" * 64


def sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def entry_hash(seq: int, ts: str, host: str, line: str, prev_hash: str) -> str:
    """Fingerprint of one log entry, linked to the previous entry (hash chain)."""
    return sha256(json.dumps([seq, ts, host, line, prev_hash], separators=(",", ":")))


# ---- Forward-secure key ratchet -------------------------------------------
# key_{n+1} = SHA256("ratchet" || key_n). The agent deletes key_n after
# stepping. An attacker who steals key_n can NOT compute key_{n-1}, so they
# cannot forge MACs on entries sealed before the break-in. The vault keeps
# key_0 (given once at setup) and can derive every epoch key to verify.

def next_key(key: bytes) -> bytes:
    return hashlib.sha256(b"ratchet" + key).digest()


def key_for_epoch(key0: bytes, epoch: int) -> bytes:
    k = key0
    for _ in range(epoch):
        k = next_key(k)
    return k


def mac(key: bytes, h: str) -> str:
    return hmac.new(key, h.encode(), hashlib.sha256).hexdigest()


# ---- Merkle tree -----------------------------------------------------------

def _pair(a: str, b: str) -> str:
    return sha256(bytes.fromhex(a) + bytes.fromhex(b))


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return GENESIS
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(leaves: list[str], index: int) -> list[tuple[str, str]]:
    """Return [(sibling_hash, 'L'|'R'), ...] from leaf to root."""
    proof, level, i = [], list(leaves), index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sib = i ^ 1
        proof.append((level[sib], "L" if sib < i else "R"))
        level = [_pair(level[j], level[j + 1]) for j in range(0, len(level), 2)]
        i //= 2
    return proof


def verify_proof(leaf: str, proof: list, root: str) -> bool:
    h = leaf
    for sib, side in proof:
        h = _pair(sib, h) if side == "L" else _pair(h, sib)
    return h == root


# ---- ⭐6 Privacy-safe redaction (salted hash commitments) -----------------
# Personal data (emails, Indian phone numbers, Aadhaar-style numbers) is
# replaced in the sealed line by a token  [[kind:commitment]]  where
# commitment = SHA256(salt || value)[:16]. The hash chain and blockchain only
# ever see the token. The real value + salt are stored separately in the
# vault, so a person's data can be erased (DPDP Act) without breaking the
# chain, or revealed to a court one field at a time.
import os as _os
import re as _re

PII_PATTERNS = [
    ("upi", r"(?<![\w.@-])[A-Za-z0-9._-]{2,}@(?:ok[a-z]+|ybl|ibl|axl|paytm|apl|upi|sbi|icici|hdfcbank|axisbank)(?![\w.])"),
    ("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"),
    ("aadhaar", r"(?<![\w-])[2-9]\d{3}[ -]\d{4}[ -]\d{4}(?![\w-])"),
    ("phone", r"(?<![\d.])(?:\+91[ -]?)?[6-9]\d{9}(?![\d.])"),
]
_PII_RE = [(k, _re.compile(p)) for k, p in PII_PATTERNS]
TOKEN_RE = _re.compile(r"\[\[(upi|email|aadhaar|phone):([0-9a-f]{16})\]\]")


def commit(value: str, salt: str) -> str:
    return sha256(bytes.fromhex(salt) + value.encode())[:16]


def redact(line: str):
    """Return (redacted_line, reveals) where reveals = [{token, kind, value, salt}]."""
    reveals = []
    for kind, rx in _PII_RE:
        def sub(m, kind=kind):
            salt = _os.urandom(16).hex()
            token = f"[[{kind}:{commit(m.group(0), salt)}]]"
            reveals.append({"token": token, "kind": kind, "value": m.group(0), "salt": salt})
            return token
        line = rx.sub(sub, line)
    return line, reveals


def unredact(line: str, values: dict) -> str:
    """values: token -> real value. Unknown (erased) tokens stay as tokens."""
    return TOKEN_RE.sub(lambda m: values.get(m.group(0), m.group(0)), line)


def normalize_pii(line: str) -> str:
    """Replace any PII or token by its kind only, for erasure-tolerant comparison."""
    line = TOKEN_RE.sub(lambda m: f"[[{m.group(1)}]]", line)
    for kind, rx in _PII_RE:
        line = rx.sub(f"[[{kind}]]", line)
    return line


# ---- ⭐3 Panic patterns (evidence-destroying commands) ----------------------
PANIC_PATTERNS = [
    (r"\brm\b[^\n]*(/var/log|\.log\b|auth\.log|syslog|wtmp|btmp|lastlog)", "deleting log files"),
    (r"\b(shred|truncate|wipe)\b[^\n]*(/var/log|\.log\b)", "shredding / truncating logs"),
    (r"\bsed\b[^\n]*-i[^\n]*(/var/log|\.log\b)", "editing a log file in place"),
    (r">\s*/var/log/", "overwriting a log file"),
    (r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|HISTFILE=/dev/null", "erasing shell history"),
    (r"\bjournalctl\b[^\n]*--(vacuum|rotate)", "vacuuming the systemd journal"),
    (r"\b(systemctl|service)\b[^\n]*\b(stop|disable|mask)\b[^\n]*\b(rsyslog|syslog|auditd|journald|sakshya)", "stopping the logging service"),
    (r"\bauditctl\b[^\n]*-(D|e\s*0)", "disabling the audit system"),
    (r"\b(pkill|killall|kill)\b[^\n]*(agent|sakshya|rsyslog|auditd)", "killing the logger"),
    (r"\bwevtutil\b[^\n]*\bcl\b|Clear-EventLog", "clearing Windows event logs"),
]
_PANIC_RE = [(_re.compile(p, _re.I), why) for p, why in PANIC_PATTERNS]


def panic_reason(line: str):
    for rx, why in _PANIC_RE:
        if rx.search(line):
            return why
    return None




# ---- ⭐8 Self-healing ---------------------------------------------------------
# A line put back by SakshyaLog after an attacker deleted or changed it starts
# with this marker, so it is never mistaken for an original and never re-triggers
# alarms (e.g. a restored "sed -i ... auth.log" line must not fire a new panic).
HEAL_MARKER = "[SAKSHYALOG RESTORED"


def is_restored(line: str) -> bool:
    return line.lstrip().startswith(HEAL_MARKER)


def heal_tag(seq) -> str:
    return f"{HEAL_MARKER} seq={seq} "
