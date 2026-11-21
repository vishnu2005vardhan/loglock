#!/usr/bin/env python3
"""SakshyaLog "Don't trust us" verifier.  Open source, Python standard library only.

An auditor, investigator or court can run this WITHOUT trusting the company
that produced the evidence and without installing anything:

    python verify_pack.py evidence_pack.zip          # whole court evidence pack
    python verify_pack.py proof_line_25.json         # one-line proof (selective disclosure)
    python verify_pack.py <file> --rpc https://orchard.rpc.quai.network/cyprus1   # also check Quai live

It independently recomputes every fingerprint, the hash chain, every Merkle
root, every single-line proof and every disclosed personal-data field, and
checks the roots against the blockchain record.
"""
import hashlib
import json
import sys
import urllib.request
import zipfile

OK, BAD, INFO = "[ OK ]", "[FAIL]", "[INFO]"
GENESIS = "0" * 64
SELECTOR_ANCHORED_AT = "9591a610"  # keccak256("anchoredAt(bytes32)")[:4]
failures = 0


def say(status, msg):
    global failures
    if status == BAD:
        failures += 1
    print(f"{status} {msg}")


# ---- the same public algorithms the system uses ----------------------------
def sha256(b):
    return hashlib.sha256(b if isinstance(b, bytes) else b.encode()).hexdigest()


def entry_hash(seq, ts, host, line, prev_hash):
    return sha256(json.dumps([seq, ts, host, line, prev_hash], separators=(",", ":")))


def pair(a, b):
    return sha256(bytes.fromhex(a) + bytes.fromhex(b))


def merkle_root(leaves):
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def verify_proof(leaf, proof, root):
    h = leaf
    for sib, side in proof:
        h = pair(sib, h) if side == "L" else pair(h, sib)
    return h == root


def commit(value, salt):
    return sha256(bytes.fromhex(salt) + value.encode())[:16]


# ---- blockchain check --------------------------------------------------------
def on_chain(root, chain, rpc, ledger_rows):
    """Return unix timestamp the root was anchored at, 0 if absent, None if not checkable."""
    if chain.get("mode") in ("web3", "quai"):  # public chain: ask it directly
        if not rpc:
            return None
        data = "0x" + SELECTOR_ANCHORED_AT + root
        method = "quai_call" if chain.get("mode") == "quai" else "eth_call"  # Quai uses the quai_ namespace
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                           "params": [{"to": chain["contract"], "data": data}, "latest"]}).encode()
        req = urllib.request.Request(rpc, body, {"Content-Type": "application/json"})
        res = json.load(urllib.request.urlopen(req, timeout=20))
        return int(res["result"], 16)
    for row in ledger_rows or []:
        if row["root"] == root:
            return row["ts"]
    return 0


def safe_on_chain(root, chain, rpc, ledger_rows):
    try:
        return on_chain(root, chain, rpc, ledger_rows)
    except Exception as ex:  # network problems are reported, never silently passed
        say(INFO, f"could not query the live chain ({str(ex)[:80]}); check the root on the explorer instead")
        return None


def check_root(root, chain, rpc, ledger_rows, label):
    t = safe_on_chain(root, chain, rpc, ledger_rows)
    if t is None:
        say(INFO, f"{label}: re-run with --rpc {chain.get('public_rpc_hint', '<url>')} to check the live blockchain "
                  f"(contract {chain.get('contract')}, chain id {chain.get('chain_id')})")
    elif t:
        say(OK, f"{label}: root found on blockchain, anchored at unix time {t}")
    else:
        say(BAD, f"{label}: root NOT found on the blockchain record")


# ---- one-line proof ------------------------------------------------------------
def verify_single(p, rpc):
    e = p["entry"]
    print(f"\nOne-line proof for {e['host']} line #{e['seq']}")
    print(f"  line: {e['line']}")
    h = entry_hash(e["seq"], e["ts"], e["host"], e["line"], e["prev_hash"])
    say(OK if h == e["hash"] == p["leaf"] else BAD, "line fingerprint recomputed and matches")
    others = p.get("batch_size", 1) - 1
    say(OK if verify_proof(p["leaf"], p["proof"], p["root"]) else BAD,
        f"Merkle proof leads to root {p['root'][:16]}... using {len(p['proof'])} sibling hash(es); "
        + (f"the other {others} line(s) in this batch stay hidden" if others else "this batch held only this line"))
    if p.get("hidden_personal_fields"):
        say(INFO, f"{p['hidden_personal_fields']} personal-data field(s) in this line stay hidden (salted hashes)")
    for d in p.get("disclosed", []):
        good = d["token"] in e["line"] and d["token"] == f"[[{d['kind']}:{commit(d['value'], d['salt'])}]]"
        say(OK if good else BAD, f"disclosed {d['kind']} '{d['value']}' matches its sealed commitment")
    check_root(p["root"], p["chain"], rpc, p.get("ledger_rows"), "anchor")


# ---- full evidence pack --------------------------------------------------------
def verify_pack(z, rpc):
    names = z.namelist()
    base = names[0].split("/")[0] + "/" if "/" in names[0] else ""
    read = lambda n: z.read(base + n).decode()
    manifest = json.loads(read("manifest.json"))
    print(f"\nEvidence pack for {manifest['host']} generated {manifest['generated_at']}")

    for name, digest in manifest["files_sha256"].items():
        say(OK if sha256(z.read(base + name)) == digest else BAD, f"file {name} is unaltered")

    entries = [json.loads(l) for l in read("entries.jsonl").splitlines() if l.strip()]
    prev, expected, bad = GENESIS, entries[0]["seq"] if entries else 1, 0
    if entries and entries[0]["seq"] != 1:
        prev = entries[0]["prev_hash"]
    for e in entries:
        if e["seq"] != expected or e["prev_hash"] != prev or \
                entry_hash(e["seq"], e["ts"], e["host"], e["line"], e["prev_hash"]) != e["hash"]:
            bad += 1
            say(BAD, f"entry #{e['seq']} breaks the chain")
        prev, expected = e["hash"], e["seq"] + 1
    if not bad:
        say(OK, f"hash chain of all {len(entries)} entries is unbroken (#{entries[0]['seq']} to #{entries[-1]['seq']})")

    by_seq = {e["seq"]: e["hash"] for e in entries}
    batches = json.loads(read("batches.json"))
    rec = next((n for n in ("chain_record.jsonl", "ledger.jsonl") if n in manifest["files_sha256"]), None)
    ledger_rows = [json.loads(l) for l in read(rec).splitlines() if l.strip()] if rec else None
    mode = manifest["chain"].get("mode")
    say(INFO, f"blockchain: {manifest['chain'].get('name')}"
              + (f", contract {manifest['chain'].get('contract')}" if manifest["chain"].get("contract") else "")
              + (" (public chain, checked live)" if mode in ("web3", "quai") and rpc else
                 " (record exported from the chain)" if mode == "evm" else
                 " (SIMULATED offline ledger)" if mode == "local" else ""))
    good = 0
    for b in batches:
        leaves = [by_seq[s] for s in range(b["start_seq"], b["end_seq"] + 1)]
        if merkle_root(leaves) != b["root"]:
            say(BAD, f"batch #{b['start_seq']}-{b['end_seq']} Merkle root does not match")
            continue
        t = safe_on_chain(b["root"], manifest["chain"], rpc, ledger_rows)
        if t == 0:
            say(BAD, f"batch #{b['start_seq']}-{b['end_seq']} root not on blockchain")
        elif t is not None:
            good += 1
    live = manifest["chain"].get("mode") in ("web3", "quai")
    say(OK if good == len(batches) else BAD if rpc or not live else INFO,
        f"{good} of {len(batches)} Merkle roots recomputed and found on the blockchain record"
        + ("" if rpc or not live else f" (add --rpc {manifest['chain'].get('public_rpc_hint', '<url>')} to check the live chain)"))

    findings = json.loads(read("findings.json"))
    for f in findings.get("findings", []):
        if f["status"] in ("DELETED", "MODIFIED") and f["seq"] in by_seq:
            say(OK, f"line #{f['seq']} {f['status']} on the server is proven by the sealed record: "
                    f"{f['vault_line'][:70]}")
    print(f"\nVerdict on server log: {findings.get('verdict', 'n/a')}")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    rpc = sys.argv[sys.argv.index("--rpc") + 1] if "--rpc" in sys.argv else None
    if rpc in args:
        args.remove(rpc)
    if not args:
        print(__doc__)
        sys.exit(2)
    path = args[0]
    print("SakshyaLog independent verifier (no trust in the log owner required)")
    if path.endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            verify_pack(z, rpc)
    else:
        with open(path, encoding="utf-8") as f:
            verify_single(json.load(f), rpc)
    print("\nRESULT:", "EVIDENCE IS AUTHENTIC - all integrity checks passed" if failures == 0
          else f"{failures} CHECK(S) FAILED - do not rely on this evidence")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
