"""Blockchain backends for the SakshyaLog vault.

CHAIN_MODE=evm   (default) a real Ethereum Virtual Machine runs inside the vault
                 (py-evm). The real compiled LogAnchor contract is deployed and
                 every anchor is a real signed transaction in a real block.
                 Needs:  pip install -r requirements-blockchain.txt
CHAIN_MODE=web3  any real EVM chain over RPC: Polygon Amoy testnet, or Anvil /
                 Hardhat on your laptop. Needs RPC_URL, PRIVATE_KEY,
                 CONTRACT_ADDRESS (deploy with tools/deploy_contract.py).
CHAIN_MODE=quai  Quai Network, Orchard Cyprus-1 testnet (the sponsor's network). The
                 contract is deployed with quai/scripts/deploy.js (Hardhat + quais),
                 and transactions are signed by quai/scripts/bridge.js using the
                 official quais SDK. run_demo.py --quai starts the bridge.
CHAIN_MODE=local last-resort offline ledger file (hash-linked JSON lines) with
                 the same rules as the contract. Say so openly if you demo it.
"""
import json
import os
import threading
import time

from common import sha256

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "contracts", "LogAnchor.json")) as _f:
    ARTIFACT = json.load(_f)
MODES = {"normal": 0, "high-alert": 1, "panic": 2, "manual": 3}


class ChainError(Exception):
    pass


# --------------------------------------------------------------------------
class LocalLedger:
    """Offline stand-in that mimics LogAnchor's rules in a hash-linked file."""
    name = "offline-ledger (simulated)"

    def __init__(self, path=os.getenv("LEDGER_PATH", "data/ledger.jsonl")):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.lock = threading.Lock()

    def _rows(self):
        if not os.path.exists(self.path):
            return []
        with open(self.path) as f:
            return [json.loads(l) for l in f if l.strip()]

    def _write(self, row):
        with self.lock:
            rows = self._rows()
            row["ts"] = int(time.time())
            row["prev"] = rows[-1]["tx"] if rows else "0" * 64
            row["tx"] = "0x" + sha256(json.dumps(row, sort_keys=True))
            with open(self.path, "a") as f:
                f.write(json.dumps(row) + "\n")
            return row

    def anchor(self, stream, root, frm, to, mode):
        last = max([r["to"] for r in self._rows() if r["type"] == "anchor" and r["stream"] == stream] or [0])
        if frm != last + 1:
            raise ChainError("gap: batches must be continuous")
        if self.anchored_at(root):
            raise ChainError("already anchored")
        return self._write({"type": "anchor", "stream": stream, "root": root, "from": frm, "to": to, "mode": mode})["tx"], 0

    def anchored_at(self, root):
        return next((r["ts"] for r in self._rows() if r.get("root") == root), 0)

    def heartbeat(self, stream):
        return self._write({"type": "heartbeat", "stream": stream})["tx"], 0

    def last_heartbeat(self, stream):
        return max([r["ts"] for r in self._rows() if r["type"] == "heartbeat" and r["stream"] == stream] or [0])

    def attest(self, stream, code_hash, key_commit):
        first = next((r for r in self._rows() if r["type"] == "attest" and r["stream"] == stream), None)
        row = self._write({"type": "attest", "stream": stream, "code_hash": code_hash, "key_commit": key_commit,
                           "changed": bool(first and first["code_hash"] != code_hash)})
        return row["tx"], 0

    def attestations(self, stream):
        return [{"code_hash": r["code_hash"], "key_commit": r["key_commit"], "timestamp": r["ts"]}
                for r in self._rows() if r["type"] == "attest" and r["stream"] == stream]

    def declare_incident(self, stream, snapshot, note):
        n = len([r for r in self._rows() if r["type"] == "incident"])
        row = self._write({"type": "incident", "id": n, "stream": stream, "root": snapshot, "note": note})
        return n, row["tx"], 0

    def mark_reported(self, inc_id, report_hash):
        inc = next(r for r in self._rows() if r["type"] == "incident" and r["id"] == inc_id)
        if any(r for r in self._rows() if r["type"] == "reported" and r["id"] == inc_id):
            raise ChainError("already reported")
        row = self._write({"type": "reported", "id": inc_id, "report_hash": report_hash,
                           "on_time": int(time.time()) <= inc["ts"] + 6 * 3600})
        return row["tx"], row["on_time"]

    def get_incident(self, inc_id):
        inc = next(r for r in self._rows() if r["type"] == "incident" and r["id"] == inc_id)
        rep = next((r for r in self._rows() if r["type"] == "reported" and r["id"] == inc_id), None)
        return {"declared_at": inc["ts"], "deadline": inc["ts"] + 6 * 3600, "snapshot_root": inc["root"],
                "reported_at": rep["ts"] if rep else 0, "on_time": rep["on_time"] if rep else False}

    def export_rows(self):
        return [{"root": r["root"], "ts": r["ts"], "tx": r["tx"]} for r in self._rows() if r.get("root")]

    def tx_url(self, tx):
        return ""

    def info(self):
        return {"mode": "local", "name": self.name, "simulated": True}


# --------------------------------------------------------------------------
class EVMLedger:
    """Talks to the real LogAnchor contract on any EVM chain."""

    def __init__(self, w3, contract, sender, key=None, name="evm", explorer="", mode="web3"):
        self.w3, self.c, self.sender, self.key = w3, contract, sender, key
        self.name, self.explorer, self.mode = name, explorer, mode
        self.lock = threading.Lock()  # one transaction at a time = no nonce clashes

    def _send(self, fn):
        with self.lock:
            try:
                if self.key:  # remote chain: sign locally with the vault's key
                    tx = fn.build_transaction({"from": self.sender,
                                               "nonce": self.w3.eth.get_transaction_count(self.sender, "pending")})
                    signed = self.w3.eth.account.sign_transaction(tx, self.key)
                    h = self.w3.eth.send_raw_transaction(signed.raw_transaction)
                else:          # built-in EVM: unlocked dev account
                    h = fn.transact({"from": self.sender})
                rc = self.w3.eth.wait_for_transaction_receipt(h, timeout=180)
            except Exception as ex:
                raise ChainError(str(ex)) from ex
            if rc.status != 1:
                raise ChainError("transaction reverted")
            return "0x" + h.hex().removeprefix("0x"), rc

    def anchor(self, stream, root, frm, to, mode):
        tx, rc = self._send(self.c.functions.anchorBatch(stream, bytes.fromhex(root), frm, to, MODES.get(mode, 0)))
        return tx, rc.gasUsed

    def anchored_at(self, root):
        return self.c.functions.anchoredAt(bytes.fromhex(root)).call()

    def heartbeat(self, stream):
        tx, rc = self._send(self.c.functions.heartbeat(stream))
        return tx, rc.gasUsed

    def last_heartbeat(self, stream):
        return self.c.functions.lastHeartbeat(self.w3.keccak(text=stream)).call()

    def attest(self, stream, code_hash, key_commit):
        tx, rc = self._send(self.c.functions.attestAgent(stream, bytes.fromhex(code_hash), bytes.fromhex(key_commit)))
        return tx, rc.gasUsed

    def attestations(self, stream):
        n = self.c.functions.attestationCount(stream).call()
        out = []
        for i in range(n):
            a = self.c.functions.getAttestation(stream, i).call()
            out.append({"code_hash": a[0].hex(), "key_commit": a[1].hex(), "timestamp": a[2]})
        return out

    def declare_incident(self, stream, snapshot, note):
        inc_id = self.c.functions.incidentCount().call()
        tx, rc = self._send(self.c.functions.declareIncident(stream, bytes.fromhex(snapshot), note))
        return inc_id, tx, rc.gasUsed

    def mark_reported(self, inc_id, report_hash):
        tx, _ = self._send(self.c.functions.markReported(inc_id, bytes.fromhex(report_hash)))
        return tx, self.get_incident(inc_id)["on_time"]

    def get_incident(self, inc_id):
        i = self.c.functions.getIncident(inc_id).call()
        return {"declared_at": i[2], "deadline": i[3], "snapshot_root": i[1].hex(),
                "reported_at": i[4], "on_time": i[6]}

    def export_rows(self):
        """Anchor events read back from the chain (for offline checking of the built-in EVM)."""
        rows = []
        for ev in self.c.events.Anchored.get_logs(from_block=0):
            rows.append({"root": ev.args.root.hex(), "ts": ev.args.timestamp, "tx": "0x" + ev.transactionHash.hex().removeprefix("0x")})
        for i in range(self.c.functions.incidentCount().call()):
            inc = self.get_incident(i)
            rows.append({"root": inc["snapshot_root"], "ts": inc["declared_at"], "tx": "incident-%d" % i})
        return rows

    def tx_url(self, tx):
        return self.explorer + tx if self.explorer else ""

    def info(self):
        d = {"currency": "test ETH", "mode": self.mode, "name": self.name, "chain_id": self.w3.eth.chain_id, "contract": self.c.address,
             "block_number": self.w3.eth.block_number, "simulated": False}
        if self.mode == "web3":
            # never expose RPC_URL (it may contain an API key) or the private key
            d["explorer_tx_url"] = self.explorer
            d["public_rpc_hint"] = os.getenv("PUBLIC_RPC", "https://rpc-amoy.polygon.technology")
        return d


# --------------------------------------------------------------------------
class QuaiLedger:
    """LogAnchor on Quai Network via the local quais bridge (quai/scripts/bridge.js)."""
    mode = "quai"
    min_fast_interval = 10  # Quai blocks take a few seconds; don't flood the testnet

    def __init__(self, url=os.getenv("QUAI_BRIDGE_URL", "http://127.0.0.1:8600")):
        import requests
        self.r, self.url = requests, url
        self._info, self._info_t = None, 0
        i = self.info(force=True)
        self.name, self.explorer = i["name"], i["explorer"]
        print(f"[chain] Quai: {i['name']}, contract {i['contract']}, wallet {i['wallet']} ({i['balance']} QUAI)")

    def _post(self, path, body, timeout=240):
        try:
            res = self.r.post(self.url + path, json=body, timeout=timeout)
        except Exception as ex:
            raise ChainError(f"Quai bridge not reachable: {ex}") from ex
        data = res.json()
        if res.status_code != 200:
            raise ChainError(data.get("error", res.text))
        return data

    def _send(self, fn, *args):
        d = self._post("/send", {"fn": fn, "args": list(args)})
        return d["tx"], int(d["gasUsed"])

    def _read(self, fn, *args):
        return self._post("/read", {"fn": fn, "args": list(args)}, timeout=20)["result"]

    def anchor(self, stream, root, frm, to, mode):
        return self._send("anchorBatch", stream, "0x" + root, frm, to, MODES.get(mode, 0))

    def anchored_at(self, root):
        return int(self._read("anchoredAt", "0x" + root))

    def heartbeat(self, stream):
        return self._send("heartbeat", stream)

    def last_heartbeat(self, stream):
        return int(self._read("lastHeartbeat", {"keccak": stream}))

    def attest(self, stream, code_hash, key_commit):
        return self._send("attestAgent", stream, "0x" + code_hash, "0x" + key_commit)

    def attestations(self, stream):
        out = []
        for i in range(int(self._read("attestationCount", stream))):
            a = self._read("getAttestation", stream, i)
            a = a if isinstance(a, dict) else {"codeHash": a[0], "keyCommitment": a[1], "timestamp": a[2]}
            out.append({"code_hash": a["codeHash"][2:], "key_commit": a["keyCommitment"][2:], "timestamp": int(a["timestamp"])})
        return out

    def declare_incident(self, stream, snapshot, note):
        inc_id = int(self._read("incidentCount"))
        tx, gas = self._send("declareIncident", stream, "0x" + snapshot, note)
        return inc_id, tx, gas

    def mark_reported(self, inc_id, report_hash):
        tx, _ = self._send("markReported", inc_id, "0x" + report_hash)
        return tx, self.get_incident(inc_id)["on_time"]

    def get_incident(self, inc_id):
        i = self._read("getIncident", inc_id)
        if not isinstance(i, dict):
            i = dict(zip(["stream", "snapshotRoot", "declaredAt", "deadline", "reportedAt", "reportHash",
                          "reportedOnTime", "note"], i))
        return {"declared_at": int(i["declaredAt"]), "deadline": int(i["deadline"]),
                "snapshot_root": i["snapshotRoot"][2:], "reported_at": int(i["reportedAt"]),
                "on_time": bool(i["reportedOnTime"])}

    def export_rows(self):
        rows = self.r.get(self.url + "/anchors", timeout=120).json()
        return rows if isinstance(rows, list) else []

    def tx_url(self, tx):
        return f"{self.explorer}/tx/{tx}" if tx and tx.startswith("0x") else ""

    def info(self, force=False):
        if force or not self._info or time.time() - self._info_t > 15:
            try:
                i = self.r.get(self.url + "/info", timeout=30 if force else 5).json()
                if "error" in i:
                    raise ChainError(i["error"])
                self._info, self._info_t = i, time.time()
            except Exception as ex:
                if force:
                    raise ChainError(f"Quai bridge not reachable: {ex}") from ex
                self._info_t = time.time()  # keep the last known info; try again in 15 s
        i = self._info
        return {"mode": "quai", "name": i["name"], "chain_id": i["chainId"], "contract": i["contract"],
                "block_number": i["blockNumber"], "wallet": i["wallet"], "balance": i["balance"],
                "explorer": i["explorer"], "explorer_address": f"{i['explorer']}/address/{i['contract']}",
                "deploy_tx": i.get("deployTx"), "currency": "QUAI", "simulated": False,
                "public_rpc_hint": "https://orchard.rpc.quai.network/cyprus1"}


def _builtin_evm():
    from web3 import EthereumTesterProvider, Web3
    w3 = Web3(EthereumTesterProvider())
    sender = w3.eth.accounts[0]
    factory = w3.eth.contract(abi=ARTIFACT["abi"], bytecode=ARTIFACT["bytecode"])
    rc = w3.eth.wait_for_transaction_receipt(factory.constructor().transact({"from": sender}))
    c = w3.eth.contract(address=rc.contractAddress, abi=ARTIFACT["abi"])
    print(f"[chain] built-in EVM started, LogAnchor deployed at {rc.contractAddress}")
    return EVMLedger(w3, c, sender, name="built-in EVM (py-evm)", mode="evm")


def _rpc_chain():
    from web3 import Web3
    w3 = Web3(Web3.HTTPProvider(os.environ["RPC_URL"]))
    if not w3.is_connected():
        raise ChainError(f"cannot reach RPC_URL {os.environ['RPC_URL']}")
    acct = w3.eth.account.from_key(os.environ["PRIVATE_KEY"])
    c = w3.eth.contract(address=Web3.to_checksum_address(os.environ["CONTRACT_ADDRESS"]), abi=ARTIFACT["abi"])
    if not w3.eth.get_code(c.address):
        raise ChainError(f"no contract at {c.address} on this chain. Run tools/deploy_contract.py")
    cid = w3.eth.chain_id
    names = {80002: "Polygon Amoy testnet", 31337: "Anvil (local Ethereum)", 1337: "local Ethereum"}
    explorer = os.getenv("EXPLORER_TX_URL", "https://amoy.polygonscan.com/tx/" if cid == 80002 else "")
    print(f"[chain] connected to {names.get(cid, 'chain ' + str(cid))}, contract {c.address}")
    return EVMLedger(w3, c, acct.address, key=os.environ["PRIVATE_KEY"],
                     name=names.get(cid, f"EVM chain {cid}"), explorer=explorer, mode="web3")


def get_ledger():
    mode = os.getenv("CHAIN_MODE", "evm")
    if mode == "quai":
        return QuaiLedger()
    if mode == "web3":
        return _rpc_chain()
    if mode == "evm":
        try:
            return _builtin_evm()
        except ImportError:
            print("[chain] WARNING: blockchain packages missing (pip install -r requirements-blockchain.txt). "
                  "Falling back to the SIMULATED offline ledger.")
    return LocalLedger()
