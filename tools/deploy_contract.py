"""Deploy the LogAnchor contract to a real chain and save the settings to .env.

Polygon Amoy testnet (public, judges can see every transaction):
    python tools/deploy_contract.py --rpc https://rpc-amoy.polygon.technology --key 0xYOUR_TESTNET_KEY

Anvil on your laptop (real local Ethereum; start `anvil` first):
    python tools/deploy_contract.py --anvil

Use a TESTNET-ONLY wallet. Never put a wallet holding real money in .env.
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "contracts", "LogAnchor.json")) as _f:
    ARTIFACT = json.load(_f)
# Anvil's first built-in development account (public, local use only)
ANVIL_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


def deploy(w3, key):
    acct = w3.eth.account.from_key(key)
    bal = w3.eth.get_balance(acct.address)
    print(f"Deployer {acct.address}, balance {w3.from_wei(bal, 'ether')} (chain id {w3.eth.chain_id})")
    if bal == 0:
        sys.exit("This wallet has no test tokens. For Amoy, get free POL from a faucet first.")
    factory = w3.eth.contract(abi=ARTIFACT["abi"], bytecode=ARTIFACT["bytecode"])
    tx = factory.constructor().build_transaction({"from": acct.address,
                                                 "nonce": w3.eth.get_transaction_count(acct.address)})
    signed = acct.sign_transaction(tx)
    h = w3.eth.send_raw_transaction(signed.raw_transaction)
    print("Deploying... tx", "0x" + h.hex().removeprefix("0x"))
    rc = w3.eth.wait_for_transaction_receipt(h, timeout=300)
    if rc.status != 1:
        sys.exit("Deployment failed")
    print(f"LogAnchor deployed at {rc.contractAddress} (gas used {rc.gasUsed})")
    return rc.contractAddress


def write_env(values):
    path = os.path.join(ROOT, ".env")
    lines = open(path).read().splitlines() if os.path.exists(path) else []
    keep = [l for l in lines if l.split("=", 1)[0].strip() not in values]
    with open(path, "w") as f:
        f.write("\n".join(keep + [f"{k}={v}" for k, v in values.items()]) + "\n")
    print(f"Saved to {path}. Now start the demo:  python run_demo.py --reset")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", help="RPC URL, e.g. https://rpc-amoy.polygon.technology")
    ap.add_argument("--key", help="private key of a TESTNET-ONLY wallet")
    ap.add_argument("--anvil", action="store_true", help="use Anvil at http://127.0.0.1:8545 with its dev account")
    a = ap.parse_args()
    from web3 import Web3
    rpc = "http://127.0.0.1:8545" if a.anvil else a.rpc
    key = ANVIL_KEY if a.anvil else a.key
    if not rpc or not key:
        ap.error("give --anvil, or both --rpc and --key")
    w3 = Web3(Web3.HTTPProvider(rpc))
    if not w3.is_connected():
        sys.exit(f"Cannot reach {rpc}." + (" Is anvil running in another window?" if a.anvil else ""))
    addr = deploy(w3, key)
    write_env({"CHAIN_MODE": "web3", "RPC_URL": rpc, "PRIVATE_KEY": key, "CONTRACT_ADDRESS": addr})


if __name__ == "__main__":
    main()
