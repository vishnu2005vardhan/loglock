# SakshyaLog on Quai Network (Orchard Cyprus-1)

The organisers require the smart contract to be written and deployed on **Quai Network**. SakshyaLog's `LogAnchor` contract follows the sponsor's **Participant Guide**, their **deployment skill** (installed in `.claude/skills/quai-orchard-deployment-skill/`), and their **reference project** (Hardhat + `quais` SDK + IPFS metadata).

| Setting | Value (from https://docs.qu.ai/build/networks, checked 20 Nov 2026) |
|---|---|
| Network | Quai **Orchard** testnet, zone **Cyprus-1** |
| Chain ID | **15000** |
| RPC | `https://orchard.rpc.quai.network` in `quai/.env` (the `quais` SDK adds `/cyprus1` itself because of `usePathing`). For direct JSON-RPC, such as `verify_pack.py --rpc`, use `https://orchard.rpc.quai.network/cyprus1` |
| Faucet | The docs list https://orchard.faucet.quai.network, but it was offline on 20 Nov 2026. We used the **organisers' QuaiDrop** link with the Pelagus wallet |
| Explorer | https://orchard.quaiscan.io |
| Compiler | Solidity **0.8.20**, EVM **london**, optimizer 1000 runs, IPFS metadata |
| Tools | Hardhat 2, `quais` SDK, `@quai/hardhat-deploy-metadata` |

> Re-check the RPC URL on https://docs.qu.ai/ on the day, as the guide asks.

## Safety rules (from the guide; enforced by our scripts)
- Use a **new, dedicated testnet wallet**. Never a wallet with real funds.
- **Never paste your private key into any chat** or screenshot, and never commit it. `scripts/new-wallet.js` writes it straight into `quai/.env`, which is git-ignored, and never prints it.
- **Do not reuse the `.env` committed in the public reference repository.** Treat it as compromised.
- The deploy script runs a **read-only preflight**, shows exactly what will be sent and the admin powers, and only broadcasts after you type **`DEPLOY`**. Mainnet (chain 9) is refused.
- If the IPFS metadata upload fails, deployment **stops**. It is never skipped silently.

## Steps (Windows: double-click; or run the commands shown)
You need **Node.js LTS** (https://nodejs.org) in addition to Python.

| Step | Double-click | Command (inside `quai/`) | What it does |
|---|---|---|---|
| 1 | `QUAI_1_SETUP_COMPILE_TEST.bat` | `npm install` → `npx hardhat compile` → `npx hardhat test --network hardhat` | Installs the sponsor's toolchain, compiles with 0.8.20 london, runs **19 real tests** |
| 2 | `QUAI_2_NEW_WALLET.bat` | `node scripts/new-wallet.js` | New Cyprus-1 testnet wallet; key saved to `quai/.env` only |
| – | (browser) | — | Get free testnet QUAI for the printed address from the **faucet** |
| 3 | `QUAI_3_PREFLIGHT.bat` | `node scripts/preflight.js` | Checks .env ignored, key, compile, chain 15000, Cyprus-1 address, RPC, balance. **Sends nothing** |
| 4 | `QUAI_4_DEPLOY.bat` | `npx hardhat run scripts/deploy.js --network cyprus1` | Preflight → summary → you type `DEPLOY` → IPFS metadata → `quais.ContractFactory` deploy |
| 5 | `START_DEMO_QUAI.bat` | `python run_demo.py --reset --quai` (project root) | Starts the Quai bridge + SakshyaLog. Every anchor, heartbeat, attestation and incident is a **real Orchard transaction** with a Quaiscan link |

Already using a Pelagus wallet? Put `RPC_URL`, `CHAIN_ID=15000` and `CYPRUS1_PK` in `quai/.env` yourself instead of step 2. The address must be a **Cyprus-1** address (starts with `0x00`).

**Note on running the demo (step 5):** the vault sends transactions from your testnet wallet automatically: an anchor about every minute (every 10 s under attack, instantly on panic), a heartbeat every 30 s in the demo, plus incident and attestation transactions. Starting step 5 is your approval for these **testnet** transactions. Keep the wallet funded from the faucet.

## How it fits together
```
agent ─▶ vault (Python) ─▶ quai bridge (Node, quais SDK, 127.0.0.1:8600) ─▶ Orchard Cyprus-1 ─▶ LogAnchor contract
                                                                                               ▲
                                                 judges / auditors: orchard.quaiscan.io ───────┘
                                                 verify_pack.py --rpc https://orchard.rpc.quai.network/cyprus1
```
Quai transactions use their own format, so they're signed by the official `quais` SDK in `quai/scripts/bridge.js`. The Python vault asks the bridge to send them.

## What the contract enforces (admin powers)
- **Owner = the deployer wallet (the vault).** Only the owner can write. Nobody, including the owner, can change or delete what is already written.
- `anchorBatch`: write-once Merkle roots; batches **must be continuous** (no skipped log lines); the mode (normal / high-alert / panic / manual) is recorded.
- `heartbeat`: public heartbeat; silence is visible on-chain.
- `attestAgent`: hash of the logging agent's code; a swapped agent is flagged (`codeChanged = true`).
- `declareIncident` / `markReported`: the contract fixes the declared time and the **6-hour CERT-In deadline**, and decides whether the report was **on time**.
- No token, no mint, no withdraw, no upgrade, no self-destruct, no external calls.

## Tests (`quai/test/LogAnchor.test.js`, 19 passing)
Deployment owner; first batch must start at line 1; continuous batches; gap rejected; duplicate root rejected; inverted range rejected; independent streams; non-owner rejected (each function); heartbeat time; agent-swap flag; incident 6 h deadline and snapshot anchored; report **on time** at +5 h; **late** at +7 h; double report rejected; unknown incident rejected.

## After deploying: evidence
`quai/deployments/orchard-cyprus1.json` is written automatically (address, tx hash, block, gas, deployer, IPFS hash, ABI path, explorer links). Copy it into `QUAI_DEPLOYMENT_EVIDENCE.md`. Only mark explorer verification as done after you have checked it yourself.

## Troubleshooting
| Problem | Fix |
|---|---|
| `npm install` fails | Install Node.js LTS; check internet |
| Compile error | Must be Solidity 0.8.20 (already configured); run step 1 again |
| Preflight: RPC timed out | `RPC_URL` in `quai/.env` must be `https://orchard.rpc.quai.network` (**without** `/cyprus1`); check internet |
| Preflight: not a Cyprus-1 address | Use `new-wallet.js`, or a Pelagus Cyprus-1 address (starts `0x00`) |
| Preflight: no testnet QUAI | Use the Orchard faucet, then wait a minute |
| Deploy: IPFS metadata upload failed (504) | Quai's server `ipfs.qu.ai` is busy. Retry in a few minutes. Deployment stops on purpose; see **IPFS server down** below |
| Demo: "Quai bridge could not reach Orchard" | See `data/run/quai-bridge.log`; run `npm run preflight` in `quai/` |
| Want to rehearse offline | `python run_demo.py --reset` uses the built-in EVM with the **same** compiled contract. Say so if you demo it |

## IPFS server down (backup, only with organiser approval)
The sponsor's workflow uploads the contract metadata to Quai's IPFS server (`ipfs.qu.ai`) before deploying. If that server keeps returning **504 Gateway time-out**:
1. Retry a few times over 15–20 minutes, and tell the organisers.
2. **Only if they agree**, deploy with the hash computed locally:
   ```cmd
   cd quai
   set QUAI_METADATA_OFFLINE=1
   npx hardhat run scripts\deploy.js --network cyprus1
   ```
   Type `DEPLOY`. When the upload fails, type `OFFLINE`.

The deployed contract is **identical**. The hash is the one the Solidity compiler already embedded in the bytecode, checked against the metadata file. The metadata is saved to `quai/metadata/LogAnchor_metadata.json` and marked `ipfsMetadataUploaded: false` in the deployment record. Upload it when `ipfs.qu.ai` is back, then verify on Quaiscan. Close the CMD window afterwards (or run `set QUAI_METADATA_OFFLINE=`) so the backup isn't left switched on.

## What has and hasn't been tested
- ✅ Compiled with Solidity 0.8.20 / london using the sponsor's Hardhat configuration; **19 tests pass**.
- ✅ The sponsor's `check-project.js`: **9/9 PASS**.
- ✅ Wallet generator (Cyprus-1, Quai ledger), preflight, and the deploy script's safety stops.
- ✅ The full SakshyaLog flow in Quai mode (anchors, panic, heartbeat, attestation, incident, on-time report, evidence pack, one-line proof, Quaiscan links), tested against a stand-in for the bridge.
- ⚠️ **Not yet run against the live Orchard network.** The build environment cannot reach it, so the first real deploy (step 4) and the live demo (step 5) need to be run on your laptop.
