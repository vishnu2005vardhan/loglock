# 🔏 SakshyaLog: logs the attacker can't erase

**Problem (B3, Cybersecurity & Blockchain):** an attacker with root access can delete or edit a server's logs, so after a breach nobody can trust them.
**Our answer:** seal every log line the moment it's written, ship it off the server, anchor its fingerprint on a blockchain, and let any auditor or court verify it with one click.

> We can't *prevent* a root attacker from touching the logs. We make sure **every touch is detected and the original survives** (tamper-evident).


> ### ⛓️ Quai Network (required by the organisers)
> The `LogAnchor` smart contract is built and deployed on **Quai Network, Orchard Cyprus-1 (chain 15000)**, following the sponsor's guide, skill and Hardhat + `quais` reference project. **See [QUAI.md](QUAI.md)**: 4 double-click steps (setup/compile/test → new wallet → preflight → deploy), then `START_DEMO_QUAI.bat`.


> ### 🏦 Use case: UPI fraud case file
> The same engine protects a **UPI fraud investigation file** as a second evidence stream on the same Quai contract. An insider who deletes a transfer or rewrites the report is caught, and the originals are recovered and proven. **See [USE_CASE_UPI.md](USE_CASE_UPI.md)**. Attack: `ATTACK_CASE.bat`. Dashboard tab: **🏦 UPI Case**.

## How it works

```
 server-01 (victim)                 VAULT (separate machine)               BLOCKCHAIN
┌──────────────────┐  sealed  ┌────────────────────────────┐  root/60s ┌─────────────┐
│ auth.log         │ entries  │ checks seq + chain + MAC    │──────────▶│ LogAnchor   │
│   ▲              │ ───────▶ │ append-only (WORM) storage  │           │ .sol        │
│ Seal Agent       │  ~1 s    │ Merkle batching, alerts     │           └─────────────┘
│ hash-chain +     │ heartbeat│ heartbeat watchdog, audits  │◀── Dashboard / Verifier
│ ratcheting key   │ ───────▶ │ CERT-In 6 h incident clock  │    (Streamlit)
└──────────────────┘          └────────────────────────────┘
```

| Layer | What it does | Defeats |
|---|---|---|
| **Hash chain + sequence no.** (`common.py`) | Each entry contains the hash of the previous one | Silent edits, deletions, reordering |
| **Forward-secure key ratchet** | Key evolves every 60 s, old key destroyed. Vault holds key₀ and derives all keys | Forging *past* entries with a key stolen at break-in |
| **Off-host vault, append-only** (`vault/api.py`) | Copy leaves the server within ~1 s. SQLite triggers forbid UPDATE/DELETE | Deleting evidence on the server |
| **Blockchain anchor** (`contracts/LogAnchor.sol`) | Merkle root of each batch stored on-chain with a timestamp. **Only hashes, no log data** | Anyone (even the company) rewriting history later |
| **Heartbeat watchdog** | Agent pings every 5 s. Silence raises an alert | Attacker killing the logger |
| **🚨 Panic anchor** | Agent spots evidence-destroying commands (`rm /var/log…`, `sed -i …log`, `history -c`, `journalctl --vacuum`, `systemctl stop rsyslog/auditd`, `kill agent`, `wevtutil cl`…) or the log file being truncated, ships everything instantly, and the vault anchors on-chain **immediately**, not at the next 60 s cycle | Attacker changing logs in the gap *before* the next blockchain anchor |
| **Verifier** | Upload a server log → DELETED / MODIFIED / INJECTED lines + Merkle proof against the chain | Lets auditors and courts check without trusting the company |
| **Freeze evidence** | Anchors a snapshot immediately and starts the CERT-In 6-hour countdown | Disputes about "what we knew when we reported" |

## ⭐ What makes us different

Most teams anchor logs on a blockchain every few minutes. A root attacker simply edits the logs **before** the next anchor, or switches the logger off. SakshyaLog closes both gaps, adds privacy and Indian legal compliance, and **repairs the evidence by itself**.

| # | Feature | Simple meaning | Where in code |
|---|---|---|---|
| ⭐1 | **Instant off-box copy** | Every page is photocopied to a friend's house the moment it's written (~0.05 s), so the thief arrives too late | `agent.py` → `/ingest` |
| ⭐2 | **Heartbeat / dead-man's switch** | The logger says "I'm alive!" every 5 s. If it goes quiet, the alarm rings | `heartbeat_loop`, `watchdog_loop` |
| ⭐3 | **Panic anchor** | A "delete the diary" command instantly puts a fingerprint on the blockchain, before anything is lost | `common.PANIC_PATTERNS`, `/panic` |
| ⭐4 | **Forward-secure keys** | The lock key changes every minute and the old key is destroyed, so even root can't re-sign old pages | `common.next_key()` |
| ⭐5 | **Show one page without revealing the rest** | Prove one line to a court with a Merkle proof; the other lines stay hidden | `/proof/{host}/{seq}`, 🔎 tab |
| ⭐6 | **Privacy-safe redaction** | Emails, phone numbers and Aadhaar numbers become salted hashes *before* sealing. Reveal one field to a court, or erase a person's data (DPDP Act) without breaking the chain | `common.redact()`, `/erase-pii` |
| ⭐8 | **Self-healing logs** | When an attacker deletes or edits sealed lines, SakshyaLog **writes the originals back by itself** within seconds, marked `[SAKSHYALOG RESTORED seq=… proof=root … tx …]`, never disguised as untouched. Delete them again and they come back again | `agent.heal_loop`, `/heal-plan`, `/self-healed` |
| ⭐7 | **Adaptive anchoring** | Anchor every 60 s normally; **every 2 s** after brute force, a root login, root commands or exfiltration | `suspicion()`, `anchor_loop` |

### 🇮🇳 India + legal features

| Feature | What it does | Where |
|---|---|---|
| **CERT-In 6-hour report generator** | One click fills in an incident report draft: categories, times, attacker IPs, indicators, timeline, blockchain evidence | 🇮🇳 tab → `/report/certin` |
| **180-day retention tracker** | "Logs kept safely for X", lock-until date, and anchors confirmed on blockchain | Live + 🇮🇳 tabs → `/retention` |
| **Court-ready evidence pack** | ZIP: sealed logs, fingerprints, Merkle roots, tx IDs, findings, timeline, retention record, report with Section 63 BSA certificate draft, and the verifier | `/evidence-pack` |
| **"Don't trust us" verifier** | `tools/verify_pack.py`, open source, **standard Python only**. Re-checks everything independently, including the live blockchain with `--rpc` | `tools/verify_pack.py` |
| **Attack timeline** | Brute force → became root → data theft → evidence destruction → tampering detected, rebuilt from the sealed copy | 🕵️ tab → `/timeline` |

**Check evidence yourself (any computer with Python):**
```
python tools/verify_pack.py sakshyalog_evidence_server-01_XXXX.zip
python tools/verify_pack.py proof_line_34.json
```

## ▶️ Run it (Windows, 3 double-clicks)

Requires **Python 3.10 or newer** (python.org, with ✅ "Add Python to PATH" ticked during install).

| Step | Double-click | What happens |
|---|---|---|
| 1 (first time only) | **`SETUP.bat`** | Installs the requirements |
| 2 | **`START_DEMO.bat`** | Starts vault + victim server + agent + dashboard, and opens **http://localhost:8501** |
| 3 | **`ATTACK.bat`** | 😈 The hacker logs in as root, steals data, deletes the evidence. 🚨 Panic anchor fires instantly, and the dashboard turns 🔴 within about 10 s |
| 4 (optional) | **`ATTACK_KILL_AGENT.bat`** | Same attack, and it also **kills the logging agent**. About 20 s later the 💀 heartbeat alarm fires (⭐2). Restart with START_DEMO.bat afterwards |

Then in the dashboard:
- **📊 Live**: 8 defence cards; ⭐7 switches to "every 2 s" during the attack
- **🕵️ Attack timeline**: the whole attack, step by step, including the steps the hacker deleted
- **✅ Verify**: "Verify live server log" → ❌ TAMPERED, originals recovered, blockchain proof, evidence report
- **🔎 Prove one line**: pick a line, choose which personal data to reveal, download the proof file; DPDP erasure
- **🇮🇳 CERT-In & Court**: freeze evidence (on-chain incident + 6 h deadline), mark reported (on-time flag decided on-chain), retention tracker, CERT-In report, court evidence pack
- **⛓️ Blockchain**: contract rules, public heartbeat, agent attestation, incident registry, live transactions, cost per server per month
To stop, close the START_DEMO window (or press Ctrl+C). Each start begins with fresh data.

**From CMD instead:** `python -m pip install -r requirements.txt`, then `python run_demo.py --reset`, then `python demo\attack.py` in a second window.
**Mac / Linux:** `python3 -m pip install -r requirements.txt`, then `./start_demo.sh`, then `python3 demo/attack.py`.
**Docker:** `docker compose up --build`, then `docker compose exec server python demo/attack.py /logs/auth.log`.

Logs from each component are in `data/run/*.log` if something goes wrong.
By default the vault runs a **built-in real EVM** with the LogAnchor contract (no internet needed). See the ⛓️ section.

## ⛓️ The blockchain

**Default: a real Ethereum Virtual Machine, built in.** `SETUP.bat` installs `requirements-blockchain.txt` (web3 + py-evm). When the vault starts, it deploys the real compiled `LogAnchor` contract to a built-in EVM, and every anchor, heartbeat, attestation and incident is a **real signed transaction in a real block**. The dashboard's ⛓️ tab shows the contract address, block number, transactions and measured gas. If those packages are missing, the demo falls back to a **simulated** offline ledger and says so clearly.

**The smart contract enforces rules even the company can't break** (`contracts/LogAnchor.sol`):

| Rule | What it proves |
|---|---|
| Continuous batches (`fromSeq == lastSeq + 1`) | No range of log lines can be skipped |
| Anchor mode recorded (normal / high-alert / panic / manual) | The panic anchor is visible on-chain |
| Public heartbeat | If the logger is silenced, the silence is visible on the chain |
| Agent attestation (code hash) | A swapped or modified logging agent is detected |
| Incident registry + 6-hour deadline + on-time flag | When the company knew, and whether it reported to CERT-In on time; the contract decides, not the company |

**Minimal on-chain, by design:** only 32-byte fingerprints go on-chain, never log text or personal data, so it's DPDP-safe and cheap. Measured: about 60,000 gas per anchor, the same however many lines are in the batch.

### Other EVM chains (optional, not used for the hackathon): Polygon Amoy
1. Install MetaMask, add **Polygon Amoy**, get free test POL from a faucet. Use a **testnet-only** wallet.
2. Deploy the contract and save the settings in one command:
   ```
   python tools/deploy_contract.py --rpc https://rpc-amoy.polygon.technology --key 0xYOUR_TESTNET_KEY
   ```
3. `python run_demo.py --reset`. The ⛓️ tab now links every transaction to **amoy.polygonscan.com**.
4. Judges can verify the evidence pack against the public chain:
   `python verify_pack.py pack.zip --rpc https://rpc-amoy.polygon.technology`

### Or a local chain: Anvil
Start `anvil` (from Foundry) in another window, then:
```
python tools/deploy_contract.py --anvil
python run_demo.py --reset
```
To go back to the built-in EVM, delete the `.env` file.

The compiled contract (`contracts/LogAnchor.json`, solc 0.8.20, EVM version london, the same build deployed on Quai) is included, so you don't need a compiler. You can also deploy `LogAnchor.sol` with Remix.

## 🎬 5-minute demo script
1. **Normal day:** dashboard green, lines flowing, personal data shown as `[[email:…]]` (⭐6), anchoring every 20–60 s.
2. **Attack:** `ATTACK.bat`. 4 failed root logins → **⭐7 switches to HIGH ALERT, anchoring every 2 s** → root login → `scp customers.sql` → `sed -i` on auth.log → **⭐3 panic anchor** → lines deleted → fake line blaming `rahul`.
3. **♻️ Self-healing:** within ~5 s the deleted lines **reappear in the server log**, marked `[SAKSHYALOG RESTORED …]` with their Quai proof (⭐8 card on 📊 Live). *"Other systems tell you the evidence was erased. SakshyaLog puts it back."*
4. **🕵️ Timeline:** brute force → became root → exfiltration → evidence destruction → tampering detected. The fake line is flagged *"logged AFTER evidence destruction began; may be planted"*.
4. **✅ Verify:** TAMPERED, all deleted lines recovered, Merkle proofs valid → download the evidence report.
5. **🔎 Prove one line (⭐5 + ⭐6):** prove the root-login line alone; reveal one customer email to the court and keep the rest hidden. Erase a customer (DPDP) → Verify again → chain still valid.
6. **🇮🇳 CERT-In & Court:** Freeze evidence (the **smart contract** records the incident and the 6 h deadline) → Mark reported (**on-time flag decided on-chain**) → generate the CERT-In report → build the evidence pack → run `python verify_pack.py pack.zip`: **"EVIDENCE IS AUTHENTIC"**, checked with no trust in us.
7. **⛓️ Blockchain tab:** contract address, live transactions, measured gas, ₹ per server per month. Say the line: *"Minimal on-chain, by design: the blockchain is our neutral notary."*
8. **Optional:** `ATTACK_KILL_AGENT.bat` → ⭐2 heartbeat 💀, and the on-chain heartbeat stops too.

## Honest limits (say these to judges)
- **Window of exposure:** lines not yet shipped (< 1 s) or not yet anchored (< 30–60 s) are only as safe as the vault.
- **Post-compromise lies:** after taking root, an attacker can make the server log false things. We prove *when* and *unchanged*, not *truth*.
- **Stopping the logger** can't be prevented. It shows up as a heartbeat alert.
- **Vault security matters:** in production it's a separate account or cloud with different credentials, and storage like S3 Object Lock (compliance mode, 180-day retention).
- The "scheduled audit" in the demo reads the server log through a read-only volume. In production this would be a periodic pull by the auditor or SIEM.

## Production roadmap
S3 Object Lock / MinIO WORM · multi-server agents (rsyslog/journald input) · Ed25519 forward-secure signatures · permissioned chain (Hyperledger Fabric) with auditor + regulator nodes · RFC 3161 timestamps · direct submission to CERT-In's portal · Hindi and regional-language reports.

## Files
```
common.py              hash chain, key ratchet, Merkle tree + proofs, PII redaction, panic patterns
agent/agent.py         Seal Agent (runs on the protected server)
vault/api.py           Vault API: ingest checks, WORM store, anchoring, alerts, verify, incident
vault/chain.py         blockchain backends (web3 / offline local ledger)
vault/reports.py       evidence report + CERT-In report (HTML, print to PDF)
tools/verify_pack.py   'don't trust us' verifier (standard library only)
contracts/LogAnchor.sol smart contract (roots, continuity, heartbeat, attestation, incident registry)
contracts/LogAnchor.json compiled ABI + bytecode (same 0.8.20 build as quai/)
quai/                  Quai Network: Hardhat project, tests, wallet/preflight/deploy scripts, quais bridge
.claude/skills/quai-orchard-deployment-skill/  sponsor's deployment skill
tools/deploy_contract.py deploy to Polygon Amoy / Anvil and write .env
app/app.py             Streamlit dashboard + verifier + CERT-In clock
demo/log_generator.py  fake server traffic
demo/upi_case.py       synthetic UPI fraud case file (use case)
demo/attack_case.py    insider edits the case file
demo/attack.py         the hacker (--kill-agent also kills the logger; attack.sh = older Linux version)
run_demo.py            one-click launcher (used by START_DEMO.bat)
SETUP.bat / START_DEMO.bat / ATTACK.bat   Windows double-click scripts
```

## New website (React)

The backend has not changed. The website reads the same vault API on port 8000.

1. Window 1: `py -3.14 run_demo.py --reset --quai` (or `START_DEMO_QUAI.bat`)
2. Window 2: `START_UI.bat` (or `cd ui` then `node serve.cjs`)
3. Open http://localhost:5173
4. Window 3: `py -3.14 demo\attack.py` and `py -3.14 demo\attack_case.py`

`ui/dist` is already built, so Node.js is the only requirement. To edit the website: `cd ui`, `npm install`, `npm run dev`.
The Streamlit dashboard on http://localhost:8501 still works as a backup.

## Reliability (Quai mode)

- If the Quai network is slow or the bridge stops, every page keeps working. Seal times fall back to
  the vault's own record and the page says so. The website never waits on the blockchain to load.
- Seals already confirmed on Quai are cached, so Verify gets faster after the first check.
- If a page ever hits a problem, it shows "Reload this page" instead of going blank.

# SakshyaLog 2.0

Everything above still works the same. 2.0 adds:

| # | Feature | Where to see it |
|---|---|---|
| 1 | Exact tamper detection: names the field and the character that changed (Monisha → Manisha, o → a) | Verify, Attack lab |
| 2 | Pre-change protection: approve a change first; only that exact text is allowed, anything else is flagged and reverted | Change control |
| 3 | Real-time tamper monitoring: the agent watches the file and reports any edit to existing lines in about 1 second | Attack lab, Overview |
| 4 | Verified recovery: the original is checked (hash + Merkle proof) before it is restored | Verify, alerts |
| 5 | Multi-server protection: server-01, server-02 and the UPI case file, each with its own agent, one vault, one contract | All machines |
| 6 | Key custody: sealing key stored with Windows DPAPI (or a TPM/HSM via PKCS#11), never in plain text | Hardening |
| 7 | Independent auditor portal: check a proof file in the browser, read-only | Auditor portal |
| 8 | SIEM integration: every alert as JSON lines, CEF or syslog (Splunk, Sentinel, QRadar, Wazuh) | Hardening |
| 9 | Immutable storage: every sealed batch as a read-only, hash-linked file (optional S3 Object Lock) | Hardening |
| 10 | Advanced attack testing: delete, change one character, change a timestamp, insert a fake line, kill the logger, approved change | Attack lab |
| 11 | Evidence provenance: origin, source signature, history, blockchain, read-only copy, machine copy, and how many independent sources agree | Prove one line, Auditor portal |

Run: `py -3.14 run_demo.py --reset --quai`. The website opens by itself at http://localhost:5173.

Options: `KEY_CUSTODY=auto|dpapi|pkcs11|software`, `SIEM_WEBHOOK=https://…`, `SIEM_SYSLOG=host:514`,
`WORM_S3_BUCKET=bucket-with-object-lock`. The attack lab only runs in demo mode (`LAB_ENABLED=1`, set by run_demo.py).
