# 🔒 LogLock — Logs the Attacker Can't Erase

**The Big Hack 2.0 · Track 02: Cybersecurity and Blockchain · Problem Statement B3**

> Tamper-evident security logs that stay provable to an auditor or court — even if the attacker has root access.

---

## 🚨 The Problem

When a company is hacked, investigators rely on logs to find out what happened. But an attacker with **root access can edit or delete those logs**, destroying the evidence. CERT-In requires Indian organisations to keep logs for **180 days** and report incidents within **6 hours** — yet logs on a compromised machine cannot be trusted.

## 💡 Our Solution

LogLock makes every log entry **tamper-evident and provable**:

1. **Hash chain** – every log entry is linked to the previous one with SHA-256. Changing one entry breaks every entry after it.
2. **Merkle batching** – thousands of entries are compressed into a single Merkle root every few seconds.
3. **Blockchain anchoring** – the Merkle root is written to a smart contract (Polygon Amoy / Sepolia). Once anchored, nobody — not even root — can change it.
4. **Independent verifier** – an auditor re-hashes the logs and checks them against the chain, pinpointing **exactly which line changed and when**.

### ⭐ What makes LogLock different (defending against a root attacker)

| Feature | What it does |
|---|---|
| **Remote witness** | Each entry is streamed off-box instantly, closing the window before anchoring |
| **Heartbeat (dead-man's switch)** | If the agent is killed, the missing heartbeat becomes evidence |
| **Panic anchor** | Log-wiping commands (`rm /var/log`, `history -c`, `journalctl --vacuum`) trigger an immediate anchor |
| **Forward-secure keys** | Signing keys evolve and old keys are destroyed, so past entries cannot be re-signed |
| **Selective disclosure** | Prove a single log line to a court with a Merkle proof, without revealing all logs |
| **Adaptive anchoring** | Anchors more often during suspicious activity, less often when quiet |

### 🇮🇳 Compliance & evidence features
- CERT-In 6-hour incident report generator
- 180-day retention tracker with proofs
- Downloadable court-ready evidence pack (logs, hashes, tx IDs, Merkle proofs, verify script)
- Attack timeline reconstruction

## 🏗️ Architecture

```
 Server logs (auth.log, nginx, app)
          │
          ▼
 ┌──────────────────┐   stream    ┌──────────────────┐
 │  LogLock Agent   │ ──────────► │  Remote Witness   │ (append-only store)
 │  hash chain +    │             └──────────────────┘
 │  Merkle batching │   heartbeat
 └────────┬─────────┘
          │ Merkle root
          ▼
 ┌──────────────────┐
 │  LogAnchor.sol   │  Polygon Amoy / Sepolia
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────┐
 │ Verifier + Web   │ → 🟢 verified / 🔴 "entry #4213 changed at 15:42"
 │ Dashboard        │ → CERT-In report, evidence pack
 └──────────────────┘
```

## 🧪 Evaluation Plan (before vs after)

| Attack | Plain logs | LogLock |
|---|---|---|
| Edit a line | ❌ | ✅ |
| Delete lines | ❌ | ✅ |
| Insert fake lines | ❌ | ✅ |
| Reorder lines | ❌ | ✅ |
| Wipe the whole file | ❌ | ✅ |
| Kill the agent | ❌ | ✅ |
| Change the system clock | ❌ | ✅ |
| Rebuild the chain with fake hashes | ❌ | ✅ |

Metrics: detection rate, time-to-detect, false positives, agent CPU/memory overhead, logs/sec throughput, anchoring cost per day.

## 🛠️ Tech Stack
- **Agent:** Python (hashlib, watchdog), Docker
- **Smart contract:** Solidity, Foundry/Hardhat, Polygon Amoy / Sepolia
- **Verifier & backend:** Python / Node.js
- **Dashboard:** React
- **Alerts:** Telegram / email

## 📁 Repository Structure
```
agent/       Log collector, hash chain, Merkle batching, heartbeat
contracts/   LogAnchor.sol smart contract
verifier/    CLI + API to verify logs against on-chain roots
dashboard/   Web dashboard (health timeline, reports)
tests/       Attack test suite
docs/        Architecture and presentation material
```

## 👥 Team
_Add team member names here._

## 📜 Status
🚧 Under active development for The Big Hack 2.0, Bengaluru.
