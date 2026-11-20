# 🔒 LogLock — Logs the Attacker Can't Erase

**The Big Hack 2.0 · Track 02: Cybersecurity and Blockchain · Problem Statement B3**

> **Hack the server. Delete the logs. Still get caught.**
> Tamper-evident security logs and incident evidence, provable to an auditor or court — even if the attacker has root access.

---

## 🚨 The Problem

Servers, applications and network devices write logs that record who logged in, which commands ran and what changed. After a break-in, investigators rely on these logs — but an attacker with **root access can edit or delete them**. The company then cannot show what happened, and an auditor or court cannot trust the logs that remain.

CERT-In requires Indian organisations to keep logs for **180 days** and report specified incidents within **6 hours**, yet logs on a compromised machine cannot be trusted.

## 💡 Our Solution

LogLock makes every log entry **tamper-evident** (any change is detected, even if it cannot be prevented) and **provable** to an outsider:

1. **Salted hash chain** – each entry is salted and linked to the previous one with SHA-256. Changing one entry breaks every link after it.
2. **Merkle batching** – thousands of entries are compressed into one Merkle root every few seconds.
3. **Blockchain anchoring** – each Merkle root is written to the `LogAnchor` smart contract on **Polygon Amoy**. Anchored roots cannot be changed by anyone, including root.
4. **Independent verifier** – auditors re-hash the logs and check them against the chain, pinpointing **exactly which line was changed, deleted or inserted, and when** — without trusting the company.

**Why blockchain is essential:** a company controls its own database and servers. The on-chain anchor is what lets an outsider verify the logs without trusting the company. Remove it and the logs are no longer provable.

## ⭐ Built to Beat a Root Attacker

Root controls the server, so LogLock keeps the proof **off the server**.

| Feature | What it does | Attack it defeats |
|---|---|---|
| 📮 **Remote witness** | Every line is streamed to a separate, append-only witness the moment it is written | Editing logs before they are anchored |
| 🔑 **Key kept off the server** | Only the witness holds the blockchain key and anchors Merkle roots | Stealing the key to anchor fake records |
| 💓 **Heartbeat** | Agent reports to the witness every few seconds with its latest chain hash | Killing the agent; faking "I'm alive" messages |
| 🚨 **Panic anchor** | Watches the log file itself — if it shrinks, is truncated, deleted, renamed or replaced, anchors immediately | `rm`, `> file`, `shred`, editor edits |
| 🔄 **Forward-secure keys** | Signing keys evolve (`k_next = H(k)`) and old keys are destroyed | Re-signing past entries after compromise |
| 🕐 **Independent clocks** | Compares server time with witness receive time and block time | Changing the system clock |
| 📶 **Offline queue** | Lines are buffered locally and sent when the network returns; gaps are flagged | Cutting the network |
| 🔍 **Selective disclosure** | Prove one log line to a court with a Merkle proof, without revealing the rest | Privacy leaks |

### 🧭 Honest threat model

No system can stop a root attacker from writing *new* false entries. LogLock guarantees the integrity of **every log written before a compromise** and makes **the compromise itself visible** (heartbeat loss, panic anchor, witness mismatch). Logs written after that point are flagged as **untrusted** on the dashboard and in the evidence pack.

## 🇮🇳 Compliance & Evidence Features

- **CERT-In 6-hour incident report** generator
- **180-day retention** tracker with proofs
- **Evidence pack** for auditors and courts: logs, hashes, transaction IDs, Merkle proofs and a verify script (designed to support electronic-evidence requirements)
- **Attack timeline** reconstruction with trusted 🟢 / untrusted 🟠 / tampered 🔴 markers
- **Alerts** via Telegram or email

## 🏗️ Architecture

```
 SERVER (may be compromised)              REMOTE WITNESS (separate)          BLOCKCHAIN
 ┌───────────────────────┐  every line   ┌───────────────────────┐  root   ┌──────────────┐
 │ LogLock Agent         │ ────────────► │ Append-only storage   │ ──────► │ LogAnchor.sol│
 │ • file watcher        │   heartbeat   │ • own chain head      │         │ Polygon Amoy │
 │ • salted hash chain   │ ────────────► │ • own clock           │         │ (only the    │
 │ • offline queue       │               │ • holds blockchain key│         │  witness can │
 │ • NO blockchain key   │               │ • alarms              │         │  anchor)     │
 └───────────────────────┘               └───────────┬───────────┘         └──────────────┘
                                                     ▼
                              Verifier + Dashboard → 🟢 trusted / 🟠 untrusted / 🔴 tampered
                                                   → CERT-In report, evidence pack
```

## 🧪 Evaluation Plan (before vs after)

| Attack | Plain logs | LogLock (target) |
|---|---|---|
| Edit a line | Not detected | Detected, exact line |
| Delete lines | Not detected | Detected |
| Insert fake lines | Not detected | Detected |
| Reorder lines | Not detected | Detected |
| Wipe or truncate the file | Not detected | Panic anchor + witness copy |
| Kill the agent | Not detected | Heartbeat missed |
| Change the system clock | Not detected | Skew > ~60 s flagged |
| Rebuild the chain with fake hashes | Not detected | On-chain root mismatch |

**Metrics:** detection rate, time-to-detect, false positives, agent CPU/memory overhead, logs/sec throughput, anchoring cost per day.

_Results will be filled in after running the test suite._

## 🛠️ Tech Stack

- **Agent:** Python (hashlib, watchdog), Docker
- **Remote witness:** Python / Node.js, append-only storage
- **Smart contract:** Solidity, Foundry, Polygon Amoy
- **Verifier & dashboard:** Python / Node.js, React
- **Alerts:** Telegram / email

## 📁 Repository Structure

```
agent/       Log watcher, salted hash chain, heartbeat, offline queue
contracts/   LogAnchor.sol smart contract
verifier/    CLI + API to verify logs against on-chain roots
dashboard/   Web dashboard (timeline, reports, evidence pack)
tests/       8-attack test suite
docs/        Architecture and presentation material
```

## 🚀 How to Run

_Setup instructions coming soon._

## 👥 Team

_Add team member names here._

## 📜 License

MIT
