# Use case: protecting a UPI fraud case file

**Same SakshyaLog engine, different evidence.** Problem statement B3 asks us to protect *"security logs and incident evidence"*. A fraud investigation file is incident evidence, and an insider has every reason to rewrite it. This use case shows SakshyaLog protecting it, with the same agent, vault and Quai contract.

> Investigating the money (fund tracing, mule detection) is the job of tools like our earlier Consensus Lien project. SakshyaLog's job is to make sure **nobody can secretly rewrite the investigation evidence**.

## What we kept and what we cut
| Kept (the intersection) | Cut (finance analytics, on the roadmap) |
|---|---|
| Synthetic UPI case file (₹50,000 phishing scenario) | FIFO / proportional / LIBR fund tracing |
| Sealing every case record + anchoring on Quai | Mule-network detection |
| Insider tampering → detection → recovery | Amount attribution and uncertainty |
| Prove one transaction without revealing the rest (⭐5) | Cross-investigation provenance, replay |
| Pseudonymised accounts + hidden mobile / UPI ID (⭐6) | PostgreSQL, large-scale ingestion |

## How it works
1. `demo/upi_case.py` writes **Case UPI-001** line by line: case opened → bank statement → 4 transfers (Victim → A ₹50,000; A → B ₹30,000; A → C ₹20,000; B → D ₹20,000) → note → finding → action → report.
2. A second sealing agent (`HOST_ID=case-UPI-001`) seals each line (hash chain, rotating keys). Personal data is hidden before sealing: the **mobile number** and the **UPI ID** become salted-hash tokens. Accounts are already pseudonymous (`ACC-…`, HMAC of a fake account number with the bank's key).
3. The vault stores it as a **separate evidence stream** and anchors its Merkle roots on the **same LogAnchor contract on Quai** (stream `case-UPI-001@…`). The contract's continuity rule applies to the case too.
4. The vault audits the case file every ~5 s, exactly like the server log.

## Demo (about 90 seconds)
1. Start as usual: `py -3.14 run_demo.py --reset --quai` (or without `--quai` offline). Wait ~30 s while the case file is written and sealed.
2. Open the **🏦 UPI Case** tab: 10 records sealed, **INTACT ✅**, money-flow graph, anchors on Quai.
3. Insider attack: double-click **`ATTACK_CASE.bat`** (or `py -3.14 demo\attack_case.py`). It deletes transfer **T2 (A → B, ₹30,000)** and rewrites the report to drop Account B and close the case.
4. Within seconds: **TAMPERED ❌**, and ⭐8 **self-healing** writes the deleted transfer and the original report **back into the case file**, marked as restored. T2 is drawn **red, dashed: "DELETED on server, recovered + restored"**, the rewritten report is shown next to the sealed original, Merkle proofs are **✅ valid**, and a **panic anchor** fires on Quai.
5. Choose **case-UPI-001** in the sidebar, then **🔎 Prove one line**: prove transfer T1 alone. The other records in its batch stay hidden. Download the proof; `python tools/verify_pack.py proof_line_N.json` → **EVIDENCE IS AUTHENTIC**.
6. **🇮🇳 CERT-In & Court** with case-UPI-001 selected → **Build evidence pack** for the case.

## Responsible design
- **Synthetic data only.** No real accounts, no UPI PINs, OTPs or passwords, ever.
- SakshyaLog **does not decide guilt** and **never freezes accounts**. Humans decide; we only prove the record wasn't changed.
- The blockchain holds **only fingerprints**. No financial data is published on-chain.
- Proving integrity is not proving truth: a record can be authentic and still wrong. The tool shows what was recorded and when.

## Pitch line
> *"SakshyaLog doesn't care what the evidence is: server logs today, a UPI fraud case file tomorrow. If someone tries to erase it, we recover the original and prove it on Quai."*
