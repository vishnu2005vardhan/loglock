# Submission Details — The Big Hack 2.0

**Track:** Track 02 – Cybersecurity and Blockchain

**Problem Statement:** B3 – Logs the attacker can't erase

**Project Name:** LogLock

**Idea Description:**
LogLock makes an organisation's security logs tamper-evident and provable, even if an attacker gains root access. Our agent links every log entry into a SHA-256 hash chain, groups entries into Merkle trees, and anchors each Merkle root on a blockchain (Polygon Amoy / Sepolia). An independent verifier re-checks the logs against the on-chain roots and pinpoints exactly which entry was changed and when. To defend against a root attacker, LogLock streams logs instantly to a remote witness, sends heartbeats so that a killed agent becomes evidence, triggers a "panic anchor" when log-wiping commands are run, and uses forward-secure keys so past entries cannot be re-signed. It also generates CERT-In 6-hour incident reports, tracks 180-day retention, and exports a court-ready evidence pack with Merkle proofs. We will evaluate it with an 8-attack test suite comparing plain logs with LogLock, measuring detection rate, time-to-detect, overhead and anchoring cost.

**GitHub Repository:** <paste link here>
