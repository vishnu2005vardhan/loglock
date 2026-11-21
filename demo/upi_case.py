"""Synthetic UPI fraud case file (use case: protecting investigation evidence).

Writes Case UPI-001 line by line, the way an investigation system would log
it. SakshyaLog seals every line exactly like a server log and anchors it on
Quai. ALL DATA IS SYNTHETIC. Account numbers are already pseudonymised
(ACC-xxxxxxxx = HMAC-SHA256 of a fake account number with the bank's case key),
and the complainant's mobile number and UPI ID are hidden by SakshyaLog's
privacy redaction (⭐6) before sealing.

Run:  python demo/upi_case.py --log demo/logs/case_upi001.log
"""
import argparse
import hashlib
import hmac
import os
import time
from datetime import datetime, timedelta

CASE_KEY = b"demo-bank-case-key"  # held by the bank, never by SakshyaLog


def pseudo(account_no: str) -> str:
    return "ACC-" + hmac.new(CASE_KEY, account_no.encode(), hashlib.sha256).hexdigest()[:8]


VICTIM, A, B, C, D = (pseudo(x) for x in ("50100123456789", "60200987654321", "70300555511112",
                                          "80400777733334", "90500999955556"))
ACCOUNT_ROLES = {VICTIM: "Victim", A: "Account A", B: "Account B", C: "Account C", D: "Account D"}


def case_lines(start: datetime):
    t = lambda m: (start + timedelta(minutes=m)).strftime("%Y-%m-%d %H:%M")
    return [
        f"{t(0)} | CASE UPI-001 | OPENED | investigator INV-07 | complaint NCRP-2026-1120-4471 | "
        f"complainant mobile 9876501234, UPI riya.k@okaxis | phishing link reported",
        f"{t(3)} | CASE UPI-001 | EVIDENCE | statement received from Bank-X for {VICTIM} | file sha256 9c1f2e7a",
        f"{t(5)} | CASE UPI-001 | TXN T1 | FROM {VICTIM} (Victim) | TO {A} (Account A) | INR 50000 | UTR 432110987654 | SUCCESS",
        f"{t(6)} | CASE UPI-001 | TXN T2 | FROM {A} (Account A) | TO {B} (Account B) | INR 30000 | UTR 432110987721 | SUCCESS",
        f"{t(7)} | CASE UPI-001 | TXN T3 | FROM {A} (Account A) | TO {C} (Account C) | INR 20000 | UTR 432110987733 | SUCCESS",
        f"{t(11)} | CASE UPI-001 | TXN T4 | FROM {B} (Account B) | TO {D} (Account D) | INR 20000 | UTR 432110987802 | SUCCESS",
        f"{t(14)} | CASE UPI-001 | NOTE | {B} (Account B) still holds INR 10000 of the inflow",
        f"{t(16)} | CASE UPI-001 | FINDING | {A} forwarded the full INR 50000 within 2 minutes "
        f"(rapid onward transfer: an indicator for review, not proof of fraud)",
        f"{t(18)} | CASE UPI-001 | ACTION | investigator requests KYC for {B} from Bank-Y (human decision, no automatic freeze)",
        f"{t(20)} | CASE UPI-001 | REPORT | INR 50000 traced: {B} (Account B) received INR 30000, "
        f"{C} (Account C) received INR 20000, {D} (Account D) received INR 20000 from {B}. Status: under review",
    ]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="demo/logs/case_upi001.log")
    ap.add_argument("--interval", type=float, default=2.0)
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.log), exist_ok=True)
    if os.path.exists(a.log) and os.path.getsize(a.log) > 0:
        print("[case] case file already exists, not rewriting it")
    else:
        print(f"[case] writing synthetic Case UPI-001 to {a.log}")
        for line in case_lines(datetime.now() - timedelta(minutes=25)):
            with open(a.log, "a") as f:
                f.write(line + "\n")
            time.sleep(a.interval)
        print("[case] case file complete")
    while True:  # stay alive so the launcher treats it like the other services
        time.sleep(3600)
