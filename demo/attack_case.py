"""Insider attack on the UPI case file (works on Windows, Mac, Linux).

Someone with admin access to the investigation server tries to protect
Account B: deletes the A -> B transfer (T2) and rewrites the report so
Account B disappears from it.

    python demo/attack_case.py [path-to-case-file]
"""
import re
import sys

LOG = sys.argv[1] if len(sys.argv) > 1 else "demo/logs/case_upi001.log"

print("=" * 60 + "\n  INSIDER TERMINAL (investigation server)\n" + "=" * 60)
with open(LOG) as f:
    lines = f.readlines()
if not any("TXN T2" in l for l in lines):
    sys.exit("[insider] T2 not found. Has the case file finished writing? Wait ~30 s after start.")

kept, removed, edited = [], 0, 0
for line in lines:
    if "| TXN T2 |" in line:
        removed += 1
        continue
    if "| REPORT |" in line:
        line = re.sub(r"INR 50000 traced: .*?Status:",
                      "INR 50000 traced: Account C received INR 20000; remaining funds not traceable. Status:", line)
        line = line.replace("under review", "closed")
        edited += 1
    kept.append(line)

with open(LOG, "w") as f:
    f.writelines(kept)
print(f"[insider] Deleted transfer T2 (Account A -> Account B, INR 30000): {removed} line")
print(f"[insider] Rewrote the final report to drop Account B and close the case: {edited} line")
print("[insider] The case file on this server now hides Account B. Check the SakshyaLog 'UPI Case' tab...")
