@echo off
title SakshyaLog - Quai step 2: new testnet wallet
cd /d "%~dp0quai"
node scripts\new-wallet.js
echo.
echo Open https://orchard.faucet.quai.network and request testnet QUAI for the address above.
echo Then run QUAI_3_PREFLIGHT.bat
pause
