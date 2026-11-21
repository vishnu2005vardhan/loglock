@echo off
title SakshyaLog - Quai step 4: deploy to Orchard Cyprus-1
cd /d "%~dp0quai"
call npx hardhat run scripts\deploy.js --network cyprus1
echo.
echo If deployed: fill in QUAI_DEPLOYMENT_EVIDENCE.md, then run START_DEMO_QUAI.bat
pause
