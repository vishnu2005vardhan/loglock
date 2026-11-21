@echo off
title SakshyaLog - Quai step 1: install, compile, test
cd /d "%~dp0quai"
where node >nul 2>nul || (echo Node.js is required. Install the LTS version from https://nodejs.org and try again. & pause & exit /b 1)
call npm install || (echo npm install failed & pause & exit /b 1)
call npx hardhat compile || (echo Compile failed & pause & exit /b 1)
call npx hardhat test --network hardhat
echo.
echo Step 1 done. Next: QUAI_2_NEW_WALLET.bat
pause
