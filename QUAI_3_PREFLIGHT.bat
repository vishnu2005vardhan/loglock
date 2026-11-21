@echo off
title SakshyaLog - Quai step 3: preflight (sends nothing)
cd /d "%~dp0quai"
node scripts\preflight.js
pause
