@echo off
title SakshyaLog - Setup
cd /d "%~dp0"
py -3.14 -c "" 2>nul && (set PY=py -3.14) || (where py >nul 2>nul && (set PY=py) || (set PY=python))
echo Installing SakshyaLog requirements...
%PY% -m pip install --upgrade pip
%PY% -m pip install -r requirements.txt
if errorlevel 1 (echo. & echo SETUP FAILED. Is Python 3.10+ installed with "Add to PATH" ticked? & pause & exit /b 1)
echo.
echo Installing the blockchain engine (real Ethereum Virtual Machine)...
%PY% -m pip install -r requirements-blockchain.txt
if errorlevel 1 (echo. & echo WARNING: blockchain engine did not install. The demo will use the SIMULATED ledger. & echo Try Python 3.12 if you are on a very new Python.)
echo.
echo Setup complete! Now double-click START_DEMO.bat
pause
