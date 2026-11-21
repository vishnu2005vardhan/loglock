@echo off
title SakshyaLog - ATTACKER
cd /d "%~dp0"
py -3.14 -c "" 2>nul && (set PY=py -3.14) || (where py >nul 2>nul && (set PY=py) || (set PY=python))
%PY% demo\attack.py
echo.
pause
