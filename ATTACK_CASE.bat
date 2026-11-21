@echo off
title SakshyaLog - INSIDER edits the UPI case file
cd /d "%~dp0"
py -3.14 -c "" 2>nul && (set PY=py -3.14) || (where py >nul 2>nul && (set PY=py) || (set PY=python))
%PY% demo\attack_case.py
echo.
pause
