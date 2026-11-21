@echo off
title SakshyaLog on Quai Network (close this window or press Ctrl+C to stop)
cd /d "%~dp0"
py -3.14 -c "" 2>nul && (set PY=py -3.14) || (where py >nul 2>nul && (set PY=py) || (set PY=python))
%PY% run_demo.py --reset --quai
pause
