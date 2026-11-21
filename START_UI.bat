@echo off
cd /d "%~dp0ui"
where node >nul 2>nul || (echo Node.js not found. Install it from nodejs.org & pause & exit /b)
if not exist dist\index.html (echo Building the website... & call npm install & call npx vite build)
echo Open http://localhost:5173 in your browser
node serve.cjs
pause
