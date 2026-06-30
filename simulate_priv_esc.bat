REM simulate_priv_esc.bat
REM Demo script to simulate privilege escalation
@echo off
echo.
echo ========================================
echo   SIMULATED PRIVILEGE ESCALATION DEMO
echo ========================================
echo.
echo Running privilege escalation check...
timeout /t 2 /nobreak >nul
echo.
echo Starting demo whoami + ping process (for monitoring)...
whoami /priv
echo.
echo Now running a longer process to simulate attack persistence...
start "" ping -n 10 127.0.0.1
echo.
echo [!] Suspected privilege escalation activity detected!
timeout /t 15 /nobreak >nul
