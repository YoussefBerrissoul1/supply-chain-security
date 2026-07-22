@echo off
REM ============================================================
REM start.bat — Script de démarrage Supply Chain Security
REM Youssef BERRISSOUL — ENSIASD Taroudant — PFE 2026
REM ============================================================
REM Ce script démarre le backend FastAPI et le frontend React
REM en parallèle dans deux fenêtres séparées.

echo.
echo  ███████╗███████╗ ██████╗    ██████╗ ██╗      █████╗ ████████╗███████╗
echo  ██╔════╝██╔════╝██╔════╝    ██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔════╝
echo  ███████╗█████╗  ██║         ██████╔╝██║     ███████║   ██║   █████╗
echo  ╚════██║██╔══╝  ██║         ██╔═══╝ ██║     ██╔══██║   ██║   ██╔══╝
echo  ███████║███████╗╚██████╗    ██║     ███████╗██║  ██║   ██║   ███████╗
echo  ╚══════╝╚══════╝ ╚═════╝    ╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝
echo.
echo  Supply Chain Security Platform — PFE 2026
echo  Youssef BERRISSOUL — SITCN 4 — ENSIASD Taroudant
echo.
echo  ============================================================
echo.

REM --- Vérification Python ---
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Python n'est pas installe ou pas dans le PATH.
    echo Installez Python 3.12+ depuis https://python.org
    pause
    exit /b 1
)

REM --- Vérification Node.js ---
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Node.js n'est pas installe ou pas dans le PATH.
    echo Installez Node.js 18+ depuis https://nodejs.org
    pause
    exit /b 1
)

echo [1/3] Démarrage du Backend FastAPI (port 8000)...
echo.
start "NEXORA Backend" cmd /k "cd /d %~dp0backend && echo Activation du venv... && venv\Scripts\activate && echo Démarrage du serveur... && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"

timeout /t 3 /nobreak >nul

echo [2/3] Démarrage du Frontend React (port 5173)...
echo.
start "NEXORA Frontend" cmd /k "cd /d %~dp0frontend && if not exist node_modules (echo Installation des dependances... && npm install) && echo Demarrage du serveur Vite... && npm run dev"

timeout /t 5 /nobreak >nul

echo [3/3] Application démarrée !
echo.
echo  ┌─────────────────────────────────────────────────┐
echo  │  Frontend  : http://localhost:5173              │
echo  │  Backend   : http://localhost:8000              │
echo  │  API Docs  : http://localhost:8000/docs         │
echo  │  Scan Page : http://localhost:5173/scan         │
echo  └─────────────────────────────────────────────────┘
echo.
echo  Appuyez sur une touche pour fermer cette fenêtre.
echo  Les serveurs continueront à tourner dans leurs fenêtres.
echo.
pause
