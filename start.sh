#!/bin/bash
# ============================================================
# start.sh — Script de démarrage Supply Chain Security
# Youssef BERRISSOUL — ENSIASD Taroudant — PFE 2026
# ============================================================

set -e

# Couleurs
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo ""
echo -e "${BLUE}███████╗███████╗ ██████╗    ██████╗ ██╗      █████╗ ████████╗███████╗${NC}"
echo -e "${BLUE}██╔════╝██╔════╝██╔════╝    ██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔════╝${NC}"
echo -e "${BLUE}███████╗█████╗  ██║         ██████╔╝██║     ███████║   ██║   █████╗  ${NC}"
echo -e "${BLUE}╚════██║██╔══╝  ██║         ██╔═══╝ ██║     ██╔══██║   ██║   ██╔══╝  ${NC}"
echo -e "${BLUE}███████║███████╗╚██████╗    ██║     ███████╗██║  ██║   ██║   ███████╗${NC}"
echo -e "${BLUE}╚══════╝╚══════╝ ╚═════╝    ╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝${NC}"
echo ""
echo -e "${GREEN}Supply Chain Security Platform — PFE 2026${NC}"
echo -e "${GREEN}Youssef BERRISSOUL — SITCN 4 — ENSIASD Taroudant${NC}"
echo ""
echo "============================================================"
echo ""

# --- Répertoire racine du projet
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# --- Vérifications ---
if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
    echo -e "${RED}[ERREUR] Python non trouvé. Installez Python 3.12+${NC}"
    exit 1
fi

if ! command -v node &>/dev/null; then
    echo -e "${RED}[ERREUR] Node.js non trouvé. Installez Node.js 18+${NC}"
    exit 1
fi

PYTHON_CMD="python3"
command -v python3 &>/dev/null || PYTHON_CMD="python"

echo -e "${YELLOW}[1/2] Démarrage du Backend FastAPI (port 8000)...${NC}"
cd "$SCRIPT_DIR/backend"

# Activer le venv si disponible
if [ -d "venv" ]; then
    source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null || true
fi

# Lancer le backend en arrière-plan
$PYTHON_CMD -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
echo -e "${GREEN}  Backend PID: $BACKEND_PID${NC}"

sleep 2

echo ""
echo -e "${YELLOW}[2/2] Démarrage du Frontend React (port 5173)...${NC}"
cd "$SCRIPT_DIR/frontend"

# Installer les dépendances si nécessaire
if [ ! -d "node_modules" ]; then
    echo "  Installation des dépendances npm..."
    npm install
fi

# Lancer le frontend en arrière-plan
npm run dev &
FRONTEND_PID=$!
echo -e "${GREEN}  Frontend PID: $FRONTEND_PID${NC}"

sleep 3

echo ""
echo "┌─────────────────────────────────────────────────────────┐"
echo "│                                                         │"
echo "│   Frontend  : http://localhost:5173                    │"
echo "│   Backend   : http://localhost:8000                    │"
echo "│   API Docs  : http://localhost:8000/docs               │"
echo "│   Scan Page : http://localhost:5173/scan               │"
echo "│                                                         │"
echo "│   Ctrl+C pour arrêter les deux serveurs                │"
echo "│                                                         │"
echo "└─────────────────────────────────────────────────────────┘"
echo ""

# Attendre Ctrl+C
trap "echo ''; echo 'Arrêt des serveurs...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" SIGINT SIGTERM
wait
