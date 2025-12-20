#!/bin/bash

# ==============================================================================
# TOR FORENSIC ANALYSIS SYSTEM - LAUNCHER
# Runs FastAPI backend + React Vite frontend
# ==============================================================================

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║          TOR FORENSIC ANALYSIS SYSTEM                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

cleanup() {
    echo -e "\n${YELLOW}Shutting down...${NC}"
    kill $API_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    exit 0
}
trap cleanup SIGINT SIGTERM

# Activate venv if exists (silently)
[ -d ".venv" ] && source .venv/bin/activate

# Quick dependency check (only install if missing)
if ! python3 -c "import fastapi" &> /dev/null; then
    echo -e "${YELLOW}Installing Python dependencies (one-time)...${NC}"
    pip3 install -r requirements.txt -q
fi

if [ ! -d "webapp/node_modules" ]; then
    echo -e "${YELLOW}Installing frontend dependencies (one-time)...${NC}"
    cd webapp && npm install --silent && cd ..
fi

# Launch services
echo -e "${BLUE}Starting services...${NC}"

# Force Python to not use cached bytecode
export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1
export QUIET_MODE=true

python3 api.py 2>&1 &
API_PID=$!
sleep 1

cd webapp && npm run dev -- --host 2>&1 | head -5 &
FRONTEND_PID=$!
cd ..
sleep 2

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ SYSTEM ONLINE${NC}"
echo ""
echo -e "   Frontend:  ${BLUE}http://localhost:5173${NC}"
echo -e "   API:       ${BLUE}http://localhost:8000${NC}"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

wait $API_PID $FRONTEND_PID
