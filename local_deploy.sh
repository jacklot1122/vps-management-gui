#!/bin/bash
# =============================================================================
# LOCAL DEPLOY SCRIPT
# Push files directly from your laptop to your VPS and restart the screen
# =============================================================================

# ===== CONFIGURATION - EDIT THESE =====
VPS_USER="root"                           # Your VPS username
VPS_HOST="51.161.131.61"                  # Your VPS IP
VPS_PASSWORD=""                           # Leave empty if using SSH key
REMOTE_PATH="/home/ubuntu/betfair-bot"    # Where to deploy on VPS
SCREEN_NAME="betfairbot"                  # Screen session name
MAIN_FILE="main.py"                       # File to run
PYTHON_CMD="python3"                      # Python command
VENV_PATH=""                              # Optional: /path/to/venv (leave empty if not using)
# =======================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get the directory to deploy (default: current directory)
LOCAL_DIR="${1:-.}"

echo -e "${YELLOW}╔════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║       LOCAL DEPLOY TO VPS              ║${NC}"
echo -e "${YELLOW}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "Local:  ${GREEN}$LOCAL_DIR${NC}"
echo -e "Remote: ${GREEN}$VPS_USER@$VPS_HOST:$REMOTE_PATH${NC}"
echo -e "Screen: ${GREEN}$SCREEN_NAME${NC}"
echo ""

# Step 1: Sync files to VPS
echo -e "${YELLOW}[1/3] Syncing files to VPS...${NC}"

# Build rsync exclude list
EXCLUDES="--exclude='.git' --exclude='__pycache__' --exclude='*.pyc' --exclude='.DS_Store' --exclude='venv' --exclude='.venv' --exclude='node_modules'"

if [ -n "$VPS_PASSWORD" ]; then
    # Use sshpass if password is provided
    if ! command -v sshpass &> /dev/null; then
        echo -e "${RED}Error: sshpass not installed. Run: brew install sshpass${NC}"
        exit 1
    fi
    sshpass -p "$VPS_PASSWORD" rsync -avz --delete $EXCLUDES "$LOCAL_DIR/" "$VPS_USER@$VPS_HOST:$REMOTE_PATH/"
else
    # Use SSH key
    rsync -avz --delete $EXCLUDES "$LOCAL_DIR/" "$VPS_USER@$VPS_HOST:$REMOTE_PATH/"
fi

if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Rsync failed!${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Files synced${NC}"

# Step 2: Kill existing screen
echo -e "${YELLOW}[2/3] Stopping existing screen session...${NC}"

SSH_CMD="screen -X -S \"$SCREEN_NAME\" quit 2>/dev/null; echo 'done'"

if [ -n "$VPS_PASSWORD" ]; then
    sshpass -p "$VPS_PASSWORD" ssh "$VPS_USER@$VPS_HOST" "$SSH_CMD"
else
    ssh "$VPS_USER@$VPS_HOST" "$SSH_CMD"
fi
echo -e "${GREEN}✓ Screen stopped${NC}"

# Step 3: Start new screen with the app
echo -e "${YELLOW}[3/3] Starting new screen session...${NC}"

# Build the run command
if [ -n "$VENV_PATH" ]; then
    RUN_CMD="source \"$VENV_PATH/bin/activate\" && $PYTHON_CMD \"$MAIN_FILE\""
else
    RUN_CMD="$PYTHON_CMD \"$MAIN_FILE\""
fi

# Create and start screen
SCREEN_CMD="cd \"$REMOTE_PATH\" && screen -dmS \"$SCREEN_NAME\" bash -c '$RUN_CMD; exec bash'"

if [ -n "$VPS_PASSWORD" ]; then
    sshpass -p "$VPS_PASSWORD" ssh "$VPS_USER@$VPS_HOST" "$SCREEN_CMD"
else
    ssh "$VPS_USER@$VPS_HOST" "$SCREEN_CMD"
fi

# Verify screen started
sleep 1
VERIFY_CMD="screen -ls | grep -q \"$SCREEN_NAME\" && echo 'running' || echo 'not running'"

if [ -n "$VPS_PASSWORD" ]; then
    STATUS=$(sshpass -p "$VPS_PASSWORD" ssh "$VPS_USER@$VPS_HOST" "$VERIFY_CMD")
else
    STATUS=$(ssh "$VPS_USER@$VPS_HOST" "$VERIFY_CMD")
fi

if [ "$STATUS" = "running" ]; then
    echo -e "${GREEN}✓ Screen '$SCREEN_NAME' is running${NC}"
else
    echo -e "${RED}✗ Screen may not have started. Check manually with: ssh $VPS_USER@$VPS_HOST 'screen -ls'${NC}"
fi

echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       DEPLOYMENT COMPLETE!             ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "To attach to screen: ${YELLOW}ssh $VPS_USER@$VPS_HOST -t 'screen -r $SCREEN_NAME'${NC}"
echo -e "To view logs:        ${YELLOW}ssh $VPS_USER@$VPS_HOST 'screen -S $SCREEN_NAME -X hardcopy /tmp/screen.log; cat /tmp/screen.log'${NC}"
