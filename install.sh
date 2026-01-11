#!/bin/bash
# VPS Manager Installation Script for Ubuntu
# Run this on your VPS: curl -sSL https://raw.githubusercontent.com/jacklot1122/vps-management-gui/main/install.sh | bash

set -e

echo "=========================================="
echo "  VPS Manager - Installation Script"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Update system
echo -e "${YELLOW}[1/6] Updating system...${NC}"
sudo apt update

# Install dependencies
echo -e "${YELLOW}[2/6] Installing dependencies...${NC}"
sudo apt install -y python3 python3-pip python3-venv git screen

# Clone or update repo
echo -e "${YELLOW}[3/6] Setting up VPS Manager...${NC}"
cd ~
if [ -d "vps-management-gui" ]; then
    echo "Updating existing installation..."
    cd vps-management-gui
    git pull
else
    echo "Cloning repository..."
    git clone https://github.com/jacklot1122/vps-management-gui.git
    cd vps-management-gui
fi

# Create virtual environment
echo -e "${YELLOW}[4/6] Setting up Python environment...${NC}"
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Generate random password if not set
if [ -z "$ADMIN_PASSWORD" ]; then
    ADMIN_PASSWORD=$(openssl rand -base64 12)
    echo ""
    echo -e "${GREEN}=========================================="
    echo "  IMPORTANT: Save these credentials!"
    echo "==========================================${NC}"
    echo ""
    echo "  Username: admin"
    echo "  Password: $ADMIN_PASSWORD"
    echo ""
    echo "=========================================="
fi

# Create systemd service
echo -e "${YELLOW}[5/6] Creating systemd service...${NC}"
sudo tee /etc/systemd/system/vpsmanager.service > /dev/null <<EOF
[Unit]
Description=VPS Management GUI
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$HOME/vps-management-gui
Environment="ADMIN_PASSWORD=$ADMIN_PASSWORD"
Environment="SECRET_KEY=$(openssl rand -hex 32)"
ExecStart=$HOME/vps-management-gui/.venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
echo -e "${YELLOW}[6/6] Starting VPS Manager...${NC}"
sudo systemctl daemon-reload
sudo systemctl enable vpsmanager
sudo systemctl restart vpsmanager

# Wait a moment for startup
sleep 3

# Get IP
IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${GREEN}=========================================="
echo "  Installation Complete!"
echo "==========================================${NC}"
echo ""
echo "  Access your VPS Manager at:"
echo "  http://$IP:5000"
echo ""
echo "  Login credentials:"
echo "  Username: admin"
echo "  Password: $ADMIN_PASSWORD"
echo ""
echo "  Commands:"
echo "  - Check status: sudo systemctl status vpsmanager"
echo "  - View logs: sudo journalctl -u vpsmanager -f"
echo "  - Restart: sudo systemctl restart vpsmanager"
echo ""
echo "=========================================="
