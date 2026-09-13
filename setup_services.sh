#!/bin/bash
# ═══════════════════════════════════════════════════════════
# Mapper — Full Service Setup (Backend + Frontend)
# Backend: port 5001  |  Frontend: port 8081
# Elasticsearch persistence enabled
# ═══════════════════════════════════════════════════════════

echo "[*] Setting up Mapper Backend service..."

sudo tee /etc/systemd/system/mapper.service > /dev/null <<EOF
[Unit]
Description=Mapper Vulnerability Scanner Backend
After=network.target elasticsearch.service

[Service]
User=halalhacker
WorkingDirectory=/home/halalhacker/mapper/backend
ExecStart=/home/halalhacker/venv/bin/python3 app.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
Environment=ES_PASS=Watchlogs@69
Environment=ES_HOST=https://localhost:9200
Environment=ES_USER=elastic

[Install]
WantedBy=multi-user.target
EOF

echo "[*] Setting up Mapper Frontend service..."

sudo tee /etc/systemd/system/mapper-ui.service > /dev/null <<'EOF'
[Unit]
Description=Mapper Vulnerability Scanner Frontend UI
After=network.target mapper.service

[Service]
User=halalhacker
WorkingDirectory=/home/halalhacker/mapper/frontend
ExecStart=/usr/bin/python3 -m http.server 8081
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Kill any stale processes
kill $(lsof -ti:5001) 2>/dev/null
kill $(lsof -ti:8081) 2>/dev/null

# Purge Python bytecode cache so old code doesn't stick
find /home/halalhacker/mapper/backend -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null

# Reload and restart both services
sudo systemctl daemon-reload
sudo systemctl enable mapper mapper-ui
sudo systemctl restart mapper
sudo systemctl restart mapper-ui

echo ""
echo "[*] Checking service status..."
echo "--- Mapper Backend ---"
sudo systemctl status mapper --no-pager | grep -E "Active|running|failed"
echo "--- Mapper Frontend ---"
sudo systemctl status mapper-ui --no-pager | grep -E "Active|running|failed"
echo ""
echo "[✓] Done! Backend: http://localhost:5001  |  Frontend: http://localhost:8081"
echo "[✓] Elasticsearch persistence is now ENABLED"
