#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# start.sh — Sentry Vulnerability Scanner Backend Server Manager
# Operates cleanly in WSL, Docker, and standard Linux environments (no systemd needed)
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="${SCRIPT_DIR}/.backend.pid"
LOG_FILE="${SCRIPT_DIR}/backend.log"
PORT=5001

case "$1" in
    start)
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo "[Sentry] Backend is already running (PID $(cat "$PID_FILE"))"
            exit 0
        fi

        # Ensure port 5001 is free before starting
        fuser -k "${PORT}/tcp" 2>/dev/null || true
        sleep 1

        echo "[Sentry] Starting backend server on port ${PORT}..."
        PYTHONUNBUFFERED=1 setsid python3 "${SCRIPT_DIR}/app.py" < /dev/null > "$LOG_FILE" 2>&1 &
        SERVER_PID=$!
        disown $SERVER_PID 2>/dev/null || true
        echo "$SERVER_PID" > "$PID_FILE"

        sleep 2
        if kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "[Sentry] Backend started successfully (PID ${SERVER_PID})"
        else
            echo "[Sentry] Failed to start backend. Check ${LOG_FILE}"
            exit 1
        fi
        ;;

    stop)
        echo "[Sentry] Stopping backend server on port ${PORT}..."
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE")
            kill -9 "$PID" 2>/dev/null || true
            rm -f "$PID_FILE"
        fi
        fuser -k "${PORT}/tcp" 2>/dev/null || true
        pkill -9 -f "python3.*backend/app.py" 2>/dev/null || true
        sleep 1
        echo "[Sentry] Stopped."
        ;;

    restart)
        "$0" stop
        sleep 1
        "$0" start
        ;;

    status)
        RUNNING_PID=""
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            RUNNING_PID=$(cat "$PID_FILE")
        else
            RUNNING_PID=$(fuser "${PORT}/tcp" 2>/dev/null | tr -d ' ')
        fi

        if [ -n "$RUNNING_PID" ]; then
            echo "[Sentry] Backend is RUNNING (PID ${RUNNING_PID})"
            curl -s "http://127.0.0.1:${PORT}/api/ai/status" | python3 -m json.tool 2>/dev/null || echo "API is starting..."
        else
            echo "[Sentry] Backend is STOPPED"
        fi
        ;;

    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
