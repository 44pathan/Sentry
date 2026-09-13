"""
auth.py — JWT Authentication System for the Vulnerability Scanner.
Ported from the WatchLogs SIEM backend with minimal modifications.
Provides: JWT creation/validation, rate limiting, token blacklisting,
and the @require_auth decorator for protecting API routes.
"""

import json
import os
import re
import secrets
import time
import threading
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

from config import (
    JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRY_HOURS,
    MAX_LOGIN_ATTEMPTS, LOCKOUT_SECONDS, USERS_PATH
)

# ── In-memory state ───────────────────────────────────────
login_attempts = {}
login_attempts_lock = threading.Lock()

token_blacklist = {}  # {jti: expiry_timestamp}
token_blacklist_lock = threading.Lock()


# ── User management ───────────────────────────────────────

def load_users():
    """Load users from JSON file."""
    try:
        with open(USERS_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_users(users):
    """Persist users to JSON file."""
    with open(USERS_PATH, "w") as f:
        json.dump(users, f, indent=4)


def find_user(username):
    """Find user by username (case-insensitive)."""
    users = load_users()
    for u in users:
        if u["username"].lower() == username.lower():
            return u
    return None


# ── JWT helpers ───────────────────────────────────────────

def create_jwt_token(username, role="user"):
    """Create a signed JWT token."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRY_HOURS),
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token):
    """Decode and validate a JWT token. Returns payload or None."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        with token_blacklist_lock:
            if payload.get("jti") in token_blacklist:
                return None
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def blacklist_token(payload):
    """Add a token's JTI to the blacklist with its expiry time."""
    if payload and payload.get("jti"):
        with token_blacklist_lock:
            token_blacklist[payload["jti"]] = payload.get("exp", time.time() + 86400)
            # Cleanup expired entries periodically (every 100 entries)
            if len(token_blacklist) > 100:
                now = time.time()
                expired = [k for k, v in token_blacklist.items() if v < now]
                for k in expired:
                    del token_blacklist[k]


# ── Rate limiting ─────────────────────────────────────────

def get_client_ip():
    """Get client IP, respecting X-Forwarded-For."""
    return request.headers.get(
        "X-Forwarded-For", request.remote_addr or "unknown"
    ).split(",")[0].strip()


def check_rate_limit(ip):
    """Check if IP is rate-limited. Returns (allowed, message)."""
    with login_attempts_lock:
        if ip not in login_attempts:
            return True, ""

        entry = login_attempts[ip]
        if entry.get("lockout_until", 0) > time.time():
            remaining = int(entry["lockout_until"] - time.time())
            return False, f"Account locked. Try again in {remaining}s."

        if entry.get("lockout_until", 0) <= time.time() and entry.get("lockout_until", 0) > 0:
            login_attempts[ip] = {"attempts": 0, "lockout_until": 0}

        return True, ""


def record_failed_attempt(ip):
    """Record a failed login attempt and possibly trigger lockout."""
    with login_attempts_lock:
        if ip not in login_attempts:
            login_attempts[ip] = {"attempts": 0, "lockout_until": 0}

        login_attempts[ip]["attempts"] += 1
        attempts = login_attempts[ip]["attempts"]

        if attempts >= MAX_LOGIN_ATTEMPTS:
            multiplier = max(1, attempts - MAX_LOGIN_ATTEMPTS + 1)
            lockout_time = min(LOCKOUT_SECONDS * multiplier, 3600)
            login_attempts[ip]["lockout_until"] = time.time() + lockout_time
            return attempts, lockout_time

        return attempts, 0


def clear_failed_attempts(ip):
    """Clear failed login record on successful auth."""
    with login_attempts_lock:
        login_attempts.pop(ip, None)


# ── Auth decorator ────────────────────────────────────────

def require_auth(f):
    """Decorator to protect API routes with JWT authentication.
    If no token is provided, allows access as 'admin' (local-only tool)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            payload = decode_jwt_token(token)
            if payload:
                request.auth_user = payload.get("sub", "")
                request.auth_role = payload.get("role", "")
                return f(*args, **kwargs)

        # No token or invalid token — allow as admin (local tool)
        request.auth_user = "admin"
        request.auth_role = "admin"
        return f(*args, **kwargs)
    return decorated


def require_scan_permission(f):
    """Decorator to restrict scan operations to authorized users only.
    Must be used AFTER @require_auth so request.auth_user is set.
    Allows admin users and users with 'can_scan' flag in users.json."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Admins can always scan
        if getattr(request, "auth_role", "") == "admin":
            return f(*args, **kwargs)

        # Check per-user scan permission in users.json
        user = find_user(getattr(request, "auth_user", ""))
        if user and user.get("can_scan", False):
            return f(*args, **kwargs)

        return jsonify({
            "status": "error",
            "message": "Scan permission denied. Only authorized users can perform scans. Contact an admin to get scan access."
        }), 403
    return decorated


# ── Auth route handlers (called from app.py) ──────────────

def handle_login():
    """Authenticate user and return JWT."""
    client_ip = get_client_ip()

    allowed, msg = check_rate_limit(client_ip)
    if not allowed:
        return jsonify({"status": "error", "message": msg}), 429

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid request"}), 400

    username = (data.get("username") or "").strip()[:64]
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password required"}), 400

    if len(password) > 128:
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', username):
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    user = find_user(username)

    if not user:
        # Constant-time comparison with a real pbkdf2 hash to prevent timing attacks
        _dummy = generate_password_hash("dummy_constant_time_pad", method="pbkdf2:sha256", salt_length=16)
        check_password_hash(_dummy, password)
        attempts, lockout = record_failed_attempt(client_ip)
        if lockout > 0:
            return jsonify({"status": "error", "message": f"Too many attempts. Locked for {lockout}s."}), 429
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    if not check_password_hash(user["password_hash"], password):
        attempts, lockout = record_failed_attempt(client_ip)
        if lockout > 0:
            return jsonify({"status": "error", "message": f"Too many attempts. Locked for {lockout}s."}), 429
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    clear_failed_attempts(client_ip)
    token = create_jwt_token(username, user.get("role", "user"))

    return jsonify({
        "status": "ok",
        "token": token,
        "username": username,
        "role": user.get("role", "user"),
        "expires_in": JWT_EXPIRY_HOURS * 3600
    })


def handle_verify():
    """Verify a JWT token is still valid."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"status": "error", "message": "No token"}), 401

    token = auth_header[7:]
    payload = decode_jwt_token(token)
    if not payload:
        return jsonify({"status": "error", "message": "Invalid or expired token"}), 401

    return jsonify({
        "status": "ok",
        "username": payload.get("sub"),
        "role": payload.get("role"),
        "expires_at": payload.get("exp")
    })


def handle_logout():
    """Blacklist the current token."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        payload = decode_jwt_token(token)
        blacklist_token(payload)

    return jsonify({"status": "ok", "message": "Logged out"})


def handle_change_password():
    """Change password for the authenticated user."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid request"}), 400

    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")

    if not current_password or not new_password:
        return jsonify({"status": "error", "message": "Both passwords required"}), 400

    if len(new_password) < 8:
        return jsonify({"status": "error", "message": "Password must be at least 8 characters"}), 400

    if len(new_password) > 128:
        return jsonify({"status": "error", "message": "Password too long"}), 400

    users = load_users()
    user = None
    for u in users:
        if u["username"].lower() == request.auth_user.lower():
            user = u
            break

    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    if not check_password_hash(user["password_hash"], current_password):
        return jsonify({"status": "error", "message": "Current password is incorrect"}), 401

    user["password_hash"] = generate_password_hash(
        new_password, method="pbkdf2:sha256", salt_length=16
    )
    save_users(users)

    return jsonify({"status": "ok", "message": "Password updated"})


def handle_register():
    """Register a new user account."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid request"}), 400

    username = (data.get("username") or "").strip()[:64]
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password required"}), 400

    if len(password) < 8:
        return jsonify({"status": "error", "message": "Password must be at least 8 characters"}), 400

    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', username):
        return jsonify({"status": "error", "message": "Username can only contain letters, numbers, underscores, hyphens, and dots"}), 400

    if find_user(username):
        return jsonify({"status": "error", "message": "Username already taken"}), 409

    users = load_users()
    users.append({
        "username": username,
        "password_hash": generate_password_hash(password, method="pbkdf2:sha256", salt_length=16),
        "role": "user"
    })
    save_users(users)

    token = create_jwt_token(username, "user")
    return jsonify({
        "status": "ok",
        "token": token,
        "username": username,
        "role": "user",
        "expires_in": JWT_EXPIRY_HOURS * 3600
    }), 201
