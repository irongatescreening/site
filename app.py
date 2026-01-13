import os
import time
import json
import secrets
import sqlite3
import hmac
import hashlib
from datetime import datetime, timezone

import requests
from flask import Flask, request, session, redirect, url_for

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman


# -------------------------
# App setup
# -------------------------
app = Flask(__name__)


# -------------------------
# Environment variables
# -------------------------
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or ""
SUPABASE_URL = (os.environ.get("SUPABASE_URL") or "").rstrip("/")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY") or ""
SITE_URL = (os.environ.get("SITE_URL") or "https://portal.irongatescreening.com").rstrip("/")
AUTH_REDIRECT_TO = (os.environ.get("AUTH_REDIRECT_TO") or f"{SITE_URL}/auth/callback").rstrip("/")
ALLOWLIST_EMAILS = os.environ.get("ALLOWLIST_EMAILS") or ""

DB_PATH = os.environ.get("DB_PATH") or "/opt/render/project/src/instance/igs.db"

CERTN_VERIFY_ENABLED = (os.environ.get("CERTN_VERIFY_ENABLED") or "false").lower() in ("1", "true", "yes", "on")
CERTN_SIGNATURE_HEADER = os.environ.get("CERTN_SIGNATURE_HEADER") or "Certn-Signature"
CERTN_WEBHOOK_SECRET = os.environ.get("CERTN_WEBHOOK_SECRET") or ""

DEBUG_ENABLED = (os.environ.get("DEBUG_ENABLED") or "false").lower() in ("1", "true", "yes", "on")
DEBUG_TOKEN = os.environ.get("DEBUG_TOKEN") or ""

LOG_LEVEL = (os.environ.get("LOG_LEVEL") or "INFO").upper()
app.logger.setLevel(LOG_LEVEL)

if not FLASK_SECRET_KEY or not SUPABASE_URL or not SUPABASE_ANON_KEY:
    raise RuntimeError("Missing required environment variables: FLASK_SECRET_KEY, SUPABASE_URL, SUPABASE_ANON_KEY")


# -------------------------
# Flask config
# -------------------------
app.secret_key = FLASK_SECRET_KEY
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# -------------------------
# Rate limiting
# -------------------------
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["300 per day", "60 per hour"],
    storage_uri="memory://",
)

# Never rate-limit health checks (belt + suspenders)
@limiter.request_filter
def _skip_limiter_for_health():
    return request.path in ("/health", "/healthz")

# -------------------------
# Security headers
# -------------------------
Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
)

# -------------------------
# Health checks
# -------------------------
@app.get("/health")
def health():
    return "ok", 200

@app.get("/healthz")
def healthz():
    return {"ok": True}, 200

# Exempt AFTER limiter exists (avoids NameError)
limiter.exempt(health)
limiter.exempt(healthz)

# -------------------------
# Allowlist helpers
# -------------------------
ALLOWLIST = {e.strip().lower() for e in ALLOWLIST_EMAILS.split(",") if e.strip()}

def is_allowed_email(email: str) -> bool:
    return bool(email) and email.strip().lower() in ALLOWLIST


# -------------------------
# Debug token helpers (only you can access)
# -------------------------
def _debug_allowed() -> bool:
    if not DEBUG_ENABLED:
        return False
    token = request.headers.get("X-Debug-Token") or ""
    return bool(DEBUG_TOKEN) and hmac.compare_digest(token, DEBUG_TOKEN)

def _redact_headers(headers: dict) -> dict:
    redacted = {}
    for k, v in headers.items():
        lk = k.lower()
        if "authorization" in lk or "cookie" in lk or "token" in lk or "secret" in lk:
            redacted[k] = "***REDACTED***"
        else:
            redacted[k] = v
    return redacted

@app.get("/debug/last-webhook")
def debug_last_webhook():
    if not _debug_allowed():
        return {"ok": False}, 404
    return app.config.get("LAST_CERTN_WEBHOOK", {"ok": True, "note": "no webhook yet"}), 200


# -------------------------
# Supabase helpers
# -------------------------
def supabase_send_magic_link(email: str) -> None:
    url = f"{SUPABASE_URL}/auth/v1/otp"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "email": email,
        "create_user": True,
        "redirect_to": AUTH_REDIRECT_TO,
    }
    r = requests.post(url, json=payload, headers=headers, timeout=15)
    if r.status_code not in (200, 201):
        app.logger.error("Supabase OTP failed: %s %s", r.status_code, r.text)
        raise RuntimeError("Supabase OTP failed")

def supabase_get_user(access_token: str) -> dict:
    url = f"{SUPABASE_URL}/auth/v1/user"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {access_token}",
    }
    r = requests.get(url, headers=headers, timeout=15)
    if r.status_code != 200:
        app.logger.error("Supabase /user failed: %s %s", r.status_code, r.text)
        raise RuntimeError("Supabase /user failed")
    return r.json()


# -------------------------
# Database helpers
# -------------------------
def _ensure_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS certn_checks (
                check_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                client_email TEXT,
                report_url TEXT
            )
        """)
        conn.commit()

def _upsert_check(check_id: str, status: str, client_email=None, report_url=None):
    if not check_id:
        return
    _ensure_db()
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO certn_checks (check_id, status, updated_at, client_email, report_url)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(check_id) DO UPDATE SET
                status=excluded.status,
                updated_at=excluded.updated_at,
                client_email=excluded.client_email,
                report_url=excluded.report_url
        """, (check_id, status or "unknown", now, client_email, report_url))
        conn.commit()


# -------------------------
# Webhook signature verification
# -------------------------
def verify_certn_signature(raw_body: bytes, header_val: str) -> bool:
    # If verification is enabled, we REQUIRE secret + header
    if not CERTN_WEBHOOK_SECRET or not header_val:
        return False

    # Expect "t=...,v1=..." style header (adjust later if Certn differs)
    parts = [p.strip() for p in header_val.split(",") if p.strip()]
    timestamp = None
    sigs = []

    for p in parts:
        if p.startswith("t="):
            timestamp = p.split("=", 1)[1]
        elif p.startswith("v1="):
            sigs.append(p.split("=", 1)[1])

    if not timestamp or not sigs:
        return False

    signed = timestamp.encode() + b"." + raw_body
    expected = hmac.new(
        CERTN_WEBHOOK_SECRET.encode(),
        signed,
        hashlib.sha256,
    ).hexdigest()

    return any(hmac.compare_digest(expected, s) for s in sigs)


# -------------------------
# Routes
# -------------------------
@app.get("/")
def home():
    return redirect(url_for("login"))

@app.get("/login")
def login():
    nonce = secrets.token_urlsafe(32)
    session["nonce"] = nonce
    return f"""
    <script>
      const f = new URLSearchParams(window.location.hash.slice(1));
      const t = f.get("access_token");
      if (t) {{
        fetch("/auth/consume", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{ access_token: t, nonce: "{nonce}" }})
        }}).then(() => location.href="/dashboard");
      }}
    </script>
    <form method="POST">
      <input name="email" type="email" required />
      <button>Send login link</button>
    </form>
    """

@app.post("/login")
@limiter.limit("8 per 15 minutes")
def login_post():
    email = (request.form.get("email") or "").strip().lower()
    if is_allowed_email(email):
        supabase_send_magic_link(email)
    time.sleep(1)
    return "Check your email", 200

@app.post("/auth/consume")
def auth_consume():
    data = request.get_json() or {}
    if data.get("nonce") != session.pop("nonce", None):
        return {"ok": False}, 400

    user = supabase_get_user(data.get("access_token") or "")
    email = (user.get("email") or "").strip().lower()
    if not is_allowed_email(email):
        return {"ok": False}, 403

    session["user_email"] = email
    return {"ok": True}, 200

@app.get("/dashboard")
def dashboard():
    if not session.get("user_email"):
        return redirect(url_for("login"))
    return f"Logged in as {session['user_email']}", 200

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# Debug DB read
@app.get("/debug/checks")
def debug_checks():
    if not _debug_allowed():
        return {"ok": False}, 404
    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT check_id, status, updated_at, report_url FROM certn_checks ORDER BY updated_at DESC LIMIT 50"
        ).fetchall()
    return {"count": len(rows), "rows": rows}, 200


# -------------------------
# Certn webhook
# -------------------------
@app.post("/webhooks/certn")
def certn_webhook():
    raw = request.get_data() or b""
    ct = request.headers.get("Content-Type", "")

    app.logger.info("CERTN webhook hit len=%s ct=%s", len(raw), ct)

    # Parse JSON safely
    try:
        payload = request.get_json(force=True, silent=False) or {}
    except Exception:
        payload = {"_parse_error": True}

    # Safe log: keys only
    if isinstance(payload, dict):
        app.logger.info("[CERTN] payload keys: %s", list(payload.keys()))
    else:
        app.logger.info("[CERTN] payload type: %s", type(payload).__name__)

    # Capture last webhook (redact headers; include payload only if debug-token is used later)
    app.config["LAST_CERTN_WEBHOOK"] = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "content_type": ct,
        "headers": _redact_headers(dict(request.headers)),
        "payload_keys": list(payload.keys()) if isinstance(payload, dict) else [],
        "payload": payload,  # view via /debug/last-webhook with X-Debug-Token
    }

    # Enforce signature verification only when enabled
    if CERTN_VERIFY_ENABLED:
        header_val = request.headers.get(CERTN_SIGNATURE_HEADER) or ""
        ok = verify_certn_signature(raw, header_val)
        if not ok:
            app.logger.warning("[CERTN] signature verify failed header=%s present=%s",
                               CERTN_SIGNATURE_HEADER, bool(header_val))
            return {"ok": False}, 401

    # Extract fields (adjust after seeing real Certn payload)
    check_id = None
    status = "unknown"

    if isinstance(payload, dict):
        check_id = payload.get("id") or payload.get("check_id") or payload.get("checkId")
        status = payload.get("status") or payload.get("state") or "unknown"

    _upsert_check(check_id or "missing-id", status)

    app.logger.info("[CERTN] upserted check_id=%s status=%s", check_id, status)
    return {"ok": True}, 200
