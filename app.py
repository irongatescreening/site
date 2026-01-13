import os
import time
import json
import secrets
import sqlite3
from datetime import datetime, timezone

import requests
from flask import Flask, request, session, redirect, url_for

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

# -------------------------------------------------
# App setup
# -------------------------------------------------
app = Flask(__name__)

# -------------------------------------------------
# Environment variables
# -------------------------------------------------
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
SUPABASE_URL = (os.environ.get("SUPABASE_URL") or "").rstrip("/")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY") or ""
SITE_URL = (os.environ.get("SITE_URL") or "https://portal.irongatescreening.com").rstrip("/")
AUTH_REDIRECT_TO = (os.environ.get("AUTH_REDIRECT_TO") or f"{SITE_URL}/auth/callback").rstrip("/")
ALLOWLIST_EMAILS = os.environ.get("ALLOWLIST_EMAILS") or ""
DB_PATH = os.environ.get("DB_PATH") or "/opt/render/project/src/instance/igs.db"

if not FLASK_SECRET_KEY or not SUPABASE_URL or not SUPABASE_ANON_KEY:
    raise RuntimeError("Missing required environment variables")

# -------------------------------------------------
# Flask config
# -------------------------------------------------
app.secret_key = FLASK_SECRET_KEY
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# -------------------------------------------------
# Rate limiting
# -------------------------------------------------
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["300 per day", "60 per hour"],
    storage_uri="memory://",
)

# Never rate-limit health checks
@limiter.request_filter
def _skip_limiter_for_health():
    return request.path in ("/health", "/healthz")

# -------------------------------------------------
# Security headers
# -------------------------------------------------
Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
)

# -------------------------------------------------
# Health checks
# -------------------------------------------------
@app.get("/health")
def health():
    return "ok", 200

@app.get("/healthz")
def healthz():
    return {"ok": True}, 200

# -------------------------------------------------
# Allowlist helpers
# -------------------------------------------------
ALLOWLIST = {e.strip().lower() for e in ALLOWLIST_EMAILS.split(",") if e.strip()}

def is_allowed_email(email: str) -> bool:
    return bool(email) and email.lower() in ALLOWLIST

# -------------------------------------------------
# Supabase helpers
# -------------------------------------------------
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
        raise RuntimeError("Supabase OTP failed")

def supabase_get_user(access_token: str) -> dict:
    url = f"{SUPABASE_URL}/auth/v1/user"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {access_token}",
    }
    r = requests.get(url, headers=headers, timeout=15)
    if r.status_code != 200:
        raise RuntimeError("Supabase /user failed")
    return r.json()

# -------------------------------------------------
# Database helpers
# -------------------------------------------------
def _ensure_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS certn_checks (
                check_id TEXT PRIMARY KEY,
                client_email TEXT,
                status TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                report_url TEXT
            )
        """)
        conn.commit()

def _upsert_check(check_id, client_email, status, report_url):
    _ensure_db()
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO certn_checks (check_id, client_email, status, updated_at, report_url)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(check_id) DO UPDATE SET
                status=excluded.status,
                updated_at=excluded.updated_at,
                report_url=excluded.report_url
        """, (check_id, client_email, status, now, report_url))
        conn.commit()

# -------------------------------------------------
# Routes
# -------------------------------------------------
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
    email = (request.form.get("email") or "").lower()
    if is_allowed_email(email):
        supabase_send_magic_link(email)
    time.sleep(1)
    return "Check your email", 200

@app.post("/auth/consume")
def auth_consume():
    data = request.get_json() or {}
    if data.get("nonce") != session.pop("nonce", None):
        return {"ok": False}, 400
    user = supabase_get_user(data.get("access_token"))
    if not is_allowed_email(user.get("email")):
        return {"ok": False}, 403
    session["user_email"] = user["email"]
    return {"ok": True}

# -------------------------------------------------
# Certn webhook (verification OFF for now)
# -------------------------------------------------
@app.post("/webhooks/certn")
def certn_webhook():
    raw = request.get_data()
    payload = request.get_json(silent=True) or {}

    app.logger.info(
        "CERTN WEBHOOK HIT: keys=%s body_len=%s",
        list(payload.keys()),
        len(raw),
    )

    check_id = payload.get("id") or payload.get("check_id")
    status = payload.get("status", "unknown")

    if check_id:
        _upsert_check(
            check_id=check_id,
            client_email=None,
            status=status,
            report_url=None,
        )

    return {"ok": True}, 200

@app.get("/dashboard")
def dashboard():
    if not session.get("user_email"):
        return redirect(url_for("login"))
    return f"Logged in as {session['user_email']}"

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))
