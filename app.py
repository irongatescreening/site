# app.py — Iron Gate Screening Portal (MVP)
# Goals right now:
# 1) App boots cleanly on Render
# 2) /healthz never rate-limited (no 429 spam)
# 3) /webhooks/certn logs hits (plumbing test)
# 4) Magic-link login flow stays intact

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
# Environment variables (Render)
# -------------------------------------------------
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or ""
SUPABASE_URL = (os.environ.get("SUPABASE_URL") or "").rstrip("/")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY") or ""
SITE_URL = (os.environ.get("SITE_URL") or "https://portal.irongatescreening.com").rstrip("/")
AUTH_REDIRECT_TO = (os.environ.get("AUTH_REDIRECT_TO") or f"{SITE_URL}/auth/callback").rstrip("/")
ALLOWLIST_EMAILS = os.environ.get("ALLOWLIST_EMAILS") or ""

# Webhook + DB (we'll tighten later)
CERTN_WEBHOOK_SECRET = os.environ.get("CERTN_WEBHOOK_SECRET") or ""
DB_PATH = os.environ.get("DB_PATH") or "/opt/render/project/src/instance/igs.db"

# Fail fast so deploy errors are obvious
missing = []
if not FLASK_SECRET_KEY:
    missing.append("FLASK_SECRET_KEY")
if not SUPABASE_URL:
    missing.append("SUPABASE_URL")
if not SUPABASE_ANON_KEY:
    missing.append("SUPABASE_ANON_KEY")
if missing:
    raise RuntimeError(f"Missing required env vars: {', '.join(missing)}")


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
# Security headers
# -------------------------------------------------
# Note: if you are behind Cloudflare/Render, force_https=True is still ok,
# but if it ever causes redirect loops, set force_https=False temporarily.
Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
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

# Never rate-limit health checks (belt + suspenders)
@limiter.request_filter
def _skip_limiter_for_health():
    return request.path in ("/health", "/healthz")


# -------------------------------------------------
# Health checks (Render will call these repeatedly)
# -------------------------------------------------
@app.get("/health")
def health():
    return "ok", 200


@app.get("/healthz")
def healthz():
    return {"ok": True}, 200


# Also explicitly exempt (in case defaults change)
limiter.exempt(health)
limiter.exempt(healthz)


# -------------------------------------------------
# Allowlist helpers
# -------------------------------------------------
ALLOWLIST = {e.strip().lower() for e in ALLOWLIST_EMAILS.split(",") if e.strip()}

def is_allowed_email(email: str) -> bool:
    if not email:
        return False
    return email.strip().lower() in ALLOWLIST


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


# -------------------------------------------------
# DB helpers (minimal; ok for now)
# -------------------------------------------------
def _ensure_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS certn_checks (
                check_id TEXT PRIMARY KEY,
                client_email TEXT,
                status TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                report_url TEXT
            )
            """
        )
        conn.commit()


def _upsert_check(check_id: str, client_email: str | None, status: str, report_url: str | None):
    if not check_id:
        return
    _ensure_db()
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO certn_checks (check_id, client_email, status, updated_at, report_url)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(check_id) DO UPDATE SET
                client_email=excluded.client_email,
                status=excluded.status,
                updated_at=excluded.updated_at,
                report_url=excluded.report_url
            """,
            (check_id, client_email, status, now, report_url),
        )
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
      <input name="email" type="email" required placeholder="you@company.com" />
      <button>Send login link</button>
    </form>
    """


@app.post("/login")
@limiter.limit("8 per 15 minutes")
def login_post():
    email = (request.form.get("email") or "").strip().lower()
    if is_allowed_email(email):
        supabase_send_magic_link(email)
    # Always respond the same (prevents allowlist enumeration)
    time.sleep(1)
    return "Check your email", 200


@app.post("/auth/consume")
def auth_consume():
    data = request.get_json(silent=True) or {}
    if data.get("nonce") != session.pop("nonce", None):
        return {"ok": False}, 400

    access_token = data.get("access_token") or ""
    user = supabase_get_user(access_token)
    email = (user.get("email") or "").lower()

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


# -------------------------------------------------
# CERTN webhook (TEMP: plumbing test, no signature enforcement)
# -------------------------------------------------
@app.post("/webhooks/certn")
def certn_webhook():
    raw = request.get_data()

    app.logger.info(
        "CERTN WEBHOOK HIT: path=%s ip=%s ua=%s content_type=%s headers=%s body_len=%s",
        request.path,
        request.headers.get("X-Forwarded-For", request.remote_addr),
        request.headers.get("User-Agent"),
        request.headers.get("Content-Type"),
        list(request.headers.keys()),
        len(raw),
    )

    # Try to parse JSON if present; don't fail if it's not JSON yet
    payload = None
    try:
        payload = request.get_json(silent=True)
    except Exception:
        payload = None

    # If payload has a check id + status, store it (safe/no-op if missing)
    if isinstance(payload, dict):
        check_id = payload.get("id") or payload.get("check_id") or ""
        status = payload.get("status") or "unknown"
        _upsert_check(check_id, None, status, None)

    return {"ok": True}, 200
