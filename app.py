import os
import time
import json
import secrets
import sqlite3
import hmac
import hashlib
import logging
import sys
from datetime import datetime, timezone

import requests
from flask import Flask, request, session, redirect, url_for

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

# -------------------------------------------------
# Logging (Render captures stdout)
# -------------------------------------------------
LOG_LEVEL = (os.environ.get("LOG_LEVEL") or "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("igs")

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

# Webhook + DB
CERTN_WEBHOOK_SECRET = os.environ.get("CERTN_WEBHOOK_SECRET") or ""
CERTN_SIGNATURE_HEADER = os.environ.get("CERTN_SIGNATURE_HEADER") or "Certn-Signature"
CERTN_VERIFY_ENABLED = (os.environ.get("CERTN_VERIFY_ENABLED") or "false").lower() == "true"

DB_PATH = os.environ.get("DB_PATH") or "/opt/render/project/src/instance/igs.db"

# Fail fast on core app requirements (webhook can run without secret while testing)
missing = []
if not FLASK_SECRET_KEY:
    missing.append("FLASK_SECRET_KEY")
if not SUPABASE_URL:
    missing.append("SUPABASE_URL")
if not SUPABASE_ANON_KEY:
    missing.append("SUPABASE_ANON_KEY")
if missing:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

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

# Never rate-limit Render health checks (belt + suspenders)
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
# Health checks (NO limiter decorators)
# -------------------------------------------------
@app.get("/health")
def health():
    return "ok", 200


@app.get("/healthz")
def healthz():
    return {"ok": True}, 200


# Exempt AFTER limiter exists (avoids NameError)
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
        logger.error("Supabase OTP failed: %s %s", r.status_code, r.text)
        raise RuntimeError("Supabase OTP failed")

def supabase_get_user(access_token: str) -> dict:
    url = f"{SUPABASE_URL}/auth/v1/user"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {access_token}",
    }
    r = requests.get(url, headers=headers, timeout=15)
    if r.status_code != 200:
        logger.error("Supabase /user failed: %s %s", r.status_code, r.text)
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

def _upsert_check(check_id: str, client_email: str | None, status: str, report_url: str | None):
    _ensure_db()
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO certn_checks (check_id, client_email, status, updated_at, report_url)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(check_id) DO UPDATE SET
                client_email=excluded.client_email,
                status=excluded.status,
                updated_at=excluded.updated_at,
                report_url=excluded.report_url
        """, (check_id, client_email, status, now, report_url))
        conn.commit()

# -------------------------------------------------
# Webhook verification (generic v1 format: t=..., v1=...)
# -------------------------------------------------
def verify_certn_signature(raw_body: bytes, header_value: str) -> bool:
    if not CERTN_WEBHOOK_SECRET or not header_value:
        return False

    parts = [p.strip() for p in header_value.split(",")]
    timestamp = None
    sigs: list[str] = []

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
    email = (request.form.get("email") or "").strip().lower()
    if is_allowed_email(email):
        supabase_send_magic_link(email)
    # Always return success to avoid email enumeration
    time.sleep(1)
    return "Check your email", 200

@app.post("/auth/consume")
def auth_consume():
    data = request.get_json(silent=True) or {}
    if data.get("nonce") != session.pop("nonce", None):
        return {"ok": False}, 400

    access_token = data.get("access_token") or ""
    if not access_token:
        return {"ok": False}, 400

    user = supabase_get_user(access_token)
    email = (user.get("email") or "").strip().lower()
    if not is_allowed_email(email):
        return {"ok": False}, 403

    session["user_email"] = email
    return {"ok": True}, 200

@app.post("/webhooks/certn")
def certn_webhook():
    raw = request.get_data() or b""

    # Always-visible logs in Render
    print(f"[CERTN] HIT path={request.path} len={len(raw)} ct={request.headers.get('Content-Type')}")
    logger.info("CERTN webhook hit len=%s ct=%s", len(raw), request.headers.get("Content-Type"))

    # Signature verification (toggleable)
    sig_header_val = request.headers.get(CERTN_SIGNATURE_HEADER, "")
    if CERTN_VERIFY_ENABLED:
        if not verify_certn_signature(raw, sig_header_val):
            print(f"[CERTN] SIGNATURE FAIL header_name={CERTN_SIGNATURE_HEADER} present={bool(sig_header_val)}")
            return {"ok": False}, 401
        print("[CERTN] signature OK")

    # Parse JSON and log keys
    try:
        payload = request.get_json(force=True, silent=False)
    except Exception as e:
        print(f"[CERTN] JSON parse failed: {e}")
        return {"ok": False, "error": "invalid_json"}, 400

    print(f"[CERTN] payload keys: {list(payload.keys())}")

    check_id = payload.get("id") or payload.get("check_id") or payload.get("case_id")
    status = payload.get("status") or payload.get("state") or "unknown"
    report_url = payload.get("report_url") or payload.get("reportUrl") or payload.get("url")

    if not check_id:
        print("[CERTN] missing id/check_id/case_id")
        return {"ok": False, "error": "missing_id"}, 400

    _upsert_check(check_id, None, status, report_url)
    print(f"[CERTN] upserted check_id={check_id} status={status}")

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

# TEMP DEBUG: view last 20 webhook rows (remove later)
@app.get("/debug/checks")
def debug_checks():
    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT check_id, status, updated_at, report_url FROM certn_checks ORDER BY updated_at DESC LIMIT 20"
        ).fetchall()
    return {"count": len(rows), "rows": rows}, 200
