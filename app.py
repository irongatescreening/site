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
CERTN_WEBHOOK_SECRET = os.environ.get("CERTN_WEBHOOK_SECRET") or ""
DB_PATH = os.environ.get("DB_PATH") or "/opt/render/project/src/instance/igs.db"

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

# -------------------------------------------------
# Health checks (NO decorators here)
# -------------------------------------------------
@app.get("/health")
def health():
    return "ok", 200

@app.get("/healthz")
def healthz():
    return {"ok": True}, 200

# -------------------------------------------------
# Exempt AFTER limiter exists (avoids NameError)
# -------------------------------------------------
limiter.exempt(health)
limiter.exempt(healthz)

# -------------------------------------------------
# Never rate-limit health checks (belt + suspenders)
# -------------------------------------------------
@limiter.request_filter
def _skip_limiter_for_health():
    return request.path in ("/health", "/healthz")


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


def require_login():
    if not session.get("user_email"):
        return redirect(url_for("login"))
    return None


# -------------------------------------------------
# Database helpers
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
            (str(check_id), client_email, str(status), now, report_url),
        )
        conn.commit()


# -------------------------------------------------
# Webhook verification
# NOTE: Header name is UNKNOWN. Keep it configurable.
# Put the real header name in CERTN_SIGNATURE_HEADER env var later.
# -------------------------------------------------
CERTN_SIGNATURE_HEADER = os.environ.get("CERTN_SIGNATURE_HEADER") or "X-Certn-Signature"


def verify_certn_signature(raw_body: bytes, header_value: str | None) -> bool:
    if not CERTN_WEBHOOK_SECRET or not header_value:
        return False

    # Supports either:
    # 1) "sha256=<hex>"
    # 2) "<hex>"
    # 3) Stripe-style: "t=...,v1=...,v1=..."
    hv = header_value.strip()

    # Stripe-style parsing (t=, v1=)
    if "t=" in hv and "v1=" in hv:
        parts = [p.strip() for p in hv.split(",") if p.strip()]
        timestamp = None
        sigs = []
        for p in parts:
            if p.startswith("t="):
                timestamp = p.split("=", 1)[1].strip()
            elif p.startswith("v1="):
                sigs.append(p.split("=", 1)[1].strip())

        if not timestamp or not sigs:
            return False

        signed = timestamp.encode("utf-8") + b"." + raw_body
        expected = hmac.new(
            CERTN_WEBHOOK_SECRET.encode("utf-8"),
            signed,
            hashlib.sha256,
        ).hexdigest()

        return any(hmac.compare_digest(expected, s) for s in sigs)

    # Simple sha256=<hex> or <hex>
    if hv.startswith("sha256="):
        hv = hv.split("=", 1)[1].strip()

    expected = hmac.new(
        CERTN_WEBHOOK_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, hv)


# -------------------------------------------------
# Routes
# -------------------------------------------------
@app.get("/")
def home():
    if session.get("user_email"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.get("/login")
def login():
    # If already logged in, go straight to dashboard
    if session.get("user_email"):
        return redirect(url_for("dashboard"))

    nonce = secrets.token_urlsafe(32)
    session["consume_nonce"] = nonce

    return f"""
    <html>
    <body>
      <script>
        const fragment = new URLSearchParams(window.location.hash.slice(1));
        const access_token = fragment.get('access_token');

        if (access_token) {{
          fetch('/auth/consume', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify({{ access_token: access_token, nonce: '{nonce}' }})
          }})
          .then(res => {{
            if (!res.ok) throw new Error('auth failed');
            history.replaceState(null, "", "/login");
            window.location.replace('/dashboard');
          }})
          .catch(() => {{
            document.body.innerHTML = "<h3>Login failed. Please try again.</h3>";
          }});
        }}
      </script>

      <h2>IGS Portal Login</h2>
      <p>Enter your email to receive a secure sign-in link.</p>
      <form method="POST" action="/login">
        <input name="email" type="email" placeholder="you@company.com" required />
        <button type="submit">Send login link</button>
      </form>
    </body>
    </html>
    """


@app.post("/login")
@limiter.limit("8 per 15 minutes")
def login_post():
    email = (request.form.get("email") or "").strip().lower()

    allowed = is_allowed_email(email)
    if allowed:
        try:
            supabase_send_magic_link(email)
        except Exception:
            app.logger.exception("Supabase OTP send failed")

    time.sleep(1)
    return """
    <h3>Check your email</h3>
    <p>If your email is authorized, you’ll receive a secure login link shortly.</p>
    """, 200


@app.post("/auth/consume")
@limiter.limit("30 per minute")
def auth_consume():
    data = request.get_json(silent=True) or {}
    access_token = (data.get("access_token") or "").strip()
    nonce = (data.get("nonce") or "").strip()

    expected = session.get("consume_nonce")
    session.pop("consume_nonce", None)

    if not expected or not secrets.compare_digest(nonce, expected):
        return {"ok": False}, 400

    if not access_token:
        return {"ok": False}, 400

    try:
        user = supabase_get_user(access_token)
    except Exception:
        app.logger.exception("Supabase /user failed during consume")
        return {"ok": False}, 401

    email = (user.get("email") or "").strip().lower()
    if not is_allowed_email(email):
        session.clear()
        return {"ok": False}, 403

    session.clear()
    session["user_email"] = email
    session["user_id"] = user.get("id")
    return {"ok": True}, 200


@app.post("/webhooks/certn")
@limiter.limit("60 per minute")
def certn_webhook():
    raw = request.get_data(cache=False)

    # Debug line you asked for (safe: logs only header keys, not values)
    app.logger.info("Certn webhook hit. headers=%s", list(request.headers.keys()))

    sig_value = request.headers.get(CERTN_SIGNATURE_HEADER)

    if not verify_certn_signature(raw, sig_value):
        app.logger.warning("Certn webhook signature verification failed")
        return {"ok": False}, 401

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        app.logger.exception("Certn webhook invalid JSON")
        return {"ok": False}, 400

    check_id = payload.get("check_id") or payload.get("checkId") or payload.get("id")
    status = payload.get("status") or payload.get("state") or "unknown"

    if not check_id:
        app.logger.warning("Webhook missing check_id. keys=%s", list(payload.keys()))
        return {"ok": False, "error": "missing check_id"}, 400

    # Minimal for now (data flow first)
    _upsert_check(str(check_id), None, str(status), None)
    return {"ok": True}, 200


@app.get("/dashboard")
def dashboard():
    gate = require_login()
    if gate:
        return gate
    return f"Logged in as {session.get('user_email')}"


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
