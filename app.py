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

app = Flask(__name__)

@app.route("/health")
@limiter.exempt
def health():
    return "ok", 200

@app.get("/healthz")
@limiter.exempt
def healthz():
    return {"ok": True}, 200

# -------------------------
# REQUIRED ENV VARS (Render)
# -------------------------
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
SUPABASE_URL = (os.environ.get("SUPABASE_URL") or "").rstrip("/")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY") or ""

SITE_URL = (os.environ.get("SITE_URL") or "https://portal.irongatescreening.com").rstrip("/")
AUTH_REDIRECT_TO = (os.environ.get("AUTH_REDIRECT_TO") or f"{SITE_URL}/auth/callback").rstrip("/")
ALLOWLIST_EMAILS = os.environ.get("ALLOWLIST_EMAILS") or ""
LOG_LEVEL = (os.environ.get("LOG_LEVEL") or "INFO").upper()

# Webhook + DB
CERTN_WEBHOOK_SECRET = os.environ.get("CERTN_WEBHOOK_SECRET") or ""
DB_PATH = os.environ.get("DB_PATH") or "/opt/render/project/src/instance/igs.db"

# Fail fast with clear errors (prevents mystery crashes)
missing = []
if not FLASK_SECRET_KEY:
    missing.append("FLASK_SECRET_KEY")
if not SUPABASE_URL:
    missing.append("SUPABASE_URL")
if not SUPABASE_ANON_KEY:
    missing.append("SUPABASE_ANON_KEY")
if missing:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

# -------------------------
# Logging
# -------------------------
app.logger.setLevel(LOG_LEVEL)

# -------------------------
# Flask config (secure cookies)
# -------------------------
app.secret_key = FLASK_SECRET_KEY
app.config.update(
    SESSION_COOKIE_SECURE=True,       # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,     # JS can't read
    SESSION_COOKIE_SAMESITE="Lax",    # Works with redirects + reduces CSRF risk
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
@app.route("/health")
@limiter.exempt
def health():
    return "ok", 200

@app.get("/healthz")
@limiter.exempt
def healthz():
    return {"ok": True}, 200

# -------------------------
# Security headers (Talisman)
# NOTE: We allow inline script because login page uses a small inline script
# to read the #access_token fragment and POST to /auth/consume.
# -------------------------
csp = {
    "default-src": "'self'",
    "script-src": ["'self'", "'unsafe-inline'"],
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'", "data:"],
    "connect-src": ["'self'"],
}
Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    content_security_policy=csp,
)

# -------------------------
# Invite-only allowlist
# -------------------------
ALLOWLIST = {e.strip().lower() for e in ALLOWLIST_EMAILS.split(",") if e.strip()}


def is_allowed_email(email: str) -> bool:
    if not email:
        return False
    return email.strip().lower() in ALLOWLIST


# -------------------------
# Supabase helpers
# -------------------------
def supabase_send_magic_link(email: str) -> None:
    """
    Sends a magic link (OTP email) via Supabase.
    """
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
    """
    Validates token and returns user profile from Supabase.
    """
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


# -------------------------
# SQLite helpers
# -------------------------
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
            (check_id, client_email, status, now, report_url),
        )
        conn.commit()


def _fetch_checks(limit: int = 50):
    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT check_id, client_email, status, updated_at, report_url
            FROM certn_checks
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


# -------------------------
# Webhook signature verification (HMAC)
# If Certn uses a different header/name, we’ll adjust in 2 minutes once you paste it.
# -------------------------
def _verify_certn_signature(raw_body: bytes, signature_header: str | None) -> bool:
    if not CERTN_WEBHOOK_SECRET:
        return False
    if not signature_header:
        return False

    # Expected format: "t=1700000000,v1=<hex>[,v1=<hex>...]"
    parts = [p.strip() for p in signature_header.split(",")]
    timestamp = None
    sigs = []

    for p in parts:
        if p.startswith("t="):
            timestamp = p.split("=", 1)[1]
        elif p.startswith("v1="):
            sigs.append(p.split("=", 1)[1])

    if not timestamp or not sigs:
        return False

    # Build signed payload: f"{t}.{raw_body}"
    signed_payload = timestamp.encode("utf-8") + b"." + raw_body

    expected = hmac.new(
        CERTN_WEBHOOK_SECRET.encode("utf-8"),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    return any(hmac.compare_digest(expected, s) for s in sigs)



# -------------------------
# Routes
# -------------------------
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

    # Create one-time nonce used by /auth/consume
    nonce = secrets.token_urlsafe(32)
    session["consume_nonce"] = nonce

    return f"""
    <html>
    <body>
      <script>
        // If Supabase redirected here with an access token in the URL fragment:
        // /login#access_token=... we can't read it server-side, so consume it in JS.
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
            // Remove token fragment from URL
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

    # Invite-only gate (avoid enumeration): always return the same message
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
    """
    Consumes Supabase access_token from fragment flow.
    We DO NOT store tokens. We store only user_email/user_id in session.
    """
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

    # Prevent session fixation: clear then set
    session.clear()
    session["user_email"] = email
    session["user_id"] = user.get("id")
    return {"ok": True}, 200


@app.post("/webhooks/certn")
@limiter.limit("60 per minute")
def certn_webhook():
    raw = request.get_data(cache=False)

    # 👇 PUT IT RIGHT HERE
    app.logger.info(
        "Certn webhook hit. headers=%s",
        list(request.headers.keys())
    )

    sig = request.headers.get("Certn-Signature")

    if not _verify_certn_signature(raw, sig):
        app.logger.warning("Certn webhook signature verification failed")
        return {"ok": False}, 401

    """
    Webhook endpoint stub:
    - verifies signature (HMAC placeholder)
    - logs basic info
    - stores check_id/status/report_url into SQLite
    """
    raw = request.get_data(cache=False)
    sig = request.headers.get("Certn-Signature")

    if not _verify_certn_signature(raw, sig):
        app.logger.warning("Certn webhook signature verification failed")
        return {"ok": False}, 401

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        app.logger.exception("Certn webhook invalid JSON")
        return {"ok": False}, 400

    # Flexible extraction until we lock Certn’s exact schema
    check_id = (
        payload.get("check_id")
        or payload.get("checkId")
        or payload.get("id")
        or (payload.get("check") or {}).get("id")
        or (payload.get("data") or {}).get("check_id")
        or (payload.get("data") or {}).get("id")
    )

    status = (
        payload.get("status")
        or payload.get("state")
        or (payload.get("check") or {}).get("status")
        or (payload.get("data") or {}).get("status")
        or "unknown"
    )

    client_email = (
        payload.get("client_email")
        or (payload.get("metadata") or {}).get("client_email")
        or (payload.get("data") or {}).get("client_email")
    )

    report_url = (
        payload.get("report_url")
        or payload.get("reportUrl")
        or (payload.get("links") or {}).get("report")
        or (payload.get("data") or {}).get("report_url")
    )

    if not check_id:
        app.logger.warning("Webhook missing check_id. keys=%s", list(payload.keys()))
        return {"ok": False, "error": "missing check_id"}, 400

    _upsert_check(str(check_id), client_email, str(status), report_url)
    app.logger.info("Webhook saved check_id=%s status=%s", check_id, status)
    return {"ok": True}, 200


@app.get("/dashboard")
def dashboard():
    gate = require_login()
    if gate:
        return gate

    email = session.get("user_email") or ""

    # Pull real statuses from DB
    rows = []
    try:
        rows = _fetch_checks(limit=50)
    except Exception:
        app.logger.exception("Failed to read DB for dashboard")

    # If empty, show your demo rows so the page never looks broken
    if not rows:
        demo = """
        <h3>Status</h3>
        <ul>
          <li>John Doe — Invitation sent</li>
          <li>Jane Smith — In progress</li>
          <li>Dan Smith — Complete — <a href="#" onclick="alert('Later: deep link to Certn'); return false;">View report</a></li>
        </ul>
        """
        return f"""
        <h2>IGS Portal</h2>
        <p>Signed in as: <b>{email}</b></p>
        {demo}
        <p><a href="/logout">Logout</a></p>
        """

    items = []
    for r in rows:
        cid = r.get("check_id", "")
        status = r.get("status", "")
        updated = r.get("updated_at", "")
        client_email = r.get("client_email") or ""
        report_url = r.get("report_url") or ""

        if report_url:
            link = f'<a href="{report_url}" target="_blank" rel="noopener">View in Certn</a>'
        else:
            link = '<span style="color:#888">Report link not available</span>'

        label = client_email if client_email else cid
        items.append(f"<li><b>{label}</b> — {status} <small style='color:#666'>({updated})</small> — {link}</li>")

    return f"""
    <h2>IGS Portal</h2>
    <p>Signed in as: <b>{email}</b></p>

    <h3>Checks</h3>
    <ul>
      {''.join(items)}
    </ul>

    <p><a href="/logout">Logout</a></p>
    """


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/healthz")
def healthz():
    return {"ok": True}, 200


@app.get("/favicon.ico")
def favicon():
    return ("", 204)


if __name__ == "__main__":
    # Local only. On Render you run via gunicorn.
    app.run(host="0.0.0.0", port=5000, debug=True)
