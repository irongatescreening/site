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
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or ""
SUPABASE_URL = (os.environ.get("SUPABASE_URL") or "").rstrip("/")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY") or ""
SITE_URL = (os.environ.get("SITE_URL") or "https://portal.irongatescreening.com").rstrip("/")
AUTH_REDIRECT_TO = (os.environ.get("AUTH_REDIRECT_TO") or f"{SITE_URL}/auth/callback").rstrip("/")
ALLOWLIST_EMAILS = os.environ.get("ALLOWLIST_EMAILS") or ""

CERTN_WEBHOOK_SECRET = os.environ.get("CERTN_WEBHOOK_SECRET") or ""
CERTN_SIGNATURE_HEADER = os.environ.get("CERTN_SIGNATURE_HEADER") or "Certn-Signature"
CERTN_VERIFY_ENABLED = (os.environ.get("CERTN_VERIFY_ENABLED") or "true").lower() == "true"

DB_PATH = os.environ.get("DB_PATH") or "/opt/render/project/src/instance/igs.db"

if not FLASK_SECRET_KEY or not SUPABASE_URL or not SUPABASE_ANON_KEY:
    raise RuntimeError("Missing required environment variables: FLASK_SECRET_KEY, SUPABASE_URL, SUPABASE_ANON_KEY")


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

# Never rate-limit health checks (belt + suspenders)
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
# Health checks (Render uses /healthz)
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
    return bool(email) and email.strip().lower() in ALLOWLIST


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
                report_url TEXT,
                raw_json TEXT
            )
        """)
        conn.commit()


def _upsert_check(check_id: str, client_email: str | None, status: str, report_url: str | None, raw_json: str | None):
    if not check_id:
        raise ValueError("Missing check_id")
    _ensure_db()
    now = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO certn_checks (check_id, client_email, status, updated_at, report_url, raw_json)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(check_id) DO UPDATE SET
                client_email=excluded.client_email,
                status=excluded.status,
                updated_at=excluded.updated_at,
                report_url=excluded.report_url,
                raw_json=excluded.raw_json
        """, (check_id, client_email, status, now, report_url, raw_json))
        conn.commit()


def _recent_checks(limit: int = 25):
    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute("""
            SELECT check_id, client_email, status, updated_at, report_url
            FROM certn_checks
            ORDER BY updated_at DESC
            LIMIT ?
        """, (limit,))
        rows = cur.fetchall()

    return [
        {"check_id": r[0], "client_email": r[1], "status": r[2], "updated_at": r[3], "report_url": r[4]}
        for r in rows
    ]


# -------------------------------------------------
# Webhook signature verification
# -------------------------------------------------
def verify_certn_signature(raw_body: bytes, header_value: str | None) -> bool:
    """
    Expected header format (Stripe-style):
      t=timestamp,v1=hexsig[,v1=hexsig2...]

    Signed payload:
      <timestamp>.<raw_body>
    HMAC SHA256 with CERTN_WEBHOOK_SECRET
    """
    if not CERTN_WEBHOOK_SECRET:
        return False
    if not header_value:
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

    signed = timestamp.encode("utf-8") + b"." + raw_body
    expected = hmac.new(
        CERTN_WEBHOOK_SECRET.encode("utf-8"),
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
    time.sleep(1)
    return "Check your email", 200


@app.post("/auth/consume")
def auth_consume():
    data = request.get_json(silent=True) or {}
    if data.get("nonce") != session.pop("nonce", None):
        return {"ok": False, "error": "bad_nonce"}, 400

    user = supabase_get_user(data.get("access_token") or "")
    email = (user.get("email") or "").strip().lower()

    if not is_allowed_email(email):
        return {"ok": False, "error": "forbidden"}, 403

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
# Debug endpoint to confirm DB writes (optional)
# -------------------------------------------------
@app.get("/debug/checks")
def debug_checks():
    # If you want to lock this down later, we can require session.
    return {"ok": True, "checks": _recent_checks(25)}, 200


# -------------------------------------------------
# Certn webhook (LOG KEYS + VERIFY + UPSERT)
# -------------------------------------------------
@app.post("/webhooks/certn")
def certn_webhook():
    raw = request.get_data() or b""

    # Parse JSON safely
    try:
        payload = request.get_json(force=True, silent=False)  # will throw if invalid
    except Exception as e:
        app.logger.warning("Certn webhook invalid JSON: err=%s body_len=%s", str(e), len(raw))
        return {"ok": False, "error": "invalid_json"}, 400

    # ✅ 1) Log keys (exactly what you requested)
    keys = sorted(list(payload.keys())) if isinstance(payload, dict) else []
    app.logger.info(
        "CERTN WEBHOOK HIT: path=%s ip=%s ua=%s header=%s verify=%s keys=%s body_len=%s",
        request.path,
        request.headers.get("X-Forwarded-For", request.remote_addr),
        request.headers.get("User-Agent"),
        CERTN_SIGNATURE_HEADER,
        CERTN_VERIFY_ENABLED,
        keys,
        len(raw),
    )

    # ✅ 2) Re-enable signature verification
    if CERTN_VERIFY_ENABLED:
        sig_header_val = request.headers.get(CERTN_SIGNATURE_HEADER)
        if not verify_certn_signature(raw, sig_header_val):
            app.logger.warning(
                "Certn webhook signature FAILED: header_present=%s",
                bool(sig_header_val),
            )
            return {"ok": False, "error": "bad_signature"}, 401

    # ✅ 3) Insert webhook data into SQLite
    check_id = None
    status = "unknown"
    report_url = None
    client_email = None

    if isinstance(payload, dict):
        check_id = payload.get("id") or payload.get("check_id") or payload.get("case_id")
        status = payload.get("status") or payload.get("state") or "unknown"
        report_url = payload.get("report_url") or payload.get("reportLink") or payload.get("report")
        client_email = payload.get("client_email") or payload.get("email")

    try:
        _upsert_check(
            check_id=str(check_id) if check_id else "",
            client_email=client_email,
            status=str(status),
            report_url=str(report_url) if report_url else None,
            raw_json=json.dumps(payload)[:100000],  # keep it bounded
        )
    except Exception as e:
        app.logger.exception("DB upsert failed: err=%s", str(e))
        return {"ok": False, "error": "db_write_failed"}, 500

    return {"ok": True}, 200
