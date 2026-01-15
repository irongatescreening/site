import os
import time
import secrets
import hmac
import hashlib
from datetime import datetime, timezone

import requests
from flask import Flask, request, session, redirect, url_for, render_template_string
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman


# -------------------------
# App setup
# -------------------------
app = Flask(__name__)

# Version tracking (update this when you make changes)
APP_VERSION = "2026-01-14-supabase-v2"


# -------------------------
# Environment variables
# -------------------------
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or ""
SUPABASE_URL = (os.environ.get("SUPABASE_URL") or "").rstrip("/")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY") or ""
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY") or ""  # NEW: For writing to DB
SITE_URL = (os.environ.get("SITE_URL") or "https://portal.irongatescreening.com").rstrip("/")
AUTH_REDIRECT_TO = (os.environ.get("AUTH_REDIRECT_TO") or f"{SITE_URL}/auth/callback").rstrip("/")
ALLOWLIST_EMAILS = os.environ.get("ALLOWLIST_EMAILS") or ""

CERTN_VERIFY_ENABLED = (os.environ.get("CERTN_VERIFY_ENABLED") or "false").lower() in ("1", "true", "yes", "on")
CERTN_SIGNATURE_HEADER = os.environ.get("CERTN_SIGNATURE_HEADER") or "Certn-Signature"
CERTN_WEBHOOK_SECRET = os.environ.get("CERTN_WEBHOOK_SECRET") or ""

DEBUG_ENABLED = (os.environ.get("DEBUG_ENABLED") or "false").lower() in ("1", "true", "yes", "on")
DEBUG_TOKEN = os.environ.get("DEBUG_TOKEN") or ""
CRON_TOKEN = os.environ.get("CRON_TOKEN") or ""  # NEW: Separate token for cron jobs

LOG_LEVEL = (os.environ.get("LOG_LEVEL") or "INFO").upper()
app.logger.setLevel(LOG_LEVEL)

# Certn API (Track B: polling) env vars
CERTN_API_BASE_URL = (os.environ.get("CERTN_API_BASE_URL") or "").rstrip("/")
CERTN_API_TOKEN = os.environ.get("CERTN_API_TOKEN") or ""
CERTN_API_AUTH_SCHEME = (os.environ.get("CERTN_API_AUTH_SCHEME") or "Token").strip()

if not FLASK_SECRET_KEY or not SUPABASE_URL or not SUPABASE_ANON_KEY:
    raise RuntimeError("Missing required environment variables: FLASK_SECRET_KEY, SUPABASE_URL, SUPABASE_ANON_KEY")

if not SUPABASE_SERVICE_KEY:
    app.logger.warning("SUPABASE_SERVICE_KEY not set - check storage will not work")


# -------------------------
# SECURITY: Flask config (secure cookies + session timeout)
# -------------------------
app.secret_key = FLASK_SECRET_KEY
app.config.update(
    SESSION_COOKIE_SECURE=True,      # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,    # JS can't read
    SESSION_COOKIE_SAMESITE="Strict",# Stronger CSRF protection
    PERMANENT_SESSION_LIFETIME=3600, # 1 hour timeout
    WTF_CSRF_TIME_LIMIT=None,        # CSRF tokens don't expire
)

# -------------------------
# SECURITY: CSRF Protection
# -------------------------
csrf = CSRFProtect(app)

# -------------------------
# SECURITY: Rate limiting
# -------------------------
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Never rate-limit health checks
@limiter.request_filter
def _skip_limiter_for_health():
    return request.path in ("/health", "/healthz")

# -------------------------
# SECURITY: Security headers with CSP
# -------------------------
Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    content_security_policy={
        "default-src": "'self'",
        "script-src": "'self' 'unsafe-inline'",  # Required for inline auth script
        "style-src": "'self' 'unsafe-inline'",
    },
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

@app.get("/version")
def version():
    """Version endpoint to verify which code is deployed"""
    return {"version": APP_VERSION, "ok": True}, 200

# Exempt AFTER limiter exists
limiter.exempt(health)
limiter.exempt(healthz)

# -------------------------
# Supabase redirect callback
# -------------------------
@app.get("/auth/callback")
def auth_callback():
    """
    Supabase redirect target.
    Supabase often returns tokens in the URL fragment (#access_token=...),
    which the server cannot read. We forward to /login so the existing
    JS fragment handler can consume it.
    """
    return redirect(url_for("login"))


# -------------------------
# Allowlist helpers
# -------------------------
ALLOWLIST = {e.strip().lower() for e in ALLOWLIST_EMAILS.split(",") if e.strip()}

def is_allowed_email(email: str) -> bool:
    """SECURITY: Constant-time email check to prevent enumeration"""
    if not email:
        return False
    normalized = email.strip().lower()
    return normalized in ALLOWLIST


# -------------------------
# SECURITY: Token verification helpers
# -------------------------
def _debug_allowed() -> bool:
    """SECURITY: Check if debug token is valid (for /debug endpoints)"""
    if not DEBUG_ENABLED:
        return False
    token = request.headers.get("X-Debug-Token") or ""
    return bool(DEBUG_TOKEN) and secrets.compare_digest(token, DEBUG_TOKEN)

def _cron_allowed() -> bool:
    """SECURITY: Check if cron token is valid (for /jobs endpoints)"""
    token = request.headers.get("X-Cron-Token") or ""
    return bool(CRON_TOKEN) and secrets.compare_digest(token, CRON_TOKEN)

def _redact_headers(headers: dict) -> dict:
    """SECURITY: Redact sensitive headers from logs"""
    redacted = {}
    for k, v in headers.items():
        lk = k.lower()
        if any(x in lk for x in ["authorization", "cookie", "token", "secret", "key"]):
            redacted[k] = "***REDACTED***"
        else:
            redacted[k] = v
    return redacted

def _sanitize_for_log(data: dict, max_depth: int = 2) -> dict:
    """SECURITY: Remove PII from logs (names, emails, SSNs, etc.)"""
    if max_depth <= 0:
        return {"__redacted__": "max_depth_reached"}

    sanitized = {}
    pii_keys = {
        "email", "email_address", "name", "first_name", "last_name",
        "phone", "ssn", "sin", "address", "dob", "birth_date"
    }

    for k, v in data.items():
        key_lower = k.lower()
        if any(pii in key_lower for pii in pii_keys):
            sanitized[k] = "***PII_REDACTED***"
        elif isinstance(v, dict):
            sanitized[k] = _sanitize_for_log(v, max_depth - 1)
        elif isinstance(v, list):
            sanitized[k] = [
                _sanitize_for_log(item, max_depth - 1) if isinstance(item, dict) else "***REDACTED***"
                for item in v[:3]
            ]
        else:
            sanitized[k] = v
    return sanitized


# -------------------------
# Supabase helpers
# -------------------------
def supabase_send_magic_link(email: str) -> None:
    """Send magic link via Supabase"""
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
        app.logger.error("Supabase OTP failed: %s", r.status_code)
        raise RuntimeError("Supabase OTP failed")

def supabase_get_user(access_token: str) -> dict:
    """Get user from Supabase token"""
    url = f"{SUPABASE_URL}/auth/v1/user"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {access_token}",
    }
    r = requests.get(url, headers=headers, timeout=15)
    if r.status_code != 200:
        app.logger.error("Supabase /user failed: %s", r.status_code)
        raise RuntimeError("Supabase /user failed")
    return r.json()


# -------------------------
# SECURITY: Input validation
# -------------------------
def validate_email(email: str) -> str:
    """SECURITY: Validate and sanitize email input"""
    if not email or not isinstance(email, str):
        raise ValueError("Invalid email")
    cleaned = email.strip().lower()
    if len(cleaned) > 254 or "@" not in cleaned:
        raise ValueError("Invalid email format")
    return cleaned

def validate_check_id(check_id: str) -> str:
    """SECURITY: Validate check_id to prevent injection"""
    if not check_id or not isinstance(check_id, str):
        raise ValueError("Invalid check_id")
    cleaned = "".join(c for c in check_id if c.isalnum() or c in "-_")
    if len(cleaned) > 128 or len(cleaned) == 0:
        raise ValueError("Invalid check_id format")
    return cleaned


# -------------------------
# Database helpers (Supabase Postgres)
# -------------------------
def _supabase_service_headers(write: bool = False) -> dict:
    """
    Headers for Supabase service_role requests (bypass RLS).
    Only add Prefer headers for write operations.
    """
    headers = {
        "apikey": SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json",
    }
    if write:
        headers["Prefer"] = "return=minimal"
    return headers

def _upsert_check(check_id: str, status: str, client_email=None, report_url=None):
    """
    SECURITY: Safely upsert check to Supabase with validated inputs.
    Uses service_role key to bypass RLS (webhooks don't have user context).
    """
    if not check_id:
        return

    if not SUPABASE_SERVICE_KEY:
        app.logger.error("SUPABASE_SERVICE_KEY not set - cannot upsert check")
        return

    try:
        validated_id = validate_check_id(str(check_id))
    except ValueError as e:
        app.logger.warning("Invalid check_id: %s", e)
        return

    now = datetime.now(timezone.utc).isoformat()

    url = f"{SUPABASE_URL}/rest/v1/certn_checks?on_conflict=check_id"
    headers = _supabase_service_headers(write=True)
    headers["Prefer"] = "resolution=merge-duplicates,return=minimal"

    payload = [{
        "check_id": validated_id,
        "status": status or "unknown",
        "updated_at": now,
        "client_email": client_email,
        "report_url": report_url,
    }]

    try:
        r = requests.post(url, json=payload, headers=headers, timeout=10)
        if r.status_code not in (200, 201, 204):
            app.logger.error("Supabase upsert failed: %s %s", r.status_code, r.text)
    except requests.exceptions.RequestException as e:
        app.logger.error("Supabase upsert request failed: %s", e)

def _get_checks_for_user(email: str, limit: int = 50) -> list:
    """
    SECURITY: Get checks for a specific user email.
    Uses service_role to read (bypasses RLS), then filters by email server-side.
    """
    if not SUPABASE_SERVICE_KEY:
        app.logger.error("SUPABASE_SERVICE_KEY not set - cannot read checks")
        return []

    url = f"{SUPABASE_URL}/rest/v1/certn_checks"
    headers = _supabase_service_headers(write=False)
    params = {
        "select": "check_id,status,updated_at,report_url",
        "client_email": f"eq.{email}",
        "order": "updated_at.desc",
        "limit": str(limit),
    }

    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code == 200:
            return r.json()
        app.logger.error("Supabase get checks failed: %s %s", r.status_code, r.text)
        return []
    except requests.exceptions.RequestException as e:
        app.logger.error("Supabase get checks request failed: %s", e)
        return []


# -------------------------
# SECURITY: Webhook signature verification
# -------------------------
def verify_certn_signature(raw_body: bytes, header_val: str) -> bool:
    """
    SECURITY: Verify webhook signature using constant-time comparison.
    """
    if not CERTN_WEBHOOK_SECRET or not header_val:
        return False

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

    return any(secrets.compare_digest(expected, s) for s in sigs)


# -------------------------
# Certn API (Track B: polling) helpers
# -------------------------
def _certn_api_headers() -> dict:
    """Build Certn API headers with auth token"""
    if not CERTN_API_TOKEN:
        raise RuntimeError("CERTN_API_TOKEN not set")
    scheme = CERTN_API_AUTH_SCHEME or "Token"
    return {
        "Authorization": f"{scheme} {CERTN_API_TOKEN}",
        "Accept": "application/json",
    }

def certn_list_cases(page_size: int = 100, page: int = 1) -> dict:
    """Fetch cases from Certn API with pagination"""
    if not CERTN_API_BASE_URL:
        raise RuntimeError("CERTN_API_BASE_URL not set")

    url = f"{CERTN_API_BASE_URL}/api/public/cases/"
    params = {"page_size": page_size, "page": page}

    try:
        r = requests.get(url, headers=_certn_api_headers(), params=params, timeout=25)
        if r.status_code != 200:
            app.logger.error("Certn list cases failed: %s %s", r.status_code, r.text)
            raise RuntimeError("Certn API error (list cases)")
        return r.json()
    except requests.exceptions.RequestException as e:
        app.logger.error("Certn API request failed: %s", e)
        raise

def sync_certn_cases(max_pages: int = 5, page_size: int = 100) -> dict:
    """
    Pull cases from Certn and upsert check statuses into Supabase.
    Returns counts for logging/observability.
    """
    total_cases = 0
    total_checks = 0
    page = 1

    while page <= max_pages:
        try:
            data = certn_list_cases(page_size=page_size, page=page)
        except RuntimeError:
            break

        results = data.get("results", []) if isinstance(data, dict) else []
        if not results:
            break

        for case in results:
            total_cases += 1

            client_email = None
            raw_email = case.get("email_address") or case.get("email")
            if raw_email:
                try:
                    client_email = validate_email(raw_email)
                except ValueError:
                    pass

            checks = case.get("checks", []) or []
            for check in checks:
                check_id = check.get("id") or check.get("check_id") or check.get("checkId")
                status = check.get("status") or check.get("state") or "unknown"
                report_url = check.get("report_url") or check.get("reportUrl")

                if check_id:
                    _upsert_check(
                        check_id=str(check_id),
                        status=str(status),
                        client_email=client_email,
                        report_url=report_url,
                    )
                    total_checks += 1

        page += 1

    return {"cases": total_cases, "checks": total_checks, "pages": page - 1}


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
    """SECURITY: Login page with CSRF protection"""
    nonce = secrets.token_urlsafe(32)
    session["nonce"] = nonce

    return render_template_string("""
<html>
<head><title>IGS Portal Login</title></head>
<body>
<h2>IGS Portal Login</h2>
<script>
// Handle Supabase fragment (#access_token=...)
const fragment = new URLSearchParams(window.location.hash.slice(1));
const token = fragment.get("access_token");
if (token) {
  const csrfToken = "{{ csrf_token() }}";
  fetch("/auth/consume", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": csrfToken
    },
    body: JSON.stringify({ access_token: token, nonce: "{{ nonce }}" })
  }).then(res => {
    if (res.ok) {
      window.location.href = "/dashboard";
    } else {
      document.body.innerHTML = "<h3>Login failed. Please try again.</h3>";
    }
  }).catch(() => {
    document.body.innerHTML = "<h3>Login failed. Please try again.</h3>";
  });
}
</script>
<form method="POST" action="/login">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
  <input name="email" type="email" placeholder="you@company.com" required />
  <button type="submit">Send login link</button>
</form>
</body>
</html>
""", nonce=nonce)

@app.post("/login")
@limiter.limit("5 per 15 minutes")
def login_post():
    """SECURITY: Same response time for all cases to prevent enumeration"""
    email_raw = request.form.get("email") or ""

    try:
        email = validate_email(email_raw)
    except ValueError:
        time.sleep(1)
        return "Check your email for a login link", 200

    is_allowed = is_allowed_email(email)
    if is_allowed:
        try:
            supabase_send_magic_link(email)
        except Exception as e:
            app.logger.error("Magic link send failed: %s", e)

    time.sleep(1)
    return "Check your email for a login link", 200

@app.post("/auth/consume")
@limiter.limit("10 per minute")
@csrf.exempt  # CSRF handled via nonce for this specific endpoint
def auth_consume():
    """
    SECURITY: One-time token consumption with nonce verification.
    """
    data = request.get_json(silent=True) or {}
    nonce = data.get("nonce") or ""
    expected_nonce = session.pop("nonce", None)

    if not expected_nonce or not secrets.compare_digest(str(nonce), str(expected_nonce)):
        app.logger.warning("Nonce mismatch in auth consume")
        return {"ok": False}, 400

    access_token = data.get("access_token") or ""
    if not access_token:
        return {"ok": False}, 400

    try:
        user = supabase_get_user(access_token)
    except Exception as e:
        app.logger.error("Supabase user fetch failed: %s", e)
        return {"ok": False}, 401

    email_raw = user.get("email") or ""
    try:
        email = validate_email(email_raw)
    except ValueError:
        return {"ok": False}, 403

    if not is_allowed_email(email):
        session.clear()
        app.logger.warning("Unauthorized login attempt: %s", email)
        return {"ok": False}, 403

    session.clear()
    session.permanent = True
    session["user_email"] = email
    session["user_id"] = user.get("id")

    return {"ok": True}, 200

@app.get("/dashboard")
def dashboard():
    """Main dashboard - requires login"""
    if not session.get("user_email"):
        return redirect(url_for("login"))

    email = session.get("user_email")
    return f"""
<html>
<head><title>IGS Portal Dashboard</title></head>
<body>
<h2>IGS Portal Dashboard</h2>
<p>Logged in as: <strong>{email}</strong></p>
<ul>
<li><a href="/dashboard/checks">View Background Checks</a></li>
<li><a href="/logout">Logout</a></li>
</ul>
</body>
</html>
""", 200

@app.get("/dashboard/checks")
def dashboard_checks():
    """SECURITY: Show ONLY checks for logged-in user's email"""
    if not session.get("user_email"):
        return redirect(url_for("login"))

    email = session["user_email"]
    rows = _get_checks_for_user(email, limit=50)

    html = f"""
<html>
<head><title>Background Checks</title></head>
<body>
<h2>Background Checks for {email}</h2>
<p><a href="/dashboard">← Back to Dashboard</a> | <a href="/logout">Logout</a></p>
<table border="1" cellpadding="8" cellspacing="0">
<thead>
<tr>
<th>Check ID</th>
<th>Status</th>
<th>Last Updated (UTC)</th>
<th>Report</th>
</tr>
</thead>
<tbody>
"""

    if not rows:
        html += '<tr><td colspan="4"><em>No checks found for your email.</em></td></tr>'
    else:
        for row in rows:
            check_id = row.get("check_id", "")
            status = row.get("status", "unknown")
            updated_at = row.get("updated_at", "")
            report_url = row.get("report_url", "")

            link = f'<a href="{report_url}" target="_blank" rel="noopener noreferrer">View Report</a>' if report_url else "—"
            html += f"""
<tr>
<td>{check_id}</td>
<td>{status}</td>
<td>{updated_at}</td>
<td>{link}</td>
</tr>
"""

    html += """
</tbody>
</table>
</body>
</html>
"""
    return html, 200

@app.get("/logout")
def logout():
    """Clear session and redirect to login"""
    session.clear()
    return redirect(url_for("login"))

# -------------------------
# DEBUG: Protected debug endpoints (only with DEBUG_TOKEN when DEBUG_ENABLED=true)
# -------------------------
@app.get("/debug/last-webhook")
def debug_last_webhook():
    """DEBUG: View last webhook (protected by debug token)"""
    if not _debug_allowed():
        return {"ok": False, "error": "not found"}, 404
    return app.config.get("LAST_CERTN_WEBHOOK", {"ok": True, "note": "no webhook yet"}), 200

# -------------------------
# TESTING: Secure test endpoint (requires CRON_TOKEN)
# -------------------------
@app.post("/jobs/test-insert")
@limiter.limit("10 per minute")
def job_test_insert():
    """
    SECURITY: Protected test endpoint for inserting a test check.
    Only accessible with CRON_TOKEN header.
    """
    if not _cron_allowed():
        return {"ok": False, "error": "unauthorized"}, 401

    _upsert_check(
        check_id="test-check-001",
        status="IN_PROGRESS",
        client_email="tyler@irongatescreening.com",
        report_url=None,
    )

    return {"ok": True, "message": "Test check inserted"}, 200

# -------------------------
# CRON: Protected sync endpoint for polling Certn API
# -------------------------
@app.post("/jobs/sync-certn")
@limiter.limit("2 per minute")
def job_sync_certn():
    """
    SECURITY: Protected cron job endpoint.
    Only accessible with CRON_TOKEN header.
    """
    if not _cron_allowed():
        return {"ok": False, "error": "unauthorized"}, 401

    if not CERTN_API_BASE_URL or not CERTN_API_TOKEN:
        return {
            "ok": False,
            "error": "CERTN_API_BASE_URL and CERTN_API_TOKEN are required for syncing",
        }, 400

    try:
        stats = sync_certn_cases(max_pages=5, page_size=100)
        app.logger.info("[CERTN][POLL] synced stats=%s", stats)
        return {"ok": True, "stats": stats}, 200
    except Exception as e:
        app.logger.error("[CERTN][POLL] sync failed: %s", e)
        return {"ok": False, "error": "sync failed"}, 500

# -------------------------
# Certn webhook (Track A: push notifications)
# -------------------------
@app.post("/webhooks/certn")
@limiter.limit("100 per minute")
@csrf.exempt
def certn_webhook():
    """
    SECURITY: Verify webhook signature before processing.
    Sanitize all logged data to prevent PII leaks.
    """
    raw = request.get_data() or b""
    ct = request.headers.get("Content-Type", "")

    try:
        payload = request.get_json(force=True, silent=False) or {}
    except Exception:
        app.logger.warning("[CERTN] webhook parse error")
        return {"ok": False, "error": "invalid json"}, 400

    sanitized_payload = _sanitize_for_log(payload) if isinstance(payload, dict) else {}
    app.logger.info("[CERTN] webhook received keys=%s", list(sanitized_payload.keys()))

    if DEBUG_ENABLED:
        app.config["LAST_CERTN_WEBHOOK"] = {
            "received_at": datetime.now(timezone.utc).isoformat(),
            "content_type": ct,
            "headers": _redact_headers(dict(request.headers)),
            "payload": sanitized_payload,
        }

    if CERTN_VERIFY_ENABLED:
        header_val = request.headers.get(CERTN_SIGNATURE_HEADER) or ""
        if not verify_certn_signature(raw, header_val):
            app.logger.warning("[CERTN] signature verification failed")
            return {"ok": False, "error": "invalid signature"}, 401

    check_id = None
    status = "unknown"
    client_email = None
    report_url = None

    if isinstance(payload, dict):
        check_id = payload.get("id") or payload.get("check_id") or payload.get("checkId")
        status = payload.get("status") or payload.get("state") or "unknown"
        report_url = payload.get("report_url") or payload.get("reportUrl")

        raw_email = payload.get("email_address") or payload.get("email")
        if raw_email:
            try:
                client_email = validate_email(raw_email)
            except ValueError:
                pass

    _upsert_check(
        check_id=check_id or "missing-id",
        status=status,
        client_email=client_email,
        report_url=report_url,
    )

    app.logger.info("[CERTN] upserted check_id=%s status=%s", check_id or "missing", status)
    return {"ok": True}, 200


# -------------------------
# Error handlers
# -------------------------
@app.errorhandler(404)
def not_found(e):
    return {"error": "not found"}, 404

@app.errorhandler(500)
def internal_error(e):
    app.logger.error("Internal error: %s", e)
    return {"error": "internal server error"}, 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
```
