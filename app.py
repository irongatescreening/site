import os
import time
import secrets
import requests
from datetime import timedelta
from flask import Flask, request, session, redirect, url_for, render_template_string
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

app = Flask(__name__)

# -------------------------
# REQUIRED ENV VARS (Render)
# -------------------------
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
SUPABASE_URL = (os.environ.get("SUPABASE_URL") or "").rstrip("/")
SUPABASE_ANON_KEY = (os.environ.get("SUPABASE_ANON_KEY") or "").strip()
SITE_URL = (os.environ.get("SITE_URL") or "https://portal.irongatescreening.com").rstrip("/")
AUTH_REDIRECT_TO = (os.environ.get("AUTH_REDIRECT_TO") or f"{SITE_URL}/auth/callback").strip()
ALLOWLIST_EMAILS = os.environ.get("ALLOWLIST_EMAILS") or ""

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
# Flask config (secure cookies + timeout)
# -------------------------
app.secret_key = FLASK_SECRET_KEY
app.config.update(
    SESSION_COOKIE_SECURE=True,        # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,      # JS can't read
    SESSION_COOKIE_SAMESITE="Lax",     # safe for magic-link flows
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
)

# -------------------------
# Security layers
# -------------------------
# CSRF: protect HTML form posts. We'll exempt /auth/consume because we already use a one-time nonce.
csrf = CSRFProtect(app)

# Rate limiting (NOTE: memory storage is per-instance; OK for MVP)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Security headers
Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    content_security_policy={
        # Minimal CSP that still allows our inline JS on /login
        "default-src": "'self'",
        "script-src": "'self' 'unsafe-inline'",
        "style-src": "'self' 'unsafe-inline'",
        "img-src": "'self' data:",
        "connect-src": "'self'",
    },
)

# -------------------------
# Invite-only allowlist
# -------------------------
ALLOWLIST = {e.strip().lower() for e in ALLOWLIST_EMAILS.split(",") if e.strip()}


def is_allowed_email(email: str) -> bool:
    return bool(email) and email.strip().lower() in ALLOWLIST


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
        # Don't log r.text (may include sensitive info)
        app.logger.error("Supabase OTP failed: %s", r.status_code)
        raise RuntimeError(f"Supabase OTP failed: {r.status_code}")


def supabase_get_user(access_token: str) -> dict:
    url = f"{SUPABASE_URL}/auth/v1/user"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {access_token}",
    }
    r = requests.get(url, headers=headers, timeout=15)
    if r.status_code != 200:
        app.logger.error("Supabase /user failed: %s", r.status_code)
        raise RuntimeError(f"Supabase /user failed: {r.status_code}")
    return r.json()


def require_login():
    if not session.get("user_email"):
        return redirect(url_for("login"))
    return None


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

    # One-time nonce for fragment-token consumption
    nonce = secrets.token_urlsafe(32)
    session["consume_nonce"] = nonce

    return render_template_string(
        f"""
        <html>
        <body>
          <script>
            // Magic links often land on /login#access_token=...
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
                // remove token fragment from address bar
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
            <input type="hidden" name="csrf_token" value="{{{{ csrf_token() }}}}"/>
            <input name="email" type="email" placeholder="you@company.com" required />
            <button type="submit">Send login link</button>
          </form>
        </body>
        </html>
        """
    )


@app.post("/login")
@limiter.limit("5 per 15 minutes")
def login_post():
    email = (request.form.get("email") or "").strip().lower()

    # Avoid email enumeration: same response either way (+ small delay)
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
    <p>You can close this window.</p>
    """, 200


@app.post("/auth/consume")
@limiter.limit("15 per minute")
def auth_consume():
    """
    One-time token consumption endpoint.
    We do NOT store Supabase tokens. We only store user_email/user_id in Flask session.

    CSRF is intentionally handled by a one-time nonce in the session.
    """
    data = request.get_json(silent=True) or {}
    access_token = (data.get("access_token") or "").strip()
    nonce = (data.get("nonce") or "").strip()

    expected = session.get("consume_nonce")
    session.pop("consume_nonce", None)

    # Nonce check (constant-time)
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

    # Prevent session fixation
    session.clear()
    session.permanent = True
    session["user_email"] = email
    session["user_id"] = user.get("id")

    return {"ok": True}, 200


# Exempt /auth/consume from Flask-WTF CSRF (nonce already protects it)
csrf.exempt(auth_consume)


@app.get("/dashboard")
def dashboard():
    gate = require_login()
    if gate:
        return gate

    email = session.get("user_email") or ""

    return f"""
    <h2>IGS Portal</h2>
    <p>Signed in as: <b>{email}</b></p>

    <h3>Status</h3>
    <ul>
      <li>John Doe — Invitation sent</li>
      <li>Jane Smith — In progress</li>
      <li>Dan Smith — Complete — <a href="#" onclick="alert('Later: deep link to Certn'); return false;">View report</a></li>
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
    app.run(host="0.0.0.0", port=5000)
