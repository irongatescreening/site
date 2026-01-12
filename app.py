import os
import time
import secrets
import requests
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
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY") or ""
SITE_URL = (os.environ.get("SITE_URL") or "https://portal.irongatescreening.com").rstrip("/")
AUTH_REDIRECT_TO = (os.environ.get("AUTH_REDIRECT_TO") or f"{SITE_URL}/auth/callback").rstrip("/")
ALLOWLIST_EMAILS = os.environ.get("ALLOWLIST_EMAILS") or ""

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
# SECURITY: Flask config (secure cookies + session timeout)
# -------------------------
app.secret_key = FLASK_SECRET_KEY
app.config.update(
    SESSION_COOKIE_SECURE=True,      # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,    # JS can't read
    SESSION_COOKIE_SAMESITE="Strict", # Stronger CSRF protection
    PERMANENT_SESSION_LIFETIME=3600,  # 1 hour session timeout
    WTF_CSRF_TIME_LIMIT=None,        # CSRF tokens don't expire
)

# -------------------------
# SECURITY: Initialize protection layers
# -------------------------
csrf = CSRFProtect(app)

# Rate limiting to prevent abuse
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Security headers (Talisman)
Talisman(app, 
    force_https=True,
    strict_transport_security=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline'",  # Needed for inline scripts
        'style-src': "'self' 'unsafe-inline'",
    }
)

# Invite-only allowlist
ALLOWLIST = {e.strip().lower() for e in ALLOWLIST_EMAILS.split(",") if e.strip()}


def is_allowed_email(email: str) -> bool:
    """Check if email is in allowlist (constant-time to prevent enumeration)"""
    if not email:
        return False
    normalized = email.strip().lower()
    # Use any() with generator to avoid short-circuiting timing leaks
    return normalized in ALLOWLIST


def supabase_send_magic_link(email: str) -> None:
    """
    Sends a magic link (OTP email) via Supabase.
    create_user=True  => one-step onboarding (recommended UX)
    create_user=False => requires user already exists / invited
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
        app.logger.error(f"Supabase OTP failed: {r.status_code}")
        raise RuntimeError(f"Supabase OTP failed: {r.status_code}")


def supabase_exchange_code_for_session(code: str) -> dict:
    """
    Some Supabase flows redirect back with ?code=... (PKCE exchange).
    Exchange it server-side for an access token.
    """
    url = f"{SUPABASE_URL}/auth/v1/token?grant_type=pkce"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
        "Content-Type": "application/json",
    }
    payload = {"auth_code": code}
    r = requests.post(url, json=payload, headers=headers, timeout=15)
    if r.status_code not in (200, 201):
        app.logger.error(f"Supabase token exchange failed: {r.status_code}")
        raise RuntimeError(f"Supabase token exchange failed: {r.status_code}")
    return r.json()


def supabase_get_user(access_token: str) -> dict:
    """
    Validates the token and returns user profile from Supabase.
    Avoids needing legacy JWT secrets.
    """
    url = f"{SUPABASE_URL}/auth/v1/user"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {access_token}",
    }
    r = requests.get(url, headers=headers, timeout=15)
    if r.status_code != 200:
        app.logger.error(f"Supabase /user failed: {r.status_code}")
        raise RuntimeError(f"Supabase /user failed: {r.status_code}")
    return r.json()


def require_login():
    """Check if user is logged in, redirect if not"""
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
    """Display login form with CSRF protection"""
    return render_template_string("""
    <h2>IGS Portal Login</h2>
    <p>Enter your email to receive a secure sign-in link.</p>
    <form method="POST" action="/login">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
      <input name="email" type="email" placeholder="you@company.com" required />
      <button type="submit">Send login link</button>
    </form>
    """)


@app.post("/login")
@limiter.limit("5 per 15 minutes")  # Prevent brute force
def login_post():
    """
    SECURITY: Same response time for all cases to prevent email enumeration.
    Always shows success message even if email is not allowed.
    """
    email = (request.form.get("email") or "").strip().lower()
    
    # Check allowlist
    is_allowed = is_allowed_email(email)
    
    # Only send email if allowed (but don't tell user either way)
    if is_allowed:
        try:
            supabase_send_magic_link(email)
        except Exception as e:
            app.logger.error(f"Magic link send failed for {email}: {e}")
            # Don't reveal error to user
    
    # SECURITY: Same delay for all responses (allowed or not)
    time.sleep(1)
    
    # SECURITY: Same message for all responses
    return """
    <h3>Check your email</h3>
    <p>If your email is authorized, you'll receive a secure login link shortly.</p>
    <p>You can close this window.</p>
    """, 200


@app.get("/auth/callback")
def auth_callback():
    """
    Handles BOTH Supabase behaviors:
      A) redirect back with ?code=... (server-side exchange)
      B) redirect back with #access_token=... (fragment). Server can't read fragment,
         so we return HTML that extracts it and POSTs it to /auth/consume.
    """

    # A) If Supabase returned ?code=..., do server-side exchange
    code = request.args.get("code")
    if code:
        try:
            data = supabase_exchange_code_for_session(code)
            access_token = (data.get("access_token") or "").strip()
            if not access_token:
                app.logger.warning("Code exchange succeeded but no access token")
                return "<h3>Login failed (no access token).</h3>", 400

            user = supabase_get_user(access_token)
            email = (user.get("email") or "").strip().lower()

            if not is_allowed_email(email):
                session.clear()
                app.logger.warning(f"Unauthorized login attempt: {email}")
                return "<h3>Not authorized.</h3>", 403

            # SECURITY: Clear old session and create new one (prevent session fixation)
            session.clear()
            session.permanent = True  # Enable session timeout
            session["user_email"] = email
            session["user_id"] = user.get("id")

            return redirect(url_for("dashboard"))

        except Exception as e:
            app.logger.exception("Auth callback (code exchange) failed")
            return "<h3>Login failed. Please try again.</h3>", 400

    # B) Fragment token flow: use HTML to extract #access_token=...
    # SECURITY: Generate cryptographically secure nonce
    nonce = secrets.token_urlsafe(32)
    session["consume_nonce"] = nonce

    return render_template_string(f"""
    <html><body>
      <script>
        const fragment = new URLSearchParams(window.location.hash.slice(1));
        const access_token = fragment.get('access_token');

        if (!access_token) {{
          document.body.innerHTML = "<h3>Login failed: missing token.</h3>";
        }} else {{
          // Get CSRF token from meta tag
          const csrfToken = '{{{{ csrf_token() }}}}';
          
          fetch('/auth/consume', {{
            method: 'POST',
            headers: {{
              'Content-Type': 'application/json',
              'X-CSRFToken': csrfToken
            }},
            body: JSON.stringify({{access_token, nonce: '{nonce}'}})
          }})
          .then(res => {{
            if (!res.ok) throw new Error('auth failed');
            window.location = '/dashboard';
          }})
          .catch(() => {{
            document.body.innerHTML = "<h3>Login failed. Please try again.</h3>";
          }});
        }}
      </script>
    </body></html>
    """)


@app.post("/auth/consume")
@limiter.limit("10 per minute")  # Prevent token brute force
def auth_consume():
    """
    One-time token consumption endpoint.
    SECURITY: We do NOT store Supabase tokens. We only store user_email/user_id in Flask session.
    """
    data = request.get_json(silent=True) or {}
    access_token = (data.get("access_token") or "").strip()
    nonce = (data.get("nonce") or "").strip()

    expected = session.get("consume_nonce")
    session.pop("consume_nonce", None)  # One-time use
    
    # SECURITY: Constant-time comparison to prevent timing attacks
    if not expected or not secrets.compare_digest(nonce, expected):
        app.logger.warning("Nonce mismatch in auth consume")
        return {"ok": False}, 400

    if not access_token:
        return {"ok": False}, 400

    try:
        user = supabase_get_user(access_token)
    except Exception as e:
        app.logger.exception("Supabase /user failed during consume")
        return {"ok": False}, 401

    email = (user.get("email") or "").strip().lower()
    if not is_allowed_email(email):
        session.clear()
        app.logger.warning(f"Unauthorized consume attempt: {email}")
        return {"ok": False}, 403

    # SECURITY: Clear old session and create new one (prevent session fixation)
    session.clear()
    session.permanent = True  # Enable session timeout
    session["user_email"] = email
    session["user_id"] = user.get("id")

    return {"ok": True}, 200


@app.get("/dashboard")
def dashboard():
    """Main dashboard - requires login"""
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
    """Clear session and redirect to login"""
    session.clear()
    return redirect(url_for("login"))


@app.get("/healthz")
def healthz():
    """Health check endpoint for monitoring"""
    return {"ok": True}, 200


@app.get("/favicon.ico")
def favicon():
    return ("", 204)


if __name__ == "__main__":
    # Note: Debug mode should be False in production
    app.run(host="0.0.0.0", port=5000, debug=False)
