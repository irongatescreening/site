import os
import time
import requests
from flask import Flask, request, session, redirect, url_for

app = Flask(__name__)

# -------------------------
# REQUIRED ENV VARS (Render)
# -------------------------
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
SUPABASE_URL = (os.environ.get("SUPABASE_URL") or "").rstrip("/")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY") or ""
SITE_URL = (os.environ.get("SITE_URL") or "https://portal.irongatescreening.com").rstrip("/")
AUTH_REDIRECT_TO = (os.environ.get("AUTH_REDIRECT_TO") or f"{SITE_URL}/auth/callback").rstrip(
    "/"
)
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
# Flask config (secure cookies)
# -------------------------
app.secret_key = FLASK_SECRET_KEY
app.config.update(
    SESSION_COOKIE_SECURE=True,  # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,  # JS can't read
    SESSION_COOKIE_SAMESITE="Lax",  # CSRF mitigation
)

# If you want cookies limited to only portal.irongatescreening.com:
# app.config["SESSION_COOKIE_DOMAIN"] = "portal.irongatescreening.com"

# Invite-only allowlist
ALLOWLIST = {e.strip().lower() for e in ALLOWLIST_EMAILS.split(",") if e.strip()}


def is_allowed_email(email: str) -> bool:
    return bool(email) and email.strip().lower() in ALLOWLIST


def supabase_send_magic_link(email: str) -> None:
    """
    Sends a magic link (OTP email) via Supabase.
    NOTE: This does NOT create new users (invite-only).
    """
    url = f"{SUPABASE_URL}/auth/v1/otp"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "email": email,
        "create_user": False,  # invite-only
        "redirect_to": AUTH_REDIRECT_TO,
    }
    r = requests.post(url, json=payload, headers=headers, timeout=10)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Supabase OTP send failed: {r.status_code} {r.text}")


def supabase_get_user(access_token: str) -> dict:
    """
    Uses Supabase to validate the token and return the user profile.
    This avoids legacy JWT secret requirements.
    """
    url = f"{SUPABASE_URL}/auth/v1/user"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {access_token}",
    }
    r = requests.get(url, headers=headers, timeout=10)
    if r.status_code != 200:
        raise RuntimeError(f"Supabase /user failed: {r.status_code} {r.text}")
    return r.json()


def require_login():
    if not session.get("user_email"):
        return redirect(url_for("login"))
    return None


@app.route("/")
def home():
    if session.get("user_email"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET"])
def login():
    return """
    <h2>IGS Portal Login</h2>
    <p>Enter your email to receive a secure sign-in link.</p>
    <form method="POST" action="/login">
      <input name="email" type="email" placeholder="you@company.com" required />
      <button type="submit">Send login link</button>
    </form>
    """


@app.route("/login", methods=["POST"])
def login_post():
    email = (request.form.get("email") or "").strip().lower()
    print("SUPABASE OTP:", r.status_code, r.text)


    # Invite-only gate (avoid email enumeration)
    if not is_allowed_email(email):
        time.sleep(1)
        return """
        <h3>If that email is authorized, you’ll receive a sign-in link shortly.</h3>
        <p>You can close this window.</p>
        """, 200

    try:
        supabase_send_magic_link(email)
    except Exception:
        # Generic error (don’t leak details)
        return "<h3>Could not send login link. Try again.</h3>", 500

    return """
    <h3>Check your email</h3>
    <p>If your email is authorized, you’ll receive a secure login link shortly.</p>
    """


@app.route("/auth/callback", methods=["GET"])
def auth_callback():
    """
    Supabase magic links commonly return tokens in the URL fragment (#access_token=...).
    The server cannot read fragments, so this page extracts the token and POSTs it to /auth/consume.
    """
    return """
    <html><body>
      <script>
        const fragment = new URLSearchParams(window.location.hash.slice(1));
        const access_token = fragment.get('access_token');

        if (!access_token) {
          document.body.innerHTML = "<h3>Login failed: missing token.</h3>";
        } else {
          fetch('/auth/consume', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({access_token})
          })
          .then(res => {
            if (!res.ok) throw new Error('auth failed');
            window.location = '/dashboard';
          })
          .catch(() => {
            document.body.innerHTML = "<h3>Login failed. Please try again.</h3>";
          });
        }
      </script>
    </body></html>
    """


@app.route("/auth/consume", methods=["POST"])
def auth_consume():
    """
    One-time token consumption endpoint.
    We do NOT store Supabase tokens. We only store user_email/user_id in Flask session.
    """
    data = request.get_json(silent=True) or {}
    access_token = data.get("access_token")
    if not access_token:
        return {"ok": False}, 400

    try:
        user = supabase_get_user(access_token)
    except Exception:
        return {"ok": False}, 401

    email = (user.get("email") or "").strip().lower()
    if not is_allowed_email(email):
        session.clear()
        return {"ok": False}, 403

    # Store minimal identity only (status-only portal)
    session["user_email"] = email
    session["user_id"] = user.get("id")

    return {"ok": True}, 200


@app.route("/dashboard", methods=["GET"])
def dashboard():
    gate = require_login()
    if gate:
        return gate

    email = session.get("user_email") or ""

    # Status-only dashboard placeholder
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


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/healthz", methods=["GET"])
def healthz():
    return {"ok": True}, 200


if __name__ == "__main__":
    # Local dev only. Render uses gunicorn start command.
    app.run(host="0.0.0.0", port=5000, debug=True)
