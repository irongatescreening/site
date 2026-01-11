import os
import time
from datetime import timedelta

import jwt
import requests
from flask import Flask, request, session, redirect, url_for

app = Flask(__name__)

# -------------------------
# Config
# -------------------------
app.secret_key = os.environ["FLASK_SECRET_KEY"]

SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
SUPABASE_ANON_KEY = os.environ["SUPABASE_ANON_KEY"]
SUPABASE_JWT_SECRET = os.environ["SUPABASE_JWT_SECRET"]

SITE_URL = os.environ.get("SITE_URL", "https://portal.irongatescreening.com").rstrip("/")
AUTH_REDIRECT_TO = os.environ.get("AUTH_REDIRECT_TO", f"{SITE_URL}/auth/callback").rstrip("/")

ALLOWLIST = {e.strip().lower() for e in os.environ.get("ALLOWLIST_EMAILS", "").split(",") if e.strip()}

# Cookie hardening
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

cookie_domain = os.environ.get("SESSION_COOKIE_DOMAIN")
if cookie_domain:
    app.config["SESSION_COOKIE_DOMAIN"] = cookie_domain

# Optional: timebox our own session to reduce risk
app.permanent_session_lifetime = timedelta(hours=8)


def is_allowed(email: str) -> bool:
    return email and email.strip().lower() in ALLOWLIST


def send_magic_link(email: str) -> None:
    """
    Sends a magic link via Supabase /otp endpoint.
    Supabase will email the user and redirect them to AUTH_REDIRECT_TO with tokens in URL fragment.
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
        raise RuntimeError(r.text)


def verify_supabase_jwt(access_token: str) -> dict:
    """
    Verify Supabase JWT signature server-side.
    Returns decoded payload if valid.
    """
    # Supabase uses HS256 with the project's JWT secret by default
    return jwt.decode(access_token, SUPABASE_JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False})


@app.get("/")
def home():
    if session.get("user_email"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.get("/login")
def login():
    return """
    <h2>IGS Portal Login</h2>
    <p>Invite-only access. Enter your email to receive a secure sign-in link.</p>
    <form method="POST" action="/login">
      <input name="email" type="email" placeholder="you@company.com" required />
      <button type="submit">Send login link</button>
    </form>
    """


@app.post("/login")
def login_post():
    email = (request.form.get("email") or "").strip().lower()

    # Don’t reveal whether allowlisted (prevents enumeration)
    if not is_allowed(email):
        time.sleep(1)
        return """
        <h3>If that email is authorized, you’ll receive a sign-in link shortly.</h3>
        """, 200

    try:
        send_magic_link(email)
    except Exception:
        return "<h3>Could not send login link. Try again.</h3>", 500

    return """
    <h3>Check your email</h3>
    <p>If your email is authorized, you’ll receive a secure sign-in link shortly.</p>
    """


@app.get("/auth/callback")
def auth_callback():
    """
    Supabase magic link returns tokens in the URL fragment (#access_token=...),
    which the server can't read directly.
    We solve that by serving a tiny page that POSTs the fragment to /auth/consume.
    """
    return """
    <html><body>
    <script>
      // Extract token data from URL fragment and send to server
      const fragment = new URLSearchParams(window.location.hash.slice(1));
      const access_token = fragment.get('access_token');
      if (!access_token) {
        document.body.innerHTML = "<h3>Login failed. Missing token.</h3>";
      } else {
        fetch('/auth/consume', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({access_token})
        }).then(() => window.location = '/dashboard')
          .catch(() => document.body.innerHTML = "<h3>Login failed.</h3>");
      }
    </script>
    </body></html>
    """


@app.post("/auth/consume")
def auth_consume():
    data = request.get_json(silent=True) or {}
    access_token = data.get("access_token")
    if not access_token:
        return {"ok": False}, 400

    try:
        payload = verify_supabase_jwt(access_token)
    except Exception:
        return {"ok": False}, 401

    email = (payload.get("email") or "").strip().lower()
    if not is_allowed(email):
        session.clear()
        return {"ok": False}, 403

    # Only store minimal identity server-side (status-only portal)
    session.permanent = True
    session["user_email"] = email
    session["sub"] = payload.get("sub")

    return {"ok": True}, 200


@app.get("/dashboard")
def dashboard():
    if not session.get("user_email"):
        return redirect(url_for("login"))

    email = session["user_email"]

    return f"""
    <h2>IGS Portal</h2>
    <p>Signed in as: <b>{email}</b></p>

    <h3>Status (MVP)</h3>
    <ul>
      <li>John Doe — Invitation sent</li>
      <li>Jane Smith — In progress</li>
      <li>Dan Smith — Complete — <a href="#" onclick="alert('Next: View Report deep-link'); return false;">View report</a></li>
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


if __name__ == "__main__":
    # local dev
    app.run(host="0.0.0.0", port=5000, debug=True)
