import os
import secrets
import time
from urllib.parse import urlencode

import requests
from flask import Flask, request, session, redirect, url_for, abort

app = Flask(__name__)

# -------------------------
# Security & session config
# -------------------------
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

app.config.update(
    SESSION_COOKIE_SECURE=True,      # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,    # JS can't read
    SESSION_COOKIE_SAMESITE="Lax",   # CSRF protection
)

# If you want the cookie to apply only to the portal subdomain:
# app.config["SESSION_COOKIE_DOMAIN"] = "portal.irongatescreening.com"

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
SITE_URL = os.environ.get("SITE_URL", "https://portal.irongatescreening.com").rstrip("/")
REDIRECT_TO = os.environ.get("AUTH_REDIRECT_TO", f"{SITE_URL}/auth/callback").rstrip("/")

# Comma-separated allowlist: "client1@x.com,client2@y.com"
ALLOWLIST = {e.strip().lower() for e in os.environ.get("ALLOWLIST_EMAILS", "").split(",") if e.strip()}


def is_allowed_email(email: str) -> bool:
    if not email:
        return False
    return email.strip().lower() in ALLOWLIST


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
        "create_user": False,  # Invite-only: do not create new users
        "data": {},            # optional metadata
        "redirect_to": REDIRECT_TO,
    }
    r = requests.post(url, json=payload, headers=headers, timeout=10)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Supabase OTP send failed: {r.status_code} {r.text}")


def supabase_exchange_code_for_session(auth_code: str) -> dict:
    """
    Supabase sends user back with ?code=... (PKCE code).
    Exchange it for a session server-side.
    """
    url = f"{SUPABASE_URL}/auth/v1/token?grant_type=pkce"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
        "Content-Type": "application/json",
    }
    # code_verifier must match what we generated at login time
    code_verifier = session.get("pkce_code_verifier")
    if not code_verifier:
        raise RuntimeError("Missing PKCE code_verifier in session. Start login again.")

    payload = {
        "auth_code": auth_code,
        "code_verifier": code_verifier,
    }

    r = requests.post(url, json=payload, headers=headers, timeout=10)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Supabase token exchange failed: {r.status_code} {r.text}")

    return r.json()


def require_login():
    if not session.get("user_email"):
        return redirect(url_for("login"))
    return None


@app.get("/")
def home():
    if session.get("user_email"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.get("/login")
def login():
    # super simple HTML to keep MVP moving
    return """
    <h2>IGS Portal Login</h2>
    <p>Enter your email to receive a secure sign-in link.</p>
    <form method="POST" action="/login">
      <input name="email" type="email" placeholder="you@company.com" required />
      <button type="submit">Send login link</button>
    </form>
    """


@app.post("/login")
def login_post():
    email = (request.form.get("email") or "").strip().lower()

    # Invite-only gate
    if not is_allowed_email(email):
        # Do NOT reveal allowlist existence (prevents email enumeration)
        time.sleep(1)
        return """
        <h3>If that email is authorized, you’ll receive a sign-in link shortly.</h3>
        <p>You can close this window.</p>
        """, 200

    # Generate PKCE verifier/challenge for this session
    # For Supabase PKCE, we store only verifier server-side.
    verifier = secrets.token_urlsafe(64)
    session["pkce_code_verifier"] = verifier

    # Supabase expects a "code_challenge" = base64url(sha256(verifier))
    # But when using the /otp endpoint, Supabase can handle PKCE behind the scenes if we pass redirect_to.
    # To be safe and explicit, we attach it via query string on redirect_to.
    # However Supabase accepts code_challenge in the otp payload for PKCE flows.
    # We'll compute and include it.
    import hashlib
    import base64

    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("utf-8")

    # Store challenge too (not strictly required, but helps debug)
    session["pkce_code_challenge"] = challenge

    # Send magic link
    url = f"{SUPABASE_URL}/auth/v1/otp"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "email": email,
        "create_user": False,  # invite-only
        "redirect_to": REDIRECT_TO,
        "code_challenge": challenge,
        "code_challenge_method": "s256",
    }

    r = requests.post(url, json=payload, headers=headers, timeout=10)
    if r.status_code not in (200, 201):
        # show generic error
        return "<h3>Could not send login link. Try again.</h3>", 500

    return """
    <h3>Check your email</h3>
    <p>If your email is authorized, you’ll receive a secure login link shortly.</p>
    """


@app.get("/auth/callback")
def auth_callback():
    # Supabase redirects back with ?code=... for PKCE exchange
    code = request.args.get("code")
    if not code:
        return "<h3>Missing code. Please start login again.</h3>", 400

    try:
        data = supabase_exchange_code_for_session(code)
    except Exception:
        return "<h3>Login failed. Please try again.</h3>", 400

    user = data.get("user") or {}
    email = (user.get("email") or "").strip().lower()

    # Re-check allowlist at callback time (defense in depth)
    if not is_allowed_email(email):
        session.clear()
        return "<h3>Not authorized.</h3>", 403

    # IMPORTANT: Do not store access/refresh tokens in session.
    # We only store the minimal identity needed for status-only portal.
    session["user_email"] = email
    session["user_id"] = user.get("id")

    # Rotate PKCE verifier after use
    session.pop("pkce_code_verifier", None)
    session.pop("pkce_code_challenge", None)

    return redirect(url_for("dashboard"))


@app.get("/dashboard")
def dashboard():
    gate = require_login()
    if gate:
        return gate

    email = session.get("user_email")

    # Placeholder: status-only dashboard
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


if __name__ == "__main__":
    # local dev
    app.run(host="0.0.0.0", port=5000, debug=True)
