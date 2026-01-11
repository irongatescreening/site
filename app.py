import os
import time
import secrets
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
AUTH_REDIRECT_TO = (os.environ.get("AUTH_REDIRECT_TO") or f"{SITE_URL}/auth/callback").rstrip("/")
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
# Flask config
# -------------------------
app.secret_key = FLASK_SECRET_KEY
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Invite-only allowlist
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
        raise RuntimeError(f"Supabase OTP failed: {r.status_code} {r.text}")


def supabase_get_user(access_token: str) -> dict:
    url = f"{SUPABASE_URL}/auth/v1/user"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {access_token}",
    }
    r = requests.get(url, headers=headers, timeout=15)
    if r.status_code != 200:
        raise RuntimeError(f"Supabase /user failed: {r.status_code} {r.text}")
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
def login_post():
    email = (request.form.get("email") or "").strip().lower()

    if not is_allowed_email(email):
        time.sleep(1)
        return "<h3>If that email is authorized, you’ll receive a sign-in link shortly.</h3>", 200

    try:
        supabase_send_magic_link(email)
    except Exception:
        app.logger.exception("Supabase OTP send failed")
        return "<h3>Could not send login link. Try again.</h3>", 500

    return "<h3>Check your email for your secure login link.</h3>"


@app.post("/auth/consume")
def auth_consume():
    data = request.get_json(silent=True) or {}
    access_token = (data.get("access_token") or "").strip()
    nonce = (data.get("nonce") or "").strip()

    expected = session.get("consume_nonce")
    session.pop("consume_nonce", None)
    if not expected or nonce != expected:
        return {"ok": False}, 400

    try:
        user = supabase_get_user(access_token)
    except Exception:
        app.logger.exception("Supabase user fetch failed")
        return {"ok": False}, 401

    email = (user.get("email") or "").strip().lower()
    if not is_allowed_email(email):
        session.clear()
        return {"ok": False}, 403

    session["user_email"] = email
    session["user_id"] = user.get("id")
    return {"ok": True}, 200


@app.get("/dashboard")
def dashboard():
    gate = require_login()
    if gate:
        return gate

    email = session.get("user_email")
    return f"""
    <h2>IGS Portal</h2>
    <p>Signed in as <b>{email}</b></p>
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
