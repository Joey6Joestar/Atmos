from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import os
import time
import requests
import jwt
from jwt.algorithms import RSAAlgorithm

from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Needed for sessions + flash messages
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")

# File uploads
app.config["UPLOAD_FOLDER"] = "static/uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# SQLite DB
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///partynow.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Login manager setup
login_manager = LoginManager()
login_manager.login_view = "login"  # where to redirect if not logged in
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))

# ---------- Supabase token verification (SECURE) ----------
JWKS_CACHE = {"keys": None, "fetched_at": 0}

def get_jwks():
    # Cache for 1 hour
    if JWKS_CACHE["keys"] and (time.time() - JWKS_CACHE["fetched_at"] < 3600):
        return JWKS_CACHE["keys"]

    jwks_url = "https://vvdagrkxsppogpkdjhzg.supabase.co/auth/v1/.well-known/jwks.json"
    resp = requests.get(jwks_url, timeout=10)
    resp.raise_for_status()
    jwks = resp.json()

    JWKS_CACHE["keys"] = jwks["keys"]
    JWKS_CACHE["fetched_at"] = time.time()
    return JWKS_CACHE["keys"]

def verify_supabase_access_token(access_token: str):
    header = jwt.get_unverified_header(access_token)
    kid = header.get("kid")
    alg = header.get("alg")

    if not kid or not alg:
        raise Exception("Token header missing kid/alg")

    keys = get_jwks()
    key_dict = next((k for k in keys if k.get("kid") == kid), None)
    if not key_dict:
        raise Exception("No matching public key (kid)")

    # Supabase projects can use RSA or EC keys
    if key_dict.get("kty") == "RSA":
        public_key = RSAAlgorithm.from_jwk(key_dict)
    else:
        public_key = jwt.algorithms.ECAlgorithm.from_jwk(key_dict)

    payload = jwt.decode(
        access_token,
        public_key,
        algorithms=[alg],
        audience="authenticated",
        issuer="https://vvdagrkxsppogpkdjhzg.supabase.co/auth/v1",
    )
    return payload
# ---------------------------------------------------------

@app.route("/")
def splash():
    return render_template("splash.html", user=current_user)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not email or not password:
            flash("Email and password are required.")
            return redirect(url_for("signup"))

        existing = User.query.filter_by(email=email).first()
        if existing:
            flash("That email is already registered. Please log in.")
            return redirect(url_for("login"))

        user = User(
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()

        flash("Account created successfully! Please log in.")
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid email or password.")
            return redirect(url_for("login"))

        login_user(user)
        return redirect(url_for("upload"))

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("splash"))

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    # You can delete this print later once you're done debugging
    print("FLASK current_user:", current_user.is_authenticated, getattr(current_user, "email", None))

    if request.method == "POST":
        file = request.files.get("photo")
        party_prompt = (request.form.get("partyPrompt") or "").strip()

        if not file or file.filename == "":
            return render_template(
                "upload.html",
                user=current_user,
                success=False,
                filename=None,
                party_prompt=None
            )

        filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(filepath)

        return render_template(
            "upload.html",
            user=current_user,
            success=True,
            filename=file.filename,
            party_prompt=party_prompt
        )

    return render_template(
        "upload.html",
        user=current_user,
        success=False,
        filename=None,
        party_prompt=None
    )

@app.route("/auth/supabase-login", methods=["POST"])
def supabase_login():
    data = request.get_json(silent=True) or {}
    access_token = data.get("access_token")

    if not access_token:
        return jsonify({"ok": False, "error": "Missing access_token"}), 400

    try:
        payload = verify_supabase_access_token(access_token)
    except Exception as e:
        return jsonify({"ok": False, "error": f"Invalid token: {e}"}), 401

    email = (payload.get("email") or "").strip().lower()
    if not email:
        return jsonify({"ok": False, "error": "No email in token"}), 400

    # 🔒 Allowlist check
    ALLOWED_EMAILS = {
        "akshaycgupta46@gmail.com",
    }

    if email not in ALLOWED_EMAILS:
        return jsonify({"ok": False, "error": "Access denied"}), 403

    # Find or create user
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(
            email=email,
            password_hash=generate_password_hash(os.urandom(24).hex())
        )
        db.session.add(user)
        db.session.commit()

    login_user(user)
    return jsonify({"ok": True})

@app.route("/auth/callback")
def oauth_callback():
    return render_template("auth_callback.html")

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)