from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import os
import time
import requests
import jwt

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

import base64
import mimetypes

# Replicate for image generation
REPLICATE_API_TOKEN = os.environ.get("REPLICATE_API_TOKEN", "")

# Folder for AI-generated room transformation images
app.config["GENERATED_FOLDER"] = "static/generated"
os.makedirs(app.config["GENERATED_FOLDER"], exist_ok=True)



@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    print(f"FLASK User: {getattr(current_user, 'email', 'Anonymous')} | Authenticated: {current_user.is_authenticated}")

    if request.method == "POST":
        file = request.files.get("photo")
        party_prompt = (request.form.get("partyPrompt") or "").strip()

        if not file or file.filename == "":
            return render_template("upload.html", user=current_user, success=False)

        # 1. Save the uploaded file
        filename = file.filename
        filepath = os.path.abspath(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        file.seek(0)
        file.save(filepath)
        print(f"Filepath: {filepath}")

        ai_feedback = "Here's your transformed room!"
        generated_filename = None

        # 2. Generate transformed room image using Replicate Flux img2img
        # Flux requires HIGH denoising (0.95+) for visible changes - 0.7 gives almost no change
        transform_prompt = (
            f"The same room fully decorated for a party: {party_prompt}. "
            "Add balloons, streamers, string lights, a party table with food and cake, "
            "colorful decorations, festive lighting, party supplies. "
            "Photorealistic interior photography, well lit, vibrant party atmosphere."
        )

        try:
            import replicate
            if not REPLICATE_API_TOKEN:
                raise ValueError("REPLICATE_API_TOKEN not set. Add it to your environment.")
            with open(filepath, "rb") as f:
                output = replicate.run(
                    "bxclib2/flux_img2img:0ce45202d83c6bd379dfe58f4c0c41e6cadf93ebbd9d938cc63cc0f2fcb729a5",
                    input={
                        "image": f,
                        "positive_prompt": transform_prompt,
                        "denoising": 0.95,
                        "steps": 30,
                    },
                )
            if not output:
                raise ValueError("Replicate returned no output")

            # Replicate returns FileOutput - use .read() for bytes or .url to fetch
            img_bytes = None
            if hasattr(output, "read"):
                img_bytes = output.read()
            elif hasattr(output, "url"):
                img_resp = requests.get(str(output.url), timeout=60)
                img_resp.raise_for_status()
                img_bytes = img_resp.content
            elif isinstance(output, (list, tuple)) and output:
                item = output[0]
                if hasattr(item, "read"):
                    img_bytes = item.read()
                elif hasattr(item, "url"):
                    img_resp = requests.get(str(item.url), timeout=60)
                    img_resp.raise_for_status()
                    img_bytes = img_resp.content
                else:
                    img_resp = requests.get(str(item), timeout=60)
                    img_resp.raise_for_status()
                    img_bytes = img_resp.content
            else:
                out_str = str(output)
                if out_str.startswith("data:"):
                    # Data URL: data:image/png;base64,...
                    header, b64 = out_str.split(",", 1)
                    img_bytes = base64.b64decode(b64)
                else:
                    img_resp = requests.get(out_str, timeout=60)
                    img_resp.raise_for_status()
                    img_bytes = img_resp.content

            if not img_bytes or len(img_bytes) < 100:
                raise ValueError("Replicate returned empty or invalid image")

            generated_filename = f"transformed_{os.path.splitext(filename)[0]}.png"
            gen_path = os.path.join(app.config["GENERATED_FOLDER"], generated_filename)
            os.makedirs(app.config["GENERATED_FOLDER"], exist_ok=True)
            with open(gen_path, "wb") as out:
                out.write(img_bytes)
        except Exception as e:
            import traceback
            traceback.print_exc()
            ai_feedback = f"Image generation failed: {str(e)}"

        return render_template(
            "upload.html",
            user=current_user,
            success=True,
            filename=filename,
            party_prompt=party_prompt,
            ai_feedback=ai_feedback,
            generated_filename=generated_filename,
        )

    return render_template("upload.html", user=current_user, success=False)

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