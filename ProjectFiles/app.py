from flask import Flask, render_template, request, redirect, url_for, flash
import os

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
    return render_template("upload.html", user=current_user)

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)