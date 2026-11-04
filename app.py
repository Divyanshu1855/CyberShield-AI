from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from functools import wraps
from bson.objectid import ObjectId
from dotenv import load_dotenv

import os
import re
import joblib

from database import (
    users,
    create_user,
    get_user,
    save_scan,
    get_user_scans
)

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("SECRET_KEY is missing from .env")

model = joblib.load("phishing_model.pkl")


# Login protection
def login_required(route):
    @wraps(route)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            return redirect(url_for("login"))

        return route(*args, **kwargs)

    return wrapper


# URL feature extraction
def extract_features(url):

    length = len(url)

    has_ip = 1 if re.search(
        r'\d+\.\d+\.\d+\.\d+',
        url
    ) else 0

    https = 1 if url.startswith("https") else 0

    suspicious = 1 if any(
        word in url.lower()
        for word in ['login', 'verify', 'bank', 'free', 'offer']
    ) else 0

    return [[length, has_ip, https, suspicious]]


# Registration
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("Please fill all fields.")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        try:
            success = create_user(
                name,
                email,
                hashed_password
            )

            if success:
                flash("Registration successful. Please login.")
                return redirect(url_for("login"))

            flash("Email already registered.")

        except Exception:
            app.logger.exception("Registration failed")
            flash("Unable to register. Please try again.")

    return render_template("register.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        try:
            user = get_user(email)

            if user and check_password_hash(
                user["password"], password
            ):

                session.clear()
                session["user_id"] = str(user["_id"])
                session["user_name"] = user["name"]

                return redirect(url_for("home"))

            flash("Invalid email or password.")

        except Exception:
            app.logger.exception("Login failed")
            flash("Unable to login. Please try again.")

    return render_template("login.html")


# Logout
@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# Home / Scanner
@app.route("/", methods=["GET", "POST"])
@login_required
def home():

    result = ""
    score = 0

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if not url or len(url) > 2048:
            flash("Please enter a valid URL (maximum 2048 characters).")
            return redirect(url_for("home"))

        features = extract_features(url)

        prediction = model.predict(features)[0]

        if prediction == 0:
            result = "SAFE"
        else:
            result = "PHISHING"

        length, has_ip, https, suspicious = features[0]

        score = 0

        if length > 75:
            score += 25
        elif length > 50:
            score += 15
        elif length > 30:
            score += 5

        if has_ip:
            score += 30

        if not https:
            score += 20

        if suspicious:
            score += 25

        score = min(score, 100)

        if prediction == 1:
            score = max(score, 70)

        save_scan(
            session["user_id"],
            url,
            result,
            score
        )

    return render_template(
        "index.html",
        result=result,
        score=score
    )


# Dashboard
@app.route("/dashboard")
@login_required
def dashboard():

    history = get_user_scans(
        session["user_id"]
    )

    return render_template(
        "dashboard.html",
        history=history
    )


if __name__ == "__main__":
    app.run(debug=True)