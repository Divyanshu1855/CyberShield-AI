
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from functools import wraps
from database import (
    init_db,
    create_user,
    get_user,
    save_scan,
    get_user_scans
)

import os
import re
import joblib


# --------------------------------
# FLASK CONFIGURATION
# --------------------------------

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "cybershield-development-secret-change-before-deployment"
)

# Initialize SQLite database
init_db()


# --------------------------------
# LOAD ML MODEL
# --------------------------------

model = joblib.load("phishing_model.pkl")


# --------------------------------
# LOGIN REQUIRED DECORATOR
# --------------------------------

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            flash("Please login to continue.", "warning")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


# --------------------------------
# URL FEATURE EXTRACTION
# --------------------------------

def extract_features(url):

    length = len(url)

    has_ip = 1 if re.search(
        r'\d+\.\d+\.\d+\.\d+',
        url
    ) else 0

    https = 1 if url.lower().startswith("https://") else 0

    suspicious_words = [
        "login",
        "verify",
        "bank",
        "free",
        "offer"
    ]

    suspicious = 1 if any(
        word in url.lower()
        for word in suspicious_words
    ) else 0

    return [[length, has_ip, https, suspicious]]


# --------------------------------
# RISK SCORE CALCULATION
# --------------------------------

def calculate_risk_score(features, prediction):

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

    return score


# --------------------------------
# HOME / URL SCANNER
# --------------------------------

@app.route("/", methods=["GET", "POST"])
@login_required
def home():

    result = ""
    score = 0
    scanned_url = ""

    if request.method == "POST":

        scanned_url = request.form.get("url", "").strip()

        if not scanned_url:
            flash("Please enter a URL to scan.", "warning")

        elif len(scanned_url) > 2048:
            flash("URL is too long.", "warning")

        else:
            try:
                features = extract_features(scanned_url)

                prediction = int(model.predict(features)[0])

                result = "SAFE" if prediction == 0 else "PHISHING"

                score = calculate_risk_score(
                    features,
                    prediction
                )

                # Save scan in SQLite for current user
                save_scan(
                    session["user_id"],
                    scanned_url,
                    result,
                    score
                )

            except Exception:
                app.logger.exception("Scanning error")
                result = ""
                score = 0
                flash("Unable to scan this URL. Please try again.", "danger")

    return render_template(
        "index.html",
        result=result,
        score=score,
        scanned_url=scanned_url
    )


# --------------------------------
# USER REGISTRATION
# --------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "danger")
            return render_template("register.html")

        password_hash = generate_password_hash(password)

        created = create_user(
            name,
            email,
            password_hash
        )

        if created:
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("login"))

        flash("Email already registered.", "warning")

    return render_template("register.html")


# --------------------------------
# USER LOGIN
# --------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = get_user(email)

        if user and check_password_hash(
            user["password"],
            password
        ):

            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["user_email"] = user["email"]

            flash("Login successful!", "success")

            return redirect(url_for("home"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html")


# --------------------------------
# USER LOGOUT
# --------------------------------

@app.route("/logout")
@login_required
def logout():

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("login"))


# --------------------------------
# USER DASHBOARD
# --------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    try:
        history = get_user_scans(session["user_id"])

    except Exception:
        app.logger.exception("Dashboard error")
        history = []
        flash("Could not load scan history.", "danger")

    total_scans = len(history)

    phishing_count = sum(
        1 for item in history
        if item["result"] == "PHISHING"
    )

    safe_count = sum(
        1 for item in history
        if item["result"] == "SAFE"
    )

    return render_template(
        "dashboard.html",
        history=history,
        total_scans=total_scans,
        phishing_count=phishing_count,
        safe_count=safe_count,
        user_name=session.get("user_name")
    )


# --------------------------------
# RUN APPLICATION
# --------------------------------

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
