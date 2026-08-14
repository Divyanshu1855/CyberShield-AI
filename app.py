from flask import Flask, render_template, request
import re
import joblib

app = Flask(__name__)

model = joblib.load("phishing_model.pkl")

history = []


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


@app.route("/", methods=["GET", "POST"])
def home():

    result = ""
    score = 0

    if request.method == "POST":

        url = request.form["url"]

        features = extract_features(url)

        prediction = model.predict(features)[0]

        if prediction == 0:
            result = "SAFE"
        else:
            result = "PHISHING"

        # Dynamic risk score
        length, has_ip, https, suspicious = features[0]

        score = 0

        # URL length
        if length > 75:
            score += 25
        elif length > 50:
            score += 15
        elif length > 30:
            score += 5

        # IP address
        if has_ip:
            score += 30

        # HTTPS
        if not https:
            score += 20

        # Suspicious keywords
        if suspicious:
            score += 25

        # Limit score
        score = min(score, 100)

        # ML phishing prediction
        if prediction == 1:
            score = max(score, 70)

        history.append({
            "url": url,
            "result": result,
            "score": score
        })

    return render_template(
        "index.html",
        result=result,
        score=score
    )


@app.route("/dashboard")
def dashboard():

    return render_template(
        "dashboard.html",
        history=history
    )


if __name__ == "__main__":
    app.run(debug=True)