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

        prediction = model.predict(
            extract_features(url)
        )[0]

        if prediction == 0:
            result = "SAFE"
            score = 20
        else:
            result = "PHISHING"
            score = 90

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