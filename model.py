import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib


data = {
    "length": [20, 25, 80, 90, 100, 30, 120],
    "has_ip": [0, 0, 1, 1, 1, 0, 1],
    "https": [1, 1, 0, 0, 0, 1, 0],
    "suspicious_words": [0, 0, 1, 1, 1, 0, 1],
    "label": [0, 0, 1, 1, 1, 0, 1]
}


df = pd.DataFrame(data)

X = df.drop("label", axis=1)
y = df["label"]


model = RandomForestClassifier(
    random_state=42
)

model.fit(X, y)

joblib.dump(
    model,
    "phishing_model.pkl"
)

print("Model saved successfully!")