from flask import Flask, render_template, request
import pickle
from urllib.parse import urlparse
from collections import Counter
import math
from extract_features import extract_features
import tldextract  # To extract TLD properly

app = Flask(__name__)

# Load trained model
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

# --- Helper Functions ---

def shannon_entropy(s):
    if not s:
        return 0
    probabilities = [freq / len(s) for freq in Counter(s).values()]
    return -sum(p * math.log2(p) for p in probabilities)

def is_gibberish(domain):
    main = domain.split(".")[0]
    entropy = shannon_entropy(main)
    return entropy > 3.5  # Tune this if needed

def has_suspicious_tld(url):
    tld = tldextract.extract(url).suffix
    return tld in ["xyz", "zip", "buzz", "tk", "ml", "ga", "cf", "gq"]  # Expandable

# --- Routes ---

@app.route("/", methods=["GET", "POST"])
def index():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    url = request.form["url"]
    domain = urlparse(url).netloc
    if domain.startswith("www."):
        domain = domain[4:]

    reason = None
    if is_gibberish(domain):
        reason = "gibberish domain name"
    elif has_suspicious_tld(url):
        reason = "suspicious TLD"

    if reason:
        result = "Suspicious Website ⚠️"
        features = [f"❌ URL flagged due to {reason} — prediction skipped."]
    else:
        features = extract_features(url)
        prediction = model.predict([features])[0]
        result = "Legitimate Website ✅" if prediction == -1 else "Suspicious Website ⚠️"

    return render_template("index.html", prediction=result, features=features, url=url)

if __name__ == "__main__":
    app.run(debug=True)
