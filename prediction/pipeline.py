import pickle
import os

# Correct model path (since this file is inside /prediction)
model_path = os.path.join(os.path.dirname(__file__), "..", "model.pkl")

with open(model_path, "rb") as f:
    model = pickle.load(f)

def predict_url(features):
    return model.predict([features])[0]
