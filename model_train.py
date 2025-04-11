import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import accuracy_score
import pickle

# Load dataset
df = pd.read_csv("phishingData.csv")

# Replace 0 with -1 for legitimate websites
df['Result'] = df['Result'].replace(0, -1)

# Features and labels
X = df.drop("Result", axis=1)
y = df["Result"]

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Grid Search for best Random Forest
param_grid = {
    "n_estimators": [100, 150, 200],
    "max_depth": [8, 10, 12],
    "min_samples_split": [2, 4],
    "min_samples_leaf": [1, 2],
}
grid = GridSearchCV(RandomForestClassifier(random_state=42), param_grid, cv=3, n_jobs=-1, verbose=1)
grid.fit(X_train, y_train)

# Best model
model = grid.best_estimator_

# Evaluate
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"✅ Model trained with accuracy: {acc:.4f}")

# Save model
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

print("📦 Model saved as model.pkl")
