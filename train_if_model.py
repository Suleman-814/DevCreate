# train_if_model.py
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# Load dataset
df = pd.read_csv("data/cicids2017_cleaned.csv")

# Select only numeric features for Isolation Forest
X = df.select_dtypes(include=['int64', 'float64'])

# Train Isolation Forest
if_model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
if_model.fit(X)

# Save model
joblib.dump(if_model, "models/if_model.joblib")
print("✅ Isolation Forest model saved to models/if_model.joblib")
