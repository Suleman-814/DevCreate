import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# Load dataset
df = pd.read_csv("data/cicids2017_cleaned.csv")

# Use features that can be derived from live flows
live_features = [
    "Flow Duration",                # total flow time
    "Total Fwd Packets",            # packets in forward direction
    "Total Length of Fwd Packets",  # total bytes in forward packets
    "Fwd Packet Length Mean",       # mean length of forward packets
    "Bwd Packet Length Mean",       # mean length of backward packets
    "Flow Bytes/s",                 # bytes per second
    "Flow Packets/s",               # packets per second
    "FIN Flag Count",               # FIN packets
    "ACK Flag Count",               # ACK packets
    "PSH Flag Count"                # PSH packets
]

X = df[live_features]

# Train Isolation Forest
if_model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
if_model.fit(X)

# Save the model
joblib.dump(if_model, "models/if_model_live.joblib")
print("✅ Isolation Forest (live features) saved to models/if_model_live.joblib")
+