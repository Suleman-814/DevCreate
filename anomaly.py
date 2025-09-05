#anomaly.py

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from joblib import dump, load

FEATURES = ["packets","bytes","duration","pps","bps","mean_iat","var_iat","syn_ratio","ack_ratio","payload_bytes"]

def to_vec(flow_row):
    return np.array([flow_row[f] for f in FEATURES], dtype = float)

def train_model(train_csv: str, model_path: str, contamination=0.03, epochs=5):
    df = pd.read_csv(train_csv)
    X = df[FEATURES].astype(float).values
    model = None
    for _ in range(epochs):
        model = IsolationForest(
            n_estimators = 200,
            contamination=contamination,
            random_state = 42,
            n_jobs = -1
        ).fit(X)
        dump(model, model_path)
        return model
    
def load_model(model_path: str):
    return load(model_path)

def score_flow(model, flow_row):
    vec = to_vec(flow_row).reshape(1,-1)
    score = -model.score_samples(vec)[0]
    return float(score)