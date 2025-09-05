# train_rf_ids.py

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from joblib import dump
import time

def train_model(input_file, model_path, n_estimators=100, max_depth=None, test_size=0.2):
    print("Loading dataset...")
    df = pd.read_csv(input_file)
    
    # Prepare features and labels
    X = df[["packets", "bytes", "duration", "pps", "bps", "mean_iat", "var_iat", 
            "syn_ratio", "ack_ratio", "payload_bytes"]].values
    y = df['label'].values
    
    # Scale the features for better performance
    print("Scaling features...")
    scaler = StandardScaler()
    X = scaler.fit_transform(X)
    
    # Save the scaler for future use
    dump(scaler, 'models/scaler.joblib')
    
    # Split into train and test sets
    print("Splitting dataset...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42, stratify=y)
    
    print(f"Training with {len(X_train)} samples...")
    print(f"Testing with {len(X_test)} samples...")
    
    # Create and train Random Forest model
    start_time = time.time()
    
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight='balanced',  # Handles imbalanced classes
        n_jobs=-1,  # Use all CPU cores
        random_state=42
    )
    
    print("Training Random Forest model...")
    model.fit(X_train, y_train)
    
    training_time = time.time() - start_time
    print(f"Training completed in {training_time:.2f} seconds")
    
    # Save the model
    print(f"Saving model to {model_path}")
    dump(model, model_path)
    
    # Calculate and print training scores
    train_score = model.score(X_train, y_train)
    test_score = model.score(X_test, y_test)
    
    print("\nTraining Summary:")
    print(f"Training accuracy: {train_score:.4f}")
    print(f"Testing accuracy: {test_score:.4f}")
    
    # Print feature importance
    feature_names = ["packets", "bytes", "duration", "pps", "bps", "mean_iat", 
                    "var_iat", "syn_ratio", "ack_ratio", "payload_bytes"]
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    print("\nFeature Importance:")
    for f in range(len(feature_names)):
        print(f"{feature_names[indices[f]]:<15} {importances[indices[f]]:.4f}")
    
    return model, scaler

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Train Random Forest IDS model')
    parser.add_argument('--input', default='data/processed_dataset.csv',
                      help='Path to the processed dataset CSV file')
    parser.add_argument('--model-output', default='models/rf_model.joblib',
                      help='Path where to save the trained model')
    parser.add_argument('--n-estimators', type=int, default=100,
                      help='Number of trees in the forest')
    parser.add_argument('--max-depth', type=int, default=None,
                      help='Maximum depth of trees. None for unlimited.')
    parser.add_argument('--test-size', type=float, default=0.2,
                      help='Proportion of dataset to use for testing')
    
    args = parser.parse_args()
    
    train_model(
        input_file=args.input,
        model_path=args.model_output,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        test_size=args.test_size
    )
